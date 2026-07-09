use std::net::SocketAddr;

use tokio::{io, sync::mpsc, time};

use vmess_prototype::{
    Client as VmessClient, ClientConfig as VmessClientConfig, UdpReader as VmessUdpReader,
};

use crate::{
    egress::{
        await_relay_idle, count_downstream, relay_udp_response, DirectEgress, EgressError,
        EgressNode, TcpDialConnection, TcpDialTarget, TcpDialer, TcpRelayOutcome, TcpRelaySession,
        UdpRelayAssociation, UdpRelayOutcome,
    },
    VmessConfig,
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct VmessEgress {
    client: VmessClient,
}

impl VmessEgress {
    pub(crate) fn new(config: VmessConfig) -> Result<Self, String> {
        Ok(Self {
            client: VmessClient::try_new(VmessClientConfig {
                server: config.server,
                port: config.port,
                uuid: config.uuid,
            })
            .map_err(|error| error.to_string())?,
        })
    }

    fn tag(&self) -> &'static str {
        "vmess"
    }

    pub(super) async fn handle_tcp_via_dialer<D>(
        &self,
        session: TcpRelaySession,
        dialer: &D,
    ) -> Result<TcpRelayOutcome, EgressError>
    where
        D: TcpDialer,
    {
        let upstream = dialer
            .dial_tcp(TcpDialTarget::host(
                self.client.server_host(),
                self.client.server_port(),
            ))
            .await?;
        let upstream_addr = upstream.upstream();
        let upstream = upstream.into_io();
        let (downstream, byte_counts) = count_downstream(session.downstream);
        let error_counts = byte_counts.clone();
        let relay = async {
            self.client
                .relay_tcp_with_io(downstream, upstream_addr, upstream, session.target)
                .await
                .map(|outcome| TcpRelayOutcome {
                    upstream: outcome.upstream,
                    client_to_upstream_bytes: outcome.client_to_upstream_bytes,
                    upstream_to_client_bytes: outcome.upstream_to_client_bytes,
                    close_reason: "normal",
                })
                .map_err(|error| vmess_error(error, None).with_plaintext_bytes(error_counts))
        };
        await_relay_idle(relay, byte_counts, session.idle_timeout, upstream_addr).await
    }

    pub(super) async fn handle_udp_via_dialer<D>(
        &self,
        association: UdpRelayAssociation,
        dialer: &D,
    ) -> Result<UdpRelayOutcome, EgressError>
    where
        D: TcpDialer,
    {
        let upstream = dialer
            .dial_tcp(TcpDialTarget::host(
                self.client.server_host(),
                self.client.server_port(),
            ))
            .await?;
        let upstream_addr = upstream.upstream();
        let upstream = upstream.into_io();
        let (parts, reader, writer) = self
            .client
            .connect_udp_with_io(upstream_addr, upstream, association.target)
            .await
            .map_err(|error| vmess_error(error, Some(upstream_addr)))?;
        self.relay_udp(association, parts.upstream, reader, writer)
            .await
    }

    async fn relay_udp<R, W>(
        &self,
        mut association: UdpRelayAssociation,
        upstream: SocketAddr,
        mut reader: VmessUdpReader<R>,
        mut writer: vmess_prototype::UdpWriter<W>,
    ) -> Result<UdpRelayOutcome, EgressError>
    where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        loop {
            let step = time::timeout(
                association.idle_timeout,
                vmess_udp_step(&mut association.downstream_rx, &mut reader),
            )
            .await;
            match step {
                Ok(VmessUdpStep::Downstream(payload)) => {
                    writer
                        .write_datagram(&payload)
                        .await
                        .map_err(|error| vmess_error(error, Some(upstream)))?;
                }
                Ok(VmessUdpStep::Upstream(payload)) => {
                    relay_udp_response(&association, self.tag(), upstream, &payload, &[]).await?;
                }
                Ok(VmessUdpStep::Closed) => {
                    return Ok(UdpRelayOutcome {
                        upstream,
                        close_reason: "inbound-closed",
                    });
                }
                Ok(VmessUdpStep::ReadError(error)) => {
                    return Err(vmess_error(error, Some(upstream)));
                }
                Err(_) => {
                    return Ok(UdpRelayOutcome {
                        upstream,
                        close_reason: "idle-timeout",
                    });
                }
            }
        }
    }
}

impl TcpDialer for VmessEgress {
    async fn dial_tcp(&self, target: TcpDialTarget) -> Result<TcpDialConnection, EgressError> {
        let target = target.resolve_socket().await?;
        let upstream = DirectEgress
            .dial_tcp(TcpDialTarget::host(
                self.client.server_host(),
                self.client.server_port(),
            ))
            .await?;
        let upstream_addr = upstream.upstream();
        let upstream = upstream.into_io();
        let client = self.client.clone();
        let (dialer_side, relay_side) = io::duplex(64 * 1024);
        tokio::spawn(async move {
            let _ = client
                .relay_tcp_with_io(relay_side, upstream_addr, upstream, target)
                .await;
        });
        Ok(TcpDialConnection::Stream {
            stream: Box::new(dialer_side),
            upstream: upstream_addr,
        })
    }
}

impl EgressNode for VmessEgress {
    fn tag(&self) -> &'static str {
        self.tag()
    }

    async fn handle_tcp(&self, session: TcpRelaySession) -> Result<TcpRelayOutcome, EgressError> {
        self.handle_tcp_via_dialer(session, &DirectEgress).await
    }

    async fn handle_udp(
        &self,
        association: UdpRelayAssociation,
    ) -> Result<UdpRelayOutcome, EgressError> {
        let (parts, reader, writer) = self
            .client
            .connect_udp(association.target)
            .await
            .map_err(|error| vmess_error(error, None))?;
        self.relay_udp(association, parts.upstream, reader, writer)
            .await
    }
}

fn vmess_error(error: vmess_prototype::Error, upstream: Option<SocketAddr>) -> EgressError {
    EgressError::new(error.stage(), upstream, error.to_string())
}

enum VmessUdpStep {
    Downstream(Vec<u8>),
    Upstream(Vec<u8>),
    Closed,
    ReadError(vmess_prototype::Error),
}

async fn vmess_udp_step(
    downstream_rx: &mut mpsc::Receiver<Vec<u8>>,
    reader: &mut VmessUdpReader<impl tokio::io::AsyncRead + Unpin>,
) -> VmessUdpStep {
    tokio::select! {
        payload = downstream_rx.recv() => match payload {
            Some(payload) => VmessUdpStep::Downstream(payload),
            None => VmessUdpStep::Closed,
        },
        result = reader.read_datagram() => match result {
            Ok(payload) => VmessUdpStep::Upstream(payload),
            Err(error) => VmessUdpStep::ReadError(error),
        },
    }
}
