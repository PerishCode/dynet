use std::net::SocketAddr;

use tokio::{io, sync::mpsc, time};

use vless_prototype::{
    Client as VlessClient, ClientConfig as VlessClientConfig, UdpReader as VlessUdpReader,
};

use crate::{
    egress::{
        await_relay_idle, count_downstream, relay_udp_response, DirectEgress, EgressError,
        EgressNode, TcpDialConnection, TcpDialTarget, TcpDialer, TcpRelayOutcome, TcpRelaySession,
        UdpRelayAssociation, UdpRelayOutcome,
    },
    VlessConfig,
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct VlessEgress {
    client: VlessClient,
}

impl VlessEgress {
    pub(crate) fn new(config: VlessConfig) -> Result<Self, String> {
        Ok(Self {
            client: VlessClient::try_new(VlessClientConfig {
                server: config.server,
                port: config.port,
                uuid: config.uuid,
                server_name: config.server_name,
                public_key: config.public_key,
                short_id: config.short_id,
            })
            .map_err(|error| error.to_string())?,
        })
    }

    fn tag(&self) -> &'static str {
        "vless"
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
        let (parts, mut upstream) = self
            .client
            .connect_tcp_with_io(session.target, upstream_addr, upstream)
            .await
            .map_err(|error| vless_error(error, None))?;
        let (mut downstream, byte_counts) = count_downstream(session.downstream);
        let error_counts = byte_counts.clone();
        let relay = async {
            let (client_to_upstream, upstream_to_client) =
                io::copy_bidirectional(&mut downstream, &mut upstream)
                    .await
                    .map_err(|error| {
                        EgressError::new(
                            "relay",
                            Some(parts.upstream),
                            format!("VLESS TCP relay failed: {error}"),
                        )
                        .with_plaintext_bytes(error_counts)
                    })?;
            Ok(TcpRelayOutcome {
                upstream: parts.upstream,
                client_to_upstream_bytes: client_to_upstream,
                upstream_to_client_bytes: upstream_to_client,
                close_reason: "normal",
            })
        };
        await_relay_idle(relay, byte_counts, session.idle_timeout, parts.upstream).await
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
            .map_err(|error| vless_error(error, Some(upstream_addr)))?;
        self.relay_udp(association, parts.upstream, reader, writer)
            .await
    }

    async fn relay_udp<R, W>(
        &self,
        mut association: UdpRelayAssociation,
        upstream: SocketAddr,
        mut reader: VlessUdpReader<R>,
        mut writer: vless_prototype::UdpWriter<W>,
    ) -> Result<UdpRelayOutcome, EgressError>
    where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        loop {
            let step = time::timeout(
                association.idle_timeout,
                vless_udp_step(&mut association.downstream_rx, &mut reader),
            )
            .await;
            match step {
                Ok(VlessUdpStep::Downstream(payload)) => {
                    writer
                        .write_datagram(&payload)
                        .await
                        .map_err(|error| vless_error(error, Some(upstream)))?;
                }
                Ok(VlessUdpStep::Upstream(payload)) => {
                    relay_udp_response(&association, self.tag(), upstream, &payload, &[]).await?;
                }
                Ok(VlessUdpStep::Closed) => {
                    return Ok(UdpRelayOutcome {
                        upstream,
                        close_reason: "inbound-closed",
                    });
                }
                Ok(VlessUdpStep::ReadError(error)) => {
                    return Err(vless_error(error, Some(upstream)));
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

impl TcpDialer for VlessEgress {
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
        let (_parts, stream) = self
            .client
            .connect_tcp_with_io(target, upstream_addr, upstream)
            .await
            .map_err(|error| vless_error(error, Some(upstream_addr)))?;
        Ok(TcpDialConnection::Stream {
            stream: Box::new(stream),
            upstream: upstream_addr,
        })
    }
}

impl EgressNode for VlessEgress {
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
            .map_err(|error| vless_error(error, None))?;
        self.relay_udp(association, parts.upstream, reader, writer)
            .await
    }
}

fn vless_error(error: vless_prototype::Error, upstream: Option<SocketAddr>) -> EgressError {
    EgressError::new(error.stage(), upstream, error.to_string())
}

enum VlessUdpStep {
    Downstream(Vec<u8>),
    Upstream(Vec<u8>),
    Closed,
    ReadError(vless_prototype::Error),
}

async fn vless_udp_step(
    downstream_rx: &mut mpsc::Receiver<Vec<u8>>,
    reader: &mut VlessUdpReader<impl tokio::io::AsyncRead + Unpin>,
) -> VlessUdpStep {
    tokio::select! {
        payload = downstream_rx.recv() => match payload {
            Some(payload) => VlessUdpStep::Downstream(payload),
            None => VlessUdpStep::Closed,
        },
        result = reader.read_datagram() => match result {
            Ok(payload) => VlessUdpStep::Upstream(payload),
            Err(error) => VlessUdpStep::ReadError(error),
        },
    }
}
