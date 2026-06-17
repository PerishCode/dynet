use std::net::SocketAddr;

use shadowsocks_prototype::{Client as ShadowsocksClient, ClientConfig, Method, UdpSession};
use tokio::{io, time};

use crate::{
    push_decision_fields, session_fields, IngressEventKind, ShadowsocksConfig, ShadowsocksMethod,
    DATAGRAM_LIMIT,
};

use super::{
    udp_step, DirectEgress, EgressError, EgressNode, TcpDialConnection, TcpDialTarget, TcpDialer,
    TcpRelayOutcome, TcpRelaySession, UdpRelayAssociation, UdpRelayOutcome, UdpStep,
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct ShadowsocksEgress {
    client: ShadowsocksClient,
}

impl ShadowsocksEgress {
    pub(super) fn new(config: ShadowsocksConfig) -> Result<Self, String> {
        Ok(Self {
            client: ShadowsocksClient::try_new(ClientConfig {
                server: config.server,
                port: config.port,
                method: shadowsocks_method(config.method),
                password: config.password,
            })
            .map_err(|error| error.to_string())?,
        })
    }

    fn tag(&self) -> &'static str {
        "ss"
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
        let outcome = self
            .client
            .relay_tcp_with_io(session.downstream, upstream_addr, upstream, session.target)
            .await
            .map_err(|error| shadowsocks_error(error, None))?;
        Ok(TcpRelayOutcome {
            upstream: outcome.upstream,
            client_to_upstream_bytes: outcome.client_to_upstream_bytes,
            upstream_to_client_bytes: outcome.upstream_to_client_bytes,
            close_reason: "normal",
        })
    }
}

impl TcpDialer for ShadowsocksEgress {
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

impl EgressNode for ShadowsocksEgress {
    fn tag(&self) -> &'static str {
        self.tag()
    }

    async fn handle_tcp(&self, session: TcpRelaySession) -> Result<TcpRelayOutcome, EgressError> {
        self.handle_tcp_via_dialer(session, &DirectEgress).await
    }

    async fn handle_udp(
        &self,
        mut association: UdpRelayAssociation,
    ) -> Result<UdpRelayOutcome, EgressError> {
        let upstream_socket = tokio::net::UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0)))
            .await
            .map_err(|error| EgressError {
                stage: "egress-bind",
                upstream: None,
                message: format!("failed to bind Shadowsocks UDP socket: {error}"),
            })?;
        upstream_socket
            .connect(self.client.server_endpoint())
            .await
            .map_err(|error| EgressError {
                stage: "egress-connect",
                upstream: None,
                message: format!(
                    "failed connecting Shadowsocks UDP server {}: {error}",
                    self.client.server_endpoint()
                ),
            })?;
        let upstream = upstream_socket.peer_addr().map_err(|error| EgressError {
            stage: "egress-connect",
            upstream: None,
            message: format!("failed reading Shadowsocks UDP server address: {error}"),
        })?;
        let mut udp_session = self.client.udp_session();
        let mut buffer = vec![0_u8; DATAGRAM_LIMIT];
        loop {
            let step = time::timeout(
                association.idle_timeout,
                udp_step(
                    &mut association.downstream_rx,
                    &upstream_socket,
                    &mut buffer,
                ),
            )
            .await;
            match step {
                Ok(UdpStep::Downstream(payload)) => {
                    let packet = udp_session
                        .encode_udp_datagram(association.target, &payload)
                        .map_err(|error| shadowsocks_error(error, Some(upstream)))?;
                    upstream_socket
                        .send(&packet)
                        .await
                        .map_err(|error| EgressError {
                            stage: "egress-write",
                            upstream: Some(upstream),
                            message: format!("failed sending Shadowsocks UDP packet: {error}"),
                        })?;
                }
                Ok(UdpStep::Upstream(size)) => {
                    self.handle_udp_response(
                        &mut udp_session,
                        &association,
                        upstream,
                        &buffer[..size],
                    )
                    .await?;
                }
                Ok(UdpStep::Closed) => {
                    return Ok(UdpRelayOutcome {
                        upstream,
                        close_reason: "inbound-closed",
                    });
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

impl ShadowsocksEgress {
    async fn handle_udp_response(
        &self,
        udp_session: &mut UdpSession,
        association: &UdpRelayAssociation,
        upstream: SocketAddr,
        packet: &[u8],
    ) -> Result<(), EgressError> {
        let payload = udp_session
            .decode_udp_datagram(packet)
            .map_err(|error| shadowsocks_error(error, Some(upstream)))?;
        association
            .downstream
            .send_to_peer(&payload, association.peer)
            .await
            .map_err(|error| EgressError {
                stage: "inbound-write",
                upstream: Some(upstream),
                message: format!("failed sending UDP downstream datagram: {error}"),
            })?;
        let mut fields = session_fields(
            association.session_id,
            association.inbound,
            self.tag(),
            association.peer,
            association.target,
            upstream,
        );
        push_decision_fields(&mut fields, &association.decision);
        fields.push(("direction", "upstream-to-client".to_string()));
        fields.push((
            "bytes",
            association.downstream.payload_len(&payload).to_string(),
        ));
        association
            .runtime
            .events()
            .record(IngressEventKind::UdpDatagram, fields);
        Ok(())
    }
}

fn shadowsocks_method(method: ShadowsocksMethod) -> Method {
    match method {
        ShadowsocksMethod::Aes256Gcm => Method::Aes256Gcm,
        ShadowsocksMethod::Blake3Aes128Gcm2022 => Method::Blake3Aes128Gcm2022,
    }
}

fn shadowsocks_error(
    error: shadowsocks_prototype::Error,
    upstream: Option<SocketAddr>,
) -> EgressError {
    EgressError {
        stage: error.stage(),
        upstream,
        message: error.to_string(),
    }
}
