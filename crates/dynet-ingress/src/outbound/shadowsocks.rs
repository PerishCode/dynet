use std::net::SocketAddr;

use shadowsocks_prototype::{Client as ShadowsocksClient, ClientConfig, Method, UdpSession};
use tokio::time;

use crate::{
    push_decision_fields, session_fields, IngressEventKind, ShadowsocksConfig, ShadowsocksMethod,
    DATAGRAM_LIMIT,
};

use super::{
    udp_step, DirectOutbound, Outbound, OutboundError, TcpDialTarget, TcpDialer,
    TcpOutboundOutcome, TcpOutboundSession, UdpOutboundAssociation, UdpOutboundOutcome, UdpStep,
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct ShadowsocksOutbound {
    client: ShadowsocksClient,
}

impl ShadowsocksOutbound {
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
        session: TcpOutboundSession,
        dialer: &D,
    ) -> Result<TcpOutboundOutcome, OutboundError>
    where
        D: TcpDialer,
    {
        let upstream = dialer
            .dial_tcp(TcpDialTarget::host(
                self.client.server_host(),
                self.client.server_port(),
            ))
            .await?;
        let outcome = self
            .client
            .relay_tcp_with_stream(session.downstream, upstream, session.target)
            .await
            .map_err(|error| shadowsocks_error(error, None))?;
        Ok(TcpOutboundOutcome {
            upstream: outcome.upstream,
            client_to_upstream_bytes: outcome.client_to_upstream_bytes,
            upstream_to_client_bytes: outcome.upstream_to_client_bytes,
            close_reason: "normal",
        })
    }
}

impl Outbound for ShadowsocksOutbound {
    fn tag(&self) -> &'static str {
        self.tag()
    }

    async fn handle_tcp(
        &self,
        session: TcpOutboundSession,
    ) -> Result<TcpOutboundOutcome, OutboundError> {
        self.handle_tcp_via_dialer(session, &DirectOutbound).await
    }

    async fn handle_udp(
        &self,
        mut association: UdpOutboundAssociation,
    ) -> Result<UdpOutboundOutcome, OutboundError> {
        let upstream_socket = tokio::net::UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0)))
            .await
            .map_err(|error| OutboundError {
                stage: "outbound-bind",
                upstream: None,
                message: format!("failed to bind Shadowsocks UDP socket: {error}"),
            })?;
        upstream_socket
            .connect(self.client.server_endpoint())
            .await
            .map_err(|error| OutboundError {
                stage: "outbound-connect",
                upstream: None,
                message: format!(
                    "failed connecting Shadowsocks UDP server {}: {error}",
                    self.client.server_endpoint()
                ),
            })?;
        let upstream = upstream_socket.peer_addr().map_err(|error| OutboundError {
            stage: "outbound-connect",
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
                        .map_err(|error| OutboundError {
                            stage: "outbound-write",
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
                    return Ok(UdpOutboundOutcome {
                        upstream,
                        close_reason: "inbound-closed",
                    });
                }
                Err(_) => {
                    return Ok(UdpOutboundOutcome {
                        upstream,
                        close_reason: "idle-timeout",
                    });
                }
            }
        }
    }
}

impl ShadowsocksOutbound {
    async fn handle_udp_response(
        &self,
        udp_session: &mut UdpSession,
        association: &UdpOutboundAssociation,
        upstream: SocketAddr,
        packet: &[u8],
    ) -> Result<(), OutboundError> {
        let payload = udp_session
            .decode_udp_datagram(packet)
            .map_err(|error| shadowsocks_error(error, Some(upstream)))?;
        association
            .downstream
            .send_to_peer(&payload, association.peer)
            .await
            .map_err(|error| OutboundError {
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
) -> OutboundError {
    OutboundError {
        stage: error.stage(),
        upstream,
        message: error.to_string(),
    }
}
