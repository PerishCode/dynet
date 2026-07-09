use std::net::SocketAddr;

use shadowsocks_prototype::{Client as ShadowsocksClient, ClientConfig, Method, UdpSession};
use tokio::{io, time};

use crate::{ShadowsocksConfig, ShadowsocksMethod, DATAGRAM_LIMIT};

use super::{
    await_relay_idle, count_downstream, relay_udp_response, udp_step, DirectEgress, EgressError,
    EgressNode, TcpDialConnection, TcpDialTarget, TcpDialer, TcpRelayOutcome, TcpRelaySession,
    UdpRelayAssociation, UdpRelayOutcome, UdpStep,
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
                .map_err(|error| shadowsocks_error(error, None).with_plaintext_bytes(error_counts))
        };
        await_relay_idle(relay, byte_counts, session.idle_timeout, upstream_addr).await
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
            .map_err(|error| {
                EgressError::new(
                    "egress-bind",
                    None,
                    format!("failed to bind Shadowsocks UDP socket: {error}"),
                )
            })?;
        upstream_socket
            .connect(self.client.server_endpoint())
            .await
            .map_err(|error| {
                EgressError::new(
                    "egress-connect",
                    None,
                    format!(
                        "failed connecting Shadowsocks UDP server {}: {error}",
                        self.client.server_endpoint()
                    ),
                )
            })?;
        let upstream = upstream_socket.peer_addr().map_err(|error| {
            EgressError::new(
                "egress-connect",
                None,
                format!("failed reading Shadowsocks UDP server address: {error}"),
            )
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
                    upstream_socket.send(&packet).await.map_err(|error| {
                        EgressError::new(
                            "egress-write",
                            Some(upstream),
                            format!("failed sending Shadowsocks UDP packet: {error}"),
                        )
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
        relay_udp_response(association, self.tag(), upstream, &payload, &[]).await
    }

    pub(super) async fn handle_udp_over_ss(
        &self,
        mut association: UdpRelayAssociation,
        underlay: &ShadowsocksEgress,
    ) -> Result<UdpRelayOutcome, EgressError> {
        let final_server = self.resolve_udp_server().await?;
        let upstream_socket = tokio::net::UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0)))
            .await
            .map_err(|error| {
                EgressError::new(
                    "egress-bind",
                    None,
                    format!("failed to bind Shadowsocks UDP socket: {error}"),
                )
            })?;
        upstream_socket
            .connect(underlay.client.server_endpoint())
            .await
            .map_err(|error| {
                EgressError::new(
                    "egress-connect",
                    None,
                    format!(
                        "failed connecting Shadowsocks UDP underlay server {}: {error}",
                        underlay.client.server_endpoint()
                    ),
                )
            })?;
        let upstream = upstream_socket.peer_addr().map_err(|error| {
            EgressError::new(
                "egress-connect",
                None,
                format!("failed reading Shadowsocks UDP underlay address: {error}"),
            )
        })?;
        let mut final_session = self.client.udp_session();
        let mut underlay_session = underlay.client.udp_session();
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
                    Self::send_chained_udp_request(
                        &association,
                        &upstream_socket,
                        &mut final_session,
                        &mut underlay_session,
                        final_server,
                        upstream,
                        &payload,
                    )
                    .await?;
                }
                Ok(UdpStep::Upstream(size)) => {
                    let payload = Self::decode_chained_udp_response(
                        &mut final_session,
                        &mut underlay_session,
                        upstream,
                        final_server,
                        &buffer[..size],
                    )?;
                    self.handle_chained_udp_response(
                        &association,
                        upstream,
                        final_server,
                        &payload,
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

    async fn handle_chained_udp_response(
        &self,
        association: &UdpRelayAssociation,
        upstream: SocketAddr,
        final_server: SocketAddr,
        payload: &[u8],
    ) -> Result<(), EgressError> {
        let fields = [
            ("udpUnderlay", upstream.to_string()),
            ("udpFinalServer", final_server.to_string()),
        ];
        relay_udp_response(association, self.tag(), upstream, payload, &fields).await
    }

    async fn send_chained_udp_request(
        association: &UdpRelayAssociation,
        upstream_socket: &tokio::net::UdpSocket,
        final_session: &mut UdpSession,
        underlay_session: &mut UdpSession,
        final_server: SocketAddr,
        upstream: SocketAddr,
        payload: &[u8],
    ) -> Result<(), EgressError> {
        let inner_packet = final_session
            .encode_udp_datagram(association.target, payload)
            .map_err(|error| {
                shadowsocks_chain_error("egress-udp-inner-encode", error, Some(final_server))
            })?;
        ensure_datagram_limit(
            "egress-udp-inner-encode",
            inner_packet.len(),
            Some(final_server),
        )?;
        let outer_packet = underlay_session
            .encode_udp_datagram(final_server, &inner_packet)
            .map_err(|error| {
                shadowsocks_chain_error("egress-udp-outer-encode", error, Some(upstream))
            })?;
        ensure_datagram_limit(
            "egress-udp-outer-encode",
            outer_packet.len(),
            Some(upstream),
        )?;
        upstream_socket.send(&outer_packet).await.map_err(|error| {
            EgressError::new(
                "egress-udp-outer-write",
                Some(upstream),
                format!("failed sending Shadowsocks UDP underlay packet: {error}"),
            )
        })?;
        Ok(())
    }

    fn decode_chained_udp_response(
        final_session: &mut UdpSession,
        underlay_session: &mut UdpSession,
        upstream: SocketAddr,
        final_server: SocketAddr,
        packet: &[u8],
    ) -> Result<Vec<u8>, EgressError> {
        let outer_payload = underlay_session
            .decode_udp_datagram(packet)
            .map_err(|error| {
                shadowsocks_chain_error("egress-udp-outer-decode", error, Some(upstream))
            })?;
        final_session
            .decode_udp_datagram(&outer_payload)
            .map_err(|error| {
                shadowsocks_chain_error("egress-udp-inner-decode", error, Some(final_server))
            })
    }

    async fn resolve_udp_server(&self) -> Result<SocketAddr, EgressError> {
        let label = self.client.server_endpoint();
        let mut addresses =
            tokio::net::lookup_host((self.client.server_host(), self.client.server_port()))
                .await
                .map_err(|error| {
                    EgressError::new(
                        "egress-udp-inner-resolve",
                        None,
                        format!("failed resolving Shadowsocks UDP server {label}: {error}"),
                    )
                })?;
        addresses.next().ok_or_else(|| {
            EgressError::new(
                "egress-udp-inner-resolve",
                None,
                format!("Shadowsocks UDP server {label} resolved no addresses"),
            )
        })
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
    EgressError::new(error.stage(), upstream, error.to_string())
}

fn shadowsocks_chain_error(
    stage: &'static str,
    error: shadowsocks_prototype::Error,
    upstream: Option<SocketAddr>,
) -> EgressError {
    EgressError::new(stage, upstream, error.to_string())
}

fn ensure_datagram_limit(
    stage: &'static str,
    size: usize,
    upstream: Option<SocketAddr>,
) -> Result<(), EgressError> {
    if size <= DATAGRAM_LIMIT {
        return Ok(());
    }
    Err(EgressError::new(
        stage,
        upstream,
        format!("encoded UDP packet exceeds {DATAGRAM_LIMIT} bytes: {size}"),
    ))
}
