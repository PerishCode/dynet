use std::{future::Future, net::SocketAddr, sync::Arc, time::Duration};

use tokio::{
    io,
    net::{TcpStream, UdpSocket},
    sync::mpsc,
    time,
};

use shadowsocks_prototype::{Client as ShadowsocksClient, ClientConfig, Method};

use crate::{
    session_fields, EventStore, IngressEventKind, OutboundConfig, ShadowsocksConfig,
    ShadowsocksMethod, DATAGRAM_LIMIT,
};

pub(crate) const DIRECT_OUTBOUND: &str = "direct";

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct DirectOutbound;

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct ShadowsocksOutbound {
    client: ShadowsocksClient,
}

#[derive(Debug)]
pub(crate) struct TcpOutboundSession {
    pub target: SocketAddr,
    pub downstream: TcpStream,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct TcpOutboundOutcome {
    pub upstream: SocketAddr,
    pub client_to_upstream_bytes: u64,
    pub upstream_to_client_bytes: u64,
    pub close_reason: &'static str,
}

#[derive(Debug)]
pub(crate) struct UdpOutboundAssociation {
    pub session_id: u64,
    pub inbound: &'static str,
    pub peer: SocketAddr,
    pub target: SocketAddr,
    pub idle_timeout: Duration,
    pub downstream: Arc<UdpSocket>,
    pub downstream_rx: mpsc::Receiver<Vec<u8>>,
    pub events: EventStore,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct UdpOutboundOutcome {
    pub upstream: SocketAddr,
    pub close_reason: &'static str,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct OutboundError {
    pub stage: &'static str,
    pub upstream: Option<SocketAddr>,
    pub message: String,
}

pub(crate) trait Outbound: Clone + Send + Sync + 'static {
    fn tag(&self) -> &'static str;

    fn handle_tcp(
        &self,
        session: TcpOutboundSession,
    ) -> impl Future<Output = Result<TcpOutboundOutcome, OutboundError>> + Send;

    fn handle_udp(
        &self,
        association: UdpOutboundAssociation,
    ) -> impl Future<Output = Result<UdpOutboundOutcome, OutboundError>> + Send;
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum OutboundMedium {
    Direct(DirectOutbound),
    Shadowsocks(ShadowsocksOutbound),
}

impl TryFrom<OutboundConfig> for OutboundMedium {
    type Error = String;

    fn try_from(config: OutboundConfig) -> Result<Self, Self::Error> {
        match config {
            OutboundConfig::Direct => Ok(Self::Direct(DirectOutbound)),
            OutboundConfig::Shadowsocks(config) => {
                Ok(Self::Shadowsocks(ShadowsocksOutbound::new(config)?))
            }
        }
    }
}

impl ShadowsocksOutbound {
    fn new(config: ShadowsocksConfig) -> Result<Self, String> {
        Ok(Self {
            client: ShadowsocksClient::new(ClientConfig {
                server: config.server,
                port: config.port,
                method: shadowsocks_method(config.method),
                password: config.password,
            }),
        })
    }

    fn tag(&self) -> &'static str {
        "ss"
    }
}

impl Outbound for OutboundMedium {
    fn tag(&self) -> &'static str {
        match self {
            Self::Direct(outbound) => outbound.tag(),
            Self::Shadowsocks(outbound) => outbound.tag(),
        }
    }

    async fn handle_tcp(
        &self,
        session: TcpOutboundSession,
    ) -> Result<TcpOutboundOutcome, OutboundError> {
        match self {
            Self::Direct(outbound) => outbound.handle_tcp(session).await,
            Self::Shadowsocks(outbound) => outbound.handle_tcp(session).await,
        }
    }

    async fn handle_udp(
        &self,
        association: UdpOutboundAssociation,
    ) -> Result<UdpOutboundOutcome, OutboundError> {
        match self {
            Self::Direct(outbound) => outbound.handle_udp(association).await,
            Self::Shadowsocks(outbound) => outbound.handle_udp(association).await,
        }
    }
}

impl Outbound for DirectOutbound {
    fn tag(&self) -> &'static str {
        DIRECT_OUTBOUND
    }

    async fn handle_tcp(
        &self,
        mut session: TcpOutboundSession,
    ) -> Result<TcpOutboundOutcome, OutboundError> {
        let mut upstream =
            TcpStream::connect(session.target)
                .await
                .map_err(|error| OutboundError {
                    stage: "outbound-connect",
                    upstream: Some(session.target),
                    message: format!("failed connecting TCP target {}: {error}", session.target),
                })?;
        let (client_to_upstream, upstream_to_client) =
            io::copy_bidirectional(&mut session.downstream, &mut upstream)
                .await
                .map_err(|error| OutboundError {
                    stage: "relay",
                    upstream: Some(session.target),
                    message: format!("TCP relay failed: {error}"),
                })?;
        Ok(TcpOutboundOutcome {
            upstream: session.target,
            client_to_upstream_bytes: client_to_upstream,
            upstream_to_client_bytes: upstream_to_client,
            close_reason: "normal",
        })
    }

    async fn handle_udp(
        &self,
        mut association: UdpOutboundAssociation,
    ) -> Result<UdpOutboundOutcome, OutboundError> {
        let upstream_socket = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0)))
            .await
            .map_err(|error| OutboundError {
                stage: "outbound-bind",
                upstream: None,
                message: format!("failed to bind UDP outbound socket: {error}"),
            })?;
        upstream_socket
            .connect(association.target)
            .await
            .map_err(|error| OutboundError {
                stage: "outbound-connect",
                upstream: Some(association.target),
                message: format!(
                    "failed connecting UDP target {}: {error}",
                    association.target
                ),
            })?;
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
                    upstream_socket
                        .send(&payload)
                        .await
                        .map_err(|error| OutboundError {
                            stage: "outbound-write",
                            upstream: Some(association.target),
                            message: format!("failed sending UDP target datagram: {error}"),
                        })?;
                }
                Ok(UdpStep::Upstream(size)) => {
                    association
                        .downstream
                        .send_to(&buffer[..size], association.peer)
                        .await
                        .map_err(|error| OutboundError {
                            stage: "inbound-write",
                            upstream: Some(association.target),
                            message: format!("failed sending UDP downstream datagram: {error}"),
                        })?;
                    let mut fields = session_fields(
                        association.session_id,
                        association.inbound,
                        self.tag(),
                        association.peer,
                        association.target,
                        association.target,
                    );
                    fields.push(("direction", "upstream-to-client".to_string()));
                    fields.push(("bytes", size.to_string()));
                    association
                        .events
                        .record(IngressEventKind::UdpDatagram, fields);
                }
                Ok(UdpStep::Closed) => {
                    return Ok(UdpOutboundOutcome {
                        upstream: association.target,
                        close_reason: "inbound-closed",
                    });
                }
                Err(_) => {
                    return Ok(UdpOutboundOutcome {
                        upstream: association.target,
                        close_reason: "idle-timeout",
                    });
                }
            }
        }
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
        let outcome = self
            .client
            .relay_tcp(session.downstream, session.target)
            .await
            .map_err(|error| shadowsocks_error(error, None))?;
        Ok(TcpOutboundOutcome {
            upstream: outcome.upstream,
            client_to_upstream_bytes: outcome.client_to_upstream_bytes,
            upstream_to_client_bytes: outcome.upstream_to_client_bytes,
            close_reason: "normal",
        })
    }

    async fn handle_udp(
        &self,
        mut association: UdpOutboundAssociation,
    ) -> Result<UdpOutboundOutcome, OutboundError> {
        let upstream_socket = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0)))
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
                    let packet = self
                        .client
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
                    self.handle_udp_response(&association, upstream, &buffer[..size])
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
        association: &UdpOutboundAssociation,
        upstream: SocketAddr,
        packet: &[u8],
    ) -> Result<(), OutboundError> {
        let payload = self
            .client
            .decode_udp_datagram(packet)
            .map_err(|error| shadowsocks_error(error, Some(upstream)))?;
        association
            .downstream
            .send_to(&payload, association.peer)
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
        fields.push(("direction", "upstream-to-client".to_string()));
        fields.push(("bytes", payload.len().to_string()));
        association
            .events
            .record(IngressEventKind::UdpDatagram, fields);
        Ok(())
    }
}

fn shadowsocks_method(method: ShadowsocksMethod) -> Method {
    match method {
        ShadowsocksMethod::Aes256Gcm => Method::Aes256Gcm,
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

enum UdpStep {
    Downstream(Vec<u8>),
    Upstream(usize),
    Closed,
}

async fn udp_step(
    downstream_rx: &mut mpsc::Receiver<Vec<u8>>,
    upstream_socket: &UdpSocket,
    buffer: &mut [u8],
) -> UdpStep {
    tokio::select! {
        payload = downstream_rx.recv() => match payload {
            Some(payload) => UdpStep::Downstream(payload),
            None => UdpStep::Closed,
        },
        result = upstream_socket.recv(buffer) => match result {
            Ok(size) => UdpStep::Upstream(size),
            Err(_) => UdpStep::Closed,
        },
    }
}
