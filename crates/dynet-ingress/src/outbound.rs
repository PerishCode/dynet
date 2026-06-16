use std::{future::Future, net::SocketAddr, time::Duration};

use dynet_runtime::{RuntimeState, SelectionDecision};
use tokio::{
    io,
    net::{TcpStream, UdpSocket},
    sync::mpsc,
    time,
};

use crate::{
    push_decision_fields, session_fields, IngressEventKind, OutboundConfig, DATAGRAM_LIMIT,
};

mod graph;
mod shadowsocks;
mod trojan;
mod udp_downstream;
mod vless;
mod vmess;

pub(crate) use graph::GraphOutbound;
use shadowsocks::ShadowsocksOutbound;
use trojan::TrojanOutbound;
pub(crate) use udp_downstream::UdpDownstream;
use vless::VlessOutbound;
use vmess::VmessOutbound;

pub(crate) const DIRECT_OUTBOUND: &str = "direct";

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct DirectOutbound;

#[derive(Debug)]
pub(crate) struct TcpOutboundSession {
    pub target: SocketAddr,
    pub downstream: TcpStream,
    pub decision: SelectionDecision,
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
    pub downstream: UdpDownstream,
    pub downstream_rx: mpsc::Receiver<Vec<u8>>,
    pub decision: SelectionDecision,
    pub runtime: RuntimeState,
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

    fn decision_tag(&self, _decision: &SelectionDecision) -> &'static str {
        self.tag()
    }

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
    Trojan(TrojanOutbound),
    Vless(VlessOutbound),
    Vmess(VmessOutbound),
}

impl TryFrom<OutboundConfig> for OutboundMedium {
    type Error = String;

    fn try_from(config: OutboundConfig) -> Result<Self, Self::Error> {
        match config {
            OutboundConfig::Direct => Ok(Self::Direct(DirectOutbound)),
            OutboundConfig::Shadowsocks(config) => {
                Ok(Self::Shadowsocks(ShadowsocksOutbound::new(config)?))
            }
            OutboundConfig::Trojan(config) => Ok(Self::Trojan(TrojanOutbound::new(config))),
            OutboundConfig::Vless(config) => Ok(Self::Vless(VlessOutbound::new(config)?)),
            OutboundConfig::Vmess(config) => Ok(Self::Vmess(VmessOutbound::new(config)?)),
        }
    }
}

impl OutboundMedium {
    pub(super) async fn handle_tcp_direct(
        &self,
        session: TcpOutboundSession,
    ) -> Result<TcpOutboundOutcome, OutboundError> {
        match self {
            Self::Shadowsocks(outbound) => outbound.handle_tcp_via_direct(session).await,
            Self::Trojan(outbound) => outbound.handle_tcp_via_direct(session).await,
            Self::Vmess(outbound) => outbound.handle_tcp_via_direct(session).await,
            Self::Direct(_) | Self::Vless(_) => Err(OutboundError {
                stage: "outbound-select",
                upstream: None,
                message: format!(
                    "TCP chained graph execution is not implemented for {}",
                    self.tag()
                ),
            }),
        }
    }
}

impl Outbound for OutboundMedium {
    fn tag(&self) -> &'static str {
        match self {
            Self::Direct(outbound) => outbound.tag(),
            Self::Shadowsocks(outbound) => outbound.tag(),
            Self::Trojan(outbound) => outbound.tag(),
            Self::Vless(outbound) => outbound.tag(),
            Self::Vmess(outbound) => outbound.tag(),
        }
    }

    async fn handle_tcp(
        &self,
        session: TcpOutboundSession,
    ) -> Result<TcpOutboundOutcome, OutboundError> {
        match self {
            Self::Direct(outbound) => outbound.handle_tcp(session).await,
            Self::Shadowsocks(outbound) => outbound.handle_tcp(session).await,
            Self::Trojan(outbound) => outbound.handle_tcp(session).await,
            Self::Vless(outbound) => outbound.handle_tcp(session).await,
            Self::Vmess(outbound) => outbound.handle_tcp(session).await,
        }
    }

    async fn handle_udp(
        &self,
        association: UdpOutboundAssociation,
    ) -> Result<UdpOutboundOutcome, OutboundError> {
        match self {
            Self::Direct(outbound) => outbound.handle_udp(association).await,
            Self::Shadowsocks(outbound) => outbound.handle_udp(association).await,
            Self::Trojan(outbound) => outbound.handle_udp(association).await,
            Self::Vless(outbound) => outbound.handle_udp(association).await,
            Self::Vmess(outbound) => outbound.handle_udp(association).await,
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
                        .send_to_peer(&buffer[..size], association.peer)
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
                    push_decision_fields(&mut fields, &association.decision);
                    fields.push(("direction", "upstream-to-client".to_string()));
                    fields.push((
                        "bytes",
                        association
                            .downstream
                            .payload_len(&buffer[..size])
                            .to_string(),
                    ));
                    association
                        .runtime
                        .events()
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
