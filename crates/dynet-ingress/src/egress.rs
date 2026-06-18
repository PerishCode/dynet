use std::{future::Future, net::SocketAddr, time::Duration};

use dynet_runtime::{RuntimeState, SelectionDecision};
use tokio::{
    io::{self, AsyncRead, AsyncWrite},
    net::{TcpStream, UdpSocket},
    sync::mpsc,
    time,
};

use crate::{
    push_decision_fields, session_fields, EgressNodeConfig, IngressEventKind, DATAGRAM_LIMIT,
};

mod graph;
mod shadowsocks;
mod trojan;
mod udp_downstream;
mod vless;
mod vmess;

pub(crate) use graph::GraphEgress;
use shadowsocks::ShadowsocksEgress;
use trojan::TrojanEgress;
pub(crate) use udp_downstream::UdpDownstream;
use vless::VlessEgress;
use vmess::VmessEgress;

pub(crate) const DIRECT_EGRESS: &str = "direct";

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct DirectEgress;

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum TcpDialTarget {
    Socket(SocketAddr),
    Host { host: String, port: u16 },
}

pub(crate) trait TcpStreamIo: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> TcpStreamIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub(crate) enum TcpDialConnection {
    TcpStream {
        stream: TcpStream,
        upstream: SocketAddr,
    },
    Stream {
        stream: Box<dyn TcpStreamIo>,
        upstream: SocketAddr,
    },
}

impl TcpDialConnection {
    pub(crate) fn upstream(&self) -> SocketAddr {
        match self {
            Self::TcpStream { upstream, .. } | Self::Stream { upstream, .. } => *upstream,
        }
    }

    pub(crate) fn into_io(self) -> Box<dyn TcpStreamIo> {
        match self {
            Self::TcpStream { stream, .. } => Box::new(stream),
            Self::Stream { stream, .. } => stream,
        }
    }
}

#[derive(Debug)]
pub(crate) struct TcpRelaySession {
    pub target: SocketAddr,
    pub downstream: TcpStream,
    pub decision: SelectionDecision,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct TcpRelayOutcome {
    pub upstream: SocketAddr,
    pub client_to_upstream_bytes: u64,
    pub upstream_to_client_bytes: u64,
    pub close_reason: &'static str,
}

#[derive(Debug)]
pub(crate) struct UdpRelayAssociation {
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
pub(crate) struct UdpRelayOutcome {
    pub upstream: SocketAddr,
    pub close_reason: &'static str,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct EgressError {
    pub stage: &'static str,
    pub upstream: Option<SocketAddr>,
    pub message: String,
}

pub(crate) trait EgressNode: Clone + Send + Sync + 'static {
    fn tag(&self) -> &'static str;

    fn decision_tag(&self, _decision: &SelectionDecision) -> &'static str {
        self.tag()
    }

    fn handle_tcp(
        &self,
        session: TcpRelaySession,
    ) -> impl Future<Output = Result<TcpRelayOutcome, EgressError>> + Send;

    fn handle_udp(
        &self,
        association: UdpRelayAssociation,
    ) -> impl Future<Output = Result<UdpRelayOutcome, EgressError>> + Send;
}

pub(crate) trait TcpDialer: Send + Sync {
    fn dial_tcp(
        &self,
        target: TcpDialTarget,
    ) -> impl Future<Output = Result<TcpDialConnection, EgressError>> + Send;
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum EgressMedium {
    Direct(DirectEgress),
    Shadowsocks(ShadowsocksEgress),
    Trojan(TrojanEgress),
    Vless(VlessEgress),
    Vmess(VmessEgress),
}

impl TryFrom<EgressNodeConfig> for EgressMedium {
    type Error = String;

    fn try_from(config: EgressNodeConfig) -> Result<Self, Self::Error> {
        match config {
            EgressNodeConfig::Direct => Ok(Self::Direct(DirectEgress)),
            EgressNodeConfig::Shadowsocks(config) => {
                Ok(Self::Shadowsocks(ShadowsocksEgress::new(config)?))
            }
            EgressNodeConfig::Trojan(config) => Ok(Self::Trojan(TrojanEgress::new(config))),
            EgressNodeConfig::Vless(config) => Ok(Self::Vless(VlessEgress::new(config)?)),
            EgressNodeConfig::Vmess(config) => Ok(Self::Vmess(VmessEgress::new(config)?)),
        }
    }
}

impl EgressMedium {
    pub(super) fn tcp_dialer(&self) -> Option<TcpDialerMedium<'_>> {
        match self {
            Self::Direct(dialer) => Some(TcpDialerMedium::Direct(dialer)),
            Self::Shadowsocks(dialer) => Some(TcpDialerMedium::Shadowsocks(dialer)),
            Self::Trojan(dialer) => Some(TcpDialerMedium::Trojan(dialer)),
            Self::Vless(dialer) => Some(TcpDialerMedium::Vless(dialer)),
            Self::Vmess(dialer) => Some(TcpDialerMedium::Vmess(dialer)),
        }
    }

    pub(super) async fn handle_tcp_with_dialer<D>(
        &self,
        session: TcpRelaySession,
        dialer: &D,
    ) -> Result<TcpRelayOutcome, EgressError>
    where
        D: TcpDialer,
    {
        match self {
            Self::Direct(egress) => egress.handle_tcp_with_dialer(session, dialer).await,
            Self::Shadowsocks(egress) => egress.handle_tcp_via_dialer(session, dialer).await,
            Self::Trojan(egress) => egress.handle_tcp_via_dialer(session, dialer).await,
            Self::Vless(egress) => egress.handle_tcp_via_dialer(session, dialer).await,
            Self::Vmess(egress) => egress.handle_tcp_via_dialer(session, dialer).await,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum TcpDialerMedium<'a> {
    Direct(&'a DirectEgress),
    Shadowsocks(&'a ShadowsocksEgress),
    Trojan(&'a TrojanEgress),
    Vless(&'a VlessEgress),
    Vmess(&'a VmessEgress),
}

impl TcpDialer for TcpDialerMedium<'_> {
    async fn dial_tcp(&self, target: TcpDialTarget) -> Result<TcpDialConnection, EgressError> {
        match self {
            Self::Direct(dialer) => dialer.dial_tcp(target).await,
            Self::Shadowsocks(dialer) => dialer.dial_tcp(target).await,
            Self::Trojan(dialer) => dialer.dial_tcp(target).await,
            Self::Vless(dialer) => dialer.dial_tcp(target).await,
            Self::Vmess(dialer) => dialer.dial_tcp(target).await,
        }
    }
}

impl EgressNode for EgressMedium {
    fn tag(&self) -> &'static str {
        match self {
            Self::Direct(egress) => egress.tag(),
            Self::Shadowsocks(egress) => egress.tag(),
            Self::Trojan(egress) => egress.tag(),
            Self::Vless(egress) => egress.tag(),
            Self::Vmess(egress) => egress.tag(),
        }
    }

    async fn handle_tcp(&self, session: TcpRelaySession) -> Result<TcpRelayOutcome, EgressError> {
        match self {
            Self::Direct(egress) => egress.handle_tcp(session).await,
            Self::Shadowsocks(egress) => egress.handle_tcp(session).await,
            Self::Trojan(egress) => egress.handle_tcp(session).await,
            Self::Vless(egress) => egress.handle_tcp(session).await,
            Self::Vmess(egress) => egress.handle_tcp(session).await,
        }
    }

    async fn handle_udp(
        &self,
        association: UdpRelayAssociation,
    ) -> Result<UdpRelayOutcome, EgressError> {
        match self {
            Self::Direct(egress) => egress.handle_udp(association).await,
            Self::Shadowsocks(egress) => egress.handle_udp(association).await,
            Self::Trojan(egress) => egress.handle_udp(association).await,
            Self::Vless(egress) => egress.handle_udp(association).await,
            Self::Vmess(egress) => egress.handle_udp(association).await,
        }
    }
}

impl EgressNode for DirectEgress {
    fn tag(&self) -> &'static str {
        DIRECT_EGRESS
    }

    async fn handle_tcp(&self, session: TcpRelaySession) -> Result<TcpRelayOutcome, EgressError> {
        self.handle_tcp_with_dialer(session, self).await
    }

    async fn handle_udp(
        &self,
        mut association: UdpRelayAssociation,
    ) -> Result<UdpRelayOutcome, EgressError> {
        let upstream_socket = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0)))
            .await
            .map_err(|error| EgressError {
                stage: "egress-bind",
                upstream: None,
                message: format!("failed to bind UDP egress socket: {error}"),
            })?;
        upstream_socket
            .connect(association.target)
            .await
            .map_err(|error| EgressError {
                stage: "egress-connect",
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
                        .map_err(|error| EgressError {
                            stage: "egress-write",
                            upstream: Some(association.target),
                            message: format!("failed sending UDP target datagram: {error}"),
                        })?;
                }
                Ok(UdpStep::Upstream(size)) => {
                    association
                        .downstream
                        .send_to_peer(&buffer[..size], association.peer)
                        .await
                        .map_err(|error| EgressError {
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
                    return Ok(UdpRelayOutcome {
                        upstream: association.target,
                        close_reason: "inbound-closed",
                    });
                }
                Err(_) => {
                    return Ok(UdpRelayOutcome {
                        upstream: association.target,
                        close_reason: "idle-timeout",
                    });
                }
            }
        }
    }
}

impl DirectEgress {
    async fn handle_tcp_with_dialer<D>(
        &self,
        mut session: TcpRelaySession,
        dialer: &D,
    ) -> Result<TcpRelayOutcome, EgressError>
    where
        D: TcpDialer,
    {
        let mut upstream = dialer
            .dial_tcp(TcpDialTarget::Socket(session.target))
            .await?
            .into_io();
        let (client_to_upstream, upstream_to_client) =
            io::copy_bidirectional(&mut session.downstream, &mut upstream)
                .await
                .map_err(|error| EgressError {
                    stage: "relay",
                    upstream: Some(session.target),
                    message: format!("TCP relay failed: {error}"),
                })?;
        Ok(TcpRelayOutcome {
            upstream: session.target,
            client_to_upstream_bytes: client_to_upstream,
            upstream_to_client_bytes: upstream_to_client,
            close_reason: "normal",
        })
    }
}

impl TcpDialer for DirectEgress {
    async fn dial_tcp(&self, target: TcpDialTarget) -> Result<TcpDialConnection, EgressError> {
        let upstream = target.upstream();
        let label = target.label();
        let stream = target.connect().await.map_err(|error| EgressError {
            stage: "egress-connect",
            upstream,
            message: format!("failed dialing TCP target {label}: {error}"),
        })?;
        let upstream = stream.peer_addr().map_err(|error| EgressError {
            stage: "egress-connect",
            upstream,
            message: format!("failed reading TCP target address {label}: {error}"),
        })?;
        Ok(TcpDialConnection::TcpStream { stream, upstream })
    }
}

impl TcpDialTarget {
    pub(crate) async fn resolve_socket(&self) -> Result<SocketAddr, EgressError> {
        match self {
            Self::Socket(address) => Ok(*address),
            Self::Host { host, port } => {
                let label = self.label();
                let mut addresses = tokio::net::lookup_host((host.as_str(), *port))
                    .await
                    .map_err(|error| EgressError {
                        stage: "egress-resolve",
                        upstream: None,
                        message: format!("failed resolving TCP target {label}: {error}"),
                    })?;
                addresses.next().ok_or_else(|| EgressError {
                    stage: "egress-resolve",
                    upstream: None,
                    message: format!("TCP target {label} resolved no addresses"),
                })
            }
        }
    }

    pub(crate) fn host(host: impl Into<String>, port: u16) -> Self {
        Self::Host {
            host: host.into(),
            port,
        }
    }

    fn upstream(&self) -> Option<SocketAddr> {
        match self {
            Self::Socket(address) => Some(*address),
            Self::Host { .. } => None,
        }
    }

    fn label(&self) -> String {
        match self {
            Self::Socket(address) => address.to_string(),
            Self::Host { host, port } => format!("{host}:{port}"),
        }
    }

    async fn connect(self) -> Result<TcpStream, std::io::Error> {
        match self {
            Self::Socket(address) => TcpStream::connect(address).await,
            Self::Host { host, port } => TcpStream::connect((host.as_str(), port)).await,
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
