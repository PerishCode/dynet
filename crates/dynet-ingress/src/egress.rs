use std::{future::Future, net::SocketAddr, time::Duration};

use dynet_runtime::{RuntimeState, SelectionDecision};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    sync::mpsc,
};

use crate::EgressNodeConfig;

mod direct;
mod graph;
mod observation;
mod reloadable;
mod shadowsocks;
mod trojan;
mod udp_downstream;
mod udp_observation;
mod vless;
mod vmess;

pub(crate) use direct::{udp_step, UdpStep};
pub(crate) use graph::GraphEgress;
pub(crate) use observation::{
    count_downstream, push_egress_error_fields, EgressError, PlaintextByteCounts,
};
pub use reloadable::ReloadableEgress;
use shadowsocks::ShadowsocksEgress;
use trojan::TrojanEgress;
pub(crate) use udp_downstream::UdpDownstream;
pub(super) use udp_observation::relay_udp_response;
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

pub(crate) struct TcpRelaySession {
    pub target: SocketAddr,
    pub downstream: Box<dyn TcpStreamIo>,
    pub decision: SelectionDecision,
    pub idle_timeout: Option<Duration>,
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

pub(crate) async fn await_relay_idle<F>(
    relay: F,
    byte_counts: PlaintextByteCounts,
    idle_timeout: Option<Duration>,
    upstream: SocketAddr,
) -> Result<TcpRelayOutcome, EgressError>
where
    F: Future<Output = Result<TcpRelayOutcome, EgressError>>,
{
    let Some(idle_timeout) = idle_timeout else {
        return relay.await;
    };
    let mut last_client_to_upstream = byte_counts.client_to_upstream();
    let mut last_upstream_to_client = byte_counts.upstream_to_client();
    tokio::pin!(relay);
    loop {
        tokio::select! {
            outcome = &mut relay => return outcome,
            _ = tokio::time::sleep(idle_timeout) => {
                let client_to_upstream = byte_counts.client_to_upstream();
                let upstream_to_client = byte_counts.upstream_to_client();
                if client_to_upstream == last_client_to_upstream
                    && upstream_to_client == last_upstream_to_client
                {
                    return Ok(TcpRelayOutcome {
                        upstream,
                        client_to_upstream_bytes: client_to_upstream,
                        upstream_to_client_bytes: upstream_to_client,
                        close_reason: "idle-timeout",
                    });
                }
                last_client_to_upstream = client_to_upstream;
                last_upstream_to_client = upstream_to_client;
            }
        }
    }
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

    pub(super) async fn handle_udp_with_dialer<D>(
        &self,
        association: UdpRelayAssociation,
        dialer: &D,
    ) -> Result<UdpRelayOutcome, EgressError>
    where
        D: TcpDialer,
    {
        match self {
            Self::Trojan(egress) => egress.handle_udp_via_dialer(association, dialer).await,
            Self::Vless(egress) => egress.handle_udp_via_dialer(association, dialer).await,
            Self::Vmess(egress) => egress.handle_udp_via_dialer(association, dialer).await,
            Self::Direct(_) | Self::Shadowsocks(_) => Err(EgressError::new(
                "egress-select",
                None,
                format!(
                    "UDP final egress {} does not support TCP-dialer underlay",
                    self.tag()
                ),
            )),
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
