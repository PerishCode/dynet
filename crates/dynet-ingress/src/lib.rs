use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use dynet_runtime::{IngressEventKind, RuntimeState};
use tokio_util::sync::CancellationToken;

mod captured;
mod dns;
mod egress;
mod inbound;
mod socks;

pub use captured::{
    relay_captured_tcp_graph, relay_captured_tcp_reloadable, relay_captured_udp_graph,
    relay_captured_udp_reloadable, CapturedTcpRelayOutcome, CapturedUdpRelayOutcome,
};
pub use dns::{run as run_dns, run_until as run_dns_until};
pub use egress::ReloadableEgress;

const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const DATAGRAM_LIMIT: usize = 65_535;
pub const DEFAULT_TCP_MAX_SESSIONS: usize = 1024;
pub const DEFAULT_UDP_MAX_SESSIONS: usize = 1024;
pub const DEFAULT_SOCKS5_MAX_SESSIONS: usize = 1024;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct DnsRelayConfig {
    pub bind: SocketAddr,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct TcpRelayConfig {
    pub bind: SocketAddr,
    pub upstream: SocketAddr,
    pub max_sessions: usize,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct UdpRelayConfig {
    pub bind: SocketAddr,
    pub upstream: SocketAddr,
    pub idle_timeout: Duration,
    pub max_sessions: usize,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Socks5IngressConfig {
    pub bind: SocketAddr,
    pub udp_advertise_ip: Option<IpAddr>,
    pub idle_timeout: Duration,
    pub max_sessions: usize,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct IngressConfig {
    pub dns: DnsRelayConfig,
    pub tcp: TcpRelayConfig,
    pub udp: UdpRelayConfig,
    pub socks5: Socks5IngressConfig,
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub enum EgressNodeConfig {
    #[default]
    Direct,
    Shadowsocks(ShadowsocksConfig),
    Trojan(TrojanConfig),
    Vless(VlessConfig),
    Vmess(VmessConfig),
}

impl EgressNodeConfig {
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Direct => egress::DIRECT_EGRESS,
            Self::Shadowsocks(_) => "ss",
            Self::Trojan(_) => "trojan",
            Self::Vless(_) => "vless",
            Self::Vmess(_) => "vmess",
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ShadowsocksConfig {
    pub server: String,
    pub port: u16,
    pub method: ShadowsocksMethod,
    pub password: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TrojanConfig {
    pub server: String,
    pub port: u16,
    pub password: String,
    pub sni: Option<String>,
    pub skip_cert_verify: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct VmessConfig {
    pub server: String,
    pub port: u16,
    pub uuid: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct VlessConfig {
    pub server: String,
    pub port: u16,
    pub uuid: String,
    pub server_name: String,
    pub public_key: String,
    pub short_id: String,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ShadowsocksMethod {
    Aes256Gcm,
    Blake3Aes128Gcm2022,
}

impl ShadowsocksMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Aes256Gcm => "aes-256-gcm",
            Self::Blake3Aes128Gcm2022 => "2022-blake3-aes-128-gcm",
        }
    }
}

impl Default for DnsRelayConfig {
    fn default() -> Self {
        Self {
            bind: SocketAddr::from(([127, 0, 0, 1], 1053)),
        }
    }
}

impl Default for TcpRelayConfig {
    fn default() -> Self {
        Self {
            bind: SocketAddr::from(([127, 0, 0, 1], 18080)),
            upstream: SocketAddr::from(([93, 184, 216, 34], 80)),
            max_sessions: DEFAULT_TCP_MAX_SESSIONS,
        }
    }
}

impl Default for UdpRelayConfig {
    fn default() -> Self {
        Self {
            bind: SocketAddr::from(([127, 0, 0, 1], 18443)),
            upstream: SocketAddr::from(([1, 1, 1, 1], 443)),
            idle_timeout: UDP_IDLE_TIMEOUT,
            max_sessions: DEFAULT_UDP_MAX_SESSIONS,
        }
    }
}

impl Default for Socks5IngressConfig {
    fn default() -> Self {
        Self {
            bind: SocketAddr::from(([127, 0, 0, 1], 11080)),
            udp_advertise_ip: None,
            idle_timeout: UDP_IDLE_TIMEOUT,
            max_sessions: DEFAULT_SOCKS5_MAX_SESSIONS,
        }
    }
}

pub async fn run_tcp(config: TcpRelayConfig, runtime: RuntimeState) -> Result<(), String> {
    run_tcp_with_egress(config, EgressNodeConfig::Direct, runtime).await
}

pub async fn run_udp(config: UdpRelayConfig, runtime: RuntimeState) -> Result<(), String> {
    run_udp_with_egress(config, EgressNodeConfig::Direct, runtime).await
}

pub async fn run_socks5(config: Socks5IngressConfig, runtime: RuntimeState) -> Result<(), String> {
    run_socks5_with_egress(config, EgressNodeConfig::Direct, runtime).await
}

pub async fn run_tcp_with_egress(
    config: TcpRelayConfig,
    node_config: EgressNodeConfig,
    runtime: RuntimeState,
) -> Result<(), String> {
    inbound::run_tcp(
        config,
        egress::EgressMedium::try_from(node_config)?,
        runtime,
        CancellationToken::new(),
    )
    .await
}

pub async fn run_tcp_graph(
    config: TcpRelayConfig,
    egress_nodes: BTreeMap<String, EgressNodeConfig>,
    runtime: RuntimeState,
) -> Result<(), String> {
    inbound::run_tcp(
        config,
        egress::GraphEgress::try_from(egress_nodes)?,
        runtime,
        CancellationToken::new(),
    )
    .await
}

pub async fn run_tcp_reloadable(
    config: TcpRelayConfig,
    egress: ReloadableEgress,
    runtime: RuntimeState,
) -> Result<(), String> {
    inbound::run_tcp(config, egress, runtime, CancellationToken::new()).await
}

pub async fn run_tcp_reloadable_until(
    config: TcpRelayConfig,
    egress: ReloadableEgress,
    runtime: RuntimeState,
    shutdown: CancellationToken,
) -> Result<(), String> {
    inbound::run_tcp(config, egress, runtime, shutdown).await
}

pub async fn run_udp_with_egress(
    config: UdpRelayConfig,
    node_config: EgressNodeConfig,
    runtime: RuntimeState,
) -> Result<(), String> {
    inbound::run_udp(
        config,
        egress::EgressMedium::try_from(node_config)?,
        runtime,
        CancellationToken::new(),
    )
    .await
}

pub async fn run_udp_graph(
    config: UdpRelayConfig,
    egress_nodes: BTreeMap<String, EgressNodeConfig>,
    runtime: RuntimeState,
) -> Result<(), String> {
    inbound::run_udp(
        config,
        egress::GraphEgress::try_from(egress_nodes)?,
        runtime,
        CancellationToken::new(),
    )
    .await
}

pub async fn run_udp_reloadable(
    config: UdpRelayConfig,
    egress: ReloadableEgress,
    runtime: RuntimeState,
) -> Result<(), String> {
    inbound::run_udp(config, egress, runtime, CancellationToken::new()).await
}

pub async fn run_udp_reloadable_until(
    config: UdpRelayConfig,
    egress: ReloadableEgress,
    runtime: RuntimeState,
    shutdown: CancellationToken,
) -> Result<(), String> {
    inbound::run_udp(config, egress, runtime, shutdown).await
}

pub async fn run_socks5_with_egress(
    config: Socks5IngressConfig,
    node_config: EgressNodeConfig,
    runtime: RuntimeState,
) -> Result<(), String> {
    socks::run_socks5(
        config,
        egress::EgressMedium::try_from(node_config)?,
        runtime,
        CancellationToken::new(),
    )
    .await
}

pub async fn run_socks5_graph(
    config: Socks5IngressConfig,
    egress_nodes: BTreeMap<String, EgressNodeConfig>,
    runtime: RuntimeState,
) -> Result<(), String> {
    socks::run_socks5(
        config,
        egress::GraphEgress::try_from(egress_nodes)?,
        runtime,
        CancellationToken::new(),
    )
    .await
}

pub async fn run_socks5_reloadable(
    config: Socks5IngressConfig,
    egress: ReloadableEgress,
    runtime: RuntimeState,
) -> Result<(), String> {
    socks::run_socks5(config, egress, runtime, CancellationToken::new()).await
}

pub async fn run_socks5_reloadable_until(
    config: Socks5IngressConfig,
    egress: ReloadableEgress,
    runtime: RuntimeState,
    shutdown: CancellationToken,
) -> Result<(), String> {
    socks::run_socks5(config, egress, runtime, shutdown).await
}

pub(crate) fn session_fields(
    session_id: u64,
    inbound: &'static str,
    node_protocol: &'static str,
    peer: SocketAddr,
    target: SocketAddr,
    upstream: SocketAddr,
) -> Vec<(&'static str, String)> {
    let mut fields = vec![
        ("sessionId", session_id.to_string()),
        ("inbound", inbound.to_string()),
        ("nodeProtocol", node_protocol.to_string()),
        ("peer", peer.to_string()),
        ("target", target.to_string()),
        ("upstream", upstream.to_string()),
    ];
    push_endpoint_fields(&mut fields, "peer", peer);
    push_endpoint_fields(&mut fields, "target", target);
    push_endpoint_fields(&mut fields, "upstream", upstream);
    fields
}

pub(crate) fn push_decision_fields(
    fields: &mut Vec<(&'static str, String)>,
    decision: &dynet_runtime::SelectionDecision,
) {
    fields.push(("decisionId", decision.decision_id.to_string()));
    fields.push(("configGeneration", decision.config_generation.to_string()));
    fields.push(("groupId", decision.group_id.to_string()));
    if let Some(rule_id) = &decision.matched_rule_id {
        fields.push(("matchedRuleId", rule_id.to_string()));
    }
    fields.push(("nodeId", decision.node_id.to_string()));
    fields.push(("groupNext", decision.next.label().to_string()));
    fields.push((
        "selectionTrace",
        decision
            .trace
            .iter()
            .map(|hop| hop.label())
            .collect::<Vec<_>>()
            .join("|"),
    ));
    fields.push((
        "selectionGroups",
        decision
            .trace
            .iter()
            .map(|hop| hop.group_id.to_string())
            .collect::<Vec<_>>()
            .join(","),
    ));
    fields.push((
        "selectionNodes",
        decision
            .trace
            .iter()
            .map(|hop| hop.node_id.to_string())
            .collect::<Vec<_>>()
            .join(","),
    ));
    fields.push(("terminalEgress", decision.terminal.label().to_string()));
    fields.push(("terminalKind", decision.terminal.kind().to_string()));
    fields.push(("selectionReason", decision.reason.as_str().to_string()));
    fields.push(("scheduler", decision.scheduler.as_str().to_string()));
    fields.push(("candidateCount", decision.candidate_count.to_string()));
}

pub(crate) fn push_endpoint_fields(
    fields: &mut Vec<(&'static str, String)>,
    prefix: &'static str,
    address: SocketAddr,
) {
    match prefix {
        "peer" => {
            fields.push(("peerIp", address.ip().to_string()));
            fields.push(("peerPort", address.port().to_string()));
        }
        "upstream" => {
            fields.push(("upstreamIp", address.ip().to_string()));
            fields.push(("upstreamPort", address.port().to_string()));
        }
        "target" => {
            fields.push(("targetIp", address.ip().to_string()));
            fields.push(("targetPort", address.port().to_string()));
        }
        "source" => {
            fields.push(("sourceIp", address.ip().to_string()));
            fields.push(("sourcePort", address.port().to_string()));
        }
        _ => {}
    }
}

pub(crate) fn push_target_context_fields(
    fields: &mut Vec<(&'static str, String)>,
    target: &dynet_runtime::TargetContext,
) {
    fields.push(("targetSource", target.source.as_str().to_string()));
    if let Some(domain) = &target.domain {
        fields.push(("targetDomain", domain.clone()));
    }
}
