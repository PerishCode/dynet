use std::{
    collections::BTreeMap,
    fmt,
    net::{IpAddr, SocketAddr},
    sync::{Arc, RwLock},
    time::Duration,
};

mod cidr;
mod forward_node;
mod matrix_active;
mod matrix_service;
mod matrix_shadow;
mod matrix_stats;
mod target_context;
use cidr::ip_matches_cidr;
pub(crate) use matrix_active::select_active_candidate;
pub use matrix_service::{MatrixService, SelectorMatrix};
pub(crate) use matrix_shadow::{MatrixCandidateInput, MATRIX_SHADOW_LIMIT};
pub use matrix_shadow::{MatrixShadowCandidate, MatrixShadowDecision};
pub use matrix_stats::{MatrixErrorSignalStats, MatrixNodeStats, MatrixTargetNodeStats};

pub(crate) const DEFAULT_NODE_ID: &str = "default-node";
pub(crate) const DEFAULT_GROUP_ID: &str = "default";

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct NodeId(String);

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct GroupId(String);

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct RuleId(String);

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct DnsUpstreamId(String);

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ForwardNode {
    pub id: NodeId,
    pub tag: String,
    pub enabled: bool,
    pub fingerprint: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ForwardGroup {
    pub id: GroupId,
    pub enabled: bool,
    pub scheduler: SchedulerPolicy,
    pub thresholds: GroupThresholds,
    pub next: NextRef,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct GroupMember {
    pub group_id: GroupId,
    pub node_id: NodeId,
    pub enabled: bool,
    pub priority: u32,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RouteRule {
    pub id: RuleId,
    pub priority: i64,
    pub enabled: bool,
    pub matcher: RouteMatcher,
    pub group_id: GroupId,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum RouteMatcher {
    DomainExact(String),
    DomainSuffix(String),
    IpExact(IpAddr),
    IpCidr(String),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DnsUpstream {
    pub id: DnsUpstreamId,
    pub address: SocketAddr,
    pub transport: DnsUpstreamTransport,
    pub enabled: bool,
    pub priority: u32,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum DnsUpstreamTransport {
    Udp,
    Https(DnsHttpsEndpoint),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DnsHttpsEndpoint {
    pub host: String,
    pub path: String,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct DnsRacePolicy {
    pub timeout: Duration,
    pub strategy: DnsRaceStrategy,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum DnsRaceStrategy {
    Parallel,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SchedulerPolicy {
    SingleFirstEnabled,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct GroupThresholds {
    pub min_success_rate_ppm: u32,
    pub min_samples: u64,
    pub max_active_sessions: Option<u64>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum NextRef {
    DirectAuditOutlet,
    Named(String),
}

#[derive(Debug, Clone, Default)]
pub struct ObservedDnsMap {
    inner: Arc<RwLock<BTreeMap<String, Vec<IpAddr>>>>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TargetContext {
    pub address: SocketAddr,
    pub domain: Option<String>,
    pub source: TargetSource,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum TargetSource {
    FixedUpstream,
    ObservedDns,
    ExternalContext,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum InboundKind {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SelectionContext {
    pub session_id: u64,
    pub inbound: InboundKind,
    pub target: TargetContext,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RuntimeSeed {
    pub nodes: Vec<ForwardNode>,
    pub default_group_id: GroupId,
    pub groups: Vec<ForwardGroup>,
    pub group_members: Vec<GroupMember>,
    pub route_rules: Vec<RouteRule>,
    pub dns_upstreams: Vec<DnsUpstream>,
    pub dns_policy: DnsRacePolicy,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SelectionDecision {
    pub decision_id: u64,
    pub group_id: GroupId,
    pub matched_rule_id: Option<RuleId>,
    pub node_id: NodeId,
    pub next: NextRef,
    pub trace: Vec<SelectionTraceHop>,
    pub terminal: SelectionTerminal,
    pub reason: SelectionReason,
    pub scheduler: SchedulerPolicy,
    pub candidate_count: usize,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SelectionTraceHop {
    pub group_id: GroupId,
    pub node_id: NodeId,
    pub next: NextRef,
    pub scheduler: SchedulerPolicy,
    pub candidate_count: usize,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum SelectionTerminal {
    DirectAuditOutlet,
    Node(NodeId),
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SelectionReason {
    SingleNode,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SelectionError {
    message: String,
}

impl NodeId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl GroupId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl RuleId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl DnsUpstreamId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl fmt::Display for GroupId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl fmt::Display for RuleId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl fmt::Display for DnsUpstreamId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl ForwardGroup {
    pub(crate) fn default_group() -> Self {
        Self {
            id: GroupId::new(DEFAULT_GROUP_ID),
            enabled: true,
            scheduler: SchedulerPolicy::SingleFirstEnabled,
            thresholds: GroupThresholds::default(),
            next: NextRef::DirectAuditOutlet,
        }
    }
}

impl GroupMember {
    pub(crate) fn default_member(node_id: NodeId, group_id: GroupId) -> Self {
        Self {
            group_id,
            node_id,
            enabled: true,
            priority: 0,
        }
    }
}

impl RouteMatcher {
    pub(crate) fn matches(&self, target: &TargetContext) -> bool {
        match self {
            Self::DomainExact(domain) => target
                .domain
                .as_deref()
                .is_some_and(|target_domain| target_domain.eq_ignore_ascii_case(domain)),
            Self::DomainSuffix(suffix) => target.domain.as_deref().is_some_and(|domain| {
                domain.eq_ignore_ascii_case(suffix)
                    || domain
                        .to_ascii_lowercase()
                        .ends_with(&format!(".{}", suffix.to_ascii_lowercase()))
            }),
            Self::IpExact(address) => target.address.ip() == *address,
            Self::IpCidr(cidr) => ip_matches_cidr(target.address.ip(), cidr),
        }
    }
}

impl RuntimeSeed {
    pub fn single_node(tag: impl Into<String>) -> Self {
        let node = ForwardNode::new(DEFAULT_NODE_ID, tag, true);
        let group = ForwardGroup::default_group();
        let member = GroupMember::default_member(node.id.clone(), group.id.clone());
        Self {
            nodes: vec![node],
            default_group_id: group.id.clone(),
            groups: vec![group],
            group_members: vec![member],
            route_rules: Vec::new(),
            dns_upstreams: default_dns_upstreams(),
            dns_policy: DnsRacePolicy::default_parallel(),
        }
    }
}

impl ObservedDnsMap {
    pub(crate) fn record(&self, domain: impl Into<String>, answers: Vec<IpAddr>) {
        if answers.is_empty() {
            return;
        }
        self.inner
            .write()
            .expect("observed DNS map lock poisoned")
            .insert(domain.into().to_ascii_lowercase(), answers);
    }

    pub fn snapshot(&self) -> BTreeMap<String, Vec<IpAddr>> {
        self.inner
            .read()
            .expect("observed DNS map lock poisoned")
            .clone()
    }

    pub fn domain_for_ip(&self, address: IpAddr) -> Option<String> {
        self.inner
            .read()
            .expect("observed DNS map lock poisoned")
            .iter()
            .find(|(_, answers)| answers.contains(&address))
            .map(|(domain, _)| domain.clone())
    }
}

impl SchedulerPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SingleFirstEnabled => "single-first-enabled",
        }
    }
}

impl Default for GroupThresholds {
    fn default() -> Self {
        Self {
            min_success_rate_ppm: 980_000,
            min_samples: 1,
            max_active_sessions: None,
        }
    }
}

impl NextRef {
    pub const DIRECT_AUDIT_OUTLET: &'static str = "direct";

    pub fn direct_audit_outlet() -> Self {
        Self::DirectAuditOutlet
    }

    pub fn named(value: impl Into<String>) -> Self {
        let value = value.into();
        if value == Self::DIRECT_AUDIT_OUTLET {
            Self::DirectAuditOutlet
        } else {
            Self::Named(value)
        }
    }

    pub fn label(&self) -> &str {
        match self {
            Self::DirectAuditOutlet => Self::DIRECT_AUDIT_OUTLET,
            Self::Named(value) => value,
        }
    }
}

impl DnsRacePolicy {
    pub(crate) fn default_parallel() -> Self {
        Self {
            timeout: Duration::from_secs(2),
            strategy: DnsRaceStrategy::Parallel,
        }
    }
}

impl DnsRaceStrategy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Parallel => "parallel",
        }
    }
}

impl SelectionReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SingleNode => "single-node",
        }
    }
}

impl SelectionTraceHop {
    pub fn label(&self) -> String {
        format!("{}:{}->{}", self.group_id, self.node_id, self.next.label())
    }
}

impl SelectionTerminal {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::DirectAuditOutlet => "direct",
            Self::Node(_) => "node",
        }
    }

    pub fn label(&self) -> &str {
        match self {
            Self::DirectAuditOutlet => NextRef::DIRECT_AUDIT_OUTLET,
            Self::Node(node_id) => node_id.as_str(),
        }
    }
}

impl TargetSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FixedUpstream => "fixed-upstream",
            Self::ObservedDns => "observed-dns",
            Self::ExternalContext => "external-context",
        }
    }
}

impl SelectionError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for SelectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for SelectionError {}
pub(crate) fn default_dns_upstreams() -> Vec<DnsUpstream> {
    vec![
        DnsUpstream {
            id: DnsUpstreamId::new("cloudflare"),
            address: SocketAddr::from(([1, 1, 1, 1], 53)),
            transport: DnsUpstreamTransport::Udp,
            enabled: true,
            priority: 0,
        },
        DnsUpstream {
            id: DnsUpstreamId::new("google"),
            address: SocketAddr::from(([8, 8, 8, 8], 53)),
            transport: DnsUpstreamTransport::Udp,
            enabled: true,
            priority: 1,
        },
    ]
}
