use std::{
    collections::BTreeMap,
    fmt,
    net::{IpAddr, SocketAddr},
    sync::{Arc, RwLock},
    time::Duration,
};

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
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ForwardGroup {
    pub id: GroupId,
    pub enabled: bool,
    pub scheduler: SchedulerPolicy,
    pub egress: EgressRef,
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
    pub enabled: bool,
    pub priority: u32,
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

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum EgressRef {
    DirectAuditOutlet,
    Named(String),
}

#[derive(Debug, Clone, Default)]
pub struct ObservedDnsMap {
    inner: Arc<RwLock<BTreeMap<String, Vec<IpAddr>>>>,
}

#[derive(Debug, Clone, Default)]
pub struct SelectorMatrix;

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
    pub egress: EgressRef,
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
    pub egress: EgressRef,
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
            egress: EgressRef::DirectAuditOutlet,
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

impl TargetContext {
    pub fn fixed_upstream(address: SocketAddr) -> Self {
        Self {
            address,
            domain: None,
            source: TargetSource::FixedUpstream,
        }
    }

    pub fn external_context(address: SocketAddr, domain: Option<String>) -> Self {
        Self {
            address,
            domain,
            source: TargetSource::ExternalContext,
        }
    }

    pub fn dynet_dns(address: SocketAddr, domain: String) -> Self {
        Self {
            address,
            domain: Some(domain),
            source: TargetSource::ObservedDns,
        }
    }
}

impl RuntimeSeed {
    pub fn single_node(tag: impl Into<String>) -> Self {
        let node = ForwardNode {
            id: NodeId::new(DEFAULT_NODE_ID),
            tag: tag.into(),
            enabled: true,
        };
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
}

impl SchedulerPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SingleFirstEnabled => "single-first-enabled",
        }
    }
}

impl EgressRef {
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
        format!(
            "{}:{}->{}",
            self.group_id,
            self.node_id,
            self.egress.label()
        )
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
            Self::DirectAuditOutlet => EgressRef::DIRECT_AUDIT_OUTLET,
            Self::Node(node_id) => node_id.as_str(),
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
            enabled: true,
            priority: 0,
        },
        DnsUpstream {
            id: DnsUpstreamId::new("google"),
            address: SocketAddr::from(([8, 8, 8, 8], 53)),
            enabled: true,
            priority: 1,
        },
    ]
}

fn ip_matches_cidr(address: IpAddr, cidr: &str) -> bool {
    let Some((base, prefix)) = cidr.split_once('/') else {
        return false;
    };
    match (address, base.parse::<IpAddr>(), prefix.parse::<u8>()) {
        (IpAddr::V4(address), Ok(IpAddr::V4(base)), Ok(prefix)) if prefix <= 32 => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            u32::from(address) & mask == u32::from(base) & mask
        }
        (IpAddr::V6(address), Ok(IpAddr::V6(base)), Ok(prefix)) if prefix <= 128 => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            u128::from(address) & mask == u128::from(base) & mask
        }
        _ => false,
    }
}
