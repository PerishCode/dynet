mod capability;
mod context;
mod dns;
mod model;
mod plan;
mod rules;
mod state;
mod validate;
mod verdict;

pub use capability::{node_capabilities, node_supports_transport};
pub use context::{InboundContext, Transport};
pub use dns::{normalize_domain, DnsReverseIndex, DnsReverseRecord};
pub use model::{
    ConfigDiagnostic, ConfigSummary, DnsChain, DnsConfig, DnsModel, DynetConfig, Endpoint, Inbound,
    LogConfig, ModeledDnsChain, ModeledNode, NetworkModel, NetworkNode, NodeRole, Outbound,
    RouteAction, RouteRule, Severity, UserRule,
};
pub use plan::{
    build_plan, dialer_payload, payload_as, plan_payload, resolve_outbound_path,
    DialerOutboundPayload, OutboundCandidate, OutboundDecision, OutboundHop, OutboundPath,
    OutboundSelector, OutboundStrategyCapability, OutboundStrategyConfig, OutboundStrategyRegistry,
    OutboundStrategyRegistryEntry, OutboundStrategyRegistryModel, OutboundStrategySnapshot, Plan,
    PlanEdge, PlanEdgeKind, PlanMatch, PlanMode, PlanOutboundPayload, PlanRule, PlanRuleSource,
    PlanSelection, PlanSummary,
};
pub use rules::{evaluate_rules, UserRuleDecision, UserRuleMatch};
pub use state::{
    AppState, OutboundQualityEntry, OutboundQualityState, QualityConfidence, QualityVerdict,
    StageQualityEntry,
};
pub use validate::validate_config;
pub use verdict::{OutboundTarget, PlanAction, Verdict, VerdictStatus};
