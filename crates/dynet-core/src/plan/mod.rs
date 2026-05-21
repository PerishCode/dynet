mod outbound;
mod outbound_trace;
mod strategy;

use serde::Serialize;

use crate::{
    normalize_domain, AppState, InboundContext, PlanAction, RouteAction, RouteRule, Transport,
    Verdict,
};

use crate::rules::matchset::{
    candidate_domains, domain_matches_suffix, ip_in_cidr, normalize_cidr_text,
};

pub use outbound::{
    dialer_payload, payload_as, plan_payload, resolve_outbound_path, DialerOutboundPayload,
    PlanEdge, PlanEdgeKind, PlanOutboundPayload, PlanSelection,
};
pub use outbound_trace::{OutboundCandidate, OutboundDecision, OutboundHop, OutboundPath};
pub use strategy::{
    OutboundSelector, OutboundStrategyCapability, OutboundStrategyConfig, OutboundStrategyRegistry,
    OutboundStrategyRegistryEntry, OutboundStrategyRegistryModel, OutboundStrategySnapshot,
};

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Plan {
    pub schema: String,
    pub mode: PlanMode,
    pub state_schema: String,
    pub rules: Vec<PlanRule>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PlanMode {
    ExplicitOnly,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanRule {
    pub order: usize,
    pub priority: usize,
    #[serde(rename = "match")]
    pub matcher: PlanMatch,
    pub action: PlanAction,
    pub dns_sensitive: bool,
    pub source: PlanRuleSource,
    pub reason: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanMatch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inbound: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<Transport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_suffix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_keyword: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_cidr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_port: Option<u16>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PlanRuleSource {
    ExplicitRoute,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanSummary {
    pub rules: usize,
    pub explicit_rules: usize,
    pub dynamic_rules: usize,
    pub has_default: bool,
    pub reject_rules: usize,
    pub dns_sensitive_rules: usize,
}

impl Plan {
    pub fn summary(&self) -> PlanSummary {
        PlanSummary {
            rules: self.rules.len(),
            explicit_rules: self
                .rules
                .iter()
                .filter(|rule| rule.source == PlanRuleSource::ExplicitRoute)
                .count(),
            dynamic_rules: 0,
            has_default: self.rules.iter().any(|rule| rule.matcher.is_default()),
            reject_rules: self
                .rules
                .iter()
                .filter(|rule| rule.action == PlanAction::Reject)
                .count(),
            dns_sensitive_rules: self.rules.iter().filter(|rule| rule.dns_sensitive).count(),
        }
    }

    pub fn evaluate(&self, context: &InboundContext, state: &AppState) -> Verdict {
        for rule in &self.rules {
            if rule.matcher.matches(context, state) {
                return Verdict::from_action(
                    Some(rule.order),
                    rule.action.clone(),
                    rule.dns_sensitive,
                    rule.reason.clone(),
                    state,
                );
            }
        }

        Verdict::from_action(
            None,
            PlanAction::NoRoute,
            false,
            "no plan rule matched inbound context",
            state,
        )
    }
}

impl PlanMatch {
    fn is_default(&self) -> bool {
        self.inbound.is_none()
            && self.transport.is_none()
            && self.domain.is_none()
            && self.domain_suffix.is_none()
            && self.domain_keyword.is_none()
            && self.ip_cidr.is_none()
            && self.destination_port.is_none()
    }

    fn matches(&self, context: &InboundContext, state: &AppState) -> bool {
        if self
            .inbound
            .as_ref()
            .is_some_and(|inbound| context.inbound.as_ref() != Some(inbound))
        {
            return false;
        }
        if self
            .transport
            .is_some_and(|transport| context.transport != Some(transport))
        {
            return false;
        }
        if let Some(destination_port) = self.destination_port {
            if context.destination_port != Some(destination_port) {
                return false;
            }
        }
        if let Some(cidr) = &self.ip_cidr {
            let Some(destination_ip) = context.destination_ip else {
                return false;
            };
            if !ip_in_cidr(destination_ip, cidr) {
                return false;
            }
        }
        let needs_domain =
            self.domain.is_some() || self.domain_suffix.is_some() || self.domain_keyword.is_some();
        if needs_domain {
            let domains = candidate_domains(context, state);
            if domains.is_empty() {
                return false;
            }
            if let Some(domain) = &self.domain {
                if !domains.iter().any(|candidate| candidate == domain) {
                    return false;
                }
            }
            if let Some(suffix) = &self.domain_suffix {
                if !domains
                    .iter()
                    .any(|candidate| domain_matches_suffix(candidate, suffix))
                {
                    return false;
                }
            }
            if let Some(keyword) = &self.domain_keyword {
                if !domains.iter().any(|candidate| candidate.contains(keyword)) {
                    return false;
                }
            }
        }
        true
    }
}

pub fn build_plan(state: &AppState) -> Plan {
    let rules: Vec<PlanRule> = state
        .config
        .routes
        .iter()
        .enumerate()
        .map(|(index, route)| {
            let action = plan_action(route);
            let reason = rule_reason(route, &action);
            PlanRule {
                order: index + 1,
                priority: 0,
                matcher: PlanMatch {
                    inbound: route.inbound.clone(),
                    transport: route.transport,
                    domain: route.domain.as_deref().and_then(normalize_domain),
                    domain_suffix: route.domain_suffix.as_deref().and_then(normalize_domain),
                    domain_keyword: route
                        .domain_keyword
                        .as_deref()
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .map(str::to_ascii_lowercase),
                    ip_cidr: route.ip_cidr.as_deref().map(normalize_cidr_text),
                    destination_port: route.destination_port,
                },
                action,
                dns_sensitive: route.dns_sensitive,
                source: PlanRuleSource::ExplicitRoute,
                reason,
            }
        })
        .collect();

    Plan {
        schema: "dynet-plan/v1alpha1".to_string(),
        mode: PlanMode::ExplicitOnly,
        state_schema: state.schema.clone(),
        rules,
    }
}

fn plan_action(route: &RouteRule) -> PlanAction {
    match route.action {
        Some(RouteAction::Reject) => PlanAction::Reject,
        None => match &route.outbound {
            Some(tag) => PlanAction::UseOutbound { tag: tag.clone() },
            None => PlanAction::NoRoute,
        },
    }
}

fn rule_reason(route: &RouteRule, action: &PlanAction) -> String {
    let mut parts = Vec::new();
    if let Some(inbound) = &route.inbound {
        parts.push(format!("inbound `{inbound}`"));
    }
    if let Some(transport) = route.transport {
        parts.push(format!("transport `{}`", transport_label(transport)));
    }
    if let Some(domain) = route.domain.as_deref().and_then(normalize_domain) {
        parts.push(format!("domain `{domain}`"));
    }
    if let Some(domain_suffix) = route.domain_suffix.as_deref().and_then(normalize_domain) {
        parts.push(format!("domain suffix `{domain_suffix}`"));
    }
    if let Some(domain_keyword) = route
        .domain_keyword
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase)
    {
        parts.push(format!("domain keyword `{domain_keyword}`"));
    }
    if let Some(ip_cidr) = &route.ip_cidr {
        parts.push(format!("IP CIDR `{}`", normalize_cidr_text(ip_cidr)));
    }
    if let Some(destination_port) = route.destination_port {
        parts.push(format!("destination port `{destination_port}`"));
    }
    if parts.is_empty() {
        parts.push("default".to_string());
    }
    let dns = if route.dns_sensitive {
        " with DNS-sensitive handling"
    } else {
        ""
    };
    format!(
        "explicit user rule matches {} and {}{}",
        parts.join(" plus "),
        action_reason(action),
        dns
    )
}

fn action_reason(action: &PlanAction) -> String {
    match action {
        PlanAction::UseOutbound { tag } => format!("uses outbound `{tag}`"),
        PlanAction::Reject => "rejects the flow".to_string(),
        PlanAction::NoRoute => "has no route".to_string(),
    }
}

fn transport_label(transport: Transport) -> &'static str {
    match transport {
        Transport::Tcp => "tcp",
        Transport::Udp => "udp",
        Transport::Dns => "dns",
    }
}
