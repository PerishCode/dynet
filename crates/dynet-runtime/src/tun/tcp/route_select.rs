use std::net::SocketAddr;

use dynet_core::{resolve_outbound_path, InboundContext, PlanAction, Transport, VerdictStatus};

use crate::{RuntimeEvent, RuntimeEventKind, RuntimePolicy};

use super::super::{outbound_events, user_rule};

pub(crate) struct TcpSelection {
    pub(crate) context: InboundContext,
    pub(crate) domain: Option<String>,
    pub(crate) outbound: String,
    pub(crate) fallback_outbounds: Vec<String>,
    pub(crate) events: Vec<RuntimeEvent>,
}

pub(crate) fn select(
    policy: &RuntimePolicy,
    target: SocketAddr,
    domains: &[String],
) -> Result<TcpSelection, String> {
    if let Some((context, domain, decision)) =
        user_rule::select(policy, Transport::Tcp, target, domains)
    {
        let outbound = decision.outbound.clone();
        return Ok(TcpSelection {
            context,
            domain: domain.clone(),
            fallback_outbounds: vec![outbound.clone()],
            outbound,
            events: user_rule_events(target, domain.as_deref(), &decision),
        });
    }

    let (context, domain) = tcp_route_context(target, domains);
    let verdict = policy.plan.evaluate(&context, &policy.state);
    let route_outbound = verdict
        .outbound
        .as_ref()
        .map(|outbound| outbound.tag.as_str())
        .unwrap_or("<none>");
    let events = vec![RuntimeEvent::new(RuntimeEventKind::RouteMatched)
        .field("transport", "tcp")
        .field("target", target)
        .field("domain", domain.as_deref().unwrap_or("<none>"))
        .field("status", format!("{:?}", verdict.status))
        .field("outbound", route_outbound)
        .field("reason", &verdict.reason)];

    match (&verdict.status, &verdict.action) {
        (VerdictStatus::Accept, PlanAction::UseOutbound { tag }) => select_plan_route(
            policy,
            context,
            domain,
            events,
            tag,
            verdict.outbound.as_ref(),
        ),
        (VerdictStatus::Deny, PlanAction::Reject) => Err(format!(
            "TUN TCP target {target} rejected by route {:?}: {}",
            verdict.matched_rule, verdict.reason
        )),
        (VerdictStatus::Deny, _) => Err(verdict.reason),
        _ => Err(format!(
            "TUN TCP target {target} has no matching user rule or route; fail closed"
        )),
    }
}

fn select_plan_route(
    policy: &RuntimePolicy,
    context: InboundContext,
    domain: Option<String>,
    mut events: Vec<RuntimeEvent>,
    tag: &str,
    route_outbound: Option<&dynet_core::OutboundTarget>,
) -> Result<TcpSelection, String> {
    let Some(route_outbound) = route_outbound else {
        return Err(format!(
            "TUN TCP route selected outbound `{tag}` but no outbound model was found"
        ));
    };
    ensure_tcp_capability(route_outbound.tag.as_str(), &route_outbound.capabilities)?;
    let path = resolve_outbound_path(&policy.state, &context, tag)?;
    events.extend(outbound_events::path_events("tcp-route", "tcp", &path));
    let selected = path.selected.clone();
    let Some(selected_outbound) = policy.state.outbound(&selected) else {
        return Err(format!(
            "TUN TCP route selected missing outbound `{selected}`"
        ));
    };
    ensure_tcp_capability(
        selected_outbound.tag.as_str(),
        &selected_outbound.capabilities,
    )?;
    Ok(TcpSelection {
        context,
        domain,
        fallback_outbounds: tcp_candidate_order(policy, &path),
        outbound: selected,
        events,
    })
}

fn tcp_candidate_order(policy: &RuntimePolicy, path: &dynet_core::OutboundPath) -> Vec<String> {
    let mut tags = Vec::new();
    push_tcp_candidate(policy, &mut tags, path.selected.as_str());
    if let Some(decision) = path.decisions.last() {
        for candidate in &decision.candidates {
            push_tcp_candidate(policy, &mut tags, candidate.to.as_str());
        }
    }
    tags
}

fn push_tcp_candidate(policy: &RuntimePolicy, tags: &mut Vec<String>, tag: &str) {
    if tags.iter().any(|existing| existing == tag) {
        return;
    }
    let Some(outbound) = policy.state.outbound(tag) else {
        return;
    };
    if has_transport_capability(&outbound.capabilities, "tcp") {
        tags.push(tag.to_string());
    }
}

fn tcp_route_context(target: SocketAddr, domains: &[String]) -> (InboundContext, Option<String>) {
    let base = InboundContext::from_inbound("tun-in")
        .with_transport(Transport::Tcp)
        .with_destination_ip(target.ip())
        .with_destination_port(target.port());
    match domains.first() {
        Some(domain) => (
            base.with_destination_domain(domain.clone()),
            Some(domain.clone()),
        ),
        None => (base, None),
    }
}

fn user_rule_events(
    target: SocketAddr,
    decision_domain: Option<&str>,
    decision: &dynet_core::UserRuleDecision,
) -> Vec<RuntimeEvent> {
    vec![
        RuntimeEvent::new(RuntimeEventKind::RuleMatched)
            .field("rule", &decision.tag)
            .field("order", decision.order)
            .field("transport", "tcp")
            .field("target", target)
            .field("domain", decision_domain.unwrap_or("<none>"))
            .field("outbound", &decision.outbound)
            .field("bypassesPlan", decision.bypasses_plan)
            .field("reason", &decision.reason),
        RuntimeEvent::new(RuntimeEventKind::PlanBypassed)
            .field("rule", &decision.tag)
            .field("outbound", &decision.outbound)
            .field("target", target)
            .field("reason", "user hard rule matched before route plan"),
    ]
}

fn ensure_tcp_capability(tag: &str, capabilities: &[String]) -> Result<(), String> {
    if has_transport_capability(capabilities, "tcp") {
        return Ok(());
    }
    Err(format!(
        "TUN TCP route selected outbound `{tag}` without tcp capability; fail closed"
    ))
}

fn has_transport_capability(capabilities: &[String], transport: &str) -> bool {
    capabilities
        .iter()
        .any(|capability| capability == transport)
}
