use std::{net::SocketAddr, time::Instant};

use dynet_core::{
    evaluate_rules, resolve_outbound_path, InboundContext, PlanAction, Transport, VerdictStatus,
};
use tracing::debug;

use crate::{
    dns,
    event::{RuntimeEvent, RuntimeEventKind},
    outbound,
    settings::RuntimePolicy,
    DnsRuntimeChain,
};

pub(crate) mod trace;
mod upstream;

use trace::{candidate_tags, classify_runtime_error, elapsed_ms, hop_kinds, hop_tags, json_field};
use upstream::{resolve_doh, resolve_udp};

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct ResolvedDns {
    pub(crate) response: Vec<u8>,
    pub(crate) route_decision: bool,
    pub(crate) proxied: bool,
    pub(crate) events: Vec<RuntimeEvent>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct ResolveError {
    pub(crate) message: String,
    pub(crate) events: Vec<RuntimeEvent>,
}

impl ResolveError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            events: Vec::new(),
        }
    }

    fn with_events(message: impl Into<String>, events: Vec<RuntimeEvent>) -> Self {
        Self {
            message: message.into(),
            events,
        }
    }
}

pub(crate) fn resolve_dns(
    query: &[u8],
    chain: &DnsRuntimeChain,
    mark: u32,
    policy: Option<&RuntimePolicy>,
) -> Result<ResolvedDns, ResolveError> {
    match chain {
        DnsRuntimeChain::Udp { upstream_dns } => {
            resolve_udp_with_policy(query, *upstream_dns, mark, policy)
        }
        DnsRuntimeChain::Doh {
            endpoint,
            bootstrap_ips,
        } => resolve_doh(query, endpoint, bootstrap_ips, mark)
            .map(direct_dns)
            .map_err(ResolveError::new),
    }
}

fn resolve_udp_with_policy(
    query: &[u8],
    upstream_dns: SocketAddr,
    mark: u32,
    policy: Option<&RuntimePolicy>,
) -> Result<ResolvedDns, ResolveError> {
    let Some(policy) = policy else {
        return resolve_udp(query, upstream_dns, mark)
            .map(direct_dns)
            .map_err(ResolveError::new);
    };
    let query_domain = dns::query_name_from_wire(query).ok();
    let mut context = InboundContext::any()
        .with_transport(Transport::Dns)
        .with_destination_ip(upstream_dns.ip())
        .with_destination_port(upstream_dns.port());
    if let Some(domain) = &query_domain {
        context = context.with_destination_domain(domain.clone());
    }
    if let Some(decision) = evaluate_rules(&policy.state, &context) {
        let prefix = vec![
            RuntimeEvent::new(RuntimeEventKind::RuleMatched)
                .field("rule", &decision.tag)
                .field("order", decision.order)
                .field("transport", "dns")
                .field("query", query_domain.as_deref().unwrap_or("<unparsed>"))
                .field("upstream", upstream_dns)
                .field("outbound", &decision.outbound)
                .field("bypassesPlan", decision.bypasses_plan)
                .field("reason", &decision.reason),
            RuntimeEvent::new(RuntimeEventKind::PlanBypassed)
                .field("rule", &decision.tag)
                .field("outbound", &decision.outbound)
                .field("query", query_domain.as_deref().unwrap_or("<unparsed>"))
                .field("reason", "user hard rule matched before route plan"),
        ];
        return prepend_events(
            resolve_selected_outbound(
                query,
                upstream_dns,
                mark,
                policy,
                &context,
                &decision.outbound,
            ),
            prefix,
        );
    }
    let verdict = policy.plan.evaluate(&context, &policy.state);
    let outbound_tag = verdict
        .outbound
        .as_ref()
        .map(|outbound| outbound.tag.as_str());
    let route_event = RuntimeEvent::new(RuntimeEventKind::RouteMatched)
        .field("query", query_domain.as_deref().unwrap_or("<unparsed>"))
        .field("upstream", upstream_dns)
        .field("status", format!("{:?}", verdict.status))
        .field("outbound", outbound_tag.unwrap_or("<none>"))
        .field("reason", &verdict.reason);
    debug!(
        query = query_domain.as_deref().unwrap_or("<unparsed>"),
        upstream = %upstream_dns,
        matched_rule = ?verdict.matched_rule,
        status = ?verdict.status,
        dns_sensitive = verdict.dns_sensitive,
        outbound = outbound_tag.unwrap_or("<none>"),
        reason = %verdict.reason,
        "runtime.route.verdict"
    );

    match (&verdict.status, &verdict.action) {
        (VerdictStatus::Accept, PlanAction::UseOutbound { tag }) => {
            match resolve_selected_outbound(query, upstream_dns, mark, policy, &context, tag) {
                Ok(mut resolution) => {
                    resolution.events.insert(0, route_event);
                    Ok(resolution)
                }
                Err(mut error) => {
                    error.events.insert(0, route_event);
                    Err(error)
                }
            }
        }
        (VerdictStatus::Deny, PlanAction::Reject) => Err(ResolveError::with_events(
            format!(
                "DNS query rejected by rule {:?}: {}",
                verdict.matched_rule, verdict.reason
            ),
            vec![route_event],
        )),
        (VerdictStatus::Deny, _) => {
            Err(ResolveError::with_events(verdict.reason, vec![route_event]))
        }
        _ => resolve_udp(query, upstream_dns, mark)
            .map(direct_dns)
            .map_err(ResolveError::new),
    }
}

fn resolve_selected_outbound(
    query: &[u8],
    upstream_dns: SocketAddr,
    mark: u32,
    policy: &RuntimePolicy,
    context: &InboundContext,
    tag: &str,
) -> Result<ResolvedDns, ResolveError> {
    let path = resolve_outbound_path(&policy.state, context, tag).map_err(ResolveError::new)?;
    debug!(
        requested = %path.requested,
        selected = %path.selected,
        hops = path.hops.len(),
        "outbound.graph.selected"
    );
    let mut events = vec![RuntimeEvent::new(RuntimeEventKind::OutboundAdmissionPassed)
        .field("scope", "plan-candidate")
        .field("outbound", tag)
        .field("gate", "admission")
        .field("transport", "dns")];
    for decision in &path.decisions {
        events.push(
            RuntimeEvent::new(RuntimeEventKind::OutboundCandidateSet)
                .field("scope", "plan-candidate")
                .field("plan", &decision.plan)
                .field("strategySource", &decision.strategy.source)
                .field("strategyKey", &decision.strategy.key)
                .field("strategyVersion", &decision.strategy.version)
                .field("selector", format!("{:?}", decision.strategy.selector))
                .field("candidateCount", decision.candidates.len())
                .field("selected", &decision.selected)
                .field(
                    "selectedEdgeType",
                    format!("{:?}", decision.selected_edge_type),
                )
                .field("candidates", candidate_tags(decision))
                .field("candidatesJson", json_field(&decision.candidates)),
        );
    }
    events.push(
        RuntimeEvent::new(RuntimeEventKind::OutboundGraphSelected)
            .field("scope", "plan-candidate")
            .field("requested", &path.requested)
            .field("selected", &path.selected)
            .field("hops", path.hops.len())
            .field("hopTags", hop_tags(&path))
            .field("hopKinds", hop_kinds(&path))
            .field("decisions", path.decisions.len()),
    );
    events.push(
        RuntimeEvent::new(RuntimeEventKind::OutboundEgressPassed)
            .field("scope", "plan-candidate")
            .field("gate", "egress")
            .field("requested", &path.requested)
            .field("selected", &path.selected)
            .field("transport", "dns"),
    );
    let outbound = policy.outbound(&path.selected).ok_or_else(|| {
        ResolveError::with_events(
            format!(
                "outbound graph selected missing outbound `{}`",
                path.selected
            ),
            events.clone(),
        )
    })?;
    match outbound.kind.as_str() {
        "direct" => resolve_direct_outbound(query, upstream_dns, mark, outbound, events),
        "vmess" => resolve_vmess_outbound(query, upstream_dns, mark, outbound, events),
        "dialer" => {
            resolve_dialer_outbound(query, upstream_dns, mark, policy, context, outbound, events)
        }
        kind => Err(ResolveError::with_events(
            format!("runtime outbound `{tag}` has unsupported type `{kind}`"),
            events,
        )),
    }
}

fn resolve_direct_outbound(
    query: &[u8],
    upstream_dns: SocketAddr,
    mark: u32,
    node: &dynet_core::NetworkNode,
    mut events: Vec<RuntimeEvent>,
) -> Result<ResolvedDns, ResolveError> {
    let started = Instant::now();
    events.push(
        RuntimeEvent::new(RuntimeEventKind::OutboundAttemptStarted)
            .field("outbound", &node.tag)
            .field("kind", &node.kind)
            .field("transport", "dns")
            .field("upstream", upstream_dns),
    );
    match resolve_udp(query, upstream_dns, mark) {
        Ok(response) => {
            events.push(outbound_attempt_finished(node, started, "success", None));
            Ok(ResolvedDns {
                response,
                route_decision: true,
                proxied: false,
                events,
            })
        }
        Err(error) => {
            events.push(outbound_attempt_finished(
                node,
                started,
                "failed",
                Some(&error),
            ));
            Err(ResolveError::with_events(error, events))
        }
    }
}

fn resolve_vmess_outbound(
    query: &[u8],
    upstream_dns: SocketAddr,
    mark: u32,
    node: &dynet_core::NetworkNode,
    mut events: Vec<RuntimeEvent>,
) -> Result<ResolvedDns, ResolveError> {
    debug!(
        outbound = %node.tag,
        kind = %node.kind,
        upstream = %upstream_dns,
        "dns.proxy.forward"
    );
    events.push(
        RuntimeEvent::new(RuntimeEventKind::DnsProxyForward)
            .field("outbound", &node.tag)
            .field("kind", &node.kind)
            .field("upstream", upstream_dns),
    );
    match outbound::resolve_dns_over_tcp(query, upstream_dns, node, mark, &mut events) {
        Ok(response) => Ok(ResolvedDns {
            response,
            route_decision: true,
            proxied: true,
            events,
        }),
        Err(error) => Err(ResolveError::with_events(error, events)),
    }
}

fn resolve_dialer_outbound(
    query: &[u8],
    upstream_dns: SocketAddr,
    mark: u32,
    policy: &RuntimePolicy,
    context: &InboundContext,
    node: &dynet_core::NetworkNode,
    mut events: Vec<RuntimeEvent>,
) -> Result<ResolvedDns, ResolveError> {
    debug!(
        outbound = %node.tag,
        kind = %node.kind,
        upstream = %upstream_dns,
        "dns.proxy.forward"
    );
    events.push(
        RuntimeEvent::new(RuntimeEventKind::DnsProxyForward)
            .field("outbound", &node.tag)
            .field("kind", &node.kind)
            .field("upstream", upstream_dns),
    );
    match outbound::resolve_dns_policy(
        query,
        upstream_dns,
        node,
        mark,
        policy,
        context,
        &mut events,
    ) {
        Ok(response) => Ok(ResolvedDns {
            response,
            route_decision: true,
            proxied: true,
            events,
        }),
        Err(error) => Err(ResolveError::with_events(error, events)),
    }
}

fn prepend_events(
    result: Result<ResolvedDns, ResolveError>,
    prefix: Vec<RuntimeEvent>,
) -> Result<ResolvedDns, ResolveError> {
    match result {
        Ok(mut resolution) => {
            let mut events = prefix;
            events.extend(resolution.events);
            resolution.events = events;
            Ok(resolution)
        }
        Err(mut error) => {
            let mut events = prefix;
            events.extend(error.events);
            error.events = events;
            Err(error)
        }
    }
}

fn outbound_attempt_finished(
    node: &dynet_core::NetworkNode,
    started: Instant,
    status: &str,
    error: Option<&str>,
) -> RuntimeEvent {
    let mut event = RuntimeEvent::new(RuntimeEventKind::OutboundAttemptFinished)
        .field("outbound", &node.tag)
        .field("kind", &node.kind)
        .field("transport", "dns")
        .field("status", status)
        .field("elapsedMs", elapsed_ms(started));
    if let Some(error) = error {
        event = event
            .field("errorType", classify_runtime_error(error))
            .field("error", error);
    }
    event
}

fn direct_dns(response: Vec<u8>) -> ResolvedDns {
    ResolvedDns {
        response,
        route_decision: false,
        proxied: false,
        events: Vec::new(),
    }
}
