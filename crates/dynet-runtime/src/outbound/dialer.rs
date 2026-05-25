use std::time::Instant;

use dynet_core::{
    dialer_payload, resolve_outbound_path, InboundContext, NetworkNode, OutboundPath, QualityScope,
};

use crate::{
    outbound::trojan,
    resolver::trace::{
        annotate_runtime_error_fields, candidate_tags, classify_runtime_error,
        classify_runtime_error_disposition, hop_kinds, hop_tags, json_field,
    },
    settings::RuntimePolicy,
    vmess, RuntimeEvent, RuntimeEventKind,
};

use super::{
    connect_tcp_policy, observe_stage, shadowsocks, vmess_server_target, vmess_spec_from_node,
    vmess_target, ProxiedTcpStream, TcpConnectOptions, TcpTarget,
};

pub(super) fn connect_with_bound_override(
    target: &TcpTarget,
    outbound: &NetworkNode,
    policy: &RuntimePolicy,
    context: &InboundContext,
    events: &mut Vec<RuntimeEvent>,
    bound_override: Option<&str>,
    options: TcpConnectOptions,
) -> Result<ProxiedTcpStream, String> {
    let payload = observe_stage(events, outbound, "dialer-payload-decode", || {
        dialer_payload(outbound)
    })?;
    let private = policy
        .outbound(&payload.target)
        .ok_or_else(|| format!("dialer target outbound `{}` is missing", payload.target))?;
    let bound_context = dialer_bound_context(context);
    let bound_path = match bound_override {
        Some(selected) => forced_bound_path(policy, &bound_context, &payload.bound, selected)?,
        None => resolve_outbound_path(&policy.state, &bound_context, &payload.bound)?,
    };
    emit_path_events(events, "dialer-bound", &bound_path);
    let bound = policy.outbound(&bound_path.selected).ok_or_else(|| {
        format!(
            "dialer bound graph selected missing outbound `{}`",
            bound_path.selected
        )
    })?;
    events.push(
        RuntimeEvent::new(RuntimeEventKind::DialerCascadeSelected)
            .field("dialer", &outbound.tag)
            .field("bound", &payload.bound)
            .field("boundSelected", &bound_path.selected)
            .field("private", &private.tag)
            .field("target", target)
            .field("bypassesPlan", true),
    );
    match private.kind.as_str() {
        "vmess" => {
            let private_spec = observe_stage(events, private, "payload-decode", || {
                vmess_spec_from_node(private)
            })?;
            let private_server = vmess_server_target(&private_spec);
            let transport = connect_tcp_policy(
                &private_server,
                bound,
                policy,
                context,
                events,
                options,
            )?;
            observe_private_connect_stage(events, private, "private-vmess-connect", target, || {
                vmess::connect_tcp_on_stream(
                    &private_spec,
                    vmess_target(target),
                    Box::new(transport),
                )
                .map(Box::new)
                .map(ProxiedTcpStream::Vmess)
            })
        }
        "ss" => {
            let private_spec = observe_stage(events, private, "payload-decode", || {
                shadowsocks::spec_from_node(private)
            })?;
            let private_server = shadowsocks::server_target(&private_spec);
            let transport = connect_tcp_policy(
                &private_server,
                bound,
                policy,
                context,
                events,
                options,
            )?;
            observe_private_connect_stage(events, private, "private-ss-connect", target, || {
                shadowsocks::connect_tcp_on_stream(&private_spec, target, Box::new(transport))
                    .map(Box::new)
                    .map(ProxiedTcpStream::Shadowsocks)
            })
        }
        "trojan" => {
            let private_spec = observe_stage(events, private, "payload-decode", || {
                trojan::spec_from_node(private)
            })?;
            let private_server = trojan::server_target(&private_spec);
            let transport = connect_tcp_policy(
                &private_server,
                bound,
                policy,
                context,
                events,
                options,
            )?;
            observe_private_connect_stage(events, private, "private-trojan-connect", target, || {
                trojan::connect_tcp_on_stream(&private_spec, target, Box::new(transport))
                    .map(Box::new)
                    .map(ProxiedTcpStream::Trojan)
            })
        }
        kind => Err(format!(
            "dialer target `{}` has unsupported type `{kind}`; supported private targets are vmess, ss, and trojan",
            private.tag
        )),
    }
}

fn observe_private_connect_stage<T>(
    events: &mut Vec<RuntimeEvent>,
    outbound: &NetworkNode,
    stage: &str,
    adapter_target: &TcpTarget,
    run: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    let started = Instant::now();
    match run() {
        Ok(value) => {
            events.push(private_connect_event(
                outbound,
                stage,
                "success",
                started,
                adapter_target,
            ));
            Ok(value)
        }
        Err(error) => {
            events.push(annotate_runtime_error_fields(
                private_connect_event(outbound, stage, "failed", started, adapter_target)
                    .field("errorType", classify_runtime_error(&error))
                    .field(
                        "errorDisposition",
                        classify_runtime_error_disposition(&error),
                    )
                    .field("error", &error),
                &error,
            ));
            Err(error)
        }
    }
}

fn private_connect_event(
    outbound: &NetworkNode,
    stage: &str,
    status: &str,
    started: Instant,
    adapter_target: &TcpTarget,
) -> RuntimeEvent {
    RuntimeEvent::new(RuntimeEventKind::OutboundStageFinished)
        .field("outbound", &outbound.tag)
        .field("kind", &outbound.kind)
        .field("stage", stage)
        .field("status", status)
        .field("adapterTarget", adapter_target)
        .field("adapterTargetKind", adapter_target_kind(adapter_target))
        .field("elapsedMs", started.elapsed().as_millis())
}

fn adapter_target_kind(target: &TcpTarget) -> &'static str {
    match target {
        TcpTarget::Domain { .. } => "domain",
        TcpTarget::Socket(_) => "socket",
    }
}

pub(super) fn bound_candidate_order(
    outbound: &NetworkNode,
    policy: &RuntimePolicy,
    context: &InboundContext,
) -> Result<Vec<String>, String> {
    let payload = dialer_payload(outbound)?;
    let bound_context = dialer_bound_context(context);
    let path = resolve_outbound_path(&policy.state, &bound_context, &payload.bound)?;
    let mut tags = Vec::new();
    push_unique(&mut tags, path.selected);
    if let Some(decision) = path.decisions.last() {
        for candidate in &decision.candidates {
            push_unique(&mut tags, candidate.to.clone());
        }
    }
    Ok(tags)
}

fn emit_path_events(events: &mut Vec<RuntimeEvent>, scope: &str, path: &dynet_core::OutboundPath) {
    events.push(
        RuntimeEvent::new(RuntimeEventKind::OutboundAdmissionPassed)
            .field("scope", scope)
            .field("outbound", &path.requested)
            .field("gate", "admission")
            .field("transport", "tcp"),
    );
    for decision in &path.decisions {
        events.push(
            RuntimeEvent::new(RuntimeEventKind::OutboundCandidateSet)
                .field("scope", scope)
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
            .field("scope", scope)
            .field("requested", &path.requested)
            .field("selected", &path.selected)
            .field("hops", path.hops.len())
            .field("hopTags", hop_tags(path))
            .field("hopKinds", hop_kinds(path))
            .field("decisions", path.decisions.len()),
    );
    events.push(
        RuntimeEvent::new(RuntimeEventKind::OutboundEgressPassed)
            .field("scope", scope)
            .field("gate", "egress")
            .field("requested", &path.requested)
            .field("selected", &path.selected)
            .field("transport", "tcp"),
    );
}

fn forced_bound_path(
    policy: &RuntimePolicy,
    context: &InboundContext,
    bound: &str,
    selected: &str,
) -> Result<OutboundPath, String> {
    let mut path = resolve_outbound_path(&policy.state, context, bound)?;
    let decision = path
        .decisions
        .last_mut()
        .ok_or_else(|| format!("dialer bound `{bound}` has no selectable candidates"))?;
    let candidate = decision
        .candidates
        .iter()
        .find(|candidate| candidate.to == selected)
        .ok_or_else(|| {
            format!("dialer bound `{bound}` cannot force unknown candidate `{selected}`")
        })?;
    let selected_node = policy
        .outbound(selected)
        .ok_or_else(|| format!("dialer bound candidate `{selected}` is missing"))?;
    decision.selected = selected.to_string();
    decision.selected_edge_type = candidate.edge_type;
    path.selected = selected.to_string();
    if let Some(position) = path
        .hops
        .iter()
        .position(|hop| hop.tag == decision.selected)
    {
        path.hops.truncate(position);
    } else if !path.hops.is_empty() {
        path.hops.pop();
    }
    path.hops.push(dynet_core::OutboundHop {
        tag: selected_node.tag.clone(),
        kind: selected_node.kind.clone(),
        edge_type: Some(candidate.edge_type),
    });
    Ok(path)
}

fn push_unique(tags: &mut Vec<String>, tag: String) {
    if !tags.iter().any(|item| item == &tag) {
        tags.push(tag);
    }
}

fn dialer_bound_context(context: &InboundContext) -> InboundContext {
    context
        .clone()
        .with_quality_scope(QualityScope::DialerBound)
}
