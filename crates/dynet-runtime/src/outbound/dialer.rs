use dynet_core::{
    dialer_payload, resolve_outbound_path, InboundContext, NetworkNode, OutboundPath,
};

use crate::{
    resolver::trace::{candidate_tags, hop_kinds, hop_tags, json_field},
    settings::RuntimePolicy,
    vmess, RuntimeEvent, RuntimeEventKind,
};

use super::{
    connect_tcp_policy, observe_stage, shadowsocks, vmess_server_target, vmess_spec_from_node,
    vmess_target, ProxiedTcpStream, TcpTarget,
};

pub(super) fn connect_with_bound_override(
    target: &TcpTarget,
    outbound: &NetworkNode,
    policy: &RuntimePolicy,
    context: &InboundContext,
    mark: u32,
    events: &mut Vec<RuntimeEvent>,
    bound_override: Option<&str>,
) -> Result<ProxiedTcpStream, String> {
    let payload = observe_stage(events, outbound, "dialer-payload-decode", || {
        dialer_payload(outbound)
    })?;
    let private = policy
        .outbound(&payload.target)
        .ok_or_else(|| format!("dialer target outbound `{}` is missing", payload.target))?;
    let bound_path = match bound_override {
        Some(selected) => forced_bound_path(policy, context, &payload.bound, selected)?,
        None => resolve_outbound_path(&policy.state, context, &payload.bound)?,
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
            let transport =
                connect_tcp_policy(&private_server, bound, policy, context, mark, events)?;
            observe_stage(events, private, "private-vmess-connect", || {
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
            let transport =
                connect_tcp_policy(&private_server, bound, policy, context, mark, events)?;
            observe_stage(events, private, "private-ss-connect", || {
                shadowsocks::connect_tcp_on_stream(&private_spec, target, Box::new(transport))
                    .map(Box::new)
                    .map(ProxiedTcpStream::Shadowsocks)
            })
        }
        kind => Err(format!(
            "dialer target `{}` has unsupported type `{kind}`; supported private targets are vmess and ss",
            private.tag
        )),
    }
}

pub(super) fn bound_candidate_order(
    outbound: &NetworkNode,
    policy: &RuntimePolicy,
    context: &InboundContext,
) -> Result<Vec<String>, String> {
    let payload = dialer_payload(outbound)?;
    let path = resolve_outbound_path(&policy.state, context, &payload.bound)?;
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
