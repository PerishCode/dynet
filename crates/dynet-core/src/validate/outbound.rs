use std::collections::{BTreeMap, BTreeSet};

use crate::{
    capability::capabilities_for, dialer_payload, plan_payload, ConfigDiagnostic, DynetConfig,
    NetworkNode, OutboundStrategyRegistry,
};

use super::deny;

pub(super) fn validate_outbound_graph(
    config: &DynetConfig,
    diagnostics: &mut Vec<ConfigDiagnostic>,
) {
    let outbounds = config
        .outbounds
        .iter()
        .map(|outbound| (outbound.tag.as_str(), outbound))
        .collect::<BTreeMap<_, _>>();
    for (index, outbound) in config.outbounds.iter().enumerate() {
        if outbound.kind == "plan" {
            validate_plan_outbound(index, outbound, &outbounds, diagnostics);
        }
        if outbound.kind == "dialer" {
            validate_dialer_outbound(index, outbound, &outbounds, diagnostics);
        }
    }
    validate_plan_cycles(config, diagnostics);
}

fn validate_plan_outbound(
    index: usize,
    outbound: &NetworkNode,
    outbounds: &BTreeMap<&str, &NetworkNode>,
    diagnostics: &mut Vec<ConfigDiagnostic>,
) {
    let payload = match plan_payload(outbound) {
        Ok(payload) => payload,
        Err(error) => {
            diagnostics.push(deny(format!("outbounds[{index}].payload"), error));
            return;
        }
    };
    validate_strategy(index, &payload.strategy, diagnostics);
    if payload.selection.edges.is_empty() {
        diagnostics.push(deny(
            format!("outbounds[{index}].payload.selection.edges"),
            "plan outbound must include at least one edge",
        ));
    }
    let mut seen_edges = BTreeSet::new();
    for (edge_index, edge) in payload.selection.edges.iter().enumerate() {
        if edge.to.trim().is_empty() {
            diagnostics.push(deny(
                format!("outbounds[{index}].payload.selection.edges[{edge_index}].to"),
                "plan edge target must not be empty",
            ));
            continue;
        }
        if edge.to == outbound.tag {
            diagnostics.push(deny(
                format!("outbounds[{index}].payload.selection.edges[{edge_index}].to"),
                "plan outbound must not reference itself",
            ));
        }
        if !seen_edges.insert((edge.kind, edge.to.as_str())) {
            diagnostics.push(deny(
                format!("outbounds[{index}].payload.selection.edges[{edge_index}]"),
                "duplicate plan edge",
            ));
        }
        match outbounds.get(edge.to.as_str()) {
            Some(target) => validate_edge_gate(index, edge_index, outbound, target, diagnostics),
            None => diagnostics.push(deny(
                format!("outbounds[{index}].payload.selection.edges[{edge_index}].to"),
                format!("plan edge references unknown outbound `{}`", edge.to),
            )),
        }
    }
}

fn validate_dialer_outbound(
    index: usize,
    outbound: &NetworkNode,
    outbounds: &BTreeMap<&str, &NetworkNode>,
    diagnostics: &mut Vec<ConfigDiagnostic>,
) {
    let payload = match dialer_payload(outbound) {
        Ok(payload) => payload,
        Err(error) => {
            diagnostics.push(deny(format!("outbounds[{index}].payload"), error));
            return;
        }
    };
    let bound = validate_dialer_reference(
        index,
        outbound,
        "bound",
        &payload.bound,
        outbounds,
        diagnostics,
    );
    let target = validate_dialer_reference(
        index,
        outbound,
        "target",
        &payload.target,
        outbounds,
        diagnostics,
    );
    if payload.bound == payload.target {
        diagnostics.push(deny(
            format!("outbounds[{index}].payload"),
            "dialer bound and target must be different outbounds",
        ));
    }
    if let Some(bound) = bound {
        validate_required_capability(index, "bound", bound, "tcp", diagnostics);
    }
    if let Some(target) = target {
        validate_required_capability(index, "target", target, "tcp", diagnostics);
        if matches!(target.kind.as_str(), "plan" | "dialer") {
            diagnostics.push(deny(
                format!("outbounds[{index}].payload.target"),
                format!(
                    "dialer target `{}` must be a concrete private outbound, not `{}`",
                    target.tag, target.kind
                ),
            ));
        }
    }
}

fn validate_dialer_reference<'a>(
    index: usize,
    outbound: &NetworkNode,
    field: &'static str,
    tag: &str,
    outbounds: &'a BTreeMap<&str, &NetworkNode>,
    diagnostics: &mut Vec<ConfigDiagnostic>,
) -> Option<&'a NetworkNode> {
    if tag.trim().is_empty() {
        diagnostics.push(deny(
            format!("outbounds[{index}].payload.{field}"),
            format!("dialer {field} outbound must not be empty"),
        ));
        return None;
    }
    if tag == outbound.tag {
        diagnostics.push(deny(
            format!("outbounds[{index}].payload.{field}"),
            "dialer outbound must not reference itself",
        ));
        return None;
    }
    match outbounds.get(tag) {
        Some(node) => Some(*node),
        None => {
            diagnostics.push(deny(
                format!("outbounds[{index}].payload.{field}"),
                format!("dialer {field} references unknown outbound `{tag}`"),
            ));
            None
        }
    }
}

fn validate_required_capability(
    index: usize,
    field: &'static str,
    target: &NetworkNode,
    capability: &'static str,
    diagnostics: &mut Vec<ConfigDiagnostic>,
) {
    let capabilities = capabilities_for(target)
        .into_iter()
        .collect::<BTreeSet<String>>();
    if !capabilities.contains(capability) {
        diagnostics.push(deny(
            format!("outbounds[{index}].payload.{field}"),
            format!(
                "dialer {field} outbound `{}` lacks required capability `{capability}`",
                target.tag
            ),
        ));
    }
}

fn validate_strategy(
    index: usize,
    strategy: &crate::OutboundStrategyConfig,
    diagnostics: &mut Vec<ConfigDiagnostic>,
) {
    let registry = OutboundStrategyRegistry::default();
    validate_strategy_text(index, strategy, diagnostics);
    let source = strategy.effective_source();
    if source != "internal" {
        diagnostics.push(deny(
            format!("outbounds[{index}].payload.strategy.source"),
            format!("unknown outbound strategy source `{source}`"),
        ));
        return;
    }
    let key = strategy.effective_key();
    let Some(entry) = registry.entry(source, key) else {
        diagnostics.push(deny(
            format!("outbounds[{index}].payload.strategy.key"),
            format!("unknown outbound strategy key `{key}`"),
        ));
        return;
    };
    let version = strategy.effective_version(entry);
    if version != entry.version {
        diagnostics.push(deny(
            format!("outbounds[{index}].payload.strategy.version"),
            format!("outbound strategy `{source}/{key}` does not support version `{version}`"),
        ));
    }
    if let Err(error) = registry.resolve(strategy) {
        diagnostics.push(deny(format!("outbounds[{index}].payload.strategy"), error));
    }
}

fn validate_strategy_text(
    index: usize,
    strategy: &crate::OutboundStrategyConfig,
    diagnostics: &mut Vec<ConfigDiagnostic>,
) {
    if strategy.source.trim() != strategy.source {
        diagnostics.push(deny(
            format!("outbounds[{index}].payload.strategy.source"),
            "outbound strategy source must not be padded",
        ));
    }
    if strategy.key.trim() != strategy.key {
        diagnostics.push(deny(
            format!("outbounds[{index}].payload.strategy.key"),
            "outbound strategy key must not be padded",
        ));
    }
    if strategy.version.trim() != strategy.version {
        diagnostics.push(deny(
            format!("outbounds[{index}].payload.strategy.version"),
            "outbound strategy version must not be padded",
        ));
    }
}

fn validate_edge_gate(
    index: usize,
    edge_index: usize,
    plan: &NetworkNode,
    target: &NetworkNode,
    diagnostics: &mut Vec<ConfigDiagnostic>,
) {
    let plan_caps = capabilities_for(plan).into_iter().collect::<BTreeSet<_>>();
    let target_caps = capabilities_for(target)
        .into_iter()
        .collect::<BTreeSet<_>>();
    for capability in plan_caps {
        if is_runtime_capability(&capability) && !target_caps.contains(&capability) {
            diagnostics.push(deny(
                format!("outbounds[{index}].payload.selection.edges[{edge_index}]"),
                format!(
                    "plan edge target `{}` lacks required capability `{capability}`",
                    target.tag
                ),
            ));
        }
    }
}

fn validate_plan_cycles(config: &DynetConfig, diagnostics: &mut Vec<ConfigDiagnostic>) {
    let outbounds = config
        .outbounds
        .iter()
        .map(|outbound| (outbound.tag.as_str(), outbound))
        .collect::<BTreeMap<_, _>>();
    for (index, outbound) in config.outbounds.iter().enumerate() {
        if !matches!(outbound.kind.as_str(), "plan" | "dialer") {
            continue;
        }
        let mut stack = Vec::new();
        if let Some(cycle) = find_cycle(outbound, &outbounds, &mut stack) {
            diagnostics.push(deny(
                format!("outbounds[{index}].payload.selection.edges"),
                format!("outbound plan graph contains cycle `{cycle}`"),
            ));
        }
    }
}

fn find_cycle<'a>(
    outbound: &'a NetworkNode,
    outbounds: &BTreeMap<&'a str, &'a NetworkNode>,
    stack: &mut Vec<&'a str>,
) -> Option<String> {
    if let Some(position) = stack.iter().position(|tag| *tag == outbound.tag) {
        let mut cycle = stack[position..].to_vec();
        cycle.push(outbound.tag.as_str());
        return Some(cycle.join(" -> "));
    }
    if !matches!(outbound.kind.as_str(), "plan" | "dialer") {
        return None;
    }
    stack.push(outbound.tag.as_str());
    for next_tag in outbound_references(outbound) {
        let Some(next) = outbounds.get(next_tag.as_str()) else {
            continue;
        };
        if let Some(cycle) = find_cycle(next, outbounds, stack) {
            return Some(cycle);
        }
    }
    stack.pop();
    None
}

fn outbound_references(outbound: &NetworkNode) -> Vec<String> {
    match outbound.kind.as_str() {
        "plan" => plan_payload(outbound)
            .map(|payload| {
                payload
                    .selection
                    .edges
                    .into_iter()
                    .map(|edge| edge.to)
                    .collect()
            })
            .unwrap_or_default(),
        "dialer" => dialer_payload(outbound)
            .map(|payload| vec![payload.bound, payload.target])
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

fn is_runtime_capability(capability: &str) -> bool {
    matches!(capability, "tcp" | "udp" | "dns")
}
