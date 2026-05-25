use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{AppState, InboundContext, NetworkNode};

use super::{
    outbound_trace::{outbound_candidates, OutboundDecision, OutboundHop, OutboundPath},
    strategy::{OutboundStrategyConfig, OutboundStrategyRegistry},
};

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct PlanOutboundPayload {
    #[serde(default)]
    pub strategy: OutboundStrategyConfig,
    pub selection: PlanSelection,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct DialerOutboundPayload {
    pub bound: String,
    pub target: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct PlanSelection {
    #[serde(default)]
    pub edges: Vec<PlanEdge>,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct PlanEdge {
    #[serde(rename = "type")]
    pub kind: PlanEdgeKind,
    pub to: String,
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PlanEdgeKind {
    Candidate,
    Fallback,
}

pub fn plan_payload(node: &NetworkNode) -> Result<PlanOutboundPayload, String> {
    payload_as(node)
        .map_err(|error| format!("plan outbound `{}` payload is invalid: {error}", node.tag))
}

pub fn dialer_payload(node: &NetworkNode) -> Result<DialerOutboundPayload, String> {
    payload_as(node)
        .map_err(|error| format!("dialer outbound `{}` payload is invalid: {error}", node.tag))
}

pub fn resolve_outbound_path(
    state: &AppState,
    context: &InboundContext,
    tag: &str,
) -> Result<OutboundPath, String> {
    let mut stack = Vec::new();
    let mut hops = Vec::new();
    let mut decisions = Vec::new();
    resolve_path_inner(
        state,
        context,
        tag,
        None,
        &mut stack,
        &mut hops,
        &mut decisions,
    )?;
    let selected = hops
        .last()
        .map(|hop| hop.tag.clone())
        .ok_or_else(|| format!("outbound path `{tag}` resolved to no hops"))?;
    Ok(OutboundPath {
        requested: tag.to_string(),
        selected,
        hops,
        decisions,
    })
}

pub fn payload_as<T>(node: &NetworkNode) -> Result<T, String>
where
    T: for<'de> Deserialize<'de>,
{
    let object = node.payload.clone().into_iter().collect();
    serde_json::from_value(Value::Object(object))
        .map_err(|error| format!("failed to decode payload for `{}`: {error}", node.tag))
}

fn resolve_path_inner(
    state: &AppState,
    context: &InboundContext,
    tag: &str,
    edge_type: Option<PlanEdgeKind>,
    stack: &mut Vec<String>,
    hops: &mut Vec<OutboundHop>,
    decisions: &mut Vec<OutboundDecision>,
) -> Result<(), String> {
    if stack.iter().any(|item| item == tag) {
        return Err(format!("outbound graph cycle detected at `{tag}`"));
    }
    let node = state
        .config
        .outbounds
        .iter()
        .find(|outbound| outbound.tag == tag)
        .ok_or_else(|| format!("outbound graph references unknown outbound `{tag}`"))?;
    hops.push(OutboundHop {
        tag: node.tag.clone(),
        kind: node.kind.clone(),
        edge_type,
    });
    if node.kind != "plan" {
        return Ok(());
    }

    stack.push(tag.to_string());
    let payload = plan_payload(node)?;
    let strategy = OutboundStrategyRegistry::default().resolve(&payload.strategy)?;
    let candidates =
        outbound_candidates(state, context, strategy.selector, &payload.selection.edges);
    let edge = strategy
        .selector
        .select(&payload.selection.edges, context, state)
        .ok_or_else(|| format!("plan outbound `{tag}` has no selectable edges"))?;
    decisions.push(OutboundDecision {
        plan: tag.to_string(),
        strategy,
        candidates,
        selected: edge.to.clone(),
        selected_edge_type: edge.kind,
    });
    resolve_path_inner(
        state,
        context,
        &edge.to,
        Some(edge.kind),
        stack,
        hops,
        decisions,
    )?;
    stack.pop();
    Ok(())
}
