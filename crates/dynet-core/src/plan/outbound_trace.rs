use serde::Serialize;

use crate::AppState;

use super::{
    outbound::{PlanEdge, PlanEdgeKind},
    strategy::OutboundStrategySnapshot,
};

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutboundPath {
    pub requested: String,
    pub selected: String,
    pub hops: Vec<OutboundHop>,
    pub decisions: Vec<OutboundDecision>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutboundHop {
    pub tag: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edge_type: Option<PlanEdgeKind>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutboundDecision {
    pub plan: String,
    pub strategy: OutboundStrategySnapshot,
    pub candidates: Vec<OutboundCandidate>,
    pub selected: String,
    pub selected_edge_type: PlanEdgeKind,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutboundCandidate {
    pub to: String,
    pub edge_type: PlanEdgeKind,
    #[serde(rename = "type")]
    pub target_kind: String,
    pub capabilities: Vec<String>,
}

pub(super) fn outbound_candidates(state: &AppState, edges: &[PlanEdge]) -> Vec<OutboundCandidate> {
    edges
        .iter()
        .map(|edge| {
            let target = state
                .config
                .outbounds
                .iter()
                .find(|node| node.tag == edge.to);
            OutboundCandidate {
                to: edge.to.clone(),
                edge_type: edge.kind,
                target_kind: target
                    .map(|node| node.kind.clone())
                    .unwrap_or_else(|| "<missing>".to_string()),
                capabilities: target
                    .map(|node| node.capabilities.clone())
                    .unwrap_or_default(),
            }
        })
        .collect()
}
