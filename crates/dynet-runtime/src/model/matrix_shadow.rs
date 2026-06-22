use std::{
    collections::VecDeque,
    sync::{Arc, RwLock},
};

use serde::Serialize;
use utoipa::ToSchema;

use super::{GroupId, InboundKind, NodeId, SelectionContext, SelectionDecision};

const MATRIX_SHADOW_LIMIT: usize = 1024;

#[derive(Debug, Clone, Default)]
pub struct MatrixShadowStore {
    inner: Arc<RwLock<VecDeque<MatrixShadowDecision>>>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MatrixShadowDecision {
    pub decision_id: u64,
    pub session_id: u64,
    pub observed_at_unix_ms: u128,
    pub inbound: String,
    pub group_id: String,
    pub actual_node_id: String,
    pub shadow_top_node_id: Option<String>,
    pub shadow_differs_from_actual: bool,
    pub shadow_reason: String,
    pub candidates: Vec<MatrixShadowCandidate>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MatrixShadowCandidate {
    pub node_id: String,
    pub priority: u32,
    pub score: i64,
    pub reason: String,
    pub selected_by_actual: bool,
    pub selected_by_shadow: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct MatrixCandidateInput {
    pub(crate) node_id: NodeId,
    pub(crate) priority: u32,
}

impl MatrixShadowStore {
    pub(crate) fn record(&self, decision: MatrixShadowDecision) {
        let mut decisions = self
            .inner
            .write()
            .expect("matrix shadow store lock poisoned");
        if decisions.len() == MATRIX_SHADOW_LIMIT {
            decisions.pop_front();
        }
        decisions.push_back(decision);
    }

    pub fn snapshot(&self) -> Vec<MatrixShadowDecision> {
        self.inner
            .read()
            .expect("matrix shadow store lock poisoned")
            .iter()
            .cloned()
            .collect()
    }
}

pub(crate) fn score_candidates(
    observed_at_unix_ms: u128,
    context: &SelectionContext,
    group_id: &GroupId,
    actual: &SelectionDecision,
    candidates: Vec<MatrixCandidateInput>,
) -> MatrixShadowDecision {
    let mut scored = candidates
        .into_iter()
        .enumerate()
        .map(|(rank, candidate)| {
            let selected_by_actual = candidate.node_id == actual.node_id;
            MatrixShadowCandidate {
                node_id: candidate.node_id.to_string(),
                priority: candidate.priority,
                score: priority_score(candidate.priority, rank),
                reason: "priority-baseline".to_string(),
                selected_by_actual,
                selected_by_shadow: false,
            }
        })
        .collect::<Vec<_>>();

    let shadow_top_node_id = scored.first().map(|candidate| candidate.node_id.clone());
    if let Some(first) = scored.first_mut() {
        first.selected_by_shadow = true;
    }
    MatrixShadowDecision {
        decision_id: actual.decision_id,
        session_id: context.session_id,
        observed_at_unix_ms,
        inbound: inbound_label(context.inbound).to_string(),
        group_id: group_id.to_string(),
        actual_node_id: actual.node_id.to_string(),
        shadow_differs_from_actual: shadow_top_node_id
            .as_deref()
            .is_some_and(|node_id| node_id != actual.node_id.as_str()),
        shadow_top_node_id,
        shadow_reason: "priority-baseline".to_string(),
        candidates: scored,
    }
}

fn priority_score(priority: u32, rank: usize) -> i64 {
    1_000_000_i64 - i64::from(priority) * 1_000 - i64::try_from(rank).unwrap_or(i64::MAX)
}

fn inbound_label(inbound: InboundKind) -> &'static str {
    match inbound {
        InboundKind::Tcp => "tcp",
        InboundKind::Udp => "udp",
    }
}
