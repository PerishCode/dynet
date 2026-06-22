use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, RwLock},
};

use serde::Serialize;
use utoipa::ToSchema;

use super::{GroupId, InboundKind, MatrixNodeStats, NodeId, SelectionContext, SelectionDecision};

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
    node_stats: &[MatrixNodeStats],
) -> MatrixShadowDecision {
    let stats_by_node = stats_by_node(group_id, node_stats);
    let mut scored = candidates
        .into_iter()
        .enumerate()
        .map(|(rank, candidate)| {
            let selected_by_actual = candidate.node_id == actual.node_id;
            let stats = stats_by_node.get(candidate.node_id.as_str());
            MatrixShadowCandidate {
                node_id: candidate.node_id.to_string(),
                priority: candidate.priority,
                score: stats_balanced_score(candidate.priority, rank, stats),
                reason: stats_balanced_reason(stats),
                selected_by_actual,
                selected_by_shadow: false,
            }
        })
        .collect::<Vec<_>>();
    scored.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.node_id.cmp(&right.node_id))
    });

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
        shadow_reason: "stats-balanced-shadow".to_string(),
        candidates: scored,
    }
}

fn stats_by_node<'a>(
    group_id: &GroupId,
    node_stats: &'a [MatrixNodeStats],
) -> BTreeMap<&'a str, &'a MatrixNodeStats> {
    node_stats
        .iter()
        .filter(|stats| stats.group_id == group_id.as_str())
        .map(|stats| (stats.node_id.as_str(), stats))
        .collect()
}

fn stats_balanced_score(priority: u32, rank: usize, stats: Option<&&MatrixNodeStats>) -> i64 {
    const PRIORITY_WEIGHT: i64 = 1_000_000_000;
    const ERROR_RATE_WEIGHT: i64 = 100;
    const LATENCY_WEIGHT: i64 = 1_000;
    const ACTIVE_SESSION_WEIGHT: i64 = 10_000;
    const RECENT_USAGE_WEIGHT: i64 = 10;

    let priority_score = 1_000_000_000_000_i64
        - i64::from(priority) * PRIORITY_WEIGHT
        - i64::try_from(rank).unwrap_or(i64::MAX);
    let Some(stats) = stats else {
        return priority_score;
    };
    priority_score
        - i64::from(stats.error_rate_ppm) * ERROR_RATE_WEIGHT
        - u128_to_score_penalty(
            stats
                .avg_first_response_latency_ms
                .unwrap_or_default()
                .min(100_000),
        ) * LATENCY_WEIGHT
        - u64_to_score_penalty(stats.active_session_count) * ACTIVE_SESSION_WEIGHT
        - u64_to_score_penalty(stats.session_count) * RECENT_USAGE_WEIGHT
}

fn stats_balanced_reason(stats: Option<&&MatrixNodeStats>) -> String {
    let Some(stats) = stats else {
        return "stats-balanced-shadow:no-history".to_string();
    };
    format!(
        "stats-balanced-shadow:sessions={},errors={},active={},latencyMs={}",
        stats.session_count,
        stats.error_count,
        stats.active_session_count,
        stats
            .avg_first_response_latency_ms
            .map(|latency| latency.to_string())
            .unwrap_or_else(|| "none".to_string())
    )
}

fn u128_to_score_penalty(value: u128) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn u64_to_score_penalty(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn inbound_label(inbound: InboundKind) -> &'static str {
    match inbound {
        InboundKind::Tcp => "tcp",
        InboundKind::Udp => "udp",
    }
}
