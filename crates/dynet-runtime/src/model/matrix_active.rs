use super::{
    GroupId, GroupThresholds, MatrixCandidateInput, MatrixNodeStats, MatrixTargetNodeStats, NodeId,
    SelectionContext,
};

pub(crate) fn select_active_candidate(
    context: &SelectionContext,
    group_id: &GroupId,
    thresholds: GroupThresholds,
    candidates: &[MatrixCandidateInput],
    node_stats: &[MatrixNodeStats],
    target_stats: &[MatrixTargetNodeStats],
) -> Option<NodeId> {
    if !active_rollout_group(group_id) {
        return None;
    }
    candidates
        .iter()
        .enumerate()
        .map(|(rank, candidate)| {
            let target = matching_target_stats(context, group_id, &candidate.node_id, target_stats);
            let aggregate = matching_node_stats(group_id, &candidate.node_id, node_stats);
            (
                candidate.node_id.clone(),
                active_score(candidate.priority, rank, thresholds, target, aggregate),
            )
        })
        .max_by(|left, right| left.1.cmp(&right.1).then_with(|| right.0.cmp(&left.0)))
        .map(|(node_id, _)| node_id)
}

fn active_rollout_group(group_id: &GroupId) -> bool {
    matches!(group_id.as_str(), "GitHub" | "Common")
}

fn active_score(
    priority: u32,
    rank: usize,
    thresholds: GroupThresholds,
    target: Option<&MatrixTargetNodeStats>,
    aggregate: Option<&MatrixNodeStats>,
) -> i64 {
    const PRIORITY_WEIGHT: i64 = 1_000_000_000;
    const ERROR_RATE_WEIGHT: i64 = 100;
    const LATENCY_WEIGHT: i64 = 1_000;
    const ACTIVE_SESSION_WEIGHT: i64 = 10_000;
    const RECENT_USAGE_WEIGHT: i64 = 10;
    const COOLDOWN_PENALTY: i64 = 2_000_000_000_000;
    const CONCURRENCY_CAP_PENALTY: i64 = 3_000_000_000_000;

    let mut score = 1_000_000_000_000_i64
        - i64::from(priority) * PRIORITY_WEIGHT
        - i64::try_from(rank).unwrap_or(i64::MAX);
    if aggregate.is_some_and(|stats| capped_node(stats, thresholds)) {
        score -= CONCURRENCY_CAP_PENALTY;
    }
    if let Some(stats) = target {
        score -= target_penalty(stats);
        if cooled_target(stats, thresholds) {
            score -= COOLDOWN_PENALTY;
        }
        return score;
    }
    if let Some(stats) = aggregate {
        score -= i64::from(stats.effective_error_rate_ppm) * ERROR_RATE_WEIGHT;
        score -= latency_penalty(stats.avg_first_response_latency_ms) * LATENCY_WEIGHT;
        score -= u64_penalty(stats.active_session_count) * ACTIVE_SESSION_WEIGHT;
        score -= u64_penalty(stats.session_count) * RECENT_USAGE_WEIGHT;
    }
    score
}

fn target_penalty(stats: &MatrixTargetNodeStats) -> i64 {
    const ERROR_RATE_WEIGHT: i64 = 100;
    const LATENCY_WEIGHT: i64 = 1_000;
    const ACTIVE_SESSION_WEIGHT: i64 = 10_000;
    const RECENT_USAGE_WEIGHT: i64 = 10;

    i64::from(stats.effective_error_rate_ppm) * ERROR_RATE_WEIGHT
        + latency_penalty(stats.avg_first_response_latency_ms) * LATENCY_WEIGHT
        + u64_penalty(stats.active_session_count) * ACTIVE_SESSION_WEIGHT
        + u64_penalty(stats.session_count) * RECENT_USAGE_WEIGHT
}

fn capped_node(stats: &MatrixNodeStats, thresholds: GroupThresholds) -> bool {
    thresholds
        .max_active_sessions
        .is_some_and(|limit| stats.active_session_count >= limit)
}

fn cooled_target(stats: &MatrixTargetNodeStats, thresholds: GroupThresholds) -> bool {
    let completed_millis = stats.success_count.saturating_mul(1_000) + stats.effective_error_millis;
    completed_millis >= thresholds.min_samples.saturating_mul(1_000)
        && weighted_success_rate_ppm(stats.success_count, completed_millis)
            < thresholds.min_success_rate_ppm
}

fn matching_target_stats<'a>(
    context: &SelectionContext,
    group_id: &GroupId,
    node_id: &NodeId,
    stats: &'a [MatrixTargetNodeStats],
) -> Option<&'a MatrixTargetNodeStats> {
    let (scope, value) = target_scope(context);
    stats.iter().find(|stats| {
        stats.group_id == group_id.as_str()
            && stats.node_id == node_id.as_str()
            && stats.target_scope == scope
            && stats.target_value == value
    })
}

fn matching_node_stats<'a>(
    group_id: &GroupId,
    node_id: &NodeId,
    stats: &'a [MatrixNodeStats],
) -> Option<&'a MatrixNodeStats> {
    stats
        .iter()
        .find(|stats| stats.group_id == group_id.as_str() && stats.node_id == node_id.as_str())
}

fn target_scope(context: &SelectionContext) -> (String, String) {
    if let Some(domain) = context.target.domain.as_deref().map(str::trim) {
        if !domain.is_empty() {
            return ("domain".to_string(), domain.to_ascii_lowercase());
        }
    }
    ("ip".to_string(), context.target.address.ip().to_string())
}

fn weighted_success_rate_ppm(success: u64, completed_millis: u64) -> u32 {
    if completed_millis == 0 {
        return 0;
    }
    u32::try_from(u128::from(success) * 1_000_000_000 / u128::from(completed_millis))
        .unwrap_or(u32::MAX)
}

fn latency_penalty(value: Option<u128>) -> i64 {
    i64::try_from(value.unwrap_or_default().min(100_000)).unwrap_or(i64::MAX)
}

fn u64_penalty(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}
