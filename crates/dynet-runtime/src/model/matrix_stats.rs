use std::collections::BTreeMap;

use serde::Serialize;
use utoipa::ToSchema;

use crate::TrafficSession;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MatrixNodeStats {
    pub group_id: String,
    pub node_id: String,
    pub session_count: u64,
    pub success_count: u64,
    pub error_count: u64,
    pub active_session_count: u64,
    pub error_rate_ppm: u32,
    pub avg_first_response_latency_ms: Option<u128>,
    pub client_to_upstream_bytes: u64,
    pub upstream_to_client_bytes: u64,
    pub client_to_upstream_datagrams: u64,
    pub upstream_to_client_datagrams: u64,
    pub last_observed_at_unix_ms: u128,
}

#[derive(Debug, Default)]
struct MatrixNodeStatsAccumulator {
    session_count: u64,
    success_count: u64,
    error_count: u64,
    active_session_count: u64,
    first_response_latency_total_ms: u128,
    first_response_latency_count: u64,
    client_to_upstream_bytes: u64,
    upstream_to_client_bytes: u64,
    client_to_upstream_datagrams: u64,
    upstream_to_client_datagrams: u64,
    last_observed_at_unix_ms: u128,
}

pub(crate) fn node_stats_from_sessions(sessions: &[TrafficSession]) -> Vec<MatrixNodeStats> {
    let mut stats = BTreeMap::<(String, String), MatrixNodeStatsAccumulator>::new();
    for session in sessions {
        let Some(pairs) = selection_pairs(session) else {
            continue;
        };
        for (group_id, node_id) in pairs {
            stats
                .entry((group_id, node_id))
                .or_default()
                .record(session);
        }
    }
    stats
        .into_iter()
        .map(|((group_id, node_id), accumulator)| accumulator.finish(group_id, node_id))
        .collect()
}

fn selection_pairs(session: &TrafficSession) -> Option<Vec<(String, String)>> {
    let groups = split_list(session.selection_groups.as_deref()?);
    let nodes = split_list(session.selection_nodes.as_deref()?);
    if groups.is_empty() || groups.len() != nodes.len() {
        return None;
    }
    Some(groups.into_iter().zip(nodes).collect())
}

fn split_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect()
}

impl MatrixNodeStatsAccumulator {
    fn record(&mut self, session: &TrafficSession) {
        self.session_count += 1;
        if session.error.is_some() {
            self.error_count += 1;
        } else if session.closed_at_unix_ms.is_some() {
            self.success_count += 1;
        } else {
            self.active_session_count += 1;
        }
        if let Some(latency) = session.first_response_latency_ms {
            self.first_response_latency_total_ms += latency;
            self.first_response_latency_count += 1;
        }
        self.client_to_upstream_bytes += session.client_to_upstream_bytes;
        self.upstream_to_client_bytes += session.upstream_to_client_bytes;
        self.client_to_upstream_datagrams += session.client_to_upstream_datagrams;
        self.upstream_to_client_datagrams += session.upstream_to_client_datagrams;
        self.last_observed_at_unix_ms = self
            .last_observed_at_unix_ms
            .max(session.last_observed_at_unix_ms);
    }

    fn finish(self, group_id: String, node_id: String) -> MatrixNodeStats {
        MatrixNodeStats {
            group_id,
            node_id,
            session_count: self.session_count,
            success_count: self.success_count,
            error_count: self.error_count,
            active_session_count: self.active_session_count,
            error_rate_ppm: rate_ppm(self.error_count, self.session_count),
            avg_first_response_latency_ms: (self.first_response_latency_count > 0).then(|| {
                self.first_response_latency_total_ms / u128::from(self.first_response_latency_count)
            }),
            client_to_upstream_bytes: self.client_to_upstream_bytes,
            upstream_to_client_bytes: self.upstream_to_client_bytes,
            client_to_upstream_datagrams: self.client_to_upstream_datagrams,
            upstream_to_client_datagrams: self.upstream_to_client_datagrams,
            last_observed_at_unix_ms: self.last_observed_at_unix_ms,
        }
    }
}

fn rate_ppm(numerator: u64, denominator: u64) -> u32 {
    if denominator == 0 {
        return 0;
    }
    let rate = u128::from(numerator) * 1_000_000 / u128::from(denominator);
    u32::try_from(rate).unwrap_or(u32::MAX)
}
