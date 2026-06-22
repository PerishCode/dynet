use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use utoipa::ToSchema;

use crate::TrafficSession;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MatrixNodeStats {
    pub group_id: String,
    pub node_id: String,
    pub node_fingerprint: String,
    pub session_count: u64,
    pub success_count: u64,
    pub error_count: u64,
    pub effective_error_count: u64,
    pub effective_error_millis: u64,
    pub active_session_count: u64,
    pub error_rate_ppm: u32,
    pub effective_error_rate_ppm: u32,
    pub avg_first_response_latency_ms: Option<u128>,
    pub client_to_upstream_bytes: u64,
    pub upstream_to_client_bytes: u64,
    pub client_to_upstream_datagrams: u64,
    pub upstream_to_client_datagrams: u64,
    pub last_observed_at_unix_ms: u128,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MatrixTargetNodeStats {
    pub group_id: String,
    pub node_id: String,
    pub node_fingerprint: String,
    pub target_scope: String,
    pub target_value: String,
    pub session_count: u64,
    pub success_count: u64,
    pub error_count: u64,
    pub effective_error_count: u64,
    pub effective_error_millis: u64,
    pub active_session_count: u64,
    pub error_rate_ppm: u32,
    pub effective_error_rate_ppm: u32,
    pub avg_first_response_latency_ms: Option<u128>,
    pub client_to_upstream_bytes: u64,
    pub upstream_to_client_bytes: u64,
    pub client_to_upstream_datagrams: u64,
    pub upstream_to_client_datagrams: u64,
    pub last_observed_at_unix_ms: u128,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MatrixErrorSignalStats {
    pub group_id: String,
    pub node_id: String,
    pub node_fingerprint: String,
    pub target_scope: String,
    pub target_value: String,
    pub node_protocol: String,
    pub error_class: String,
    pub error_code: String,
    pub error_side: String,
    pub error_phase: String,
    pub error_protocol_phase: String,
    pub error_score_impact: String,
    pub attempt_count: u64,
    pub logical_session_count: u64,
    pub effective_error_count: u64,
    pub effective_error_millis: u64,
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
    effective_error_millis: u64,
    active_session_count: u64,
    first_response_latency_total_ms: u128,
    first_response_latency_count: u64,
    client_to_upstream_bytes: u64,
    upstream_to_client_bytes: u64,
    client_to_upstream_datagrams: u64,
    upstream_to_client_datagrams: u64,
    last_observed_at_unix_ms: u128,
}

#[derive(Debug, Default)]
struct MatrixErrorSignalAccumulator {
    attempt_count: u64,
    logical_session_ids: BTreeSet<u64>,
    effective_error_millis: u64,
    client_to_upstream_bytes: u64,
    upstream_to_client_bytes: u64,
    client_to_upstream_datagrams: u64,
    upstream_to_client_datagrams: u64,
    last_observed_at_unix_ms: u128,
}

pub(crate) fn node_stats_from_sessions(
    sessions: &[TrafficSession],
    fingerprints_by_node: &BTreeMap<String, String>,
) -> Vec<MatrixNodeStats> {
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
        .map(|((group_id, node_id), accumulator)| {
            let node_fingerprint = node_fingerprint(&node_id, fingerprints_by_node);
            accumulator.finish(group_id, node_id, node_fingerprint)
        })
        .collect()
}

pub(crate) fn target_stats_from_sessions(
    sessions: &[TrafficSession],
    fingerprints_by_node: &BTreeMap<String, String>,
) -> Vec<MatrixTargetNodeStats> {
    let mut stats = BTreeMap::<(String, String, String, String), MatrixNodeStatsAccumulator>::new();
    for session in sessions {
        let Some((target_scope, target_value)) = target_scope(session) else {
            continue;
        };
        let Some(pairs) = selection_pairs(session) else {
            continue;
        };
        for (group_id, node_id) in pairs {
            stats
                .entry((
                    group_id,
                    node_id,
                    target_scope.clone(),
                    target_value.clone(),
                ))
                .or_default()
                .record(session);
        }
    }
    stats
        .into_iter()
        .map(
            |((group_id, node_id, target_scope, target_value), accumulator)| {
                let node_fingerprint = node_fingerprint(&node_id, fingerprints_by_node);
                accumulator.finish_target(
                    group_id,
                    node_id,
                    node_fingerprint,
                    target_scope,
                    target_value,
                )
            },
        )
        .collect()
}

pub(crate) fn error_signals_from_sessions(
    sessions: &[TrafficSession],
    fingerprints_by_node: &BTreeMap<String, String>,
) -> Vec<MatrixErrorSignalStats> {
    let mut stats = BTreeMap::<
        (
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            String,
        ),
        MatrixErrorSignalAccumulator,
    >::new();
    for session in sessions {
        if session.error.is_none() {
            continue;
        }
        let Some(pairs) = selection_pairs(session) else {
            continue;
        };
        let (target_scope, target_value) =
            target_scope(session).unwrap_or_else(|| ("unknown".to_string(), String::new()));
        let node_protocol = optional_value(&session.node_protocol);
        let error_class = optional_value(&session.error_class);
        let error_code = optional_value(&session.error_code);
        let error_side = optional_value(&session.error_side);
        let error_phase = optional_value(&session.error_phase);
        let error_protocol_phase = optional_value(&session.error_protocol_phase);
        let error_score_impact = optional_value(&session.error_score_impact);
        for (group_id, node_id) in pairs {
            stats
                .entry((
                    group_id,
                    node_id,
                    target_scope.clone(),
                    target_value.clone(),
                    node_protocol.clone(),
                    error_class.clone(),
                    error_code.clone(),
                    error_side.clone(),
                    error_phase.clone(),
                    error_protocol_phase.clone(),
                    error_score_impact.clone(),
                ))
                .or_default()
                .record(session);
        }
    }
    stats
        .into_iter()
        .map(
            |(
                (
                    group_id,
                    node_id,
                    target_scope,
                    target_value,
                    node_protocol,
                    error_class,
                    error_code,
                    error_side,
                    error_phase,
                    error_protocol_phase,
                    error_score_impact,
                ),
                accumulator,
            )| {
                let node_fingerprint = node_fingerprint(&node_id, fingerprints_by_node);
                accumulator.finish(
                    group_id,
                    node_id,
                    node_fingerprint,
                    target_scope,
                    target_value,
                    node_protocol,
                    error_class,
                    error_code,
                    error_side,
                    error_phase,
                    error_protocol_phase,
                    error_score_impact,
                )
            },
        )
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

fn optional_value(value: &Option<String>) -> String {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown")
        .to_string()
}

impl MatrixNodeStatsAccumulator {
    fn record(&mut self, session: &TrafficSession) {
        self.session_count += 1;
        if session.error.is_some() {
            self.error_count += 1;
            self.effective_error_millis += effective_error_millis(session);
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

    fn finish(
        self,
        group_id: String,
        node_id: String,
        node_fingerprint: String,
    ) -> MatrixNodeStats {
        MatrixNodeStats {
            group_id,
            node_id,
            node_fingerprint,
            session_count: self.session_count,
            success_count: self.success_count,
            error_count: self.error_count,
            effective_error_count: millis_to_count(self.effective_error_millis),
            effective_error_millis: self.effective_error_millis,
            active_session_count: self.active_session_count,
            error_rate_ppm: rate_ppm(self.error_count, self.session_count),
            effective_error_rate_ppm: effective_rate_ppm(
                self.effective_error_millis,
                self.session_count,
            ),
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

    fn finish_target(
        self,
        group_id: String,
        node_id: String,
        node_fingerprint: String,
        target_scope: String,
        target_value: String,
    ) -> MatrixTargetNodeStats {
        MatrixTargetNodeStats {
            group_id,
            node_id,
            node_fingerprint,
            target_scope,
            target_value,
            session_count: self.session_count,
            success_count: self.success_count,
            error_count: self.error_count,
            effective_error_count: millis_to_count(self.effective_error_millis),
            effective_error_millis: self.effective_error_millis,
            active_session_count: self.active_session_count,
            error_rate_ppm: rate_ppm(self.error_count, self.session_count),
            effective_error_rate_ppm: effective_rate_ppm(
                self.effective_error_millis,
                self.session_count,
            ),
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

impl MatrixErrorSignalAccumulator {
    fn record(&mut self, session: &TrafficSession) {
        self.attempt_count += 1;
        self.logical_session_ids.insert(session.session_id);
        self.effective_error_millis += effective_error_millis(session);
        self.client_to_upstream_bytes += session.client_to_upstream_bytes;
        self.upstream_to_client_bytes += session.upstream_to_client_bytes;
        self.client_to_upstream_datagrams += session.client_to_upstream_datagrams;
        self.upstream_to_client_datagrams += session.upstream_to_client_datagrams;
        self.last_observed_at_unix_ms = self
            .last_observed_at_unix_ms
            .max(session.last_observed_at_unix_ms);
    }

    #[allow(clippy::too_many_arguments)]
    fn finish(
        self,
        group_id: String,
        node_id: String,
        node_fingerprint: String,
        target_scope: String,
        target_value: String,
        node_protocol: String,
        error_class: String,
        error_code: String,
        error_side: String,
        error_phase: String,
        error_protocol_phase: String,
        error_score_impact: String,
    ) -> MatrixErrorSignalStats {
        MatrixErrorSignalStats {
            group_id,
            node_id,
            node_fingerprint,
            target_scope,
            target_value,
            node_protocol,
            error_class,
            error_code,
            error_side,
            error_phase,
            error_protocol_phase,
            error_score_impact,
            attempt_count: self.attempt_count,
            logical_session_count: u64::try_from(self.logical_session_ids.len())
                .unwrap_or(u64::MAX),
            effective_error_count: millis_to_count(self.effective_error_millis),
            effective_error_millis: self.effective_error_millis,
            client_to_upstream_bytes: self.client_to_upstream_bytes,
            upstream_to_client_bytes: self.upstream_to_client_bytes,
            client_to_upstream_datagrams: self.client_to_upstream_datagrams,
            upstream_to_client_datagrams: self.upstream_to_client_datagrams,
            last_observed_at_unix_ms: self.last_observed_at_unix_ms,
        }
    }
}

pub(crate) fn target_scope(session: &TrafficSession) -> Option<(String, String)> {
    if let Some(domain) = session.target_domain.as_deref().map(str::trim) {
        if !domain.is_empty() {
            return Some(("domain".to_string(), domain.to_ascii_lowercase()));
        }
    }
    if let Some(ip) = session.target_ip.as_deref().map(str::trim) {
        if !ip.is_empty() {
            return Some(("ip".to_string(), ip.to_string()));
        }
    }
    None
}

fn node_fingerprint(node_id: &str, fingerprints_by_node: &BTreeMap<String, String>) -> String {
    fingerprints_by_node
        .get(node_id)
        .cloned()
        .filter(|fingerprint| !fingerprint.is_empty())
        .unwrap_or_else(|| format!("node-id:{node_id}"))
}

fn effective_error_millis(session: &TrafficSession) -> u64 {
    match session.error_class.as_deref() {
        Some("client-aborted") => 0,
        Some("response-interrupted") if session.upstream_to_client_bytes > 0 => 250,
        Some("no-response-before-first-byte") => 750,
        Some("response-interrupted") => 750,
        Some("handshake-failed") => 1_000,
        Some("connect-failed" | "protocol-invalid" | "request-write-failed") => 1_000,
        Some("unknown-failure") | Some(_) | None => 1_000,
    }
}

fn millis_to_count(value: u64) -> u64 {
    value.div_ceil(1_000)
}

fn rate_ppm(numerator: u64, denominator: u64) -> u32 {
    if denominator == 0 {
        return 0;
    }
    let rate = u128::from(numerator) * 1_000_000 / u128::from(denominator);
    u32::try_from(rate).unwrap_or(u32::MAX)
}

fn effective_rate_ppm(error_millis: u64, sessions: u64) -> u32 {
    if sessions == 0 {
        return 0;
    }
    let rate = u128::from(error_millis) * 1_000 / u128::from(sessions);
    u32::try_from(rate).unwrap_or(u32::MAX)
}
