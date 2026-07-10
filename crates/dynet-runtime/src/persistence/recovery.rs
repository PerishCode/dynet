use sqlx::{sqlite::SqliteRow, Row};

use crate::{
    persistence::{usize_to_i64, RuntimeStore, RuntimeStoreError},
    traffic_session::{TrafficSession, TRAFFIC_SESSION_LIMIT},
    MatrixShadowCandidate, MatrixShadowDecision, MATRIX_SHADOW_LIMIT,
};

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub(crate) struct RuntimeIdWatermarks {
    pub(crate) event_id: u64,
    pub(crate) session_id: u64,
    pub(crate) decision_id: u64,
}

impl RuntimeStore {
    pub(crate) async fn load_id_watermarks(
        &self,
    ) -> Result<RuntimeIdWatermarks, RuntimeStoreError> {
        let event_id =
            sqlx::query_scalar::<_, i64>("select coalesce(max(event_id), 0) from runtime_events")
                .fetch_one(&self.pool)
                .await?;
        let session_id = sqlx::query_scalar::<_, i64>(
            "select coalesce(max(value), 0)
             from (
                select max(session_id) as value from runtime_traffic_sessions
                union all
                select max(session_id) as value from selection_decisions
                union all
                select max(session_id) as value from matrix_shadow_decisions
             )",
        )
        .fetch_one(&self.pool)
        .await?;
        let decision_id = sqlx::query_scalar::<_, i64>(
            "select coalesce(max(value), 0)
             from (
                select max(decision_id) as value from runtime_traffic_sessions
                union all
                select max(decision_id) as value from selection_decisions
                union all
                select max(decision_id) as value from matrix_shadow_decisions
             )",
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(RuntimeIdWatermarks {
            event_id: i64_to_u64(event_id),
            session_id: i64_to_u64(session_id),
            decision_id: i64_to_u64(decision_id),
        })
    }

    pub(crate) async fn load_recent_traffic_sessions(
        &self,
    ) -> Result<Vec<TrafficSession>, RuntimeStoreError> {
        let rows = sqlx::query(
            "select *
             from (
                select *
                from runtime_traffic_sessions
                where closed_at_unix_ms is not null or error is not null
                order by last_observed_at_unix_ms desc, session_key desc
                limit ?1
             )
             order by last_observed_at_unix_ms asc, session_key asc",
        )
        .bind(usize_to_i64(TRAFFIC_SESSION_LIMIT))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_traffic_session).collect()
    }

    pub(crate) async fn load_recent_shadows(
        &self,
    ) -> Result<Vec<MatrixShadowDecision>, RuntimeStoreError> {
        let rows = sqlx::query(
            "select *
             from (
                select *
                from matrix_shadow_decisions
                order by observed_at_unix_ms desc, row_id desc
                limit ?1
             )
             order by observed_at_unix_ms asc, row_id asc",
        )
        .bind(usize_to_i64(MATRIX_SHADOW_LIMIT))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_shadow).collect()
    }
}

fn row_to_traffic_session(row: SqliteRow) -> Result<TrafficSession, RuntimeStoreError> {
    Ok(TrafficSession {
        session_key: row.get("session_key"),
        session_id: i64_to_u64(row.get("session_id")),
        decision_id: row.get::<Option<i64>, _>("decision_id").map(i64_to_u64),
        config_generation: row
            .get::<Option<i64>, _>("config_generation")
            .map(i64_to_u64),
        inbound: row.get("inbound"),
        node_protocol: row.get("node_protocol"),
        peer: row.get("peer_addr"),
        target: row.get("target_addr"),
        target_ip: row.get("target_ip"),
        target_port: row
            .get::<Option<i64>, _>("target_port")
            .and_then(i64_to_u16),
        target_domain: row.get("target_domain"),
        target_source: row.get("target_source"),
        upstream: row.get("upstream_addr"),
        selection_groups: row.get("selection_groups"),
        selection_nodes: row.get("selection_nodes"),
        selection_trace: row.get("selection_trace"),
        started_at_unix_ms: i64_to_u128(row.get("started_at_unix_ms")),
        closed_at_unix_ms: row
            .get::<Option<i64>, _>("closed_at_unix_ms")
            .map(i64_to_u128),
        duration_ms: row.get::<Option<i64>, _>("duration_ms").map(i64_to_u128),
        close_reason: row.get("close_reason"),
        error_stage: row.get("error_stage"),
        error_code: row.get("error_code"),
        error_class: row.get("error_class"),
        error_side: row.get("error_side"),
        error_phase: row.get("error_phase"),
        error_protocol_phase: row.get("error_protocol_phase"),
        error_score_impact: row.get("error_score_impact"),
        error: row.get("error"),
        client_to_upstream_bytes: i64_to_u64(row.get("client_to_upstream_bytes")),
        upstream_to_client_bytes: i64_to_u64(row.get("upstream_to_client_bytes")),
        client_to_upstream_datagrams: i64_to_u64(row.get("client_to_upstream_datagrams")),
        upstream_to_client_datagrams: i64_to_u64(row.get("upstream_to_client_datagrams")),
        first_upstream_at_unix_ms: row
            .get::<Option<i64>, _>("first_upstream_at_unix_ms")
            .map(i64_to_u128),
        first_downstream_at_unix_ms: row
            .get::<Option<i64>, _>("first_downstream_at_unix_ms")
            .map(i64_to_u128),
        first_response_latency_ms: row
            .get::<Option<i64>, _>("first_response_latency_ms")
            .map(i64_to_u128),
        last_observed_at_unix_ms: i64_to_u128(row.get("last_observed_at_unix_ms")),
    })
}

fn row_to_shadow(row: SqliteRow) -> Result<MatrixShadowDecision, RuntimeStoreError> {
    let candidates_json = row.get::<String, _>("candidates_json");
    let candidates = serde_json::from_str::<Vec<MatrixShadowCandidate>>(&candidates_json)?;
    Ok(MatrixShadowDecision {
        decision_id: i64_to_u64(row.get("decision_id")),
        session_id: i64_to_u64(row.get("session_id")),
        observed_at_unix_ms: i64_to_u128(row.get("observed_at_unix_ms")),
        inbound: row.get("inbound"),
        group_id: row.get("group_id"),
        actual_node_id: row.get("actual_node_id"),
        shadow_top_node_id: row.get("shadow_node_id"),
        shadow_differs_from_actual: row.get::<i64, _>("shadow_differs_from_actual") != 0,
        shadow_reason: row.get("shadow_reason"),
        candidates,
    })
}

fn i64_to_u64(value: i64) -> u64 {
    u64::try_from(value).unwrap_or_default()
}

fn i64_to_u128(value: i64) -> u128 {
    u128::try_from(value).unwrap_or_default()
}

fn i64_to_u16(value: i64) -> Option<u16> {
    u16::try_from(value).ok()
}
