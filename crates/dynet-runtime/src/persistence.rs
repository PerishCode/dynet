use std::{fmt, path::Path};

use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
    SqlitePool,
};

use crate::{
    traffic_session::{session_update_from_event, TrafficSessionUpdate},
    unix_ms, InboundKind, IngressEvent, IngressEventKind, MatrixShadowDecision, SelectionContext,
    SelectionDecision,
};

mod bootstrap;
mod dns_policy;
mod schema;
mod sink;
mod validation;

pub(crate) use bootstrap::RuntimeBootstrap;
pub(crate) use sink::ObservationSink;
pub use sink::PersistenceStatsSnapshot;

const OBSERVATION_QUEUE_CAPACITY: usize = 16_384;
const SCHEMA_VERSION: &str = "12";

#[derive(Debug, Clone)]
pub struct RuntimeStore {
    pub(super) pool: SqlitePool,
}

#[derive(Debug)]
pub enum RuntimeStoreError {
    Sqlx(sqlx::Error),
    Serde(serde_json::Error),
    InvalidNode {
        id: String,
        message: String,
    },
    InvalidGroup {
        id: String,
        message: String,
    },
    InvalidGroupMember {
        group_id: String,
        node_id: String,
        message: String,
    },
    InvalidDnsUpstream {
        id: String,
        message: String,
    },
    InvalidRouteRule {
        id: String,
        message: String,
    },
    InvalidBootstrap(String),
}

impl RuntimeStore {
    pub async fn open(path: impl AsRef<Path>) -> Result<Self, RuntimeStoreError> {
        let options = SqliteConnectOptions::new()
            .filename(path.as_ref())
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .min_connections(1)
            .max_connections(4)
            .connect_with(options)
            .await?;
        schema::migrate(&pool).await?;
        Ok(Self { pool })
    }

    pub(super) async fn insert_event(&self, event: &IngressEvent) -> Result<(), RuntimeStoreError> {
        let fields_json = serde_json::to_string(&event.fields)?;
        sqlx::query(
            "insert into runtime_events (event_id, observed_at_unix_ms, kind, fields_json)
             values (?1, ?2, ?3, ?4)",
        )
        .bind(u64_to_i64(event.id))
        .bind(u128_to_i64(event.observed_at_unix_ms))
        .bind(event.kind.as_str())
        .bind(fields_json)
        .execute(&self.pool)
        .await?;
        if let Some(update) = session_update_from_event(event) {
            self.upsert_traffic_session(update).await?;
        }
        Ok(())
    }

    async fn upsert_traffic_session(
        &self,
        update: TrafficSessionUpdate,
    ) -> Result<(), RuntimeStoreError> {
        sqlx::query(
            "insert into runtime_traffic_sessions (
                session_key,
                session_id,
                decision_id,
                inbound,
                node_protocol,
                peer_addr,
                target_addr,
                target_ip,
                target_port,
                target_domain,
                target_source,
                upstream_addr,
                selection_groups,
                selection_nodes,
                selection_trace,
                started_at_unix_ms,
                closed_at_unix_ms,
                duration_ms,
                close_reason,
                error_stage,
                error_code,
                error_class,
                error_side,
                error_phase,
                error_protocol_phase,
                error_score_impact,
                error,
                client_to_upstream_bytes,
                upstream_to_client_bytes,
                client_to_upstream_datagrams,
                upstream_to_client_datagrams,
                first_upstream_at_unix_ms,
                first_downstream_at_unix_ms,
                first_response_latency_ms,
                last_observed_at_unix_ms
             )
             values (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                ?11, ?12, ?13, ?14, ?15, ?16,
                case when ?30 then ?31 else null end,
                case when ?30 then max(?31 - ?16, 0) else null end,
                ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25,
                coalesce(?26, 0) + coalesce(?28, 0),
                coalesce(?27, 0) + coalesce(?29, 0),
                case when ?28 is null then 0 else 1 end,
                case when ?29 is null then 0 else 1 end,
                case when ?28 is null then null else ?31 end,
                case when ?29 is null then null else ?31 end,
                case when ?29 is null then null else max(?31 - ?16, 0) end,
                ?31
             )
             on conflict(session_key) do update set
                decision_id = coalesce(runtime_traffic_sessions.decision_id, excluded.decision_id),
                node_protocol = coalesce(excluded.node_protocol, runtime_traffic_sessions.node_protocol),
                peer_addr = coalesce(excluded.peer_addr, runtime_traffic_sessions.peer_addr),
                target_addr = coalesce(excluded.target_addr, runtime_traffic_sessions.target_addr),
                target_ip = coalesce(excluded.target_ip, runtime_traffic_sessions.target_ip),
                target_port = coalesce(excluded.target_port, runtime_traffic_sessions.target_port),
                target_domain = coalesce(excluded.target_domain, runtime_traffic_sessions.target_domain),
                target_source = coalesce(excluded.target_source, runtime_traffic_sessions.target_source),
                upstream_addr = coalesce(excluded.upstream_addr, runtime_traffic_sessions.upstream_addr),
                selection_groups = coalesce(excluded.selection_groups, runtime_traffic_sessions.selection_groups),
                selection_nodes = coalesce(excluded.selection_nodes, runtime_traffic_sessions.selection_nodes),
                selection_trace = coalesce(excluded.selection_trace, runtime_traffic_sessions.selection_trace),
                closed_at_unix_ms = coalesce(excluded.closed_at_unix_ms, runtime_traffic_sessions.closed_at_unix_ms),
                duration_ms = coalesce(excluded.duration_ms, runtime_traffic_sessions.duration_ms),
                close_reason = coalesce(excluded.close_reason, runtime_traffic_sessions.close_reason),
                error_stage = coalesce(excluded.error_stage, runtime_traffic_sessions.error_stage),
                error_code = coalesce(excluded.error_code, runtime_traffic_sessions.error_code),
                error_class = coalesce(excluded.error_class, runtime_traffic_sessions.error_class),
                error_side = coalesce(excluded.error_side, runtime_traffic_sessions.error_side),
                error_phase = coalesce(excluded.error_phase, runtime_traffic_sessions.error_phase),
                error_protocol_phase = coalesce(excluded.error_protocol_phase, runtime_traffic_sessions.error_protocol_phase),
                error_score_impact = coalesce(excluded.error_score_impact, runtime_traffic_sessions.error_score_impact),
                error = coalesce(excluded.error, runtime_traffic_sessions.error),
                client_to_upstream_bytes =
                    case
                        when ?26 is not null then ?26
                        else runtime_traffic_sessions.client_to_upstream_bytes + coalesce(?28, 0)
                    end,
                upstream_to_client_bytes =
                    case
                        when ?27 is not null then ?27
                        else runtime_traffic_sessions.upstream_to_client_bytes + coalesce(?29, 0)
                    end,
                client_to_upstream_datagrams =
                    runtime_traffic_sessions.client_to_upstream_datagrams
                    + case when ?28 is null then 0 else 1 end,
                upstream_to_client_datagrams =
                    runtime_traffic_sessions.upstream_to_client_datagrams
                    + case when ?29 is null then 0 else 1 end,
                first_upstream_at_unix_ms =
                    coalesce(runtime_traffic_sessions.first_upstream_at_unix_ms, excluded.first_upstream_at_unix_ms),
                first_downstream_at_unix_ms =
                    coalesce(runtime_traffic_sessions.first_downstream_at_unix_ms, excluded.first_downstream_at_unix_ms),
                first_response_latency_ms =
                    coalesce(runtime_traffic_sessions.first_response_latency_ms, excluded.first_response_latency_ms),
                last_observed_at_unix_ms = excluded.last_observed_at_unix_ms",
        )
        .bind(update.session_key)
        .bind(u64_to_i64(update.session_id))
        .bind(update.decision_id.map(u64_to_i64))
        .bind(update.inbound)
        .bind(update.node_protocol)
        .bind(update.peer)
        .bind(update.target)
        .bind(update.target_ip)
        .bind(update.target_port.map(i64::from))
        .bind(update.target_domain)
        .bind(update.target_source)
        .bind(update.upstream)
        .bind(update.selection_groups)
        .bind(update.selection_nodes)
        .bind(update.selection_trace)
        .bind(u128_to_i64(update.observed_at_unix_ms))
        .bind(update.close_reason)
        .bind(update.error_stage)
        .bind(update.error_code)
        .bind(update.error_class)
        .bind(update.error_side)
        .bind(update.error_phase)
        .bind(update.error_protocol_phase)
        .bind(update.error_score_impact)
        .bind(update.error)
        .bind(update.client_to_upstream_bytes.map(u64_to_i64))
        .bind(update.upstream_to_client_bytes.map(u64_to_i64))
        .bind(update.client_to_upstream_datagram.map(u64_to_i64))
        .bind(update.upstream_to_client_datagram.map(u64_to_i64))
        .bind(update.closes_session)
        .bind(u128_to_i64(update.observed_at_unix_ms))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(super) async fn insert_selection_decision(
        &self,
        observed_at_unix_ms: u128,
        context: &SelectionContext,
        decision: &SelectionDecision,
    ) -> Result<(), RuntimeStoreError> {
        sqlx::query(
            "insert into selection_decisions (
                decision_id,
                observed_at_unix_ms,
                session_id,
                inbound,
                target_addr,
                target_domain,
                target_source,
                group_id,
                matched_rule_id,
                node_id,
                next,
                reason,
                scheduler,
                candidate_count
             )
             values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        )
        .bind(u64_to_i64(decision.decision_id))
        .bind(u128_to_i64(observed_at_unix_ms))
        .bind(u64_to_i64(context.session_id))
        .bind(context.inbound.as_str())
        .bind(context.target.address.to_string())
        .bind(context.target.domain.as_deref())
        .bind(context.target.source.as_str())
        .bind(decision.group_id.as_str())
        .bind(decision.matched_rule_id.as_ref().map(|id| id.as_str()))
        .bind(decision.node_id.as_str())
        .bind(decision.next.label())
        .bind(decision.reason.as_str())
        .bind(decision.scheduler.as_str())
        .bind(usize_to_i64(decision.candidate_count))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(super) async fn insert_matrix_shadow(
        &self,
        decision: &MatrixShadowDecision,
    ) -> Result<(), RuntimeStoreError> {
        let candidates_json = serde_json::to_string(&decision.candidates)?;
        sqlx::query(
            "insert into matrix_shadow_decisions (
                decision_id,
                session_id,
                observed_at_unix_ms,
                inbound,
                group_id,
                actual_node_id,
                shadow_node_id,
                shadow_differs_from_actual,
                shadow_reason,
                candidates_json
             )
             values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        )
        .bind(u64_to_i64(decision.decision_id))
        .bind(u64_to_i64(decision.session_id))
        .bind(u128_to_i64(decision.observed_at_unix_ms))
        .bind(decision.inbound.as_str())
        .bind(decision.group_id.as_str())
        .bind(decision.actual_node_id.as_str())
        .bind(decision.shadow_top_node_id.as_deref())
        .bind(decision.shadow_differs_from_actual)
        .bind(decision.shadow_reason.as_str())
        .bind(candidates_json)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

impl fmt::Display for RuntimeStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlx(error) => write!(formatter, "sqlite runtime store error: {error}"),
            Self::Serde(error) => write!(formatter, "runtime store serialization error: {error}"),
            Self::InvalidNode { id, message } => {
                write!(formatter, "runtime store node {id:?} is invalid: {message}")
            }
            Self::InvalidGroup { id, message } => {
                write!(
                    formatter,
                    "runtime store group {id:?} is invalid: {message}"
                )
            }
            Self::InvalidGroupMember {
                group_id,
                node_id,
                message,
            } => write!(
                formatter,
                "runtime store group member {group_id:?}/{node_id:?} is invalid: {message}"
            ),
            Self::InvalidDnsUpstream { id, message } => write!(
                formatter,
                "runtime store DNS upstream {id:?} is invalid: {message}"
            ),
            Self::InvalidRouteRule { id, message } => {
                write!(
                    formatter,
                    "runtime store route rule {id:?} is invalid: {message}"
                )
            }
            Self::InvalidBootstrap(message) => {
                write!(formatter, "runtime store bootstrap is invalid: {message}")
            }
        }
    }
}

impl std::error::Error for RuntimeStoreError {}

impl From<sqlx::Error> for RuntimeStoreError {
    fn from(error: sqlx::Error) -> Self {
        Self::Sqlx(error)
    }
}

impl From<serde_json::Error> for RuntimeStoreError {
    fn from(error: serde_json::Error) -> Self {
        Self::Serde(error)
    }
}

pub(super) fn unix_ms_i64() -> i64 {
    u128_to_i64(unix_ms())
}

fn u64_to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn u128_to_i64(value: u128) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn usize_to_i64(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

impl IngressEventKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::DnsQuery => "dns-query",
            Self::DnsResponse => "dns-response",
            Self::DnsError => "dns-error",
            Self::TcpAccept => "tcp-accept",
            Self::TcpClose => "tcp-close",
            Self::TcpError => "tcp-error",
            Self::UdpSessionStart => "udp-session-start",
            Self::UdpDatagram => "udp-datagram",
            Self::UdpSessionClose => "udp-session-close",
            Self::UdpError => "udp-error",
        }
    }
}

impl InboundKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}
