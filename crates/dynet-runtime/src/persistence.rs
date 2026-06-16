use std::{fmt, path::Path};

use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
    SqlitePool,
};

use crate::{
    unix_ms, InboundKind, IngressEvent, IngressEventKind, SelectionContext, SelectionDecision,
    TargetSource,
};

mod bootstrap;
mod dns_policy;
mod schema;
mod sink;

pub(crate) use bootstrap::RuntimeBootstrap;
pub(crate) use sink::ObservationSink;
pub use sink::PersistenceStatsSnapshot;

const OBSERVATION_QUEUE_CAPACITY: usize = 16_384;
const SCHEMA_VERSION: &str = "3";

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
                reason,
                scheduler,
                candidate_count
             )
             values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
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
        .bind(decision.reason.as_str())
        .bind(decision.scheduler.as_str())
        .bind(usize_to_i64(decision.candidate_count))
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

impl TargetSource {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::FixedUpstream => "fixed-upstream",
            Self::ObservedDns => "observed-dns",
            Self::ExternalContext => "external-context",
        }
    }
}
