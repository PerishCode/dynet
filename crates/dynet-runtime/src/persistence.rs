use std::{
    fmt,
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteRow},
    Row, SqlitePool,
};
use tokio::sync::mpsc;

use crate::{
    unix_ms, InboundKind, IngressEvent, IngressEventKind, NodeId, OutboundNode, SelectionContext,
    SelectionDecision, TargetSource,
};

const OBSERVATION_QUEUE_CAPACITY: usize = 16_384;

#[derive(Debug, Clone)]
pub struct RuntimeStore {
    pool: SqlitePool,
}

#[derive(Debug, Clone)]
pub(crate) struct ObservationSink {
    sender: mpsc::Sender<RuntimeObservation>,
    stats: PersistenceStats,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct PersistenceStats {
    dropped_observations: Arc<AtomicU64>,
    sink_errors: Arc<AtomicU64>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct PersistenceStatsSnapshot {
    pub dropped_observations: u64,
    pub sink_errors: u64,
}

#[derive(Debug)]
pub enum RuntimeStoreError {
    Sqlx(sqlx::Error),
    Serde(serde_json::Error),
    InvalidNode { id: String, message: String },
}

#[derive(Debug, Clone)]
pub(crate) enum RuntimeObservation {
    Event(IngressEvent),
    SelectionDecision {
        observed_at_unix_ms: u128,
        context: SelectionContext,
        decision: SelectionDecision,
    },
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
        let store = Self { pool };
        store.migrate().await?;
        Ok(store)
    }

    pub async fn load_nodes(&self) -> Result<Vec<OutboundNode>, RuntimeStoreError> {
        let rows = sqlx::query(
            "select id, tag, enabled from runtime_nodes order by case when id = 'default' then 0 else 1 end, id",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_node).collect()
    }

    pub async fn seed_node(&self, node: &OutboundNode) -> Result<(), RuntimeStoreError> {
        let enabled = if node.enabled { 1_i64 } else { 0_i64 };
        let updated_at_unix_ms = unix_ms_i64();
        let mut transaction = self.pool.begin().await?;
        sqlx::query(
            "insert into runtime_nodes (id, tag, enabled, updated_at_unix_ms)
             values (?1, ?2, ?3, ?4)
             on conflict(id) do update set
               tag = excluded.tag,
               enabled = excluded.enabled,
               updated_at_unix_ms = excluded.updated_at_unix_ms",
        )
        .bind(node.id.as_str())
        .bind(&node.tag)
        .bind(enabled)
        .bind(updated_at_unix_ms)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "insert into runtime_meta (key, value)
             values ('default_node_id', ?1)
             on conflict(key) do update set value = excluded.value",
        )
        .bind(node.id.as_str())
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub(crate) fn spawn_observation_sink(&self) -> ObservationSink {
        let (sender, receiver) = mpsc::channel(OBSERVATION_QUEUE_CAPACITY);
        let stats = PersistenceStats::default();
        let sink = ObservationSink {
            sender,
            stats: stats.clone(),
        };
        let worker = ObservationSinkWorker {
            store: self.clone(),
            receiver,
            stats,
        };
        tokio::spawn(worker.run());
        sink
    }

    async fn migrate(&self) -> Result<(), RuntimeStoreError> {
        sqlx::query(
            "create table if not exists runtime_meta (
                key text primary key,
                value text not null
            )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "create table if not exists runtime_nodes (
                id text primary key,
                tag text not null,
                enabled integer not null,
                updated_at_unix_ms integer not null
            )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "create table if not exists runtime_events (
                row_id integer primary key autoincrement,
                event_id integer not null,
                observed_at_unix_ms integer not null,
                kind text not null,
                fields_json text not null
            )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "create table if not exists selection_decisions (
                row_id integer primary key autoincrement,
                decision_id integer not null,
                observed_at_unix_ms integer not null,
                session_id integer not null,
                inbound text not null,
                target_addr text not null,
                target_domain text,
                target_source text not null,
                node_id text not null,
                reason text not null
            )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "insert into runtime_meta (key, value)
             values ('schema_version', '1')
             on conflict(key) do nothing",
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn insert_event(&self, event: &IngressEvent) -> Result<(), RuntimeStoreError> {
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

    async fn insert_selection_decision(
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
                node_id,
                reason
             )
             values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        )
        .bind(u64_to_i64(decision.decision_id))
        .bind(u128_to_i64(observed_at_unix_ms))
        .bind(u64_to_i64(context.session_id))
        .bind(context.inbound.as_str())
        .bind(context.target.address.to_string())
        .bind(context.target.domain.as_deref())
        .bind(context.target.source.as_str())
        .bind(decision.node_id.as_str())
        .bind(decision.reason.as_str())
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

impl ObservationSink {
    pub(crate) fn record_event(&self, event: IngressEvent) {
        self.try_send(RuntimeObservation::Event(event));
    }

    pub(crate) fn record_selection_decision(
        &self,
        context: SelectionContext,
        decision: SelectionDecision,
    ) {
        self.try_send(RuntimeObservation::SelectionDecision {
            observed_at_unix_ms: unix_ms(),
            context,
            decision,
        });
    }

    pub(crate) fn stats_snapshot(&self) -> PersistenceStatsSnapshot {
        self.stats.snapshot()
    }

    fn try_send(&self, observation: RuntimeObservation) {
        match self.sender.try_send(observation) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.stats
                    .dropped_observations
                    .fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    "runtime persistence observation dropped because sink queue is full"
                );
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.stats.sink_errors.fetch_add(1, Ordering::Relaxed);
                tracing::warn!("runtime persistence observation dropped because sink is closed");
            }
        }
    }
}

impl PersistenceStats {
    fn snapshot(&self) -> PersistenceStatsSnapshot {
        PersistenceStatsSnapshot {
            dropped_observations: self.dropped_observations.load(Ordering::Relaxed),
            sink_errors: self.sink_errors.load(Ordering::Relaxed),
        }
    }

    fn record_sink_error(&self) {
        self.sink_errors.fetch_add(1, Ordering::Relaxed);
    }
}

struct ObservationSinkWorker {
    store: RuntimeStore,
    receiver: mpsc::Receiver<RuntimeObservation>,
    stats: PersistenceStats,
}

impl ObservationSinkWorker {
    async fn run(mut self) {
        while let Some(observation) = self.receiver.recv().await {
            if let Err(error) = self.persist(observation).await {
                self.stats.record_sink_error();
                tracing::warn!(%error, "runtime persistence observation write failed");
            }
        }
    }

    async fn persist(&self, observation: RuntimeObservation) -> Result<(), RuntimeStoreError> {
        match observation {
            RuntimeObservation::Event(event) => self.store.insert_event(&event).await,
            RuntimeObservation::SelectionDecision {
                observed_at_unix_ms,
                context,
                decision,
            } => {
                self.store
                    .insert_selection_decision(observed_at_unix_ms, &context, &decision)
                    .await
            }
        }
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

fn row_to_node(row: SqliteRow) -> Result<OutboundNode, RuntimeStoreError> {
    let id = row.get::<String, _>("id");
    let tag = row.get::<String, _>("tag");
    let enabled = row.get::<i64, _>("enabled");
    if enabled != 0 && enabled != 1 {
        return Err(RuntimeStoreError::InvalidNode {
            id,
            message: format!("enabled must be 0 or 1, got {enabled}"),
        });
    }
    Ok(OutboundNode {
        id: NodeId::new(id),
        tag,
        enabled: enabled == 1,
    })
}

fn unix_ms_i64() -> i64 {
    u128_to_i64(unix_ms())
}

fn u64_to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn u128_to_i64(value: u128) -> i64 {
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
