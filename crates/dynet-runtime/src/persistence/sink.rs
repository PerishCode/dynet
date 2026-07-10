use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use tokio::sync::{mpsc, oneshot};

use crate::{unix_ms, IngressEvent, MatrixShadowDecision, SelectionContext, SelectionDecision};

use super::{RuntimeStore, RuntimeStoreError, OBSERVATION_QUEUE_CAPACITY};

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
pub(crate) enum RuntimeObservation {
    Event(IngressEvent),
    SelectionDecision {
        observed_at_unix_ms: u128,
        context: SelectionContext,
        decision: SelectionDecision,
    },
    MatrixShadow(MatrixShadowDecision),
    Flush(oneshot::Sender<()>),
}

impl RuntimeStore {
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

    pub(crate) fn record_matrix_shadow(&self, decision: MatrixShadowDecision) {
        self.try_send(RuntimeObservation::MatrixShadow(decision));
    }

    pub(crate) fn stats_snapshot(&self) -> PersistenceStatsSnapshot {
        self.stats.snapshot()
    }

    pub(crate) async fn flush(&self) -> Result<(), String> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(RuntimeObservation::Flush(sender))
            .await
            .map_err(|_| "runtime persistence sink is closed".to_string())?;
        receiver
            .await
            .map_err(|_| "runtime persistence flush was canceled".to_string())
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
            RuntimeObservation::MatrixShadow(decision) => {
                self.store.insert_matrix_shadow(&decision).await
            }
            RuntimeObservation::Flush(sender) => {
                let _ = sender.send(());
                Ok(())
            }
        }
    }
}
