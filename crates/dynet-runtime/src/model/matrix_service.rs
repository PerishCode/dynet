use std::sync::Arc;

use crate::{
    persistence::{ObservationSink, PersistenceStatsSnapshot},
    traffic_session::{TrafficSession, TrafficSessionStore},
    IngressEvent, SelectionContext, SelectionDecision,
};

use super::{
    matrix_shadow::{score_candidates, MatrixShadowStore},
    GroupId, MatrixCandidateInput, MatrixShadowDecision,
};

#[derive(Debug, Clone)]
pub struct MatrixService {
    inner: Arc<MatrixServiceInner>,
}

#[derive(Debug, Clone, Default)]
pub struct SelectorMatrix;

#[derive(Debug)]
struct MatrixServiceInner {
    traffic_sessions: TrafficSessionStore,
    shadow_decisions: MatrixShadowStore,
    observation_sink: Option<ObservationSink>,
}

impl Default for MatrixService {
    fn default() -> Self {
        Self::new(None)
    }
}

impl MatrixService {
    pub(crate) fn new(observation_sink: Option<ObservationSink>) -> Self {
        Self {
            inner: Arc::new(MatrixServiceInner {
                traffic_sessions: TrafficSessionStore::default(),
                shadow_decisions: MatrixShadowStore::default(),
                observation_sink,
            }),
        }
    }

    pub(crate) fn record_ingress_event(&self, event: IngressEvent) {
        self.inner.traffic_sessions.record_event(&event);
        if let Some(sink) = &self.inner.observation_sink {
            sink.record_event(event);
        }
    }

    pub(crate) fn record_selection_decision(
        &self,
        context: SelectionContext,
        decision: SelectionDecision,
    ) {
        if let Some(sink) = &self.inner.observation_sink {
            sink.record_selection_decision(context, decision);
        }
    }

    pub(crate) fn record_shadow_selection(
        &self,
        observed_at_unix_ms: u128,
        context: &SelectionContext,
        group_id: &GroupId,
        actual: &SelectionDecision,
        candidates: Vec<MatrixCandidateInput>,
    ) {
        let decision = score_candidates(observed_at_unix_ms, context, group_id, actual, candidates);
        self.inner.shadow_decisions.record(decision.clone());
        if let Some(sink) = &self.inner.observation_sink {
            sink.record_matrix_shadow(decision);
        }
    }

    pub fn traffic_sessions(&self) -> Vec<TrafficSession> {
        self.inner.traffic_sessions.snapshot()
    }

    pub fn shadow_decisions(&self) -> Vec<MatrixShadowDecision> {
        self.inner.shadow_decisions.snapshot()
    }

    pub fn persistence_stats(&self) -> PersistenceStatsSnapshot {
        self.inner.observation_sink.as_ref().map_or(
            PersistenceStatsSnapshot {
                dropped_observations: 0,
                sink_errors: 0,
            },
            ObservationSink::stats_snapshot,
        )
    }
}
