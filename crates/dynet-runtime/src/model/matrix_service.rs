use std::{collections::BTreeMap, sync::Arc};

use crate::{
    persistence::{ObservationSink, PersistenceStatsSnapshot},
    traffic_session::{TrafficSession, TrafficSessionStore},
    IngressEvent, SelectionContext, SelectionDecision,
};

use super::{
    matrix_shadow::{score_candidates, MatrixShadowStore},
    matrix_stats::{
        error_signals_from_sessions, node_stats_from_sessions, target_stats_from_sessions,
    },
    GroupId, MatrixCandidateInput, MatrixErrorSignalStats, MatrixNodeStats, MatrixShadowDecision,
    MatrixTargetNodeStats,
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
        fingerprints_by_node: &BTreeMap<String, String>,
    ) {
        let node_stats = self.node_stats(fingerprints_by_node);
        let target_node_stats = self.target_node_stats(fingerprints_by_node);
        let decision = score_candidates(
            observed_at_unix_ms,
            context,
            group_id,
            actual,
            candidates,
            &node_stats,
            &target_node_stats,
        );
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

    pub(crate) fn node_stats(
        &self,
        fingerprints_by_node: &BTreeMap<String, String>,
    ) -> Vec<MatrixNodeStats> {
        node_stats_from_sessions(&self.traffic_sessions(), fingerprints_by_node)
    }

    pub(crate) fn target_node_stats(
        &self,
        fingerprints_by_node: &BTreeMap<String, String>,
    ) -> Vec<MatrixTargetNodeStats> {
        target_stats_from_sessions(&self.traffic_sessions(), fingerprints_by_node)
    }

    pub(crate) fn error_signal_stats(
        &self,
        fingerprints_by_node: &BTreeMap<String, String>,
    ) -> Vec<MatrixErrorSignalStats> {
        error_signals_from_sessions(&self.traffic_sessions(), fingerprints_by_node)
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
