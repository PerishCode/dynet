use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{SystemTime, UNIX_EPOCH},
};

mod dns;
mod event;
mod model;
mod persistence;
mod stores;
mod traffic_session;

pub use dns::{
    sniff_dns_query, sniff_dns_response, DnsQueryInfo, DnsResolution, DnsResolveError,
    DnsResponseInfo,
};
pub use event::{EventStore, IngressEvent, IngressEventKind, IntoFields};
pub use model::{
    DnsHttpsEndpoint, DnsRacePolicy, DnsRaceStrategy, DnsUpstream, DnsUpstreamId,
    DnsUpstreamTransport, ForwardGroup, ForwardNode, GroupId, GroupMember, GroupThresholds,
    InboundKind, MatrixErrorSignalStats, MatrixNodeStats, MatrixService, MatrixShadowCandidate,
    MatrixShadowDecision, MatrixTargetNodeStats, NextRef, NodeId, ObservedDnsMap, RouteMatcher,
    RouteRule, RuleId, RuntimeSeed, SchedulerPolicy, SelectionContext, SelectionDecision,
    SelectionError, SelectionReason, SelectionTerminal, SelectionTraceHop, SelectorMatrix,
    TargetContext, TargetSource,
};
pub use persistence::{PersistenceStatsSnapshot, RuntimeStore, RuntimeStoreError};
pub use stores::{DnsUpstreamStore, GroupStore, NodeStore, RouteRuleStore};
pub use traffic_session::TrafficSession;

use model::{default_dns_upstreams, select_active_candidate, DEFAULT_NODE_ID};

#[derive(Debug, Clone)]
pub struct RuntimeState {
    inner: Arc<RuntimeInner>,
}

#[derive(Debug)]
struct RuntimeInner {
    events: EventStore,
    nodes: NodeStore,
    groups: GroupStore,
    routes: RouteRuleStore,
    dns_upstreams: DnsUpstreamStore,
    dns_policy: DnsRacePolicy,
    dns_map: ObservedDnsMap,
    matrix: MatrixService,
    selector_matrix: SelectorMatrix,
    next_decision_id: AtomicU64,
}

impl Default for RuntimeState {
    fn default() -> Self {
        Self::single_node("direct")
    }
}

impl RuntimeState {
    pub fn single_node(tag: impl Into<String>) -> Self {
        Self::single_node_with_dns(tag, default_dns_upstreams())
    }

    pub fn single_node_with_dns(tag: impl Into<String>, dns_upstreams: Vec<DnsUpstream>) -> Self {
        Self::single_node_dns_policy(tag, dns_upstreams, DnsRacePolicy::default_parallel())
    }

    pub fn single_node_dns_policy(
        tag: impl Into<String>,
        dns_upstreams: Vec<DnsUpstream>,
        dns_policy: DnsRacePolicy,
    ) -> Self {
        let node = ForwardNode::new(DEFAULT_NODE_ID, tag, true);
        let group = ForwardGroup::default_group();
        let member = GroupMember::default_member(node.id.clone(), group.id.clone());
        let nodes = NodeStore::single_node(node);
        let matrix = MatrixService::default();
        Self {
            inner: Arc::new(RuntimeInner {
                events: EventStore::with_matrix(matrix.clone()),
                nodes,
                groups: GroupStore::from_parts(group.id.clone(), vec![group], vec![member]),
                routes: RouteRuleStore::default(),
                dns_upstreams: DnsUpstreamStore::from_upstreams(dns_upstreams),
                dns_policy,
                dns_map: ObservedDnsMap::default(),
                matrix,
                selector_matrix: SelectorMatrix,
                next_decision_id: AtomicU64::new(0),
            }),
        }
    }

    pub async fn from_store_seed(
        store: RuntimeStore,
        seed: RuntimeSeed,
    ) -> Result<Self, RuntimeStoreError> {
        let bootstrap = store.load_or_seed_bootstrap(seed).await?;
        let observation_sink = store.spawn_observation_sink();
        Ok(Self::from_bootstrap(bootstrap, Some(observation_sink)))
    }

    fn from_bootstrap(
        bootstrap: persistence::RuntimeBootstrap,
        observation_sink: Option<persistence::ObservationSink>,
    ) -> Self {
        let matrix = MatrixService::new(observation_sink);
        Self {
            inner: Arc::new(RuntimeInner {
                events: EventStore::with_matrix(matrix.clone()),
                nodes: NodeStore::from_nodes(bootstrap.nodes),
                groups: GroupStore::from_parts(
                    bootstrap.default_group_id,
                    bootstrap.groups,
                    bootstrap.group_members,
                ),
                routes: RouteRuleStore::from_rules(bootstrap.route_rules),
                dns_upstreams: DnsUpstreamStore::from_upstreams(bootstrap.dns_upstreams),
                dns_policy: bootstrap.dns_policy,
                dns_map: ObservedDnsMap::default(),
                matrix,
                selector_matrix: SelectorMatrix,
                next_decision_id: AtomicU64::new(0),
            }),
        }
    }

    pub fn events(&self) -> &EventStore {
        &self.inner.events
    }

    pub fn nodes(&self) -> &NodeStore {
        &self.inner.nodes
    }

    pub fn groups(&self) -> &GroupStore {
        &self.inner.groups
    }

    pub fn routes(&self) -> &RouteRuleStore {
        &self.inner.routes
    }

    pub fn dns_upstreams(&self) -> &DnsUpstreamStore {
        &self.inner.dns_upstreams
    }

    pub fn dns_policy(&self) -> DnsRacePolicy {
        self.inner.dns_policy
    }

    pub fn dns_map(&self) -> &ObservedDnsMap {
        &self.inner.dns_map
    }

    pub fn matrix(&self) -> &MatrixService {
        &self.inner.matrix
    }

    pub fn matrix_node_stats(&self) -> Vec<MatrixNodeStats> {
        self.inner
            .matrix
            .node_stats(&self.inner.nodes.fingerprints_by_id())
    }

    pub fn matrix_target_node_stats(&self) -> Vec<MatrixTargetNodeStats> {
        self.inner
            .matrix
            .target_node_stats(&self.inner.nodes.fingerprints_by_id())
    }

    pub fn matrix_error_signal_stats(&self) -> Vec<MatrixErrorSignalStats> {
        self.inner
            .matrix
            .error_signal_stats(&self.inner.nodes.fingerprints_by_id())
    }

    pub fn selector_matrix(&self) -> &SelectorMatrix {
        &self.inner.selector_matrix
    }

    pub fn persistence_stats(&self) -> PersistenceStatsSnapshot {
        self.inner.matrix.persistence_stats()
    }

    pub fn select(&self, context: SelectionContext) -> Result<SelectionDecision, SelectionError> {
        let route_match = self.inner.routes.match_group(&context.target);
        let group_id = route_match
            .group_id
            .or_else(|| self.inner.groups.default_group_id())
            .ok_or_else(|| SelectionError::new("no default forwarding group is available"))?;
        let node_fingerprints = self.inner.nodes.fingerprints_by_id();
        let node_stats = self.inner.matrix.node_stats(&node_fingerprints);
        let target_node_stats = self.inner.matrix.target_node_stats(&node_fingerprints);
        let selection = self
            .inner
            .groups
            .select_graph_with(&group_id, &self.inner.nodes, |candidate_set| {
                select_active_candidate(
                    &context,
                    &candidate_set.group_id,
                    candidate_set.thresholds,
                    &candidate_set.candidates,
                    &node_stats,
                    &target_node_stats,
                )
            })
            .map_err(SelectionError::new)?;
        let first_hop = selection
            .trace
            .first()
            .expect("selection graph has at least one hop");
        let decision = SelectionDecision {
            decision_id: self.inner.next_decision_id.fetch_add(1, Ordering::SeqCst) + 1,
            group_id: group_id.clone(),
            matched_rule_id: route_match.rule_id,
            node_id: first_hop.node_id.clone(),
            next: first_hop.next.clone(),
            trace: selection.trace,
            terminal: selection.terminal,
            reason: SelectionReason::SingleNode,
            scheduler: selection.scheduler,
            candidate_count: selection.candidate_count,
        };
        if let Ok(candidates) = self
            .inner
            .groups
            .enabled_candidates(&group_id, &self.inner.nodes)
        {
            self.inner.matrix.record_shadow_selection(
                unix_ms(),
                &context,
                &group_id,
                &decision,
                candidates,
                &node_fingerprints,
            );
        }
        self.inner
            .matrix
            .record_selection_decision(context, decision.clone());
        Ok(decision)
    }
}

pub(crate) fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before unix epoch")
        .as_millis()
}
