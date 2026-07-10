use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, RwLock,
    },
    time::{SystemTime, UNIX_EPOCH},
};

mod dns;
mod event;
mod model;
mod persistence;
#[path = "model/runtime_config.rs"]
mod runtime_config;
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
pub use runtime_config::{
    ConfigReloadAudit, ConfigReloadOutcome, ConfigReloadTrigger, RuntimeConfigAudit,
    RuntimeConfigStatus,
};
pub use stores::{DnsUpstreamStore, GroupStore, NodeStore, RouteRuleStore};
pub use traffic_session::TrafficSession;

pub(crate) use model::MATRIX_SHADOW_LIMIT;
use model::{default_dns_upstreams, select_active_candidate, DEFAULT_NODE_ID};

#[derive(Debug, Clone)]
pub struct RuntimeState {
    inner: Arc<RuntimeInner>,
}

#[derive(Debug)]
struct RuntimeInner {
    events: EventStore,
    routing: RwLock<Arc<RuntimeRouting>>,
    dns_map: ObservedDnsMap,
    matrix: MatrixService,
    selector_matrix: SelectorMatrix,
    next_decision_id: AtomicU64,
}

#[derive(Debug)]
struct RuntimeRouting {
    generation: u64,
    nodes: NodeStore,
    groups: GroupStore,
    routes: RouteRuleStore,
    dns_upstreams: DnsUpstreamStore,
    dns_policy: DnsRacePolicy,
}

#[derive(Debug)]
pub struct RuntimeReconfigure {
    previous_generation: u64,
    routing: Arc<RuntimeRouting>,
}

impl RuntimeReconfigure {
    pub fn generation(&self) -> u64 {
        self.routing.generation
    }
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
        let matrix = MatrixService::default();
        Self {
            inner: Arc::new(RuntimeInner {
                events: EventStore::with_matrix(matrix.clone()),
                routing: RwLock::new(Arc::new(RuntimeRouting {
                    generation: 1,
                    nodes: NodeStore::single_node(node),
                    groups: GroupStore::from_parts(group.id.clone(), vec![group], vec![member]),
                    routes: RouteRuleStore::default(),
                    dns_upstreams: DnsUpstreamStore::from_upstreams(dns_upstreams),
                    dns_policy,
                })),
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
        let bootstrap = store.replace_and_load_bootstrap(seed).await?;
        let traffic_sessions = store.load_recent_traffic_sessions().await?;
        let shadow_decisions = store.load_recent_shadows().await?;
        let id_watermarks = store.load_id_watermarks().await?;
        let observation_sink = store.spawn_observation_sink();
        Ok(Self::from_bootstrap(
            bootstrap,
            traffic_sessions,
            shadow_decisions,
            id_watermarks,
            Some(observation_sink),
        ))
    }

    pub fn from_seed(seed: RuntimeSeed) -> Self {
        let matrix = MatrixService::default();
        Self {
            inner: Arc::new(RuntimeInner {
                events: EventStore::with_matrix(matrix.clone()),
                routing: RwLock::new(Arc::new(RuntimeRouting::from_seed(1, seed))),
                dns_map: ObservedDnsMap::default(),
                matrix,
                selector_matrix: SelectorMatrix,
                next_decision_id: AtomicU64::new(0),
            }),
        }
    }

    fn from_bootstrap(
        bootstrap: persistence::RuntimeBootstrap,
        traffic_sessions: Vec<TrafficSession>,
        shadow_decisions: Vec<MatrixShadowDecision>,
        id_watermarks: persistence::RuntimeIdWatermarks,
        observation_sink: Option<persistence::ObservationSink>,
    ) -> Self {
        let matrix =
            MatrixService::from_parts(traffic_sessions, shadow_decisions, observation_sink);
        Self {
            inner: Arc::new(RuntimeInner {
                events: EventStore::with_matrix_watermarks(
                    matrix.clone(),
                    id_watermarks.event_id,
                    id_watermarks.session_id,
                ),
                routing: RwLock::new(Arc::new(RuntimeRouting {
                    generation: 1,
                    nodes: NodeStore::from_nodes(bootstrap.nodes),
                    groups: GroupStore::from_parts(
                        bootstrap.default_group_id,
                        bootstrap.groups,
                        bootstrap.group_members,
                    ),
                    routes: RouteRuleStore::from_rules(bootstrap.route_rules),
                    dns_upstreams: DnsUpstreamStore::from_upstreams(bootstrap.dns_upstreams),
                    dns_policy: bootstrap.dns_policy,
                })),
                dns_map: ObservedDnsMap::default(),
                matrix,
                selector_matrix: SelectorMatrix,
                next_decision_id: AtomicU64::new(id_watermarks.decision_id),
            }),
        }
    }

    pub fn events(&self) -> &EventStore {
        &self.inner.events
    }

    pub fn generation(&self) -> u64 {
        self.routing().generation
    }

    pub fn prepare_reconfigure(&self, seed: RuntimeSeed) -> RuntimeReconfigure {
        let previous_generation = self.generation();
        RuntimeReconfigure {
            previous_generation,
            routing: Arc::new(RuntimeRouting::from_seed(previous_generation + 1, seed)),
        }
    }

    pub fn commit_reconfigure(&self, prepared: RuntimeReconfigure) -> Result<u64, String> {
        let mut routing = self
            .inner
            .routing
            .write()
            .expect("runtime routing lock poisoned");
        if routing.generation != prepared.previous_generation {
            return Err(format!(
                "runtime generation changed from {} to {} while reload was prepared",
                prepared.previous_generation, routing.generation
            ));
        }
        let generation = prepared.generation();
        *routing = prepared.routing;
        Ok(generation)
    }

    pub fn nodes(&self) -> NodeStore {
        self.routing().nodes.clone()
    }

    pub fn groups(&self) -> GroupStore {
        self.routing().groups.clone()
    }

    pub fn routes(&self) -> RouteRuleStore {
        self.routing().routes.clone()
    }

    pub fn dns_upstreams(&self) -> DnsUpstreamStore {
        self.routing().dns_upstreams.clone()
    }

    pub fn dns_policy(&self) -> DnsRacePolicy {
        self.routing().dns_policy
    }

    pub(crate) fn dns_config(&self) -> (DnsRacePolicy, DnsUpstreamStore) {
        let routing = self.routing();
        (routing.dns_policy, routing.dns_upstreams.clone())
    }

    pub fn dns_map(&self) -> &ObservedDnsMap {
        &self.inner.dns_map
    }

    pub fn matrix(&self) -> &MatrixService {
        &self.inner.matrix
    }

    pub fn matrix_node_stats(&self) -> Vec<MatrixNodeStats> {
        let routing = self.routing();
        self.inner
            .matrix
            .node_stats(&routing.nodes.fingerprints_by_id())
    }

    pub fn matrix_target_node_stats(&self) -> Vec<MatrixTargetNodeStats> {
        let routing = self.routing();
        self.inner
            .matrix
            .target_node_stats(&routing.nodes.fingerprints_by_id())
    }

    pub fn matrix_error_signal_stats(&self) -> Vec<MatrixErrorSignalStats> {
        let routing = self.routing();
        self.inner
            .matrix
            .error_signal_stats(&routing.nodes.fingerprints_by_id())
    }

    pub fn selector_matrix(&self) -> &SelectorMatrix {
        &self.inner.selector_matrix
    }

    pub fn persistence_stats(&self) -> PersistenceStatsSnapshot {
        self.inner.matrix.persistence_stats()
    }

    pub fn select(&self, context: SelectionContext) -> Result<SelectionDecision, SelectionError> {
        let routing = self.routing();
        let route_match = routing.routes.match_group(&context.target);
        let group_id = route_match
            .group_id
            .or_else(|| routing.groups.default_group_id())
            .ok_or_else(|| SelectionError::new("no default forwarding group is available"))?;
        let node_fingerprints = routing.nodes.fingerprints_by_id();
        let node_stats = self.inner.matrix.node_stats(&node_fingerprints);
        let target_node_stats = self.inner.matrix.target_node_stats(&node_fingerprints);
        let selection = routing
            .groups
            .select_graph_with(&group_id, &routing.nodes, |candidate_set| {
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
            config_generation: routing.generation,
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
        if let Ok(candidates) = routing.groups.enabled_candidates(&group_id, &routing.nodes) {
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

    fn routing(&self) -> Arc<RuntimeRouting> {
        self.inner
            .routing
            .read()
            .expect("runtime routing lock poisoned")
            .clone()
    }
}

impl RuntimeRouting {
    fn from_seed(generation: u64, seed: RuntimeSeed) -> Self {
        Self {
            generation,
            nodes: NodeStore::from_nodes(seed.nodes),
            groups: GroupStore::from_parts(seed.default_group_id, seed.groups, seed.group_members),
            routes: RouteRuleStore::from_rules(seed.route_rules),
            dns_upstreams: DnsUpstreamStore::from_upstreams(seed.dns_upstreams),
            dns_policy: seed.dns_policy,
        }
    }
}

pub(crate) fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before unix epoch")
        .as_millis()
}
