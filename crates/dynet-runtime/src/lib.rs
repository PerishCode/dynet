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

pub use dns::{
    sniff_dns_query, sniff_dns_response, DnsQueryInfo, DnsResolution, DnsResolveError,
    DnsResponseInfo,
};
pub use event::{EventStore, IngressEvent, IngressEventKind, IntoFields};
pub use model::{
    DnsRacePolicy, DnsRaceStrategy, DnsUpstream, DnsUpstreamId, ForwardGroup, ForwardNode, GroupId,
    GroupMember, InboundKind, NextRef, NodeId, ObservedDnsMap, RouteMatcher, RouteRule, RuleId,
    RuntimeSeed, SchedulerPolicy, SelectionContext, SelectionDecision, SelectionError,
    SelectionReason, SelectionTerminal, SelectionTraceHop, SelectorMatrix, TargetContext,
    TargetSource,
};
pub use persistence::{PersistenceStatsSnapshot, RuntimeStore, RuntimeStoreError};
pub use stores::{DnsUpstreamStore, GroupStore, NodeStore, RouteRuleStore};

use model::{default_dns_upstreams, DEFAULT_NODE_ID};

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
    selector_matrix: SelectorMatrix,
    observation_sink: Option<persistence::ObservationSink>,
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
        let node = ForwardNode {
            id: NodeId::new(DEFAULT_NODE_ID),
            tag: tag.into(),
            enabled: true,
        };
        let group = ForwardGroup::default_group();
        let member = GroupMember::default_member(node.id.clone(), group.id.clone());
        let nodes = NodeStore::single_node(node);
        Self {
            inner: Arc::new(RuntimeInner {
                events: EventStore::default(),
                nodes,
                groups: GroupStore::from_parts(group.id.clone(), vec![group], vec![member]),
                routes: RouteRuleStore::default(),
                dns_upstreams: DnsUpstreamStore::from_upstreams(dns_upstreams),
                dns_policy,
                dns_map: ObservedDnsMap::default(),
                selector_matrix: SelectorMatrix,
                observation_sink: None,
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
        Self {
            inner: Arc::new(RuntimeInner {
                events: EventStore::with_sink(observation_sink.clone()),
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
                selector_matrix: SelectorMatrix,
                observation_sink,
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

    pub fn selector_matrix(&self) -> &SelectorMatrix {
        &self.inner.selector_matrix
    }

    pub fn persistence_stats(&self) -> PersistenceStatsSnapshot {
        self.inner.observation_sink.as_ref().map_or(
            PersistenceStatsSnapshot {
                dropped_observations: 0,
                sink_errors: 0,
            },
            |sink| sink.stats_snapshot(),
        )
    }

    pub fn select(&self, context: SelectionContext) -> Result<SelectionDecision, SelectionError> {
        let route_match = self.inner.routes.match_group(&context.target);
        let group_id = route_match
            .group_id
            .or_else(|| self.inner.groups.default_group_id())
            .ok_or_else(|| SelectionError::new("no default forwarding group is available"))?;
        let selection = self
            .inner
            .groups
            .select_graph(&group_id, &self.inner.nodes)
            .map_err(SelectionError::new)?;
        let first_hop = selection
            .trace
            .first()
            .expect("selection graph has at least one hop");
        let decision = SelectionDecision {
            decision_id: self.inner.next_decision_id.fetch_add(1, Ordering::SeqCst) + 1,
            group_id,
            matched_rule_id: route_match.rule_id,
            node_id: first_hop.node_id.clone(),
            next: first_hop.next.clone(),
            trace: selection.trace,
            terminal: selection.terminal,
            reason: SelectionReason::SingleNode,
            scheduler: selection.scheduler,
            candidate_count: selection.candidate_count,
        };
        if let Some(sink) = &self.inner.observation_sink {
            sink.record_selection_decision(context, decision.clone());
        }
        Ok(decision)
    }
}

pub(crate) fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before unix epoch")
        .as_millis()
}
