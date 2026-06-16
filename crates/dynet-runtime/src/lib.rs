use std::{
    collections::{BTreeMap, VecDeque},
    fmt,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, RwLock,
    },
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Serialize;
use utoipa::ToSchema;

mod persistence;

pub use persistence::{PersistenceStatsSnapshot, RuntimeStore, RuntimeStoreError};

const EVENT_LIMIT: usize = 1024;
const DEFAULT_NODE_ID: &str = "default";

#[derive(Debug, Clone)]
pub struct RuntimeState {
    inner: Arc<RuntimeInner>,
}

#[derive(Debug)]
struct RuntimeInner {
    events: EventStore,
    nodes: NodeStore,
    dns_map: ObservedDnsMap,
    selector_matrix: SelectorMatrix,
    observation_sink: Option<persistence::ObservationSink>,
    next_decision_id: AtomicU64,
}

#[derive(Debug, Clone)]
pub struct EventStore {
    inner: Arc<EventInner>,
}

#[derive(Debug)]
struct EventInner {
    next_event_id: AtomicU64,
    next_session_id: AtomicU64,
    events: Mutex<VecDeque<IngressEvent>>,
    observation_sink: Option<persistence::ObservationSink>,
}

#[derive(Debug, Clone, Default)]
pub struct NodeStore {
    inner: Arc<RwLock<NodeStoreInner>>,
}

#[derive(Debug, Default)]
struct NodeStoreInner {
    default_node: Option<NodeId>,
    nodes: BTreeMap<NodeId, OutboundNode>,
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct NodeId(String);

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct OutboundNode {
    pub id: NodeId,
    pub tag: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ObservedDnsMap;

#[derive(Debug, Clone, Default)]
pub struct SelectorMatrix;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TargetContext {
    pub address: SocketAddr,
    pub domain: Option<String>,
    pub source: TargetSource,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum TargetSource {
    FixedUpstream,
    ObservedDns,
    ExternalContext,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum InboundKind {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SelectionContext {
    pub session_id: u64,
    pub inbound: InboundKind,
    pub target: TargetContext,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SelectionDecision {
    pub decision_id: u64,
    pub node_id: NodeId,
    pub reason: SelectionReason,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SelectionReason {
    SingleNode,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SelectionError {
    message: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct IngressEvent {
    pub id: u64,
    pub observed_at_unix_ms: u128,
    pub kind: IngressEventKind,
    pub fields: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "kebab-case")]
pub enum IngressEventKind {
    DnsQuery,
    DnsResponse,
    DnsError,
    TcpAccept,
    TcpClose,
    TcpError,
    UdpSessionStart,
    UdpDatagram,
    UdpSessionClose,
    UdpError,
}

impl Default for RuntimeState {
    fn default() -> Self {
        Self::single_node("direct")
    }
}

impl RuntimeState {
    pub fn single_node(tag: impl Into<String>) -> Self {
        let nodes = NodeStore::single_node(OutboundNode {
            id: NodeId::new(DEFAULT_NODE_ID),
            tag: tag.into(),
            enabled: true,
        });
        Self {
            inner: Arc::new(RuntimeInner {
                events: EventStore::default(),
                nodes,
                dns_map: ObservedDnsMap,
                selector_matrix: SelectorMatrix,
                observation_sink: None,
                next_decision_id: AtomicU64::new(0),
            }),
        }
    }

    pub async fn from_store_seed(
        store: RuntimeStore,
        tag: impl Into<String>,
    ) -> Result<Self, RuntimeStoreError> {
        let mut nodes = store.load_nodes().await?;
        if nodes.is_empty() {
            let node = OutboundNode {
                id: NodeId::new(DEFAULT_NODE_ID),
                tag: tag.into(),
                enabled: true,
            };
            store.seed_node(&node).await?;
            nodes.push(node);
        }
        let observation_sink = store.spawn_observation_sink();
        Ok(Self::from_nodes(nodes, Some(observation_sink)))
    }

    fn from_nodes(
        nodes: Vec<OutboundNode>,
        observation_sink: Option<persistence::ObservationSink>,
    ) -> Self {
        Self {
            inner: Arc::new(RuntimeInner {
                events: EventStore::with_sink(observation_sink.clone()),
                nodes: NodeStore::from_nodes(nodes),
                dns_map: ObservedDnsMap,
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
        let node_id =
            self.inner.nodes.default_node_id().ok_or_else(|| {
                SelectionError::new("no enabled default outbound node is available")
            })?;
        let decision = SelectionDecision {
            decision_id: self.inner.next_decision_id.fetch_add(1, Ordering::SeqCst) + 1,
            node_id,
            reason: SelectionReason::SingleNode,
        };
        if let Some(sink) = &self.inner.observation_sink {
            sink.record_selection_decision(context, decision.clone());
        }
        Ok(decision)
    }
}

impl NodeStore {
    pub fn single_node(node: OutboundNode) -> Self {
        let default_node = Some(node.id.clone());
        let mut nodes = BTreeMap::new();
        nodes.insert(node.id.clone(), node);
        Self {
            inner: Arc::new(RwLock::new(NodeStoreInner {
                default_node,
                nodes,
            })),
        }
    }

    pub fn from_nodes(nodes: Vec<OutboundNode>) -> Self {
        let default_node = nodes
            .iter()
            .find(|node| node.id.as_str() == DEFAULT_NODE_ID && node.enabled)
            .or_else(|| nodes.iter().find(|node| node.enabled))
            .map(|node| node.id.clone());
        let nodes = nodes
            .into_iter()
            .map(|node| (node.id.clone(), node))
            .collect();
        Self {
            inner: Arc::new(RwLock::new(NodeStoreInner {
                default_node,
                nodes,
            })),
        }
    }

    pub fn default_node_id(&self) -> Option<NodeId> {
        let store = self.inner.read().expect("node store lock poisoned");
        let node_id = store.default_node.as_ref()?;
        let node = store.nodes.get(node_id)?;
        node.enabled.then(|| node_id.clone())
    }

    pub fn snapshot(&self) -> Vec<OutboundNode> {
        self.inner
            .read()
            .expect("node store lock poisoned")
            .nodes
            .values()
            .cloned()
            .collect()
    }
}

impl NodeId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl TargetContext {
    pub fn fixed_upstream(address: SocketAddr) -> Self {
        Self {
            address,
            domain: None,
            source: TargetSource::FixedUpstream,
        }
    }
}

impl SelectionReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SingleNode => "single-node",
        }
    }
}

impl SelectionError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for SelectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for SelectionError {}

impl Default for EventStore {
    fn default() -> Self {
        Self::with_sink(None)
    }
}

impl EventStore {
    fn with_sink(observation_sink: Option<persistence::ObservationSink>) -> Self {
        Self {
            inner: Arc::new(EventInner {
                next_event_id: AtomicU64::new(0),
                next_session_id: AtomicU64::new(0),
                events: Mutex::new(VecDeque::new()),
                observation_sink,
            }),
        }
    }

    pub fn next_session_id(&self) -> u64 {
        self.inner.next_session_id.fetch_add(1, Ordering::SeqCst) + 1
    }

    pub fn record(&self, kind: IngressEventKind, fields: impl IntoFields) {
        let event = IngressEvent {
            id: self.inner.next_event_id.fetch_add(1, Ordering::SeqCst) + 1,
            observed_at_unix_ms: unix_ms(),
            kind,
            fields: fields.into_fields(),
        };
        let mut events = self.inner.events.lock().expect("event store lock poisoned");
        if events.len() == EVENT_LIMIT {
            events.pop_front();
        }
        events.push_back(event.clone());
        drop(events);
        if let Some(sink) = &self.inner.observation_sink {
            sink.record_event(event);
        }
    }

    pub fn snapshot(&self) -> Vec<IngressEvent> {
        self.inner
            .events
            .lock()
            .expect("event store lock poisoned")
            .iter()
            .cloned()
            .collect()
    }
}

pub trait IntoFields {
    fn into_fields(self) -> BTreeMap<String, String>;
}

impl<const N: usize> IntoFields for [(&str, String); N] {
    fn into_fields(self) -> BTreeMap<String, String> {
        self.into_iter()
            .map(|(key, value)| (key.to_string(), value))
            .collect()
    }
}

impl IntoFields for Vec<(&'static str, String)> {
    fn into_fields(self) -> BTreeMap<String, String> {
        self.into_iter()
            .map(|(key, value)| (key.to_string(), value))
            .collect()
    }
}

pub(crate) fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before unix epoch")
        .as_millis()
}
