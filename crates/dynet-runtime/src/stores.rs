use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
};

use crate::{
    DnsUpstream, DnsUpstreamId, GroupId, GroupMember, NodeId, OutboundGroup, OutboundNode,
    RouteRule, TargetContext, DEFAULT_NODE_ID,
};

#[derive(Debug, Clone, Default)]
pub struct NodeStore {
    inner: Arc<RwLock<NodeStoreInner>>,
}

#[derive(Debug, Default)]
struct NodeStoreInner {
    default_node: Option<NodeId>,
    nodes: BTreeMap<NodeId, OutboundNode>,
}

#[derive(Debug, Clone, Default)]
pub struct GroupStore {
    inner: Arc<RwLock<GroupStoreInner>>,
}

#[derive(Debug, Default)]
struct GroupStoreInner {
    default_group: Option<GroupId>,
    groups: BTreeMap<GroupId, OutboundGroup>,
    members: BTreeMap<GroupId, Vec<GroupMember>>,
}

#[derive(Debug, Clone, Default)]
pub struct RouteRuleStore {
    inner: Arc<RwLock<RouteRuleStoreInner>>,
}

#[derive(Debug, Default)]
struct RouteRuleStoreInner {
    rules: Vec<RouteRule>,
}

#[derive(Debug, Clone, Default)]
pub struct DnsUpstreamStore {
    inner: Arc<RwLock<DnsUpstreamStoreInner>>,
}

#[derive(Debug, Default)]
struct DnsUpstreamStoreInner {
    upstreams: BTreeMap<DnsUpstreamId, DnsUpstream>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct RouteMatch {
    pub(crate) group_id: Option<GroupId>,
    pub(crate) rule_id: Option<crate::RuleId>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct GroupSelection {
    pub(crate) node_id: NodeId,
    pub(crate) scheduler: crate::SchedulerPolicy,
    pub(crate) candidate_count: usize,
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

    pub fn is_enabled(&self, node_id: &NodeId) -> bool {
        self.inner
            .read()
            .expect("node store lock poisoned")
            .nodes
            .get(node_id)
            .is_some_and(|node| node.enabled)
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

impl GroupStore {
    pub fn from_parts(
        default_group: GroupId,
        groups: Vec<OutboundGroup>,
        members: Vec<GroupMember>,
    ) -> Self {
        let groups = groups
            .into_iter()
            .map(|group| (group.id.clone(), group))
            .collect::<BTreeMap<_, _>>();
        let default_group = groups
            .get(&default_group)
            .is_some_and(|group| group.enabled)
            .then_some(default_group)
            .or_else(|| {
                groups
                    .values()
                    .find(|group| group.enabled)
                    .map(|group| group.id.clone())
            });
        let mut grouped_members = BTreeMap::<GroupId, Vec<GroupMember>>::new();
        for member in members {
            grouped_members
                .entry(member.group_id.clone())
                .or_default()
                .push(member);
        }
        for members in grouped_members.values_mut() {
            members.sort_by(|left, right| {
                left.priority
                    .cmp(&right.priority)
                    .then_with(|| left.node_id.cmp(&right.node_id))
            });
        }
        Self {
            inner: Arc::new(RwLock::new(GroupStoreInner {
                default_group,
                groups,
                members: grouped_members,
            })),
        }
    }

    pub fn default_group_id(&self) -> Option<GroupId> {
        self.inner
            .read()
            .expect("group store lock poisoned")
            .default_group
            .clone()
    }

    pub(crate) fn select_node(
        &self,
        group_id: &GroupId,
        nodes: &NodeStore,
    ) -> Option<GroupSelection> {
        let store = self.inner.read().expect("group store lock poisoned");
        let group = store.groups.get(group_id)?;
        if !group.enabled {
            return None;
        }
        let members = store.members.get(group_id)?;
        let candidates = members
            .iter()
            .filter(|member| member.enabled && nodes.is_enabled(&member.node_id))
            .collect::<Vec<_>>();
        let selected = candidates.first()?;
        Some(GroupSelection {
            node_id: selected.node_id.clone(),
            scheduler: group.scheduler,
            candidate_count: candidates.len(),
        })
    }

    pub fn snapshot(&self) -> Vec<OutboundGroup> {
        self.inner
            .read()
            .expect("group store lock poisoned")
            .groups
            .values()
            .cloned()
            .collect()
    }

    pub fn member_snapshot(&self) -> Vec<GroupMember> {
        self.inner
            .read()
            .expect("group store lock poisoned")
            .members
            .values()
            .flat_map(|members| members.iter().cloned())
            .collect()
    }
}

impl RouteRuleStore {
    pub fn from_rules(mut rules: Vec<RouteRule>) -> Self {
        rules.sort_by(|left, right| {
            right
                .priority
                .cmp(&left.priority)
                .then_with(|| left.id.cmp(&right.id))
        });
        Self {
            inner: Arc::new(RwLock::new(RouteRuleStoreInner { rules })),
        }
    }

    pub(crate) fn match_group(&self, target: &TargetContext) -> RouteMatch {
        let store = self.inner.read().expect("route rule store lock poisoned");
        for rule in store.rules.iter().filter(|rule| rule.enabled) {
            if rule.matcher.matches(target) {
                return RouteMatch {
                    group_id: Some(rule.group_id.clone()),
                    rule_id: Some(rule.id.clone()),
                };
            }
        }
        RouteMatch {
            group_id: None,
            rule_id: None,
        }
    }

    pub fn snapshot(&self) -> Vec<RouteRule> {
        self.inner
            .read()
            .expect("route rule store lock poisoned")
            .rules
            .clone()
    }
}

impl DnsUpstreamStore {
    pub fn from_upstreams(upstreams: Vec<DnsUpstream>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(DnsUpstreamStoreInner {
                upstreams: upstreams
                    .into_iter()
                    .map(|upstream| (upstream.id.clone(), upstream))
                    .collect(),
            })),
        }
    }

    pub fn snapshot(&self) -> Vec<DnsUpstream> {
        self.inner
            .read()
            .expect("dns upstream store lock poisoned")
            .upstreams
            .values()
            .cloned()
            .collect()
    }
}
