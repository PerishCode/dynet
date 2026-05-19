use std::collections::BTreeSet;

use serde::Serialize;

use crate::{DynetConfig, ModeledNode, NetworkModel, NodeRole};

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Plan {
    pub schema: String,
    pub mode: PlanMode,
    pub network_schema: String,
    pub rules: Vec<PlanRule>,
    pub edges: Vec<PlanEdge>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_outbound: Option<PlanNodeRef>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PlanMode {
    ExplicitOnly,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanRule {
    pub order: usize,
    pub priority: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inbound: Option<PlanNodeRef>,
    pub outbound: PlanNodeRef,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transports: Vec<String>,
    pub source: PlanRuleSource,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PlanRuleSource {
    ExplicitRoute,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanEdge {
    pub order: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<PlanNodeRef>,
    pub to: PlanNodeRef,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transports: Vec<String>,
    pub source: PlanRuleSource,
    pub reason: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanNodeRef {
    pub role: NodeRole,
    pub tag: String,
    pub resolved: bool,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanSummary {
    pub rules: usize,
    pub edges: usize,
    pub explicit_rules: usize,
    pub dynamic_rules: usize,
    pub has_final: bool,
}

impl Plan {
    pub fn summary(&self) -> PlanSummary {
        PlanSummary {
            rules: self.rules.len(),
            edges: self.edges.len(),
            explicit_rules: self
                .rules
                .iter()
                .filter(|rule| rule.source == PlanRuleSource::ExplicitRoute)
                .count(),
            dynamic_rules: 0,
            has_final: self.final_outbound.is_some(),
        }
    }
}

pub fn build_plan(config: &DynetConfig) -> Plan {
    let network = config.network_model();
    let rules = config
        .routes
        .iter()
        .enumerate()
        .map(|(index, route)| {
            let inbound = route.inbound.as_ref().map(|tag| inbound_ref(&network, tag));
            let outbound = outbound_ref(&network, &route.outbound);
            let transports = planned_transports(inbound.as_ref(), &outbound);
            PlanRule {
                order: index + 1,
                priority: 0,
                inbound,
                outbound,
                transports,
                source: PlanRuleSource::ExplicitRoute,
                reason: match route.inbound.as_deref() {
                    Some(inbound) => format!(
                        "explicit user route maps inbound `{inbound}` to outbound `{}`",
                        route.outbound
                    ),
                    None => {
                        format!(
                            "explicit user default route maps to outbound `{}`",
                            route.outbound
                        )
                    }
                },
            }
        })
        .collect::<Vec<_>>();
    let edges = rules
        .iter()
        .filter(|rule| {
            rule.outbound.resolved && rule.inbound.as_ref().is_none_or(|node| node.resolved)
        })
        .map(|rule| PlanEdge {
            order: rule.order,
            from: rule.inbound.clone(),
            to: rule.outbound.clone(),
            transports: rule.transports.clone(),
            source: rule.source,
            reason: rule.reason.clone(),
        })
        .collect();
    let final_outbound = rules
        .iter()
        .find(|rule| rule.inbound.is_none())
        .map(|rule| rule.outbound.clone());

    Plan {
        schema: "dynet-plan/v1alpha1".to_string(),
        mode: PlanMode::ExplicitOnly,
        network_schema: network.schema,
        rules,
        edges,
        final_outbound,
    }
}

fn inbound_ref(network: &NetworkModel, tag: &str) -> PlanNodeRef {
    node_ref(NodeRole::Inbound, tag, find_node(&network.inbounds, tag))
}

fn outbound_ref(network: &NetworkModel, tag: &str) -> PlanNodeRef {
    node_ref(NodeRole::Outbound, tag, find_node(&network.outbounds, tag))
}

fn find_node<'a>(nodes: &'a [ModeledNode], tag: &str) -> Option<&'a ModeledNode> {
    nodes.iter().find(|node| node.tag == tag)
}

fn node_ref(role: NodeRole, tag: &str, node: Option<&ModeledNode>) -> PlanNodeRef {
    match node {
        Some(node) => PlanNodeRef {
            role,
            tag: node.tag.clone(),
            resolved: true,
            kind: node.kind.clone(),
            id: Some(node.id.clone()),
            fingerprint: Some(node.fingerprint.clone()),
            capabilities: node.capabilities.clone(),
        },
        None => PlanNodeRef {
            role,
            tag: tag.to_string(),
            resolved: false,
            kind: "unknown".to_string(),
            id: None,
            fingerprint: None,
            capabilities: Vec::new(),
        },
    }
}

fn planned_transports(inbound: Option<&PlanNodeRef>, outbound: &PlanNodeRef) -> Vec<String> {
    let outbound_transports = transport_set(outbound);
    match inbound {
        Some(inbound) => transport_set(inbound)
            .intersection(&outbound_transports)
            .cloned()
            .collect(),
        None => outbound_transports.into_iter().collect(),
    }
}

fn transport_set(node: &PlanNodeRef) -> BTreeSet<String> {
    node.capabilities
        .iter()
        .filter(|capability| matches!(capability.as_str(), "tcp" | "udp"))
        .cloned()
        .collect()
}
