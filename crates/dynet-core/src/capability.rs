use std::collections::BTreeSet;

use crate::{DynetConfig, ModeledNode, NetworkModel, NetworkNode, NodeRole};

pub(crate) const CAP_TCP: &str = "tcp";
pub(crate) const CAP_UDP: &str = "udp";
pub(crate) const CAP_DNS: &str = "dns";
pub(crate) const CAP_IP_TARGET: &str = "ip-target";
pub(crate) const CAP_DOMAIN_TARGET: &str = "domain-target";
pub(crate) const CAP_TRANSPARENT: &str = "transparent";
pub(crate) const CAP_PROBEABLE: &str = "probeable";

pub(crate) const KNOWN_CAPABILITIES: &[&str] = &[
    CAP_TCP,
    CAP_UDP,
    CAP_DNS,
    CAP_IP_TARGET,
    CAP_DOMAIN_TARGET,
    CAP_TRANSPARENT,
    CAP_PROBEABLE,
];

pub(crate) fn network_model(config: &DynetConfig) -> NetworkModel {
    NetworkModel {
        schema: "dynet-network/v1alpha1".to_string(),
        inbounds: config
            .inbounds
            .iter()
            .map(|node| model_node(NodeRole::Inbound, node))
            .collect(),
        outbounds: config
            .outbounds
            .iter()
            .map(|node| model_node(NodeRole::Outbound, node))
            .collect(),
    }
}

pub(crate) fn capabilities_for(node: &NetworkNode) -> Vec<String> {
    let mut capabilities = BTreeSet::<String>::new();
    for capability in implied_capabilities(node.kind.as_str()) {
        capabilities.insert(capability.to_string());
    }
    for capability in &node.capabilities {
        let normalized = capability.trim().to_ascii_lowercase();
        if !normalized.is_empty() {
            capabilities.insert(normalized);
        }
    }
    capabilities.into_iter().collect()
}

pub(crate) fn transport_capabilities(node: &NetworkNode) -> BTreeSet<String> {
    capabilities_for(node)
        .into_iter()
        .filter(|capability| matches!(capability.as_str(), CAP_TCP | CAP_UDP))
        .collect()
}

fn model_node(role: NodeRole, node: &NetworkNode) -> ModeledNode {
    let id = node
        .id
        .clone()
        .unwrap_or_else(|| format!("{}:{}", role_label(role), node.tag));
    ModeledNode {
        role,
        tag: node.tag.clone(),
        id,
        fingerprint: fingerprint(role, node),
        kind: node.kind.clone(),
        capabilities: capabilities_for(node),
        constraints: normalized_unique(node.constraints.iter().map(String::as_str)),
        protocol_fields: node.protocol.keys().cloned().collect(),
    }
}

fn implied_capabilities(kind: &str) -> &'static [&'static str] {
    match kind {
        "tcp" => &[CAP_TCP, CAP_IP_TARGET, CAP_DOMAIN_TARGET, CAP_PROBEABLE],
        "udp" => &[CAP_UDP, CAP_IP_TARGET, CAP_DOMAIN_TARGET, CAP_PROBEABLE],
        "mixed" => &[
            CAP_TCP,
            CAP_UDP,
            CAP_IP_TARGET,
            CAP_DOMAIN_TARGET,
            CAP_PROBEABLE,
        ],
        "tun" => &[CAP_TCP, CAP_UDP, CAP_DNS, CAP_IP_TARGET, CAP_TRANSPARENT],
        "direct" => &[
            CAP_TCP,
            CAP_UDP,
            CAP_DNS,
            CAP_IP_TARGET,
            CAP_DOMAIN_TARGET,
            CAP_PROBEABLE,
        ],
        _ => &[],
    }
}

fn normalized_unique<'a>(values: impl Iterator<Item = &'a str>) -> Vec<String> {
    values
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn fingerprint(role: NodeRole, node: &NetworkNode) -> String {
    let mut canonical = String::new();
    canonical.push_str(role_label(role));
    canonical.push('\n');
    canonical.push_str(node.id.as_deref().unwrap_or(""));
    canonical.push('\n');
    canonical.push_str(node.tag.as_str());
    canonical.push('\n');
    canonical.push_str(node.kind.as_str());
    canonical.push('\n');
    for (key, value) in &node.protocol {
        canonical.push_str(key);
        canonical.push('=');
        canonical.push_str(&value.to_string());
        canonical.push('\n');
    }
    format!("dynet:{}:{:016x}", role_label(role), fnv1a64(&canonical))
}

fn fnv1a64(value: &str) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn role_label(role: NodeRole) -> &'static str {
    match role {
        NodeRole::Inbound => "inbound",
        NodeRole::Outbound => "outbound",
    }
}
