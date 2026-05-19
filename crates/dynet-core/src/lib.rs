use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

const CAP_TCP: &str = "tcp";
const CAP_UDP: &str = "udp";
const CAP_DNS: &str = "dns";
const CAP_IP_TARGET: &str = "ip-target";
const CAP_DOMAIN_TARGET: &str = "domain-target";
const CAP_TRANSPARENT: &str = "transparent";
const CAP_PROBEABLE: &str = "probeable";

const KNOWN_CAPABILITIES: &[&str] = &[
    CAP_TCP,
    CAP_UDP,
    CAP_DNS,
    CAP_IP_TARGET,
    CAP_DOMAIN_TARGET,
    CAP_TRANSPARENT,
    CAP_PROBEABLE,
];

#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DynetConfig {
    #[serde(default)]
    pub log: Option<LogConfig>,
    #[serde(default)]
    pub inbounds: Vec<Inbound>,
    #[serde(default)]
    pub outbounds: Vec<Outbound>,
    #[serde(default)]
    pub routes: Vec<RouteRule>,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogConfig {
    pub level: String,
}

pub type Inbound = NetworkNode;
pub type Outbound = NetworkNode;
pub type Endpoint = NetworkNode;

#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkNode {
    pub tag: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub constraints: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
    #[serde(flatten)]
    pub protocol: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteRule {
    #[serde(default)]
    pub inbound: Option<String>,
    pub outbound: String,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    Deny,
    Warning,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigDiagnostic {
    pub severity: Severity,
    pub path: String,
    pub message: String,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigSummary {
    pub inbounds: usize,
    pub outbounds: usize,
    pub routes: usize,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkModel {
    pub schema: String,
    pub inbounds: Vec<ModeledNode>,
    pub outbounds: Vec<ModeledNode>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NodeRole {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModeledNode {
    pub role: NodeRole,
    pub tag: String,
    pub id: String,
    pub fingerprint: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub capabilities: Vec<String>,
    pub constraints: Vec<String>,
    pub protocol_fields: Vec<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Plan {
    pub mode: PlanMode,
    pub rules: Vec<PlanRule>,
    pub final_outbound: Option<String>,
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
    pub inbound: Option<String>,
    pub outbound: String,
    pub source: PlanRuleSource,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PlanRuleSource {
    ExplicitRoute,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanSummary {
    pub rules: usize,
    pub has_final: bool,
}

impl DynetConfig {
    pub fn summary(&self) -> ConfigSummary {
        ConfigSummary {
            inbounds: self.inbounds.len(),
            outbounds: self.outbounds.len(),
            routes: self.routes.len(),
        }
    }

    pub fn network_model(&self) -> NetworkModel {
        NetworkModel {
            schema: "dynet-network/v1alpha1".to_string(),
            inbounds: self
                .inbounds
                .iter()
                .map(|node| model_node(NodeRole::Inbound, node))
                .collect(),
            outbounds: self
                .outbounds
                .iter()
                .map(|node| model_node(NodeRole::Outbound, node))
                .collect(),
        }
    }
}

impl Plan {
    pub fn summary(&self) -> PlanSummary {
        PlanSummary {
            rules: self.rules.len(),
            has_final: self.final_outbound.is_some(),
        }
    }
}

pub fn build_plan(config: &DynetConfig) -> Plan {
    let rules = config
        .routes
        .iter()
        .enumerate()
        .map(|(index, route)| PlanRule {
            order: index + 1,
            inbound: route.inbound.clone(),
            outbound: route.outbound.clone(),
            source: PlanRuleSource::ExplicitRoute,
            reason: match route.inbound.as_deref() {
                Some(inbound) => {
                    format!(
                        "explicit route maps inbound `{inbound}` to `{}`",
                        route.outbound
                    )
                }
                None => format!("explicit default route maps to `{}`", route.outbound),
            },
        })
        .collect();
    let final_outbound = config
        .routes
        .iter()
        .find(|route| route.inbound.is_none())
        .map(|route| route.outbound.clone());

    Plan {
        mode: PlanMode::ExplicitOnly,
        rules,
        final_outbound,
    }
}

pub fn validate_config(config: &DynetConfig) -> Vec<ConfigDiagnostic> {
    let mut diagnostics = Vec::new();
    validate_nodes(
        NodeRole::Inbound,
        "inbounds",
        &config.inbounds,
        &mut diagnostics,
    );
    validate_nodes(
        NodeRole::Outbound,
        "outbounds",
        &config.outbounds,
        &mut diagnostics,
    );
    validate_routes(config, &mut diagnostics);
    diagnostics
}

fn model_node(role: NodeRole, node: &NetworkNode) -> ModeledNode {
    let capabilities = capabilities_for(node);
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
        capabilities,
        constraints: normalized_unique(node.constraints.iter().map(String::as_str)),
        protocol_fields: node.protocol.keys().cloned().collect(),
    }
}

fn validate_nodes(
    role: NodeRole,
    section: &'static str,
    nodes: &[NetworkNode],
    diagnostics: &mut Vec<ConfigDiagnostic>,
) {
    let mut seen = BTreeMap::<&str, usize>::new();
    for (index, node) in nodes.iter().enumerate() {
        if node.tag.trim().is_empty() {
            diagnostics.push(deny(
                format!("{section}[{index}].tag"),
                "node tag must not be empty",
            ));
        }
        if node.kind.trim().is_empty() {
            diagnostics.push(deny(
                format!("{section}[{index}].type"),
                "node type must not be empty",
            ));
        }
        if let Some(id) = node.id.as_deref() {
            if id.trim().is_empty() {
                diagnostics.push(deny(
                    format!("{section}[{index}].id"),
                    "node id must not be empty when set",
                ));
            }
        }
        if let Some(previous) = seen.insert(node.tag.as_str(), index) {
            diagnostics.push(deny(
                format!("{section}[{index}].tag"),
                format!("duplicate node tag also used at {section}[{previous}]"),
            ));
        }
        validate_capabilities(section, index, node, diagnostics);
        validate_builtin_protocol(role, section, index, node, diagnostics);
    }
}

fn validate_capabilities(
    section: &'static str,
    index: usize,
    node: &NetworkNode,
    diagnostics: &mut Vec<ConfigDiagnostic>,
) {
    let mut seen = BTreeSet::<String>::new();
    for (capability_index, capability) in node.capabilities.iter().enumerate() {
        let normalized = capability.trim().to_ascii_lowercase();
        if normalized.is_empty() {
            diagnostics.push(deny(
                format!("{section}[{index}].capabilities[{capability_index}]"),
                "capability must not be empty",
            ));
            continue;
        }
        if !KNOWN_CAPABILITIES.contains(&normalized.as_str()) {
            diagnostics.push(warning(
                format!("{section}[{index}].capabilities[{capability_index}]"),
                format!("unknown capability `{capability}` is preserved for future adapters"),
            ));
        }
        if !seen.insert(normalized) {
            diagnostics.push(warning(
                format!("{section}[{index}].capabilities[{capability_index}]"),
                format!("duplicate capability `{capability}`"),
            ));
        }
    }
}

fn validate_builtin_protocol(
    role: NodeRole,
    section: &'static str,
    index: usize,
    node: &NetworkNode,
    diagnostics: &mut Vec<ConfigDiagnostic>,
) {
    match (role, node.kind.as_str()) {
        (NodeRole::Inbound, "tcp" | "udp") => {
            require_string_field(section, index, node, "listen", diagnostics);
            require_port_field(section, index, node, "listenPort", diagnostics);
        }
        (NodeRole::Outbound, "tcp" | "udp") => {
            require_string_field(section, index, node, "server", diagnostics);
            require_port_field(section, index, node, "serverPort", diagnostics);
        }
        _ => {}
    }
}

fn validate_routes(config: &DynetConfig, diagnostics: &mut Vec<ConfigDiagnostic>) {
    let inbounds = config
        .inbounds
        .iter()
        .map(|node| (node.tag.as_str(), node))
        .collect::<BTreeMap<_, _>>();
    let outbounds = config
        .outbounds
        .iter()
        .map(|node| (node.tag.as_str(), node))
        .collect::<BTreeMap<_, _>>();

    for (index, route) in config.routes.iter().enumerate() {
        let outbound = if route.outbound.trim().is_empty() {
            diagnostics.push(deny(
                format!("routes[{index}].outbound"),
                "route outbound must not be empty",
            ));
            None
        } else {
            match outbounds.get(route.outbound.as_str()) {
                Some(outbound) => Some(*outbound),
                None => {
                    diagnostics.push(deny(
                        format!("routes[{index}].outbound"),
                        format!("route references unknown outbound `{}`", route.outbound),
                    ));
                    None
                }
            }
        };

        let inbound = if let Some(inbound) = route.inbound.as_deref() {
            if inbound.trim().is_empty() {
                diagnostics.push(deny(
                    format!("routes[{index}].inbound"),
                    "route inbound must not be empty when set",
                ));
                None
            } else {
                match inbounds.get(inbound) {
                    Some(inbound) => Some(*inbound),
                    None => {
                        diagnostics.push(deny(
                            format!("routes[{index}].inbound"),
                            format!("route references unknown inbound `{inbound}`"),
                        ));
                        None
                    }
                }
            }
        } else {
            None
        };

        if let (Some(inbound), Some(outbound)) = (inbound, outbound) {
            validate_route_transport(index, inbound, outbound, diagnostics);
        }
    }
}

fn validate_route_transport(
    index: usize,
    inbound: &NetworkNode,
    outbound: &NetworkNode,
    diagnostics: &mut Vec<ConfigDiagnostic>,
) {
    let inbound_transport = transport_capabilities(inbound);
    let outbound_transport = transport_capabilities(outbound);
    if inbound_transport.is_empty() || outbound_transport.is_empty() {
        return;
    }
    if inbound_transport.is_disjoint(&outbound_transport) {
        diagnostics.push(deny(
            format!("routes[{index}]"),
            format!(
                "route maps inbound `{}` to outbound `{}` with no shared tcp/udp capability",
                inbound.tag, outbound.tag
            ),
        ));
    }
}

fn require_string_field(
    section: &'static str,
    index: usize,
    node: &NetworkNode,
    field: &'static str,
    diagnostics: &mut Vec<ConfigDiagnostic>,
) {
    match node.protocol.get(field) {
        Some(Value::String(value)) if !value.trim().is_empty() => {}
        Some(Value::String(_)) => diagnostics.push(deny(
            format!("{section}[{index}].{field}"),
            format!("{field} must not be empty"),
        )),
        Some(_) => diagnostics.push(deny(
            format!("{section}[{index}].{field}"),
            format!("{field} must be a string"),
        )),
        None => diagnostics.push(deny(
            format!("{section}[{index}].{field}"),
            format!("{field} is required for {} nodes", node.kind),
        )),
    }
}

fn require_port_field(
    section: &'static str,
    index: usize,
    node: &NetworkNode,
    field: &'static str,
    diagnostics: &mut Vec<ConfigDiagnostic>,
) {
    match node.protocol.get(field) {
        Some(Value::Number(value)) => match value.as_u64() {
            Some(port) if (1..=65535).contains(&port) => {}
            _ => diagnostics.push(deny(
                format!("{section}[{index}].{field}"),
                format!("{field} must be a TCP/UDP port from 1 to 65535"),
            )),
        },
        Some(_) => diagnostics.push(deny(
            format!("{section}[{index}].{field}"),
            format!("{field} must be a number"),
        )),
        None => diagnostics.push(deny(
            format!("{section}[{index}].{field}"),
            format!("{field} is required for {} nodes", node.kind),
        )),
    }
}

fn capabilities_for(node: &NetworkNode) -> Vec<String> {
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

fn transport_capabilities(node: &NetworkNode) -> BTreeSet<String> {
    capabilities_for(node)
        .into_iter()
        .filter(|capability| matches!(capability.as_str(), CAP_TCP | CAP_UDP))
        .collect()
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

fn deny(path: impl Into<String>, message: impl Into<String>) -> ConfigDiagnostic {
    ConfigDiagnostic {
        severity: Severity::Deny,
        path: path.into(),
        message: message.into(),
    }
}

fn warning(path: impl Into<String>, message: impl Into<String>) -> ConfigDiagnostic {
    ConfigDiagnostic {
        severity: Severity::Warning,
        path: path.into(),
        message: message.into(),
    }
}
