use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::{
    capability::{transport_capabilities, KNOWN_CAPABILITIES},
    normalize_domain, ConfigDiagnostic, DynetConfig, NetworkNode, NodeRole, Severity,
};

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

fn validate_nodes(
    role: NodeRole,
    section: &'static str,
    nodes: &[NetworkNode],
    diagnostics: &mut Vec<ConfigDiagnostic>,
) {
    let mut seen = BTreeMap::<&str, usize>::new();
    for (index, node) in nodes.iter().enumerate() {
        validate_node_base(section, index, node, diagnostics);
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

fn validate_node_base(
    section: &'static str,
    index: usize,
    node: &NetworkNode,
    diagnostics: &mut Vec<ConfigDiagnostic>,
) {
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
    if matches!(node.id.as_deref(), Some(id) if id.trim().is_empty()) {
        diagnostics.push(deny(
            format!("{section}[{index}].id"),
            "node id must not be empty when set",
        ));
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
    let inbounds = node_index(&config.inbounds);
    let outbounds = node_index(&config.outbounds);

    for (index, route) in config.routes.iter().enumerate() {
        validate_route_domain(index, route.domain.as_deref(), diagnostics);
        let outbound = required_route_node(
            &outbounds,
            route.outbound.as_str(),
            format!("routes[{index}].outbound"),
            "outbound",
            diagnostics,
        );
        let inbound = route.inbound.as_deref().and_then(|inbound| {
            required_route_node(
                &inbounds,
                inbound,
                format!("routes[{index}].inbound"),
                "inbound",
                diagnostics,
            )
        });
        if let (Some(inbound), Some(outbound)) = (inbound, outbound) {
            validate_route_transport(index, inbound, outbound, diagnostics);
        }
    }
}

fn validate_route_domain(
    index: usize,
    domain: Option<&str>,
    diagnostics: &mut Vec<ConfigDiagnostic>,
) {
    match domain {
        Some(value) if normalize_domain(value).is_none() => diagnostics.push(deny(
            format!("routes[{index}].domain"),
            "route domain must not be empty",
        )),
        _ => {}
    }
}

fn node_index(nodes: &[NetworkNode]) -> BTreeMap<&str, &NetworkNode> {
    nodes.iter().map(|node| (node.tag.as_str(), node)).collect()
}

fn required_route_node<'a>(
    nodes: &'a BTreeMap<&str, &'a NetworkNode>,
    tag: &str,
    path: String,
    role: &str,
    diagnostics: &mut Vec<ConfigDiagnostic>,
) -> Option<&'a NetworkNode> {
    if tag.trim().is_empty() {
        diagnostics.push(deny(path, format!("route {role} must not be empty")));
        return None;
    }
    match nodes.get(tag) {
        Some(node) => Some(*node),
        None => {
            diagnostics.push(deny(
                path,
                format!("route references unknown {role} `{tag}`"),
            ));
            None
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
