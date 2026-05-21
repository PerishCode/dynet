use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

mod outbound;
mod protocol;
mod routes;
mod rules;

use crate::{
    capability::KNOWN_CAPABILITIES, ConfigDiagnostic, DnsChain, DynetConfig, NetworkNode, NodeRole,
    Severity,
};

pub fn validate_config(config: &DynetConfig) -> Vec<ConfigDiagnostic> {
    let mut diagnostics = Vec::new();
    validate_dns(config, &mut diagnostics);
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
    outbound::validate_outbound_graph(config, &mut diagnostics);
    rules::validate_rules(config, &mut diagnostics);
    routes::validate_routes(config, &mut diagnostics);
    diagnostics
}

fn validate_dns(config: &DynetConfig, diagnostics: &mut Vec<ConfigDiagnostic>) {
    let mut seen = BTreeMap::<&str, usize>::new();
    for (index, chain) in config.dns.chains.iter().enumerate() {
        validate_dns_chain_base(index, chain, diagnostics);
        if let Some(previous) = seen.insert(chain.tag.as_str(), index) {
            diagnostics.push(deny(
                format!("dns.chains[{index}].tag"),
                format!("duplicate DNS chain tag also used at dns.chains[{previous}]"),
            ));
        }
        validate_dns_chain_protocol(index, chain, diagnostics);
    }
}

fn validate_dns_chain_base(
    index: usize,
    chain: &DnsChain,
    diagnostics: &mut Vec<ConfigDiagnostic>,
) {
    if chain.tag.trim().is_empty() {
        diagnostics.push(deny(
            format!("dns.chains[{index}].tag"),
            "DNS chain tag must not be empty",
        ));
    }
    if chain.kind.trim().is_empty() {
        diagnostics.push(deny(
            format!("dns.chains[{index}].type"),
            "DNS chain type must not be empty",
        ));
    }
}

fn validate_dns_chain_protocol(
    index: usize,
    chain: &DnsChain,
    diagnostics: &mut Vec<ConfigDiagnostic>,
) {
    match chain.kind.as_str() {
        "doh" => validate_doh_chain(index, chain, diagnostics),
        "udp" => validate_udp_chain(index, chain, diagnostics),
        other => diagnostics.push(warning(
            format!("dns.chains[{index}].type"),
            format!("unknown DNS chain type `{other}` is preserved for future resolvers"),
        )),
    }
}

fn validate_doh_chain(index: usize, chain: &DnsChain, diagnostics: &mut Vec<ConfigDiagnostic>) {
    match chain.endpoint.as_deref() {
        Some(endpoint) => validate_doh_endpoint(index, endpoint, diagnostics),
        None => diagnostics.push(deny(
            format!("dns.chains[{index}].endpoint"),
            "endpoint is required for DoH DNS chains",
        )),
    }
    if chain.bootstrap_ips.is_empty() {
        diagnostics.push(deny(
            format!("dns.chains[{index}].bootstrapIps"),
            "bootstrapIps is required for DoH chains to avoid polluted DNS bootstrap",
        ));
    }
    if chain.server.is_some() {
        diagnostics.push(warning(
            format!("dns.chains[{index}].server"),
            "server is ignored for DoH chains",
        ));
    }
    if chain.server_port.is_some() {
        diagnostics.push(warning(
            format!("dns.chains[{index}].serverPort"),
            "serverPort is ignored for DoH chains",
        ));
    }
}

fn validate_udp_chain(index: usize, chain: &DnsChain, diagnostics: &mut Vec<ConfigDiagnostic>) {
    match chain.server.as_deref() {
        Some(server) if server.parse::<IpAddr>().is_ok() => {}
        Some(_) => diagnostics.push(deny(
            format!("dns.chains[{index}].server"),
            "UDP DNS server must be an IP address",
        )),
        None => diagnostics.push(deny(
            format!("dns.chains[{index}].server"),
            "server is required for UDP DNS chains",
        )),
    }
    match chain.server_port {
        Some(1..=65535) => {}
        _ => diagnostics.push(deny(
            format!("dns.chains[{index}].serverPort"),
            "serverPort must be a UDP port from 1 to 65535",
        )),
    }
    if chain.endpoint.is_some() {
        diagnostics.push(warning(
            format!("dns.chains[{index}].endpoint"),
            "endpoint is ignored for UDP DNS chains",
        ));
    }
}

fn validate_doh_endpoint(index: usize, endpoint: &str, diagnostics: &mut Vec<ConfigDiagnostic>) {
    if endpoint.trim() != endpoint || endpoint.is_empty() {
        diagnostics.push(deny(
            format!("dns.chains[{index}].endpoint"),
            "DoH endpoint must not be empty or padded",
        ));
        return;
    }
    let Some(rest) = endpoint.strip_prefix("https://") else {
        diagnostics.push(deny(
            format!("dns.chains[{index}].endpoint"),
            "DoH endpoint must use https://",
        ));
        return;
    };
    let Some((host, path)) = rest.split_once('/') else {
        diagnostics.push(deny(
            format!("dns.chains[{index}].endpoint"),
            "DoH endpoint must include an absolute path",
        ));
        return;
    };
    if host.is_empty() || path.is_empty() || host.contains(char::is_whitespace) {
        diagnostics.push(deny(
            format!("dns.chains[{index}].endpoint"),
            "DoH endpoint must include a non-empty host and path",
        ));
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
        validate_node_base(section, index, node, diagnostics);
        if let Some(previous) = seen.insert(node.tag.as_str(), index) {
            diagnostics.push(deny(
                format!("{section}[{index}].tag"),
                format!("duplicate node tag also used at {section}[{previous}]"),
            ));
        }
        validate_capabilities(role, section, index, node, diagnostics);
        protocol::validate_builtin_protocol(role, section, index, node, diagnostics);
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
    role: NodeRole,
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
        if unsupported_runtime_cap(role, node, normalized.as_str()) {
            diagnostics.push(deny(
                format!("{section}[{index}].capabilities[{capability_index}]"),
                format!(
                    "{} node type `{}` does not currently support capability `{normalized}`",
                    role_label(role),
                    node.kind
                ),
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

fn unsupported_runtime_cap(role: NodeRole, node: &NetworkNode, capability: &str) -> bool {
    if !matches!(capability, "tcp" | "udp" | "dns") {
        return false;
    }
    match (role, node.kind.as_str()) {
        (NodeRole::Inbound, "tcp") => capability != "tcp",
        (NodeRole::Inbound, "udp") => capability != "udp",
        (NodeRole::Inbound, "mixed" | "tun") => false,
        (NodeRole::Outbound, "tcp") => capability != "tcp",
        (NodeRole::Outbound, "udp") => capability != "udp",
        (NodeRole::Outbound, "direct" | "plan") => false,
        (NodeRole::Outbound, "vmess" | "ss" | "trojan" | "dialer") => capability == "udp",
        _ => false,
    }
}

fn role_label(role: NodeRole) -> &'static str {
    match role {
        NodeRole::Inbound => "inbound",
        NodeRole::Outbound => "outbound",
    }
}

fn validate_ip_cidr(
    path: String,
    label: &'static str,
    value: &str,
    diagnostics: &mut Vec<ConfigDiagnostic>,
) {
    let Some((address, prefix)) = value.trim().split_once('/') else {
        diagnostics.push(deny(path, format!("{label} must use CIDR notation")));
        return;
    };
    let Ok(address) = address.parse::<IpAddr>() else {
        diagnostics.push(deny(path, format!("{label} address must be an IP address")));
        return;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        diagnostics.push(deny(path, format!("{label} prefix must be a number")));
        return;
    };
    let max_prefix = if address.is_ipv4() { 32 } else { 128 };
    if prefix > max_prefix {
        diagnostics.push(deny(
            path,
            format!("{label} prefix must be <= {max_prefix}"),
        ));
    }
}

fn node_index(nodes: &[NetworkNode]) -> BTreeMap<&str, &NetworkNode> {
    nodes.iter().map(|node| (node.tag.as_str(), node)).collect()
}

pub(super) fn deny(path: impl Into<String>, message: impl Into<String>) -> ConfigDiagnostic {
    ConfigDiagnostic {
        severity: Severity::Deny,
        path: path.into(),
        message: message.into(),
    }
}

pub(super) fn warning(path: impl Into<String>, message: impl Into<String>) -> ConfigDiagnostic {
    ConfigDiagnostic {
        severity: Severity::Warning,
        path: path.into(),
        message: message.into(),
    }
}
