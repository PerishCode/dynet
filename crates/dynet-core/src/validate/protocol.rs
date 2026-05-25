use std::net::IpAddr;

use serde_json::Value;

use crate::{ConfigDiagnostic, NetworkNode, NodeRole};

use super::deny;

pub(super) fn validate_builtin_protocol(
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
        (NodeRole::Outbound, "vmess") => {
            validate_vmess_outbound(section, index, node, diagnostics);
        }
        (NodeRole::Outbound, "ss") => {
            validate_shadowsocks_outbound(section, index, node, diagnostics);
        }
        (NodeRole::Outbound, "trojan") => {
            validate_trojan_outbound(section, index, node, diagnostics);
        }
        _ => {}
    }
}

fn validate_vmess_outbound(
    section: &'static str,
    index: usize,
    node: &NetworkNode,
    diagnostics: &mut Vec<ConfigDiagnostic>,
) {
    require_string_field(section, index, node, "server", diagnostics);
    require_one_port_field(section, index, node, &["serverPort", "port"], diagnostics);
    require_string_field(section, index, node, "uuid", diagnostics);
    if let Some(server_ip) = node.payload.get("serverIp") {
        match server_ip
            .as_str()
            .and_then(|value| value.parse::<IpAddr>().ok())
        {
            Some(_) => {}
            None => diagnostics.push(deny(
                format!("{section}[{index}].payload.serverIp"),
                "serverIp must be an IP address string",
            )),
        }
    }
    if let Some(alter_id) = node.payload.get("alterId") {
        match alter_id.as_u64() {
            Some(0) => {}
            Some(_) => diagnostics.push(deny(
                format!("{section}[{index}].payload.alterId"),
                "VMess runtime currently supports only alterId 0",
            )),
            None => diagnostics.push(deny(
                format!("{section}[{index}].payload.alterId"),
                "alterId must be a number",
            )),
        }
    }
    if let Some(network) = node.payload.get("network") {
        match network.as_str() {
            Some("tcp") => {}
            Some(_) => diagnostics.push(deny(
                format!("{section}[{index}].payload.network"),
                "VMess runtime currently supports only plain tcp transport",
            )),
            None => diagnostics.push(deny(
                format!("{section}[{index}].payload.network"),
                "network must be a string",
            )),
        }
    }
}

fn validate_shadowsocks_outbound(
    section: &'static str,
    index: usize,
    node: &NetworkNode,
    diagnostics: &mut Vec<ConfigDiagnostic>,
) {
    require_string_field(section, index, node, "server", diagnostics);
    require_one_port_field(section, index, node, &["serverPort", "port"], diagnostics);
    require_string_field(section, index, node, "password", diagnostics);
    match node.payload.get("cipher").and_then(Value::as_str) {
        Some("aes-128-gcm") => {}
        Some(_) => diagnostics.push(deny(
            format!("{section}[{index}].payload.cipher"),
            "Shadowsocks runtime currently supports only aes-128-gcm",
        )),
        None => diagnostics.push(deny(
            format!("{section}[{index}].payload.cipher"),
            "cipher is required for ss nodes",
        )),
    }
    if let Some(server_ip) = node.payload.get("serverIp") {
        match server_ip
            .as_str()
            .and_then(|value| value.parse::<IpAddr>().ok())
        {
            Some(_) => {}
            None => diagnostics.push(deny(
                format!("{section}[{index}].payload.serverIp"),
                "serverIp must be an IP address string",
            )),
        }
    }
}

fn validate_trojan_outbound(
    section: &'static str,
    index: usize,
    node: &NetworkNode,
    diagnostics: &mut Vec<ConfigDiagnostic>,
) {
    require_string_field(section, index, node, "server", diagnostics);
    require_one_port_field(section, index, node, &["serverPort", "port"], diagnostics);
    require_string_field(section, index, node, "password", diagnostics);
    optional_string_field(section, index, node, "serverIp", diagnostics);
    optional_string_field(section, index, node, "sni", diagnostics);
    optional_string_field(section, index, node, "interfaceName", diagnostics);
    optional_bool_field(section, index, node, "skipCertVerify", diagnostics);
    if let Some(server_ip) = node.payload.get("serverIp") {
        match server_ip
            .as_str()
            .and_then(|value| value.parse::<IpAddr>().ok())
        {
            Some(_) => {}
            None => diagnostics.push(deny(
                format!("{section}[{index}].payload.serverIp"),
                "serverIp must be an IP address string",
            )),
        }
    }
    if let Some(network) = node.payload.get("network") {
        match network.as_str() {
            Some("tcp") => {}
            Some(_) => diagnostics.push(deny(
                format!("{section}[{index}].payload.network"),
                "Trojan runtime currently supports only plain tcp transport",
            )),
            None => diagnostics.push(deny(
                format!("{section}[{index}].payload.network"),
                "network must be a string",
            )),
        }
    }
}

fn require_string_field(
    section: &'static str,
    index: usize,
    node: &NetworkNode,
    field: &'static str,
    diagnostics: &mut Vec<ConfigDiagnostic>,
) {
    match node.payload.get(field) {
        Some(Value::String(value)) if !value.trim().is_empty() => {}
        Some(Value::String(_)) => diagnostics.push(deny(
            format!("{section}[{index}].payload.{field}"),
            format!("{field} must not be empty"),
        )),
        Some(_) => diagnostics.push(deny(
            format!("{section}[{index}].payload.{field}"),
            format!("{field} must be a string"),
        )),
        None => diagnostics.push(deny(
            format!("{section}[{index}].payload.{field}"),
            format!("{field} is required for {} nodes", node.kind),
        )),
    }
}

fn optional_string_field(
    section: &'static str,
    index: usize,
    node: &NetworkNode,
    field: &'static str,
    diagnostics: &mut Vec<ConfigDiagnostic>,
) {
    match node.payload.get(field) {
        Some(Value::String(value)) if !value.trim().is_empty() => {}
        Some(Value::String(_)) => diagnostics.push(deny(
            format!("{section}[{index}].payload.{field}"),
            format!("{field} must not be empty"),
        )),
        Some(_) => diagnostics.push(deny(
            format!("{section}[{index}].payload.{field}"),
            format!("{field} must be a string"),
        )),
        None => {}
    }
}

fn optional_bool_field(
    section: &'static str,
    index: usize,
    node: &NetworkNode,
    field: &'static str,
    diagnostics: &mut Vec<ConfigDiagnostic>,
) {
    match node.payload.get(field) {
        Some(Value::Bool(_)) | None => {}
        Some(_) => diagnostics.push(deny(
            format!("{section}[{index}].payload.{field}"),
            format!("{field} must be a boolean"),
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
    match node.payload.get(field) {
        Some(Value::Number(value)) => match value.as_u64() {
            Some(port) if (1..=65535).contains(&port) => {}
            _ => diagnostics.push(deny(
                format!("{section}[{index}].payload.{field}"),
                format!("{field} must be a TCP/UDP port from 1 to 65535"),
            )),
        },
        Some(_) => diagnostics.push(deny(
            format!("{section}[{index}].payload.{field}"),
            format!("{field} must be a number"),
        )),
        None => diagnostics.push(deny(
            format!("{section}[{index}].payload.{field}"),
            format!("{field} is required for {} nodes", node.kind),
        )),
    }
}

fn require_one_port_field(
    section: &'static str,
    index: usize,
    node: &NetworkNode,
    fields: &[&'static str],
    diagnostics: &mut Vec<ConfigDiagnostic>,
) {
    if fields.iter().any(|field| {
        node.payload
            .get(*field)
            .and_then(Value::as_u64)
            .is_some_and(|port| (1..=65535).contains(&port))
    }) {
        return;
    }
    diagnostics.push(deny(
        format!("{section}[{index}].payload.{}", fields.join("|")),
        format!(
            "{} must include one TCP port field from {}",
            node.kind,
            fields.join(", ")
        ),
    ));
}
