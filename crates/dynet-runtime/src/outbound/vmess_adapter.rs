use std::net::SocketAddr;

use dynet_core::{payload_as, NetworkNode};
use serde::Deserialize;

use crate::vmess;

use super::TcpTarget;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VmessPayload {
    server: String,
    #[serde(default)]
    server_ip: Option<String>,
    #[serde(default)]
    server_port: Option<u16>,
    #[serde(default)]
    port: Option<u16>,
    uuid: String,
    #[serde(default)]
    alter_id: u16,
    #[serde(default)]
    network: Option<String>,
    #[serde(default)]
    cipher: Option<String>,
}

pub(crate) fn vmess_target(target: &TcpTarget) -> vmess::VmessTarget {
    match target {
        TcpTarget::Socket(address) => vmess::VmessTarget::Ip(*address),
        TcpTarget::Domain { host, port } => vmess::VmessTarget::Domain {
            host: host.clone(),
            port: *port,
        },
    }
}

pub(crate) fn vmess_server_target(spec: &vmess::VmessSpec) -> TcpTarget {
    match spec.server.parse::<std::net::IpAddr>() {
        Ok(address) => TcpTarget::Socket(SocketAddr::new(address, spec.server_port)),
        Err(_) => TcpTarget::Domain {
            host: spec.server.clone(),
            port: spec.server_port,
        },
    }
}

pub(crate) fn vmess_spec_from_node(node: &NetworkNode) -> Result<vmess::VmessSpec, String> {
    let payload = payload_as::<VmessPayload>(node)?;
    if payload.alter_id != 0 {
        return Err(format!(
            "VMess outbound `{}` has unsupported alterId {}; only alterId 0 is supported",
            node.tag, payload.alter_id
        ));
    }
    let network = payload.network.as_deref().unwrap_or("tcp");
    if network != "tcp" {
        return Err(format!(
            "VMess outbound `{}` has unsupported network `{network}`; only plain tcp is supported",
            node.tag
        ));
    }
    let server_port = payload.server_port.or(payload.port).ok_or_else(|| {
        format!(
            "VMess outbound `{}` requires payload.serverPort or payload.port",
            node.tag
        )
    })?;
    let server = payload
        .server_ip
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(payload.server.as_str())
        .to_string();
    Ok(vmess::VmessSpec {
        tag: node.tag.clone(),
        server,
        server_port,
        uuid: payload.uuid,
        cipher: payload.cipher.unwrap_or_else(|| "auto".to_string()),
    })
}
