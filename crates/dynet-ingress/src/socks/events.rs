use std::net::SocketAddr;

use dynet_runtime::RuntimeState;

use crate::{
    outbound::OutboundError, push_decision_fields, push_endpoint_fields, session_fields,
    IngressEventKind,
};

use super::protocol::SocksDestination;

pub(super) const SOCKS5_INBOUND: &str = "socks5";

pub(super) fn socks_session_fields(
    session_id: u64,
    node_protocol: &'static str,
    peer: SocketAddr,
    target: SocketAddr,
    destination: &SocksDestination,
) -> Vec<(&'static str, String)> {
    let mut fields = session_fields(
        session_id,
        SOCKS5_INBOUND,
        node_protocol,
        peer,
        target,
        target,
    );
    push_destination_fields(&mut fields, destination);
    fields
}

pub(super) fn outbound_error_fields(
    session_id: u64,
    node_protocol: &'static str,
    peer: SocketAddr,
    target: SocketAddr,
    destination: &SocksDestination,
    error: OutboundError,
    decision: Option<&dynet_runtime::SelectionDecision>,
) -> Vec<(&'static str, String)> {
    let upstream = error.upstream.unwrap_or(target);
    let mut fields = session_fields(
        session_id,
        SOCKS5_INBOUND,
        node_protocol,
        peer,
        target,
        upstream,
    );
    push_destination_fields(&mut fields, destination);
    if let Some(decision) = decision {
        push_decision_fields(&mut fields, decision);
    }
    fields.push(("errorStage", error.stage.to_string()));
    fields.push(("error", error.message));
    fields
}

pub(super) fn record_socks_error(
    runtime: &RuntimeState,
    session_id: u64,
    peer: SocketAddr,
    stage: &'static str,
    message: &str,
) {
    let mut fields = base_socks_fields(session_id, "unknown", peer);
    fields.push(("errorStage", stage.to_string()));
    fields.push(("error", message.to_string()));
    runtime.events().record(IngressEventKind::TcpError, fields);
}

pub(super) fn base_socks_fields(
    session_id: u64,
    node_protocol: &'static str,
    peer: SocketAddr,
) -> Vec<(&'static str, String)> {
    let mut fields = vec![
        ("sessionId", session_id.to_string()),
        ("inbound", SOCKS5_INBOUND.to_string()),
        ("nodeProtocol", node_protocol.to_string()),
        ("peer", peer.to_string()),
    ];
    push_endpoint_fields(&mut fields, "peer", peer);
    fields
}

fn push_destination_fields(
    fields: &mut Vec<(&'static str, String)>,
    destination: &SocksDestination,
) {
    if let Some(domain) = destination.domain() {
        fields.push(("targetDomain", domain.to_string()));
    }
}
