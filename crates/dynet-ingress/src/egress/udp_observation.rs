use std::net::SocketAddr;

use crate::{push_decision_fields, session_fields, IngressEventKind};

use super::{EgressError, UdpRelayAssociation};

pub(crate) async fn relay_udp_response(
    association: &UdpRelayAssociation,
    node_protocol: &'static str,
    upstream: SocketAddr,
    payload: &[u8],
    extra_fields: &[(&'static str, String)],
) -> Result<(), EgressError> {
    association
        .downstream
        .send_to_peer(payload, association.peer)
        .await
        .map_err(|error| EgressError {
            stage: "inbound-write",
            upstream: Some(upstream),
            message: format!("failed sending UDP downstream datagram: {error}"),
        })?;
    let mut fields = session_fields(
        association.session_id,
        association.inbound,
        node_protocol,
        association.peer,
        association.target,
        upstream,
    );
    push_decision_fields(&mut fields, &association.decision);
    fields.push(("direction", "upstream-to-client".to_string()));
    fields.push((
        "bytes",
        association.downstream.payload_len(payload).to_string(),
    ));
    fields.extend(extra_fields.iter().cloned());
    association
        .runtime
        .events()
        .record(IngressEventKind::UdpDatagram, fields);
    Ok(())
}
