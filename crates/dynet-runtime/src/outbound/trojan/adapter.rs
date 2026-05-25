use dynet_core::NetworkNode;

use crate::{settings::OutboundTcpSettings, RuntimeEvent};

use super::super::{
    annotate_tcp_settings, observe_stage, observe_stage_with, ProxiedTcpStream, TcpTarget,
};
use super::{connect_transport, spec_from_node, tls_handshake, write_request};

pub(in crate::outbound) fn connect_tcp(
    target: &TcpTarget,
    outbound: &NetworkNode,
    mark: u32,
    events: &mut Vec<RuntimeEvent>,
    tcp_settings: OutboundTcpSettings,
) -> Result<ProxiedTcpStream, String> {
    let spec = observe_stage(events, outbound, "payload-decode", || {
        spec_from_node(outbound)
    })?;
    let transport = observe_stage_with(
        events,
        outbound,
        "tcp-connect",
        |event| {
            annotate_tcp_settings(event, tcp_settings)
                .field("interfaceNameConfigured", spec.interface_name.is_some())
                .field(
                    "interfaceNameLength",
                    spec.interface_name.as_ref().map_or(0, String::len),
                )
        },
        || connect_transport(&spec, mark, tcp_settings),
    )?;
    let stream = observe_stage_with(
        events,
        outbound,
        "trojan-tls-handshake",
        |event| {
            annotate_tcp_settings(event, tcp_settings)
                .field("pendingBudgetMs", super::tls_pending_budget_ms())
                .field("pendingSleepMs", super::tls_pending_sleep_ms())
        },
        || tls_handshake(&spec, transport),
    )?;
    observe_stage_with(
        events,
        outbound,
        "trojan-request-write",
        |event| annotate_tcp_settings(event, tcp_settings),
        || {
            write_request(&spec, target, stream)
                .map(Box::new)
                .map(ProxiedTcpStream::Trojan)
        },
    )
}
