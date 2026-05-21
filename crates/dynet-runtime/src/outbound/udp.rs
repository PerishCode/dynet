use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    time::Duration,
};

use dynet_core::{InboundContext, NetworkNode};

use crate::{
    resolver::trace::classify_runtime_error, settings::RuntimePolicy, socket, RuntimeEvent,
    RuntimeEventKind,
};

use super::observe_stage;

const UDP_WRITE_TIMEOUT: Duration = Duration::from_secs(2);

pub(crate) enum ProxiedUdpSocket {
    Direct(UdpSocket),
}

pub(crate) fn connect_udp_policy(
    target: SocketAddr,
    outbound: &NetworkNode,
    _policy: &RuntimePolicy,
    _context: &InboundContext,
    mark: u32,
    events: &mut Vec<RuntimeEvent>,
) -> Result<ProxiedUdpSocket, String> {
    let started = std::time::Instant::now();
    events.push(
        RuntimeEvent::new(RuntimeEventKind::OutboundAttemptStarted)
            .field("outbound", &outbound.tag)
            .field("kind", &outbound.kind)
            .field("transport", "udp")
            .field("protocol", "udp-connect")
            .field("target", target),
    );
    let result = match outbound.kind.as_str() {
        "direct" => observe_stage(events, outbound, "udp-connect", || {
            connect_direct_udp(target, mark).map(ProxiedUdpSocket::Direct)
        }),
        kind => Err(format!(
            "UDP forwarding egress does not support outbound type `{kind}`; missing udp egress adapter"
        )),
    };
    match &result {
        Ok(_) => events.push(
            RuntimeEvent::new(RuntimeEventKind::OutboundAttemptFinished)
                .field("outbound", &outbound.tag)
                .field("kind", &outbound.kind)
                .field("transport", "udp")
                .field("protocol", "udp-connect")
                .field("target", target)
                .field("status", "success")
                .field("elapsedMs", started.elapsed().as_millis()),
        ),
        Err(error) => events.push(
            RuntimeEvent::new(RuntimeEventKind::OutboundAttemptFinished)
                .field("outbound", &outbound.tag)
                .field("kind", &outbound.kind)
                .field("transport", "udp")
                .field("protocol", "udp-connect")
                .field("target", target)
                .field("status", "failed")
                .field("errorType", classify_runtime_error(error))
                .field("error", error)
                .field("elapsedMs", started.elapsed().as_millis()),
        ),
    }
    result
}

fn connect_direct_udp(target: SocketAddr, mark: u32) -> Result<UdpSocket, String> {
    let bind = if target.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    };
    let socket = UdpSocket::bind(bind)
        .map_err(|error| format!("failed to bind UDP forwarding socket: {error}"))?;
    socket::set_socket_mark(&socket, mark)?;
    socket
        .connect(target)
        .map_err(|error| format!("failed to connect UDP target {target}: {error}"))?;
    socket
        .set_nonblocking(true)
        .map_err(|error| format!("failed to set UDP target nonblocking mode: {error}"))?;
    socket
        .set_write_timeout(Some(UDP_WRITE_TIMEOUT))
        .map_err(|error| format!("failed to set UDP target write timeout: {error}"))?;
    Ok(socket)
}

impl ProxiedUdpSocket {
    pub(crate) fn send(&self, payload: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Direct(socket) => socket.send(payload),
        }
    }

    pub(crate) fn recv(&self, output: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Direct(socket) => socket.recv(output),
        }
    }
}
