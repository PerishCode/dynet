use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

use smoltcp::{
    socket::tcp,
    time::Duration as SmolDuration,
    wire::{IpAddress, IpEndpoint},
};

use crate::{RuntimeCounters, RuntimeEvent, RuntimeEventKind, RuntimeSettings};

const TCP_BUFFER_BYTES: usize = 65_535;

mod packet;
mod poller;
mod route_fallback;
mod route_select;
mod session;
mod start_failure;
pub(super) mod target_select;

pub(super) use packet::{observed_device, packet_tracker, ObservedTunDevice, PacketTracker};
pub(super) use poller::{poll_egress, service_slots, ServiceContext, ServiceSlots};
pub(super) use session::{
    close_session, emit_session_failed, first_payload_written, forward_session,
    start_session_async, ForwardSession, PendingSession,
};
pub(super) use start_failure::SessionStartFailure;

pub(super) struct SlotState {
    pub(super) port: u16,
    pub(super) active: bool,
}

pub(super) fn socket() -> tcp::Socket<'static> {
    let mut socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; TCP_BUFFER_BYTES]),
        tcp::SocketBuffer::new(vec![0; TCP_BUFFER_BYTES]),
    );
    socket.set_keep_alive(Some(SmolDuration::from_millis(10_000)));
    socket.set_timeout(Some(SmolDuration::from_millis(30_000)));
    socket
}

pub(super) fn listen_on_port(socket: &mut tcp::Socket<'_>, port: u16) -> Result<(), String> {
    socket
        .listen(port)
        .map_err(|error| format!("failed to listen on TUN TCP port {port}: {error:?}"))
}

pub(super) fn emit_preflow(
    port: u16,
    socket: &tcp::Socket<'_>,
    counters: &RuntimeCounters,
) -> Result<(), String> {
    let mut event = RuntimeEvent::new(RuntimeEventKind::TcpForwarderPreflow)
        .field("port", port)
        .field("state", format!("{:?}", socket.state()))
        .field("transport", "tcp");
    if let Some(local) = socket.local_endpoint() {
        event = event.field("target", local);
    }
    if let Some(remote) = socket.remote_endpoint() {
        event = event.field("clientPort", remote.port);
    }
    counters.emit(event)
}

pub(super) fn endpoint_to_socket(endpoint: IpEndpoint) -> Result<SocketAddr, String> {
    match endpoint.addr {
        IpAddress::Ipv4(address) => Ok(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::from(address.octets())),
            endpoint.port,
        )),
        #[allow(unreachable_patterns)]
        other => Err(format!(
            "experimental TUN forwarding currently supports IPv4 socket endpoints only, got {other:?}"
        )),
    }
}

pub(super) fn random_seed() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

pub(super) fn emit_capacity(
    settings: &RuntimeSettings,
    capacity: usize,
    counters: &RuntimeCounters,
) -> Result<(), String> {
    counters.emit(
        RuntimeEvent::new(RuntimeEventKind::TcpForwarderCapacity)
            .field("listenPorts", ports_csv(settings))
            .field(
                "slotsPerPort",
                settings.tcp_forwarding.listen_slots_per_port,
            )
            .field("capacity", capacity),
    )
}

pub(super) fn observe(
    slots: impl IntoIterator<Item = SlotState>,
    settings: &RuntimeSettings,
    capacity: usize,
    counters: &RuntimeCounters,
) -> Result<(), String> {
    if !settings.tcp_forwarding.enabled {
        return Ok(());
    }
    let states: Vec<SlotState> = slots.into_iter().collect();
    let active = states.iter().filter(|slot| slot.active).count();
    update_max(&counters.tcp_active_slots_max, active);
    let pressure_ports = pressure_ports(&states, settings.tcp_forwarding.listen_slots_per_port);
    if pressure_ports.is_empty() {
        return Ok(());
    }
    counters
        .tcp_slot_pressure_events
        .fetch_add(1, Ordering::SeqCst);
    counters.emit(
        RuntimeEvent::new(RuntimeEventKind::TcpForwarderPressure)
            .field("activeSlots", active)
            .field("capacity", capacity)
            .field("pressurePorts", pressure_ports.join(",")),
    )
}

fn ports_csv(settings: &RuntimeSettings) -> String {
    settings
        .tcp_forwarding
        .listen_ports()
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn pressure_ports(slots: &[SlotState], slots_per_port: usize) -> Vec<String> {
    let mut ports = Vec::new();
    for port in crate::TcpForwardingSettings::LISTEN_PORTS {
        let active = slots
            .iter()
            .filter(|slot| slot.port == port && slot.active)
            .count();
        if active >= slots_per_port {
            ports.push(port.to_string());
        }
    }
    ports
}

fn update_max(max: &std::sync::atomic::AtomicUsize, value: usize) {
    let mut current = max.load(Ordering::SeqCst);
    while value > current {
        match max.compare_exchange(current, value, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => break,
            Err(next) => current = next,
        }
    }
}

pub(super) fn transient_read_error(error: &std::io::Error) -> bool {
    let message = error.to_string();
    matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ) || message.contains("timed out")
        || message.contains("Resource temporarily unavailable")
        || message.contains("operation would block")
}
