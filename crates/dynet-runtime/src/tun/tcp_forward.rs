use std::{
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    os::fd::AsRawFd,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration as StdDuration, SystemTime, UNIX_EPOCH},
};

use dynet_core::Transport;
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::{wait as phy_wait, Medium, TunTapInterface},
    socket::tcp,
    time::{Duration as SmolDuration, Instant as SmolInstant},
    wire::{HardwareAddress, IpAddress, IpEndpoint},
};
use tracing::debug;

use crate::{
    outbound::{self, ProxiedTcpStream, TcpTarget},
    resolver::trace::classify_runtime_error,
    RuntimeCounters, RuntimeEvent, RuntimeEventKind, RuntimeSettings,
};

use super::{event_context, ipv6_guard, udp_forward, user_rule, TunDevice};

const MTU: usize = 1500;
const TCP_BUFFER_BYTES: usize = 65_535;
const FORWARD_BUFFER_BYTES: usize = 8192;
const FORWARD_READ_TIMEOUT: StdDuration = StdDuration::from_millis(20);
const LISTEN_PORTS: [u16; 2] = [443, 80];

pub(crate) fn run(
    tun: TunDevice,
    settings: RuntimeSettings,
    counters: Arc<RuntimeCounters>,
    stop: Arc<AtomicBool>,
) -> Result<(), String> {
    if settings.policy.is_none() {
        return Err("experimental TUN forwarding requires a runtime policy".to_string());
    }
    let raw_fd = tun.into_raw_fd();
    let mut device = TunTapInterface::from_fd(raw_fd, Medium::Ip, MTU)
        .map_err(|error| format!("failed to attach smoltcp to TUN fd: {error}"))?;
    let fd = device.as_raw_fd();
    let mut config = Config::new(HardwareAddress::Ip);
    config.random_seed = random_seed();
    let mut iface = Interface::new(config, &mut device, SmolInstant::now());
    iface.set_any_ip(true);

    let mut sockets = SocketSet::new(Vec::new());
    let mut tcp_slots = if settings.tcp_forwarding.enabled {
        LISTEN_PORTS
            .into_iter()
            .map(|port| ForwardSlot {
                port,
                handle: sockets.add(tcp_socket()),
                session: None,
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let mut udp_slots = if settings.udp_forwarding.enabled {
        udp_forward::LISTEN_PORTS
            .into_iter()
            .map(|port| udp_forward::ForwardSlot {
                port,
                handle: sockets.add(udp_forward::socket()),
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let mut ipv6_guard_slot = ipv6_guard::Slot {
        handle: sockets.add(ipv6_guard::socket()),
    };
    let mut udp_sessions = udp_forward::Sessions::new();

    while !stop.load(Ordering::SeqCst) {
        let timestamp = SmolInstant::now();
        iface.poll(timestamp, &mut device, &mut sockets);
        for slot in &mut tcp_slots {
            handle_slot(slot, &mut sockets, &settings, &counters)?;
        }
        for slot in &mut udp_slots {
            udp_forward::handle_slot(slot, &mut sockets, &settings, &counters, &mut udp_sessions)?;
        }
        ipv6_guard::handle_slot(&mut ipv6_guard_slot, &mut sockets, &counters)?;
        if settings.udp_forwarding.enabled {
            udp_forward::poll_sessions(&mut udp_slots, &mut sockets, &counters, &mut udp_sessions)?;
        }
        udp_forward::expire_sessions(&mut udp_sessions, &counters)?;
        let delay = iface
            .poll_delay(timestamp, &sockets)
            .map(|delay| {
                if delay.total_millis() < 50 {
                    delay
                } else {
                    SmolDuration::from_millis(50)
                }
            })
            .or_else(|| Some(SmolDuration::from_millis(50)));
        phy_wait(fd, delay).map_err(|error| format!("failed waiting for TUN events: {error}"))?;
    }
    Ok(())
}

struct ForwardSlot {
    port: u16,
    handle: SocketHandle,
    session: Option<ForwardSession>,
}

struct ForwardSession {
    id: usize,
    target: SocketAddr,
    client: SocketAddr,
    outbound: String,
    stream: ProxiedTcpStream,
    first_payload_written: bool,
    closed: bool,
}

fn tcp_socket() -> tcp::Socket<'static> {
    let rx = tcp::SocketBuffer::new(vec![0; TCP_BUFFER_BYTES]);
    let tx = tcp::SocketBuffer::new(vec![0; TCP_BUFFER_BYTES]);
    let mut socket = tcp::Socket::new(rx, tx);
    socket.set_keep_alive(Some(SmolDuration::from_millis(10_000)));
    socket.set_timeout(Some(SmolDuration::from_millis(30_000)));
    socket
}

fn handle_slot(
    slot: &mut ForwardSlot,
    sockets: &mut SocketSet<'_>,
    settings: &RuntimeSettings,
    counters: &RuntimeCounters,
) -> Result<(), String> {
    let socket = sockets.get_mut::<tcp::Socket>(slot.handle);
    if !socket.is_open() {
        socket.listen(slot.port).map_err(|error| {
            format!("failed to listen on TUN TCP port {}: {error:?}", slot.port)
        })?;
        return Ok(());
    }

    if socket.is_active() && slot.session.is_none() {
        match start_session(socket, settings, counters) {
            Ok(session) => slot.session = Some(session),
            Err(error) => {
                socket.abort();
                counters.tcp_session_failures.fetch_add(1, Ordering::SeqCst);
                counters.emit(
                    RuntimeEvent::new(RuntimeEventKind::TcpSessionFailed)
                        .field("port", slot.port)
                        .field("flowId", "<unattributed>")
                        .field("errorType", classify_runtime_error(&error))
                        .field("error", error),
                )?;
            }
        }
    }

    let Some(session) = slot.session.as_mut() else {
        return Ok(());
    };
    if !socket.is_active() {
        close_session(
            slot.session.take().expect("session exists"),
            "tun-closed",
            counters,
        )?;
        return Ok(());
    }
    if let Err(error) = forward_session(socket, session, counters) {
        let session = slot.session.take().expect("session exists");
        socket.abort();
        counters.tcp_session_failures.fetch_add(1, Ordering::SeqCst);
        counters.emit(
            RuntimeEvent::new(RuntimeEventKind::TcpSessionFailed)
                .field("session", session.id)
                .field("flowId", format!("tcp-session-{}", session.id))
                .field("target", session.target)
                .field("client", session.client)
                .field("outbound", session.outbound)
                .field("errorType", classify_runtime_error(&error))
                .field("error", error),
        )?;
    }
    Ok(())
}

fn start_session(
    socket: &mut tcp::Socket<'_>,
    settings: &RuntimeSettings,
    counters: &RuntimeCounters,
) -> Result<ForwardSession, String> {
    let local_endpoint = socket
        .local_endpoint()
        .ok_or_else(|| "TUN TCP socket has no local endpoint".to_string())?;
    let remote_endpoint = socket
        .remote_endpoint()
        .ok_or_else(|| "TUN TCP socket has no remote endpoint".to_string())?;
    deny_ipv6_endpoint("tcp", local_endpoint, remote_endpoint, counters)?;
    let target = endpoint_to_socket(local_endpoint)?;
    let client = endpoint_to_socket(remote_endpoint)?;
    counters.tun_packets.fetch_add(1, Ordering::SeqCst);
    let id = counters.tcp_sessions.fetch_add(1, Ordering::SeqCst) + 1;
    counters.emit(
        RuntimeEvent::new(RuntimeEventKind::TcpSessionStarted)
            .field("session", id)
            .field("flowId", format!("tcp-session-{id}"))
            .field("client", client)
            .field("target", target)
            .field("transport", "tcp"),
    )?;

    let policy = settings
        .policy
        .as_ref()
        .ok_or_else(|| "experimental TUN forwarding requires a runtime policy".to_string())?;
    let domains = counters
        .dns_reverse
        .lock()
        .map_err(|_| "dns reverse index lock poisoned".to_string())?
        .domains_for_ip(target.ip());
    let (context, decision_domain, decision) =
        user_rule::select(policy, Transport::Tcp, target, &domains).ok_or_else(|| {
            format!("TUN TCP target {target} has no matching top-level identity rule; fail closed")
        })?;
    counters.route_decisions.fetch_add(1, Ordering::SeqCst);
    counters.emit(
        RuntimeEvent::new(RuntimeEventKind::RuleMatched)
            .field("rule", &decision.tag)
            .field("order", decision.order)
            .field("transport", "tcp")
            .field("session", id)
            .field("flowId", format!("tcp-session-{id}"))
            .field("target", target)
            .field("domain", decision_domain.as_deref().unwrap_or("<none>"))
            .field("outbound", &decision.outbound)
            .field("bypassesPlan", decision.bypasses_plan)
            .field("reason", &decision.reason),
    )?;
    counters.emit(
        RuntimeEvent::new(RuntimeEventKind::PlanBypassed)
            .field("rule", &decision.tag)
            .field("session", id)
            .field("flowId", format!("tcp-session-{id}"))
            .field("outbound", &decision.outbound)
            .field("target", target)
            .field("reason", "user hard rule matched before route plan"),
    )?;
    counters.emit(
        RuntimeEvent::new(RuntimeEventKind::TcpSessionAttributed)
            .field("session", id)
            .field("flowId", format!("tcp-session-{id}"))
            .field("target", target)
            .field("domain", decision_domain.as_deref().unwrap_or("<none>"))
            .field("reverseDomains", domains.join(","))
            .field("rule", &decision.tag)
            .field("outbound", &decision.outbound),
    )?;

    let outbound = policy.outbound(&decision.outbound).ok_or_else(|| {
        format!(
            "user rule selected missing outbound `{}`",
            decision.outbound
        )
    })?;
    counters.emit(
        RuntimeEvent::new(RuntimeEventKind::TcpSessionOutboundConnecting)
            .field("session", id)
            .field("flowId", format!("tcp-session-{id}"))
            .field("target", target)
            .field("outbound", &outbound.tag)
            .field("kind", &outbound.kind)
            .field("replaySafe", "pre-payload"),
    )?;
    let mut events = Vec::new();
    let stream = outbound::connect_tcp_policy(
        &TcpTarget::Socket(target),
        outbound,
        policy,
        &context,
        settings.bypass_mark,
        &mut events,
    );
    event_context::emit_session_events(
        counters,
        &event_context::SessionEventContext::tcp(id, target, client),
        events,
    )?;
    let stream = stream?;
    stream
        .set_read_timeout(Some(FORWARD_READ_TIMEOUT))
        .map_err(|error| format!("failed to set TCP forwarder read timeout: {error}"))?;
    counters.emit(
        RuntimeEvent::new(RuntimeEventKind::TcpSessionEstablished)
            .field("session", id)
            .field("flowId", format!("tcp-session-{id}"))
            .field("target", target)
            .field("outbound", &decision.outbound)
            .field("candidateLocked", "true"),
    )?;
    Ok(ForwardSession {
        id,
        target,
        client,
        outbound: decision.outbound,
        stream,
        first_payload_written: false,
        closed: false,
    })
}

fn forward_session(
    socket: &mut tcp::Socket<'_>,
    session: &mut ForwardSession,
    counters: &RuntimeCounters,
) -> Result<(), String> {
    if socket.can_recv() {
        let payload = socket
            .recv(|buffer| {
                let count = buffer.len().min(FORWARD_BUFFER_BYTES);
                (count, buffer[..count].to_vec())
            })
            .map_err(|error| format!("failed to read TUN TCP payload: {error:?}"))?;
        if !payload.is_empty() {
            session
                .stream
                .write_all(&payload)
                .and_then(|_| session.stream.flush())
                .map_err(|error| format!("failed to write proxied TCP payload: {error}"))?;
            counters
                .tcp_upstream_bytes
                .fetch_add(payload.len(), Ordering::SeqCst);
            if !session.first_payload_written {
                session.first_payload_written = true;
                counters.emit(
                    RuntimeEvent::new(RuntimeEventKind::TcpSessionPayloadFirstWrite)
                        .field("session", session.id)
                        .field("flowId", format!("tcp-session-{}", session.id))
                        .field("target", session.target)
                        .field("outbound", &session.outbound)
                        .field("bytes", payload.len())
                        .field("candidateRetryAllowed", "false"),
                )?;
            }
            debug!(
                session = session.id,
                target = %session.target,
                bytes = payload.len(),
                "tcp.forward.upstream"
            );
        }
    }

    if session.first_payload_written && socket.can_send() {
        let mut buffer = [0_u8; FORWARD_BUFFER_BYTES];
        match session.stream.read(&mut buffer) {
            Ok(0) => {
                socket.close();
                session.closed = true;
                counters.emit(
                    RuntimeEvent::new(RuntimeEventKind::TcpSessionClosed)
                        .field("session", session.id)
                        .field("flowId", format!("tcp-session-{}", session.id))
                        .field("target", session.target)
                        .field("client", session.client)
                        .field("outbound", &session.outbound)
                        .field("reason", "outbound-eof"),
                )?;
            }
            Ok(size) => {
                let sent = socket
                    .send_slice(&buffer[..size])
                    .map_err(|error| format!("failed to write TUN TCP payload: {error:?}"))?;
                counters
                    .tcp_downstream_bytes
                    .fetch_add(sent, Ordering::SeqCst);
                counters.emit(
                    RuntimeEvent::new(RuntimeEventKind::TcpSessionPayloadReceived)
                        .field("session", session.id)
                        .field("flowId", format!("tcp-session-{}", session.id))
                        .field("target", session.target)
                        .field("outbound", &session.outbound)
                        .field("bytes", sent),
                )?;
                debug!(
                    session = session.id,
                    target = %session.target,
                    bytes = sent,
                    "tcp.forward.downstream"
                );
            }
            Err(error) if transient_read_error(&error) => {}
            Err(error) => return Err(format!("failed to read proxied TCP payload: {error}")),
        }
    }
    Ok(())
}

fn close_session(
    session: ForwardSession,
    reason: &str,
    counters: &RuntimeCounters,
) -> Result<(), String> {
    if session.closed {
        return Ok(());
    }
    counters.emit(
        RuntimeEvent::new(RuntimeEventKind::TcpSessionClosed)
            .field("session", session.id)
            .field("flowId", format!("tcp-session-{}", session.id))
            .field("target", session.target)
            .field("client", session.client)
            .field("outbound", session.outbound)
            .field("reason", reason),
    )
}

fn deny_ipv6_endpoint(
    protocol: &str,
    local_endpoint: IpEndpoint,
    remote_endpoint: IpEndpoint,
    counters: &RuntimeCounters,
) -> Result<(), String> {
    if !endpoint_is_ipv6(local_endpoint) && !endpoint_is_ipv6(remote_endpoint) {
        return Ok(());
    }
    counters.ipv6_packets_denied.fetch_add(1, Ordering::SeqCst);
    counters.emit(
        RuntimeEvent::new(RuntimeEventKind::IpPacketDenied)
            .field("ipVersion", 6)
            .field("protocol", protocol)
            .field("source", remote_endpoint)
            .field("destination", local_endpoint)
            .field("destinationPort", local_endpoint.port)
            .field("reason", "ipv6 forwarding is not implemented; fail closed"),
    )?;
    Err(format!(
        "experimental {protocol} forwarding currently supports IPv4 only, got {remote_endpoint}->{local_endpoint}"
    ))
}

fn endpoint_to_socket(endpoint: IpEndpoint) -> Result<SocketAddr, String> {
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

fn endpoint_is_ipv6(endpoint: IpEndpoint) -> bool {
    matches!(endpoint.addr, IpAddress::Ipv6(_))
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

fn random_seed() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}
