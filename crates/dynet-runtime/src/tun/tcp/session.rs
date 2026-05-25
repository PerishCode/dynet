use std::{
    io::{Read, Write},
    net::SocketAddr,
    sync::{
        atomic::Ordering,
        mpsc::{self, TryRecvError},
        Arc,
    },
    thread,
    time::Duration as StdDuration,
};

use smoltcp::{
    socket::tcp,
    wire::{IpAddress, IpEndpoint},
};
use tracing::debug;

use crate::{
    outbound::ProxiedTcpStream,
    resolver::trace::{classify_runtime_error, classify_runtime_error_disposition},
    RuntimeCounters, RuntimeEvent, RuntimeEventKind, RuntimeSettings,
};

use super::super::event_context;
use super::{
    endpoint_to_socket, route_fallback, route_select, target_select, transient_read_error,
    SessionStartFailure,
};

const FORWARD_BUFFER_BYTES: usize = 8192;
const FORWARD_READ_TIMEOUT: StdDuration = StdDuration::from_millis(20);

pub(in crate::tun) struct ForwardSession {
    id: usize,
    target: SocketAddr,
    client: SocketAddr,
    outbound: String,
    stream: ProxiedTcpStream,
    first_payload_written: bool,
    closed: bool,
    upstream_bytes: usize,
    downstream_bytes: usize,
}

pub(in crate::tun) struct PendingSession {
    receiver: mpsc::Receiver<Result<ForwardSession, SessionStartFailure>>,
    handle: Option<thread::JoinHandle<()>>,
}

impl PendingSession {
    pub(in crate::tun) fn poll(&mut self) -> Option<Result<ForwardSession, SessionStartFailure>> {
        match self.receiver.try_recv() {
            Ok(result) => {
                if let Some(handle) = self.handle.take() {
                    let _ = handle.join();
                }
                Some(result)
            }
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => Some(Err(SessionStartFailure::unattributed(
                "TCP pending session worker disconnected".to_string(),
            ))),
        }
    }
}

pub(in crate::tun) fn start_session_async(
    socket: &tcp::Socket<'_>,
    settings: &RuntimeSettings,
    counters: Arc<RuntimeCounters>,
) -> Result<PendingSession, String> {
    let local_endpoint = socket
        .local_endpoint()
        .ok_or_else(|| "TUN TCP socket has no local endpoint".to_string())?;
    let remote_endpoint = socket
        .remote_endpoint()
        .ok_or_else(|| "TUN TCP socket has no remote endpoint".to_string())?;
    let settings = settings.clone();
    let (sender, receiver) = mpsc::channel();
    let handle = thread::spawn(move || {
        let result =
            start_session_for_endpoints(local_endpoint, remote_endpoint, &settings, &counters);
        let _ = sender.send(result);
    });
    Ok(PendingSession {
        receiver,
        handle: Some(handle),
    })
}

fn start_session_for_endpoints(
    local_endpoint: IpEndpoint,
    remote_endpoint: IpEndpoint,
    settings: &RuntimeSettings,
    counters: &RuntimeCounters,
) -> Result<ForwardSession, SessionStartFailure> {
    deny_ipv6_endpoint("tcp", local_endpoint, remote_endpoint, counters)
        .map_err(SessionStartFailure::unattributed)?;
    let target = endpoint_to_socket(local_endpoint).map_err(SessionStartFailure::unattributed)?;
    let client = endpoint_to_socket(remote_endpoint).map_err(SessionStartFailure::unattributed)?;
    counters.tun_packets.fetch_add(1, Ordering::SeqCst);
    let id = counters.tcp_sessions.fetch_add(1, Ordering::SeqCst) + 1;
    counters
        .emit(
            RuntimeEvent::new(RuntimeEventKind::TcpSessionStarted)
                .field("session", id)
                .field("flowId", format!("tcp-session-{id}"))
                .field("clientPort", client.port())
                .field("target", target)
                .field("transport", "tcp"),
        )
        .map_err(|error| SessionStartFailure::session_scoped(error, id, target, client))?;

    let policy = settings.policy.as_ref().ok_or_else(|| {
        SessionStartFailure::session_scoped(
            "experimental TUN forwarding requires a runtime policy".to_string(),
            id,
            target,
            client,
        )
    })?;
    let domains = counters
        .dns_reverse
        .lock()
        .map_err(|_| {
            SessionStartFailure::session_scoped(
                "dns reverse index lock poisoned".to_string(),
                id,
                target,
                client,
            )
        })?
        .domains_for_ip(target.ip());
    let route_select::TcpSelection {
        context,
        domain: decision_domain,
        outbound: selected_outbound,
        fallback_outbounds,
        events: route_events,
    } = route_select::select(policy, target, &domains)
        .map_err(|error| SessionStartFailure::session_scoped(error, id, target, client))?;
    counters.route_decisions.fetch_add(1, Ordering::SeqCst);
    event_context::emit_session_events(
        counters,
        &event_context::SessionEventContext::tcp(id, target, client),
        route_events,
    )
    .map_err(|error| SessionStartFailure::session_scoped(error, id, target, client))?;
    counters
        .emit(
            RuntimeEvent::new(RuntimeEventKind::TcpSessionAttributed)
                .field("session", id)
                .field("flowId", format!("tcp-session-{id}"))
                .field("target", target)
                .field("domain", decision_domain.as_deref().unwrap_or("<none>"))
                .field("reverseDomains", domains.join(","))
                .field("outbound", &selected_outbound),
        )
        .map_err(|error| {
            SessionStartFailure::outbound_scoped(
                error,
                id,
                target,
                client,
                selected_outbound.clone(),
            )
        })?;

    let connected = route_fallback::connect(route_fallback::ConnectArgs {
        id,
        target,
        client,
        domains: &domains,
        decision_domain: decision_domain.as_deref(),
        route_selected: &selected_outbound,
        candidates: &fallback_outbounds,
        policy,
        context: &context,
        settings,
        counters,
    })?;
    let route_selected = selected_outbound;
    let selected_outbound = connected.outbound;
    let forward_target = connected.forward_target;
    let stream = connected.stream;
    stream
        .set_read_timeout(Some(FORWARD_READ_TIMEOUT))
        .map_err(|error| {
            SessionStartFailure::outbound_scoped(
                format!("failed to set TCP forwarder read timeout: {error}"),
                id,
                target,
                client,
                selected_outbound.clone(),
            )
        })?;
    counters
        .emit(target_select::annotate(
            RuntimeEvent::new(RuntimeEventKind::TcpSessionEstablished)
                .field("session", id)
                .field("flowId", format!("tcp-session-{id}"))
                .field("target", target)
                .field("outbound", &selected_outbound)
                .field("routeSelected", &route_selected)
                .field("candidateLocked", "true"),
            &forward_target,
        ))
        .map_err(|error| {
            SessionStartFailure::outbound_scoped(
                error,
                id,
                target,
                client,
                selected_outbound.clone(),
            )
        })?;
    Ok(ForwardSession {
        id,
        target,
        client,
        outbound: selected_outbound,
        stream,
        first_payload_written: false,
        closed: false,
        upstream_bytes: 0,
        downstream_bytes: 0,
    })
}

pub(in crate::tun) fn forward_session(
    socket: &mut tcp::Socket<'_>,
    session: &mut ForwardSession,
    counters: &RuntimeCounters,
) -> Result<(), String> {
    if session.closed {
        return Ok(());
    }
    forward_upstream(socket, session, counters)?;
    forward_downstream(socket, session, counters)
}

pub(in crate::tun) fn close_session(
    session: ForwardSession,
    reason: &str,
    counters: &RuntimeCounters,
) -> Result<(), String> {
    if session.closed {
        return Ok(());
    }
    counters.tcp_closed_sessions.fetch_add(1, Ordering::SeqCst);
    counters.emit(
        RuntimeEvent::new(RuntimeEventKind::TcpSessionClosed)
            .field("session", session.id)
            .field("flowId", format!("tcp-session-{}", session.id))
            .field("target", session.target)
            .field("clientPort", session.client.port())
            .field("outbound", session.outbound)
            .field("upstreamBytes", session.upstream_bytes)
            .field("downstreamBytes", session.downstream_bytes)
            .field("reason", reason),
    )
}

pub(in crate::tun) fn emit_session_failed(
    session: ForwardSession,
    error: String,
    counters: &RuntimeCounters,
) -> Result<(), String> {
    counters.tcp_session_failures.fetch_add(1, Ordering::SeqCst);
    counters.emit(
        RuntimeEvent::new(RuntimeEventKind::TcpSessionFailed)
            .field("session", session.id)
            .field("flowId", format!("tcp-session-{}", session.id))
            .field("target", session.target)
            .field("clientPort", session.client.port())
            .field("outbound", session.outbound)
            .field("failurePhase", "forwarding")
            .field("cleanupAction", "socket-abort")
            .field("replaySafe", "post-payload")
            .field("upstreamBytes", session.upstream_bytes)
            .field("downstreamBytes", session.downstream_bytes)
            .field("errorType", classify_runtime_error(&error))
            .field(
                "errorDisposition",
                classify_runtime_error_disposition(&error),
            )
            .field("error", error),
    )
}

pub(in crate::tun) fn first_payload_written(session: &ForwardSession) -> bool {
    session.first_payload_written
}

fn forward_upstream(
    socket: &mut tcp::Socket<'_>,
    session: &mut ForwardSession,
    counters: &RuntimeCounters,
) -> Result<(), String> {
    if !socket.can_recv() {
        return Ok(());
    }
    let payload = socket
        .recv(|buffer| {
            let count = buffer.len().min(FORWARD_BUFFER_BYTES);
            (count, buffer[..count].to_vec())
        })
        .map_err(|error| format!("failed to read TUN TCP payload: {error:?}"))?;
    if payload.is_empty() {
        return Ok(());
    }
    session
        .stream
        .write_all(&payload)
        .and_then(|_| session.stream.flush())
        .map_err(|error| format!("failed to write proxied TCP payload: {error}"))?;
    counters
        .tcp_upstream_bytes
        .fetch_add(payload.len(), Ordering::SeqCst);
    session.upstream_bytes += payload.len();
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
    Ok(())
}

fn forward_downstream(
    socket: &mut tcp::Socket<'_>,
    session: &mut ForwardSession,
    counters: &RuntimeCounters,
) -> Result<(), String> {
    if !session.first_payload_written || !socket.can_send() {
        return Ok(());
    }
    let mut buffer = [0_u8; FORWARD_BUFFER_BYTES];
    match session.stream.read(&mut buffer) {
        Ok(0) => {
            socket.close();
            session.closed = true;
            counters.tcp_closed_sessions.fetch_add(1, Ordering::SeqCst);
            counters.emit(
                RuntimeEvent::new(RuntimeEventKind::TcpSessionClosed)
                    .field("session", session.id)
                    .field("flowId", format!("tcp-session-{}", session.id))
                    .field("target", session.target)
                    .field("clientPort", session.client.port())
                    .field("outbound", &session.outbound)
                    .field("upstreamBytes", session.upstream_bytes)
                    .field("downstreamBytes", session.downstream_bytes)
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
            session.downstream_bytes += sent;
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
    Ok(())
}

fn deny_ipv6_endpoint(
    protocol: &str,
    local_endpoint: IpEndpoint,
    remote_endpoint: IpEndpoint,
    counters: &RuntimeCounters,
) -> Result<(), String> {
    if !matches!(local_endpoint.addr, IpAddress::Ipv6(_))
        && !matches!(remote_endpoint.addr, IpAddress::Ipv6(_))
    {
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
