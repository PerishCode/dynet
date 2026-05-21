use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

use dynet_core::{resolve_outbound_path, InboundContext, PlanAction, Transport, VerdictStatus};
use smoltcp::{iface::SocketSet, socket::udp};

use crate::{
    outbound::{self, ProxiedUdpSocket},
    resolver::trace::classify_runtime_error,
    RuntimeCounters, RuntimeEvent, RuntimeEventKind, RuntimeSettings,
};

use super::{event_context, outbound_events, udp_downstream, udp_packet, user_rule};

pub(crate) const LISTEN_PORTS: [u16; 3] = [443, 123, 53];

const BUFFER_BYTES: usize = 2048;
const PACKET_QUEUE: usize = 16;
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const HARD_TTL: Duration = Duration::from_secs(120);

pub(crate) type Sessions = HashMap<SessionKey, Session>;

pub(crate) struct ForwardSlot {
    pub(crate) port: u16,
    pub(crate) handle: smoltcp::iface::SocketHandle,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub(crate) struct SessionKey {
    client: SocketAddr,
    target: SocketAddr,
    outbound: String,
}

pub(crate) struct Session {
    pub(crate) id: usize,
    pub(crate) target: SocketAddr,
    pub(crate) client: SocketAddr,
    pub(crate) outbound: String,
    pub(crate) socket: ProxiedUdpSocket,
    created_at: Instant,
    pub(crate) last_activity: Instant,
    upstream_bytes: usize,
    pub(crate) downstream_bytes: usize,
}

struct UdpSelection {
    context: InboundContext,
    domain: Option<String>,
    outbound: String,
}

pub(crate) fn socket() -> udp::Socket<'static> {
    let rx_meta = vec![udp::PacketMetadata::EMPTY; PACKET_QUEUE];
    let tx_meta = vec![udp::PacketMetadata::EMPTY; PACKET_QUEUE];
    let rx = udp::PacketBuffer::new(rx_meta, vec![0; BUFFER_BYTES * PACKET_QUEUE]);
    let tx = udp::PacketBuffer::new(tx_meta, vec![0; BUFFER_BYTES * PACKET_QUEUE]);
    udp::Socket::new(rx, tx)
}

pub(crate) fn handle_slot(
    slot: &mut ForwardSlot,
    sockets: &mut SocketSet<'_>,
    settings: &RuntimeSettings,
    counters: &RuntimeCounters,
    sessions: &mut Sessions,
) -> Result<(), String> {
    let socket = sockets.get_mut::<udp::Socket>(slot.handle);
    if !socket.is_open() {
        socket
            .bind(slot.port)
            .map_err(|error| format!("failed to listen on TUN UDP port {}: {error}", slot.port))?;
        return Ok(());
    }
    while socket.can_recv() {
        let mut payload = [0_u8; BUFFER_BYTES];
        let (size, metadata) = match socket.recv_slice(&mut payload) {
            Ok(received) => received,
            Err(error) => {
                counters.udp_dropped_packets.fetch_add(1, Ordering::SeqCst);
                counters.emit(
                    RuntimeEvent::new(RuntimeEventKind::UdpSessionFailed)
                        .field("port", slot.port)
                        .field("flowId", "<unattributed>")
                        .field("errorType", "udp-recv")
                        .field("error", format!("failed to read TUN UDP payload: {error}")),
                )?;
                continue;
            }
        };
        if udp_packet::metadata_is_ipv6(metadata) {
            counters.udp_dropped_packets.fetch_add(1, Ordering::SeqCst);
            continue;
        }
        counters.tun_packets.fetch_add(1, Ordering::SeqCst);
        let (client, target) = match udp_packet::metadata_to_sockets(slot.port, metadata) {
            Ok(pair) => pair,
            Err(error) => {
                counters.udp_dropped_packets.fetch_add(1, Ordering::SeqCst);
                counters.emit(
                    RuntimeEvent::new(RuntimeEventKind::UdpSessionDenied)
                        .field("port", slot.port)
                        .field("flowId", "<unattributed>")
                        .field("transport", "udp")
                        .field("errorType", classify_runtime_error(&error))
                        .field("error", error),
                )?;
                continue;
            }
        };
        if target.is_ipv6() || client.is_ipv6() {
            counters.udp_dropped_packets.fetch_add(1, Ordering::SeqCst);
            continue;
        }
        forward_datagram(
            socket,
            sessions,
            settings,
            counters,
            client,
            target,
            &payload[..size],
        )?;
    }
    Ok(())
}

pub(crate) fn expire_sessions(
    sessions: &mut Sessions,
    counters: &RuntimeCounters,
) -> Result<(), String> {
    let now = Instant::now();
    let mut expired = Vec::new();
    for (key, session) in sessions.iter() {
        let reason = if now.duration_since(session.created_at) >= HARD_TTL {
            Some("hard-ttl")
        } else if now.duration_since(session.last_activity) >= IDLE_TIMEOUT {
            Some("idle-timeout")
        } else {
            None
        };
        if let Some(reason) = reason {
            expired.push((key.clone(), reason));
        }
    }
    for (key, reason) in expired {
        if let Some(session) = sessions.remove(&key) {
            counters.emit(
                RuntimeEvent::new(RuntimeEventKind::UdpSessionClosed)
                    .field("session", session.id)
                    .field("flowId", format!("udp-session-{}", session.id))
                    .field("target", session.target)
                    .field("client", session.client)
                    .field("outbound", session.outbound)
                    .field("reason", reason)
                    .field("upstreamBytes", session.upstream_bytes)
                    .field("downstreamBytes", session.downstream_bytes),
            )?;
        }
    }
    Ok(())
}

fn forward_datagram(
    tun_socket: &mut udp::Socket<'_>,
    sessions: &mut Sessions,
    settings: &RuntimeSettings,
    counters: &RuntimeCounters,
    client: SocketAddr,
    target: SocketAddr,
    payload: &[u8],
) -> Result<(), String> {
    let policy = settings
        .policy
        .as_ref()
        .ok_or_else(|| "experimental UDP forwarding requires a runtime policy".to_string())?;
    let domains = counters
        .dns_reverse
        .lock()
        .map_err(|_| "dns reverse index lock poisoned".to_string())?
        .domains_for_ip(target.ip());
    let selection = match select_udp_outbound(policy, target, &domains, counters) {
        Ok(selection) => selection,
        Err(error) => {
            counters.udp_session_failures.fetch_add(1, Ordering::SeqCst);
            counters.udp_dropped_packets.fetch_add(1, Ordering::SeqCst);
            let kind = if is_denial(&error) {
                RuntimeEventKind::UdpSessionDenied
            } else {
                RuntimeEventKind::UdpSessionFailed
            };
            counters.emit(
                RuntimeEvent::new(kind)
                    .field("client", client)
                    .field("target", target)
                    .field("transport", "udp")
                    .field("flowId", "<unattributed>")
                    .field("errorType", classify_runtime_error(&error))
                    .field("error", error),
            )?;
            return Ok(());
        }
    };

    let key = SessionKey {
        client,
        target,
        outbound: selection.outbound.clone(),
    };
    if !sessions.contains_key(&key) {
        match start_session(
            policy, &selection, &domains, settings, counters, client, target,
        ) {
            Ok(session) => {
                sessions.insert(key.clone(), session);
            }
            Err(error) => {
                counters.udp_session_failures.fetch_add(1, Ordering::SeqCst);
                counters.udp_dropped_packets.fetch_add(1, Ordering::SeqCst);
                let kind = if is_denial(&error) {
                    RuntimeEventKind::UdpSessionDenied
                } else {
                    RuntimeEventKind::UdpSessionFailed
                };
                counters.emit(
                    RuntimeEvent::new(kind)
                        .field("client", client)
                        .field("target", target)
                        .field("outbound", &selection.outbound)
                        .field("flowId", "<unattributed>")
                        .field("errorType", classify_runtime_error(&error))
                        .field("error", error),
                )?;
                return Ok(());
            }
        }
    }

    let Some(session) = sessions.get_mut(&key) else {
        return Ok(());
    };
    session
        .socket
        .send(payload)
        .map_err(|error| format!("failed to write proxied UDP payload: {error}"))?;
    session.upstream_bytes += payload.len();
    session.last_activity = Instant::now();
    counters
        .udp_upstream_bytes
        .fetch_add(payload.len(), Ordering::SeqCst);
    counters.emit(
        RuntimeEvent::new(RuntimeEventKind::UdpSessionPayloadSent)
            .field("session", session.id)
            .field("flowId", format!("udp-session-{}", session.id))
            .field("target", session.target)
            .field("client", session.client)
            .field("outbound", &session.outbound)
            .field("bytes", payload.len()),
    )?;

    udp_downstream::drain(tun_socket, session, counters)?;
    Ok(())
}

pub(crate) fn poll_sessions(
    slots: &mut [ForwardSlot],
    sockets: &mut SocketSet<'_>,
    counters: &RuntimeCounters,
    sessions: &mut Sessions,
) -> Result<(), String> {
    for slot in slots {
        let socket = sockets.get_mut::<udp::Socket>(slot.handle);
        for session in sessions
            .values_mut()
            .filter(|session| session.target.port() == slot.port)
        {
            udp_downstream::drain(socket, session, counters)?;
        }
    }
    Ok(())
}

fn select_udp_outbound(
    policy: &crate::RuntimePolicy,
    target: SocketAddr,
    domains: &[String],
    counters: &RuntimeCounters,
) -> Result<UdpSelection, String> {
    if let Some((context, domain, decision)) =
        user_rule::select(policy, Transport::Udp, target, domains)
    {
        counters.route_decisions.fetch_add(1, Ordering::SeqCst);
        emit_rule_events(counters, target, domain.as_deref(), &decision)?;
        return Ok(UdpSelection {
            context,
            domain,
            outbound: decision.outbound,
        });
    }

    let context = InboundContext::from_inbound("tun-in")
        .with_transport(Transport::Udp)
        .with_destination_ip(target.ip())
        .with_destination_port(target.port());
    let verdict = policy.plan.evaluate(&context, &policy.state);
    let outbound_tag = verdict
        .outbound
        .as_ref()
        .map(|outbound| outbound.tag.as_str())
        .unwrap_or("<none>");
    counters.route_decisions.fetch_add(1, Ordering::SeqCst);
    counters.emit(
        RuntimeEvent::new(RuntimeEventKind::RouteMatched)
            .field("transport", "udp")
            .field("target", target)
            .field("status", format!("{:?}", verdict.status))
            .field("outbound", outbound_tag)
            .field("reason", &verdict.reason),
    )?;
    match (&verdict.status, &verdict.action) {
        (VerdictStatus::Accept, PlanAction::UseOutbound { tag }) => {
            let Some(outbound) = verdict.outbound.as_ref() else {
                return Err(format!(
                    "TUN UDP route selected outbound `{tag}` but no outbound model was found"
                ));
            };
            if !outbound
                .capabilities
                .iter()
                .any(|capability| capability == "udp")
            {
                return Err(format!(
                    "TUN UDP route selected outbound `{}` without udp capability; fail closed",
                    outbound.tag
                ));
            }
            let path = resolve_outbound_path(&policy.state, &context, tag)?;
            outbound_events::emit_path_events(counters, "udp-route", "udp", &path)?;
            Ok(UdpSelection {
                context,
                domain: None,
                outbound: path.selected,
            })
        }
        (VerdictStatus::Deny, PlanAction::Reject) => Err(format!(
            "TUN UDP target {target} rejected by route {:?}: {}",
            verdict.matched_rule, verdict.reason
        )),
        (VerdictStatus::Deny, _) => Err(verdict.reason),
        _ => Err(format!(
            "TUN UDP target {target} has no matching user rule or route; fail closed"
        )),
    }
}

fn start_session(
    policy: &crate::RuntimePolicy,
    selection: &UdpSelection,
    domains: &[String],
    settings: &RuntimeSettings,
    counters: &RuntimeCounters,
    client: SocketAddr,
    target: SocketAddr,
) -> Result<Session, String> {
    let context = &selection.context;
    let outbound_tag = selection.outbound.as_str();
    let decision_domain = selection.domain.as_deref();
    let id = counters.udp_sessions.fetch_add(1, Ordering::SeqCst) + 1;
    counters.emit(
        RuntimeEvent::new(RuntimeEventKind::UdpSessionStarted)
            .field("session", id)
            .field("flowId", format!("udp-session-{id}"))
            .field("client", client)
            .field("target", target)
            .field("transport", "udp"),
    )?;
    counters.emit(
        RuntimeEvent::new(RuntimeEventKind::UdpSessionAttributed)
            .field("session", id)
            .field("flowId", format!("udp-session-{id}"))
            .field("target", target)
            .field("domain", decision_domain.unwrap_or("<none>"))
            .field("reverseDomains", domains.join(","))
            .field("outbound", outbound_tag),
    )?;
    let outbound = policy
        .outbound(outbound_tag)
        .ok_or_else(|| format!("user rule selected missing outbound `{outbound_tag}`"))?;
    counters.emit(
        RuntimeEvent::new(RuntimeEventKind::UdpSessionOutboundConnecting)
            .field("session", id)
            .field("flowId", format!("udp-session-{id}"))
            .field("target", target)
            .field("outbound", &outbound.tag)
            .field("kind", &outbound.kind)
            .field(
                "udpEgressSupport",
                udp_egress_support(outbound.kind.as_str()),
            ),
    )?;
    let mut events = Vec::new();
    let socket = outbound::connect_udp_policy(
        target,
        outbound,
        policy,
        context,
        settings.bypass_mark,
        &mut events,
    );
    event_context::emit_session_events(
        counters,
        &event_context::SessionEventContext::udp(id, target, client),
        events,
    )?;
    let socket = socket?;
    counters.emit(
        RuntimeEvent::new(RuntimeEventKind::UdpSessionEstablished)
            .field("session", id)
            .field("flowId", format!("udp-session-{id}"))
            .field("target", target)
            .field("outbound", outbound_tag),
    )?;
    let now = Instant::now();
    Ok(Session {
        id,
        target,
        client,
        outbound: outbound_tag.to_string(),
        socket,
        created_at: now,
        last_activity: now,
        upstream_bytes: 0,
        downstream_bytes: 0,
    })
}

fn emit_rule_events(
    counters: &RuntimeCounters,
    target: SocketAddr,
    decision_domain: Option<&str>,
    decision: &dynet_core::UserRuleDecision,
) -> Result<(), String> {
    counters.emit(
        RuntimeEvent::new(RuntimeEventKind::RuleMatched)
            .field("rule", &decision.tag)
            .field("order", decision.order)
            .field("transport", "udp")
            .field("target", target)
            .field("domain", decision_domain.unwrap_or("<none>"))
            .field("outbound", &decision.outbound)
            .field("bypassesPlan", decision.bypasses_plan)
            .field("reason", &decision.reason),
    )?;
    counters.emit(
        RuntimeEvent::new(RuntimeEventKind::PlanBypassed)
            .field("rule", &decision.tag)
            .field("outbound", &decision.outbound)
            .field("target", target)
            .field("reason", "user hard rule matched before route plan"),
    )
}

fn is_denial(error: &str) -> bool {
    error.contains("does not support outbound type")
        || error.contains("without udp capability")
        || error.contains("no matching top-level identity rule")
        || error.contains("no outbound model was found")
        || error.contains("selected missing outbound")
}

fn udp_egress_support(kind: &str) -> &'static str {
    match kind {
        "direct" => "direct",
        _ => "unsupported",
    }
}
