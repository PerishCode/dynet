use std::{
    os::fd::AsRawFd,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use smoltcp::{
    iface::{Config, Interface, PollIngressSingleResult, SocketHandle, SocketSet},
    phy::{wait as phy_wait, Medium, TunTapInterface},
    socket::tcp,
    time::{Duration as SmolDuration, Instant as SmolInstant},
    wire::HardwareAddress,
};

use crate::{
    resolver::trace::{classify_runtime_error, classify_runtime_error_disposition},
    RuntimeCounters, RuntimeEvent, RuntimeEventKind, RuntimeSettings,
};

use super::{ipv6_guard, tcp as tcp_support, udp_forward, TunDevice};

const MTU: usize = 1500;

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
    let device = TunTapInterface::from_fd(raw_fd, Medium::Ip, MTU)
        .map_err(|error| format!("failed to attach smoltcp to TUN fd: {error}"))?;
    let packet_tracker = tcp_support::packet_tracker();
    let mut device = tcp_support::observed_device(
        device,
        counters.clone(),
        packet_tracker.clone(),
        settings.tcp_forwarding.listen_ports(),
    );
    let fd = device.as_raw_fd();
    let mut config = Config::new(HardwareAddress::Ip);
    config.random_seed = tcp_support::random_seed();
    let mut iface = Interface::new(config, &mut device, SmolInstant::now());
    iface.set_any_ip(true);

    let mut sockets = SocketSet::new(Vec::new());
    let mut tcp_slots = Vec::new();
    if settings.tcp_forwarding.enabled {
        for port in settings.tcp_forwarding.listen_ports() {
            for _ in 0..settings.tcp_forwarding.listen_slots_per_port {
                tcp_slots.push(ForwardSlot {
                    port,
                    handle: sockets.add(tcp_support::socket()),
                    session: None,
                    pending: None,
                    preflow_reported: false,
                });
            }
        }
        tcp_support::emit_capacity(&settings, tcp_slots.len(), &counters)?;
    }
    let mut udp_slots = Vec::new();
    if settings.udp_forwarding.enabled {
        for port in udp_forward::LISTEN_PORTS {
            udp_slots.push(udp_forward::ForwardSlot {
                port,
                handle: sockets.add(udp_forward::socket()),
            });
        }
    }
    let mut ipv6_guard_slot = ipv6_guard::Slot {
        handle: sockets.add(ipv6_guard::socket()),
    };
    let mut udp_sessions = udp_forward::Sessions::new();

    while !stop.load(Ordering::SeqCst) {
        let timestamp = SmolInstant::now();
        iface.poll_maintenance(timestamp);
        tcp_support::poll_egress(&mut iface, timestamp, &mut device, &mut sockets);
        loop {
            let result = iface.poll_ingress_single(timestamp, &mut device, &mut sockets);
            if matches!(result, PollIngressSingleResult::None) {
                break;
            }
            tcp_support::service_slots(
                &mut tcp_slots,
                &mut udp_slots,
                &mut ipv6_guard_slot,
                &mut udp_sessions,
                &mut sockets,
                &settings,
                &counters,
                &packet_tracker,
            )?;
            tcp_support::poll_egress(&mut iface, timestamp, &mut device, &mut sockets);
            tcp_support::service_slots(
                &mut tcp_slots,
                &mut udp_slots,
                &mut ipv6_guard_slot,
                &mut udp_sessions,
                &mut sockets,
                &settings,
                &counters,
                &packet_tracker,
            )?;
            tcp_support::poll_egress(&mut iface, timestamp, &mut device, &mut sockets);
        }
        tcp_support::service_slots(
            &mut tcp_slots,
            &mut udp_slots,
            &mut ipv6_guard_slot,
            &mut udp_sessions,
            &mut sockets,
            &settings,
            &counters,
            &packet_tracker,
        )?;
        tcp_support::poll_egress(&mut iface, timestamp, &mut device, &mut sockets);
        tcp_support::service_slots(
            &mut tcp_slots,
            &mut udp_slots,
            &mut ipv6_guard_slot,
            &mut udp_sessions,
            &mut sockets,
            &settings,
            &counters,
            &packet_tracker,
        )?;
        tcp_support::poll_egress(&mut iface, timestamp, &mut device, &mut sockets);
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

pub(super) struct ForwardSlot {
    port: u16,
    handle: SocketHandle,
    session: Option<tcp_support::ForwardSession>,
    pending: Option<tcp_support::PendingSession>,
    preflow_reported: bool,
}

impl ForwardSlot {
    pub(super) fn slot_state(&self) -> tcp_support::SlotState {
        tcp_support::SlotState {
            port: self.port,
            active: self.session.is_some() || self.pending.is_some(),
        }
    }

    pub(super) fn port(&self) -> u16 {
        self.port
    }

    pub(super) fn occupies_accept_order(&self, sockets: &SocketSet<'_>) -> bool {
        if self.session.is_some() || self.pending.is_some() {
            return true;
        }
        let socket = sockets.get::<tcp::Socket>(self.handle);
        socket.remote_endpoint().is_some()
    }
}

pub(super) fn handle_slot(
    slot: &mut ForwardSlot,
    sockets: &mut SocketSet<'_>,
    settings: &RuntimeSettings,
    counters: &Arc<RuntimeCounters>,
    packet_tracker: &tcp_support::PacketTracker,
    listen_allowed: bool,
) -> Result<(), String> {
    let socket = sockets.get_mut::<tcp::Socket>(slot.handle);

    if let Some(result) = poll_pending(slot) {
        match result {
            Ok(session) => {
                if socket.is_active() {
                    slot.session = Some(session);
                } else {
                    socket.abort();
                    tcp_support::close_session(
                        session,
                        "tun-closed-before-payload",
                        counters.as_ref(),
                    )?;
                    slot.preflow_reported = false;
                    return Ok(());
                }
            }
            Err(error) => {
                socket.abort();
                emit_session_start_failed(slot.port, error, counters.as_ref())?;
                slot.preflow_reported = false;
                return Ok(());
            }
        }
    }

    if socket.is_listening() && !listen_allowed {
        socket.close();
        slot.preflow_reported = false;
        return Ok(());
    }

    if !socket.is_open() {
        if slot.pending.is_some() {
            return Ok(());
        }
        if !slot.preflow_reported {
            emit_missed_preflow(slot.port, socket, counters, packet_tracker)?;
        }
        if listen_allowed {
            tcp_support::listen_on_port(socket, slot.port)?;
        }
        slot.preflow_reported = false;
        return Ok(());
    }

    if slot.session.is_none() && socket.remote_endpoint().is_some() && !slot.preflow_reported {
        tcp_support::emit_preflow(slot.port, socket, counters.as_ref())?;
        if let Some(remote) = socket.remote_endpoint() {
            packet_tracker.promote(slot.port, remote.port);
        }
        slot.preflow_reported = true;
    }

    if socket.is_active() && slot.session.is_none() && slot.pending.is_none() {
        match tcp_support::start_session_async(socket, settings, Arc::clone(counters)) {
            Ok(pending) => slot.pending = Some(pending),
            Err(error) => {
                socket.abort();
                emit_session_start_failed(
                    slot.port,
                    tcp_support::SessionStartFailure::unattributed(error),
                    counters.as_ref(),
                )?;
                slot.preflow_reported = false;
                return Ok(());
            }
        }
    }

    if slot.pending.is_some() {
        return Ok(());
    }

    let Some(session) = slot.session.as_mut() else {
        return Ok(());
    };
    if !socket.is_active() {
        tcp_support::close_session(
            slot.session.take().expect("session exists"),
            "tun-closed",
            counters.as_ref(),
        )?;
        if !socket.is_open() {
            if listen_allowed {
                tcp_support::listen_on_port(socket, slot.port)?;
            }
            slot.preflow_reported = false;
        }
        return Ok(());
    }
    if let Err(error) = tcp_support::forward_session(socket, session, counters.as_ref()) {
        let session = slot.session.take().expect("session exists");
        socket.abort();
        tcp_support::emit_session_failed(session, error, counters.as_ref())?;
        slot.preflow_reported = false;
        return Ok(());
    }
    if !tcp_support::first_payload_written(session)
        && matches!(socket.state(), tcp::State::CloseWait)
    {
        let session = slot.session.take().expect("session exists");
        socket.abort();
        tcp_support::close_session(session, "tun-closed-before-payload", counters.as_ref())?;
        slot.preflow_reported = false;
    }
    Ok(())
}

fn poll_pending(
    slot: &mut ForwardSlot,
) -> Option<Result<tcp_support::ForwardSession, tcp_support::SessionStartFailure>> {
    let result = slot.pending.as_mut()?.poll()?;
    slot.pending = None;
    Some(result)
}

fn emit_session_start_failed(
    port: u16,
    failure: tcp_support::SessionStartFailure,
    counters: &RuntimeCounters,
) -> Result<(), String> {
    counters.tcp_session_failures.fetch_add(1, Ordering::SeqCst);
    let mut event = RuntimeEvent::new(RuntimeEventKind::TcpSessionFailed)
        .field("port", port)
        .field(
            "flowId",
            failure
                .session
                .map(|session| format!("tcp-session-{session}"))
                .unwrap_or_else(|| "<unattributed>".to_string()),
        )
        .field("failurePhase", "session-start")
        .field("cleanupAction", "socket-abort")
        .field("replaySafe", "pre-payload")
        .field("errorType", classify_runtime_error(&failure.error))
        .field(
            "errorDisposition",
            classify_runtime_error_disposition(&failure.error),
        )
        .field("error", &failure.error);
    if let Some(session) = failure.session {
        event = event.field("session", session);
    }
    if let Some(target) = failure.target {
        event = event.field("target", target);
    }
    if let Some(client) = failure.client {
        event = event.field("clientPort", client.port());
    }
    if let Some(outbound) = failure.outbound {
        event = event.field("outbound", outbound);
    }
    if let Some(stage) = failure.stage {
        event = event
            .field("failureStage", stage.stage)
            .field("failureStageOutbound", stage.outbound)
            .field("failureStageKind", stage.kind)
            .field("failureStageErrorType", stage.error_type)
            .field("failureStageDisposition", stage.error_disposition);
    }
    counters.emit(event)
}

fn emit_missed_preflow(
    port: u16,
    socket: &tcp::Socket<'_>,
    counters: &RuntimeCounters,
    packet_tracker: &tcp_support::PacketTracker,
) -> Result<(), String> {
    let Some(terminal) = packet_tracker.take_unpromoted_terminal(port) else {
        return Ok(());
    };
    counters.emit(
        RuntimeEvent::new(RuntimeEventKind::TcpForwarderPreflowMissed)
            .field("port", port)
            .field("clientPort", terminal.client_port)
            .field("transport", "tcp")
            .field("reason", "socket-closed-before-preflow-service")
            .field("socketState", format!("{:?}", socket.state()))
            .field("terminalReason", "closed-before-preflow")
            .field("packetHandshakeComplete", terminal.handshake_complete)
            .field("promotedToRuntimeSession", terminal.promoted)
            .field("ingressControlPackets", terminal.ingress_control)
            .field("ingressSynPackets", terminal.ingress_syn)
            .field("egressControlPackets", terminal.egress_control)
            .field("egressSynAckPackets", terminal.egress_syn_ack)
            .field("ingressPayloadPackets", terminal.ingress_payload_packets)
            .field("ingressPayloadBytes", terminal.ingress_payload_bytes)
            .field("egressPayloadPackets", terminal.egress_payload_packets)
            .field("egressPayloadBytes", terminal.egress_payload_bytes)
            .field("finPackets", terminal.fin)
            .field("rstPackets", terminal.rst),
    )
}
