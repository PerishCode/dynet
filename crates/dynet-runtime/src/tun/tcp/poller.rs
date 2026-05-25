use std::sync::Arc;

use smoltcp::{
    iface::{Interface, PollResult, SocketSet},
    time::Instant as SmolInstant,
};

use crate::{RuntimeCounters, RuntimeSettings};

use super::super::{
    ipv6_guard,
    tcp_forward::{self, ForwardSlot},
    udp_forward,
};
use super::{observe, ObservedTunDevice, PacketTracker};

pub(in crate::tun) fn poll_egress(
    iface: &mut Interface,
    timestamp: SmolInstant,
    device: &mut ObservedTunDevice,
    sockets: &mut SocketSet<'_>,
) {
    while matches!(
        iface.poll_egress(timestamp, device, sockets),
        PollResult::SocketStateChanged
    ) {}
}

pub(in crate::tun) struct ServiceSlots<'a> {
    pub(in crate::tun) tcp: &'a mut [ForwardSlot],
    pub(in crate::tun) udp: &'a mut [udp_forward::ForwardSlot],
    pub(in crate::tun) ipv6_guard: &'a mut ipv6_guard::Slot,
    pub(in crate::tun) udp_sessions: &'a mut udp_forward::Sessions,
}

pub(in crate::tun) struct ServiceContext<'a> {
    pub(in crate::tun) settings: &'a RuntimeSettings,
    pub(in crate::tun) counters: &'a Arc<RuntimeCounters>,
    pub(in crate::tun) packet_tracker: &'a PacketTracker,
}

pub(in crate::tun) fn service_slots(
    slots: ServiceSlots<'_>,
    sockets: &mut SocketSet<'_>,
    context: ServiceContext<'_>,
) -> Result<(), String> {
    let ServiceSlots {
        tcp,
        udp,
        ipv6_guard,
        udp_sessions,
    } = slots;
    let ServiceContext {
        settings,
        counters,
        packet_tracker,
    } = context;

    let listen_allowed = tcp_listen_allowed(tcp, sockets);
    for (slot, listen_allowed) in tcp.iter_mut().zip(listen_allowed) {
        tcp_forward::handle_slot(
            slot,
            sockets,
            settings,
            counters,
            packet_tracker,
            listen_allowed,
        )?;
    }
    observe(
        tcp.iter().map(ForwardSlot::slot_state),
        settings,
        tcp.len(),
        counters.as_ref(),
    )?;
    for slot in udp.iter_mut() {
        udp_forward::handle_slot(slot, sockets, settings, counters.as_ref(), udp_sessions)?;
    }
    ipv6_guard::handle_slot(ipv6_guard, sockets, counters.as_ref())?;
    if settings.udp_forwarding.enabled {
        udp_forward::poll_sessions(udp, sockets, counters.as_ref(), udp_sessions)?;
    }
    udp_forward::expire_sessions(udp_sessions, counters.as_ref())
}

fn tcp_listen_allowed(tcp_slots: &[ForwardSlot], sockets: &SocketSet<'_>) -> Vec<bool> {
    let ports: Vec<u16> = tcp_slots.iter().map(ForwardSlot::port).collect();
    let occupied: Vec<bool> = tcp_slots
        .iter()
        .map(|slot| slot.occupies_accept_order(sockets))
        .collect();
    listen_allowed_by_order(&ports, &occupied)
}

fn listen_allowed_by_order(ports: &[u16], occupied: &[bool]) -> Vec<bool> {
    ports
        .iter()
        .enumerate()
        .map(|(index, port)| {
            !ports
                .iter()
                .enumerate()
                .skip(index + 1)
                .any(|(other, other_port)| other_port == port && occupied[other])
        })
        .collect()
}
