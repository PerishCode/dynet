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

pub(in crate::tun) fn service_slots(
    tcp_slots: &mut [ForwardSlot],
    udp_slots: &mut [udp_forward::ForwardSlot],
    ipv6_guard_slot: &mut ipv6_guard::Slot,
    udp_sessions: &mut udp_forward::Sessions,
    sockets: &mut SocketSet<'_>,
    settings: &RuntimeSettings,
    counters: &Arc<RuntimeCounters>,
    packet_tracker: &PacketTracker,
) -> Result<(), String> {
    let listen_allowed = tcp_listen_allowed(tcp_slots, sockets);
    for (slot, listen_allowed) in tcp_slots.iter_mut().zip(listen_allowed) {
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
        tcp_slots.iter().map(ForwardSlot::slot_state),
        settings,
        tcp_slots.len(),
        counters.as_ref(),
    )?;
    for slot in udp_slots.iter_mut() {
        udp_forward::handle_slot(slot, sockets, settings, counters.as_ref(), udp_sessions)?;
    }
    ipv6_guard::handle_slot(ipv6_guard_slot, sockets, counters.as_ref())?;
    if settings.udp_forwarding.enabled {
        udp_forward::poll_sessions(udp_slots, sockets, counters.as_ref(), udp_sessions)?;
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
