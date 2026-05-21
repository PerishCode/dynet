use std::{net::SocketAddr, sync::atomic::Ordering};

use smoltcp::{
    iface::{SocketHandle, SocketSet},
    socket::raw,
    wire::{IpProtocol, IpVersion, Ipv6Packet, UdpPacket},
};

use crate::{RuntimeCounters, RuntimeEvent, RuntimeEventKind};

const PACKET_QUEUE: usize = 8;
const PACKET_BYTES: usize = 2048;

pub(crate) struct Slot {
    pub(crate) handle: SocketHandle,
}

pub(crate) fn socket() -> raw::Socket<'static> {
    let rx = raw::PacketBuffer::new(
        vec![raw::PacketMetadata::EMPTY; PACKET_QUEUE],
        vec![0; PACKET_BYTES * PACKET_QUEUE],
    );
    let tx = raw::PacketBuffer::new(Vec::new(), Vec::new());
    raw::Socket::new(Some(IpVersion::Ipv6), Some(IpProtocol::Udp), rx, tx)
}

pub(crate) fn handle_slot(
    slot: &mut Slot,
    sockets: &mut SocketSet<'_>,
    counters: &RuntimeCounters,
) -> Result<(), String> {
    let socket = sockets.get_mut::<raw::Socket>(slot.handle);
    while socket.can_recv() {
        let mut packet = [0_u8; PACKET_BYTES];
        let size = match socket.recv_slice(&mut packet) {
            Ok(size) => size,
            Err(error) => {
                counters.udp_dropped_packets.fetch_add(1, Ordering::SeqCst);
                counters.emit(
                    RuntimeEvent::new(RuntimeEventKind::IpPacketDenied)
                        .field("ipVersion", 6)
                        .field("protocol", "udp")
                        .field("reason", format!("failed to inspect IPv6 packet: {error}")),
                )?;
                continue;
            }
        };
        emit_denied(counters, &packet[..size])?;
    }
    Ok(())
}

fn emit_denied(counters: &RuntimeCounters, packet: &[u8]) -> Result<(), String> {
    counters.tun_packets.fetch_add(1, Ordering::SeqCst);
    counters.ipv6_packets_denied.fetch_add(1, Ordering::SeqCst);
    match ipv6_udp_summary(packet) {
        Some(summary) => counters.emit(
            RuntimeEvent::new(RuntimeEventKind::IpPacketDenied)
                .field("ipVersion", 6)
                .field("protocol", "udp")
                .field("source", summary.source)
                .field("destination", summary.destination)
                .field("destinationPort", summary.destination.port())
                .field("reason", "ipv6 forwarding is not implemented; fail closed"),
        ),
        None => counters.emit(
            RuntimeEvent::new(RuntimeEventKind::IpPacketDenied)
                .field("ipVersion", 6)
                .field("protocol", "udp")
                .field("reason", "ipv6 forwarding is not implemented; fail closed"),
        ),
    }
}

struct Ipv6UdpSummary {
    source: SocketAddr,
    destination: SocketAddr,
}

fn ipv6_udp_summary(packet: &[u8]) -> Option<Ipv6UdpSummary> {
    let ipv6 = Ipv6Packet::new_checked(packet).ok()?;
    if ipv6.next_header() != IpProtocol::Udp {
        return None;
    }
    let udp = UdpPacket::new_checked(ipv6.payload()).ok()?;
    Some(Ipv6UdpSummary {
        source: SocketAddr::new(ipv6.src_addr().into(), udp.src_port()),
        destination: SocketAddr::new(ipv6.dst_addr().into(), udp.dst_port()),
    })
}
