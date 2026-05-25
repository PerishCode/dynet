use std::{
    collections::HashMap,
    os::fd::{AsRawFd, RawFd},
    sync::{Arc, Mutex},
};

use smoltcp::{
    phy::{
        Device, DeviceCapabilities, PacketMeta, RxToken as SmolRxToken, TunTapInterface,
        TxToken as SmolTxToken,
    },
    time::Instant as SmolInstant,
};

use crate::{RuntimeCounters, RuntimeEvent, RuntimeEventKind};

const TCP_PROTOCOL: u8 = 6;
const TCP_FLAG_FIN: u8 = 0x01;
const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_RST: u8 = 0x04;
const TCP_FLAG_ACK: u8 = 0x10;

pub(in crate::tun) fn observed_device(
    inner: TunTapInterface,
    counters: Arc<RuntimeCounters>,
    packet_tracker: Arc<PacketTracker>,
    listen_ports: Vec<u16>,
) -> ObservedTunDevice {
    ObservedTunDevice {
        inner,
        counters,
        packet_tracker,
        listen_ports: Arc::new(listen_ports),
    }
}

pub(in crate::tun) fn packet_tracker() -> Arc<PacketTracker> {
    Arc::new(PacketTracker::default())
}

pub(in crate::tun) struct ObservedTunDevice {
    inner: TunTapInterface,
    counters: Arc<RuntimeCounters>,
    packet_tracker: Arc<PacketTracker>,
    listen_ports: Arc<Vec<u16>>,
}

impl AsRawFd for ObservedTunDevice {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

impl Device for ObservedTunDevice {
    type RxToken<'a>
        = ObservedRxToken<<TunTapInterface as Device>::RxToken<'a>>
    where
        Self: 'a;
    type TxToken<'a>
        = ObservedTxToken<<TunTapInterface as Device>::TxToken<'a>>
    where
        Self: 'a;

    fn receive(
        &mut self,
        timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.inner.receive(timestamp).map(|(rx, tx)| {
            (
                ObservedRxToken {
                    inner: rx,
                    counters: Arc::clone(&self.counters),
                    packet_tracker: Arc::clone(&self.packet_tracker),
                    listen_ports: Arc::clone(&self.listen_ports),
                },
                ObservedTxToken {
                    inner: tx,
                    counters: Arc::clone(&self.counters),
                    packet_tracker: Arc::clone(&self.packet_tracker),
                    listen_ports: Arc::clone(&self.listen_ports),
                },
            )
        })
    }

    fn transmit(&mut self, timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        self.inner.transmit(timestamp).map(|tx| ObservedTxToken {
            inner: tx,
            counters: Arc::clone(&self.counters),
            packet_tracker: Arc::clone(&self.packet_tracker),
            listen_ports: Arc::clone(&self.listen_ports),
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        self.inner.capabilities()
    }
}

pub(in crate::tun) struct ObservedRxToken<T> {
    inner: T,
    counters: Arc<RuntimeCounters>,
    packet_tracker: Arc<PacketTracker>,
    listen_ports: Arc<Vec<u16>>,
}

impl<T: SmolRxToken> SmolRxToken for ObservedRxToken<T> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        let Self {
            inner,
            counters,
            packet_tracker,
            listen_ports,
        } = self;
        inner.consume(|packet| {
            emit_packet_event(
                packet,
                PacketDirection::Ingress,
                &listen_ports,
                &counters,
                &packet_tracker,
            );
            f(packet)
        })
    }

    fn meta(&self) -> PacketMeta {
        self.inner.meta()
    }
}

pub(in crate::tun) struct ObservedTxToken<T> {
    inner: T,
    counters: Arc<RuntimeCounters>,
    packet_tracker: Arc<PacketTracker>,
    listen_ports: Arc<Vec<u16>>,
}

impl<T: SmolTxToken> SmolTxToken for ObservedTxToken<T> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let Self {
            inner,
            counters,
            packet_tracker,
            listen_ports,
        } = self;
        inner.consume(len, |packet| {
            let result = f(packet);
            emit_packet_event(
                packet,
                PacketDirection::Egress,
                &listen_ports,
                &counters,
                &packet_tracker,
            );
            result
        })
    }

    fn set_meta(&mut self, meta: PacketMeta) {
        self.inner.set_meta(meta);
    }
}

fn emit_packet_event(
    packet: &[u8],
    direction: PacketDirection,
    listen_ports: &[u16],
    counters: &RuntimeCounters,
    packet_tracker: &PacketTracker,
) {
    let Some(summary) = TcpPacket::parse(packet, direction, listen_ports) else {
        return;
    };
    for event in packet_tracker.observe(direction, &summary) {
        let _ = counters.emit(event);
    }
    if !summary.is_control() {
        return;
    }
    let _ = counters.emit(
        RuntimeEvent::new(RuntimeEventKind::TcpForwarderPacket)
            .field("direction", direction.label())
            .field("port", summary.port)
            .field("clientPort", summary.client_port)
            .field("transport", "tcp")
            .field("syn", summary.syn)
            .field("ack", summary.ack)
            .field("fin", summary.fin)
            .field("rst", summary.rst)
            .field("payloadBytes", summary.payload_bytes),
    );
}

#[derive(Clone, Copy)]
enum PacketDirection {
    Ingress,
    Egress,
}

impl PacketDirection {
    fn label(self) -> &'static str {
        match self {
            Self::Ingress => "ingress",
            Self::Egress => "egress",
        }
    }
}

struct TcpPacket {
    port: u16,
    client_port: u16,
    syn: bool,
    ack: bool,
    fin: bool,
    rst: bool,
    payload_bytes: usize,
}

#[derive(Default)]
pub(in crate::tun) struct PacketTracker {
    tracks: Mutex<HashMap<PacketKey, PacketTrack>>,
}

impl PacketTracker {
    pub(in crate::tun) fn promote(&self, port: u16, client_port: u16) {
        let Ok(mut tracks) = self.tracks.lock() else {
            return;
        };
        tracks
            .entry(PacketKey { port, client_port })
            .or_default()
            .promoted = true;
    }

    pub(in crate::tun) fn take_unpromoted_terminal(
        &self,
        port: u16,
    ) -> Option<PacketTerminalSnapshot> {
        let Ok(mut tracks) = self.tracks.lock() else {
            return None;
        };
        let key = tracks
            .iter()
            .find(|(key, track)| key.port == port && track.terminal_reported && !track.promoted)
            .map(|(key, _)| *key)?;
        let track = tracks.remove(&key)?;
        Some(PacketTerminalSnapshot {
            client_port: key.client_port,
            handshake_complete: track.handshake_complete(),
            promoted: track.promoted,
            ingress_control: track.ingress_control,
            ingress_syn: track.ingress_syn,
            egress_control: track.egress_control,
            egress_syn_ack: track.egress_syn_ack,
            ingress_payload_packets: track.ingress_payload_packets,
            ingress_payload_bytes: track.ingress_payload_bytes,
            egress_payload_packets: track.egress_payload_packets,
            egress_payload_bytes: track.egress_payload_bytes,
            fin: track.fin,
            rst: track.rst,
        })
    }

    fn observe(&self, direction: PacketDirection, summary: &TcpPacket) -> Vec<RuntimeEvent> {
        let Ok(mut tracks) = self.tracks.lock() else {
            return Vec::new();
        };
        let key = PacketKey {
            port: summary.port,
            client_port: summary.client_port,
        };
        let track = tracks.entry(key).or_default();
        track.observe(direction, summary);
        let mut events = Vec::new();
        if track.should_emit_preflow_candidate() {
            track.preflow_candidate_reported = true;
            events.push(track.preflow_candidate_event(&key));
        }
        if track.should_emit_terminal() {
            track.terminal_reported = true;
            events.push(track.terminal_event(&key));
        }
        events
    }
}

pub(in crate::tun) struct PacketTerminalSnapshot {
    pub(in crate::tun) client_port: u16,
    pub(in crate::tun) handshake_complete: bool,
    pub(in crate::tun) promoted: bool,
    pub(in crate::tun) ingress_control: usize,
    pub(in crate::tun) ingress_syn: usize,
    pub(in crate::tun) egress_control: usize,
    pub(in crate::tun) egress_syn_ack: usize,
    pub(in crate::tun) ingress_payload_packets: usize,
    pub(in crate::tun) ingress_payload_bytes: usize,
    pub(in crate::tun) egress_payload_packets: usize,
    pub(in crate::tun) egress_payload_bytes: usize,
    pub(in crate::tun) fin: usize,
    pub(in crate::tun) rst: usize,
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
struct PacketKey {
    port: u16,
    client_port: u16,
}

#[derive(Default)]
struct PacketTrack {
    ingress_control: usize,
    ingress_syn: usize,
    egress_control: usize,
    egress_syn_ack: usize,
    ingress_payload_packets: usize,
    ingress_payload_bytes: usize,
    egress_payload_packets: usize,
    egress_payload_bytes: usize,
    fin: usize,
    rst: usize,
    promoted: bool,
    preflow_candidate_reported: bool,
    terminal_reported: bool,
}

impl PacketTrack {
    fn observe(&mut self, direction: PacketDirection, summary: &TcpPacket) {
        match direction {
            PacketDirection::Ingress => {
                if summary.is_control() {
                    self.ingress_control += 1;
                    if summary.syn {
                        self.ingress_syn += 1;
                    }
                }
                if summary.payload_bytes > 0 {
                    self.ingress_payload_packets += 1;
                    self.ingress_payload_bytes += summary.payload_bytes;
                }
            }
            PacketDirection::Egress => {
                if summary.is_control() {
                    self.egress_control += 1;
                    if summary.syn && summary.ack {
                        self.egress_syn_ack += 1;
                    }
                }
                if summary.payload_bytes > 0 {
                    self.egress_payload_packets += 1;
                    self.egress_payload_bytes += summary.payload_bytes;
                }
            }
        }
        if summary.fin {
            self.fin += 1;
        }
        if summary.rst {
            self.rst += 1;
        }
    }

    fn should_emit_terminal(&self) -> bool {
        !self.promoted
            && !self.terminal_reported
            && self.handshake_complete()
            && self.fin + self.rst > 0
    }

    fn should_emit_preflow_candidate(&self) -> bool {
        !self.promoted
            && !self.preflow_candidate_reported
            && self.handshake_complete()
            && self.ingress_payload_packets > 0
    }

    fn handshake_complete(&self) -> bool {
        self.ingress_syn > 0 && self.egress_syn_ack > 0
    }

    fn preflow_candidate_event(&self, key: &PacketKey) -> RuntimeEvent {
        self.packet_state_event(RuntimeEventKind::TcpForwarderPreflowCandidate, key)
            .field("reason", "ingress-payload-before-preflow-service")
    }

    fn terminal_event(&self, key: &PacketKey) -> RuntimeEvent {
        self.packet_state_event(RuntimeEventKind::TcpForwarderPacketTerminal, key)
            .field("reason", "closed-before-preflow")
    }

    fn packet_state_event(&self, kind: RuntimeEventKind, key: &PacketKey) -> RuntimeEvent {
        RuntimeEvent::new(kind)
            .field("port", key.port)
            .field("clientPort", key.client_port)
            .field("transport", "tcp")
            .field("packetHandshakeComplete", self.handshake_complete())
            .field("promotedToRuntimeSession", self.promoted)
            .field("ingressControlPackets", self.ingress_control)
            .field("ingressSynPackets", self.ingress_syn)
            .field("egressControlPackets", self.egress_control)
            .field("egressSynAckPackets", self.egress_syn_ack)
            .field("ingressPayloadPackets", self.ingress_payload_packets)
            .field("ingressPayloadBytes", self.ingress_payload_bytes)
            .field("egressPayloadPackets", self.egress_payload_packets)
            .field("egressPayloadBytes", self.egress_payload_bytes)
            .field("finPackets", self.fin)
            .field("rstPackets", self.rst)
    }
}

impl TcpPacket {
    fn parse(packet: &[u8], direction: PacketDirection, listen_ports: &[u16]) -> Option<Self> {
        if packet.len() < 40 || packet.first()? >> 4 != 4 || packet.get(9).copied()? != TCP_PROTOCOL
        {
            return None;
        }
        let ihl = usize::from(packet[0] & 0x0f) * 4;
        let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]])).min(packet.len());
        if ihl < 20 || total_len < ihl + 20 {
            return None;
        }
        let segment = &packet[ihl..total_len];
        let source_port = u16::from_be_bytes([segment[0], segment[1]]);
        let destination_port = u16::from_be_bytes([segment[2], segment[3]]);
        let (port, client_port) = match direction {
            PacketDirection::Ingress if listen_ports.contains(&destination_port) => {
                (destination_port, source_port)
            }
            PacketDirection::Egress if listen_ports.contains(&source_port) => {
                (source_port, destination_port)
            }
            _ => return None,
        };
        let data_offset = usize::from(segment[12] >> 4) * 4;
        if data_offset < 20 || segment.len() < data_offset {
            return None;
        }
        let flags = segment[13];
        Some(Self {
            port,
            client_port,
            syn: flags & TCP_FLAG_SYN != 0,
            ack: flags & TCP_FLAG_ACK != 0,
            fin: flags & TCP_FLAG_FIN != 0,
            rst: flags & TCP_FLAG_RST != 0,
            payload_bytes: segment.len().saturating_sub(data_offset),
        })
    }

    fn is_control(&self) -> bool {
        self.syn || self.fin || self.rst
    }
}
