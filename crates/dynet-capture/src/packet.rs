use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::{CapturedFlow, CapturedTarget, CapturedTransport};

const IPV4_MIN_HEADER_LEN: usize = 20;
const TCP_PROTOCOL: u8 = 6;
const UDP_PROTOCOL: u8 = 17;
const DNS_PORT: u16 = 53;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PacketFlow {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub transport: CapturedTransport,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum PacketParseError {
    TooShort,
    UnsupportedVersion(u8),
    InvalidHeaderLength,
    TruncatedPacket,
    UnsupportedProtocol(u8),
    MissingTransportHeader,
}

impl PacketFlow {
    pub fn into_captured_flow(self, flow_id: u64) -> CapturedFlow {
        CapturedFlow {
            flow_id,
            peer: Some(IpAddr::V4(source_ip(self.source))),
            target: CapturedTarget::packet_destination(self.destination),
            transport: self.transport,
        }
    }
}

pub fn parse_ipv4_packet(packet: &[u8]) -> Result<PacketFlow, PacketParseError> {
    if packet.len() < IPV4_MIN_HEADER_LEN {
        return Err(PacketParseError::TooShort);
    }
    let version = packet[0] >> 4;
    if version != 4 {
        return Err(PacketParseError::UnsupportedVersion(version));
    }
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    if ihl < IPV4_MIN_HEADER_LEN {
        return Err(PacketParseError::InvalidHeaderLength);
    }
    if packet.len() < ihl {
        return Err(PacketParseError::TruncatedPacket);
    }
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len < ihl || packet.len() < total_len {
        return Err(PacketParseError::TruncatedPacket);
    }

    let protocol = packet[9];
    let source = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let transport = &packet[ihl..total_len];
    match protocol {
        TCP_PROTOCOL => parse_ports(transport).map(|(source_port, destination_port)| PacketFlow {
            source: SocketAddr::new(IpAddr::V4(source), source_port),
            destination: SocketAddr::new(IpAddr::V4(destination), destination_port),
            transport: classify_tcp(source_port, destination_port),
        }),
        UDP_PROTOCOL => parse_ports(transport).map(|(source_port, destination_port)| PacketFlow {
            source: SocketAddr::new(IpAddr::V4(source), source_port),
            destination: SocketAddr::new(IpAddr::V4(destination), destination_port),
            transport: classify_udp(source_port, destination_port),
        }),
        protocol => Err(PacketParseError::UnsupportedProtocol(protocol)),
    }
}

fn parse_ports(packet: &[u8]) -> Result<(u16, u16), PacketParseError> {
    if packet.len() < 4 {
        return Err(PacketParseError::MissingTransportHeader);
    }
    Ok((
        u16::from_be_bytes([packet[0], packet[1]]),
        u16::from_be_bytes([packet[2], packet[3]]),
    ))
}

fn classify_tcp(source_port: u16, destination_port: u16) -> CapturedTransport {
    if source_port == DNS_PORT || destination_port == DNS_PORT {
        CapturedTransport::DnsTcp
    } else {
        CapturedTransport::Tcp
    }
}

fn classify_udp(source_port: u16, destination_port: u16) -> CapturedTransport {
    if source_port == DNS_PORT || destination_port == DNS_PORT {
        CapturedTransport::DnsUdp
    } else {
        CapturedTransport::Udp
    }
}

fn source_ip(address: SocketAddr) -> Ipv4Addr {
    match address.ip() {
        IpAddr::V4(address) => address,
        IpAddr::V6(_) => unreachable!("packet parser only emits IPv4 addresses"),
    }
}
