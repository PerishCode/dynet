use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use dynet_capture::{parse_ipv4_packet, CapturedTransport, PacketParseError, TargetCaptureSource};

#[test]
fn parses_udp_dns() {
    let packet = ipv4_packet(17, [192, 168, 1, 10], [1, 1, 1, 1], 55123, 53);

    let flow = parse_ipv4_packet(&packet).expect("packet parses");

    assert_eq!(
        flow.source,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 55123)
    );
    assert_eq!(
        flow.destination,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53)
    );
    assert_eq!(flow.transport, CapturedTransport::DnsUdp);
}

#[test]
fn parses_tcp_flow() {
    let packet = ipv4_packet(6, [192, 168, 1, 10], [93, 184, 216, 34], 52000, 80);

    let flow = parse_ipv4_packet(&packet).expect("packet parses");

    assert_eq!(flow.transport, CapturedTransport::Tcp);
    assert_eq!(flow.destination.port(), 80);
}

#[test]
fn converts_to_captured_flow() {
    let packet = ipv4_packet(17, [192, 168, 1, 10], [8, 8, 8, 8], 45000, 443);

    let captured = parse_ipv4_packet(&packet)
        .expect("packet parses")
        .into_captured_flow(7);

    assert_eq!(captured.flow_id, 7);
    assert_eq!(
        captured.peer,
        Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)))
    );
    assert_eq!(captured.target.address.port(), 443);
    assert_eq!(
        captured.target.source,
        TargetCaptureSource::PacketDestination
    );
    assert_eq!(captured.transport, CapturedTransport::Udp);
}

#[test]
fn rejects_ipv6() {
    let packet = [0x60; 40];

    let error = parse_ipv4_packet(&packet).expect_err("IPv6 rejected");

    assert_eq!(error, PacketParseError::UnsupportedVersion(6));
}

#[test]
fn rejects_unsupported_protocol() {
    let packet = ipv4_packet(1, [192, 168, 1, 10], [1, 1, 1, 1], 0, 0);

    let error = parse_ipv4_packet(&packet).expect_err("ICMP rejected");

    assert_eq!(error, PacketParseError::UnsupportedProtocol(1));
}

fn ipv4_packet(
    protocol: u8,
    source: [u8; 4],
    target: [u8; 4],
    source_port: u16,
    target_port: u16,
) -> Vec<u8> {
    let total_len = 24_u16;
    let mut packet = vec![0_u8; usize::from(total_len)];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&total_len.to_be_bytes());
    packet[8] = 64;
    packet[9] = protocol;
    packet[12..16].copy_from_slice(&source);
    packet[16..20].copy_from_slice(&target);
    packet[20..22].copy_from_slice(&source_port.to_be_bytes());
    packet[22..24].copy_from_slice(&target_port.to_be_bytes());
    packet
}
