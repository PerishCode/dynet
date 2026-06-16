use std::{
    io::Cursor,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};

use sha2::{Digest, Sha224};
use trojan_prototype::{read_udp_for_test, request_header_for_test, udp_packet_for_test};

#[test]
fn tcp_request_header_layout() {
    let target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 443));
    let header = request_header_for_test("secret", 0x01, target);
    let expected_hash = hex_sha224("secret");

    assert_eq!(&header[..56], expected_hash.as_bytes());
    assert_eq!(&header[56..58], b"\r\n");
    assert_eq!(header[58], 0x01);
    assert_eq!(&header[59..], &[0x01, 1, 2, 3, 4, 0x01, 0xbb, b'\r', b'\n']);
}

#[test]
fn udp_associate_header_layout() {
    let target = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 53, 0, 0));
    let header = request_header_for_test("secret", 0x03, target);

    assert_eq!(&header[56..58], b"\r\n");
    assert_eq!(header[58], 0x03);
    assert_eq!(header[59], 0x04);
    assert_eq!(&header[76..78], &53_u16.to_be_bytes());
    assert_eq!(&header[78..], b"\r\n");
}

#[test]
fn udp_packet_layout() {
    let target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53));
    let packet = udp_packet_for_test(target, b"dns-query").unwrap();

    assert_eq!(
        packet,
        vec![
            0x01, 8, 8, 8, 8, 0, 53, 0, 9, b'\r', b'\n', b'd', b'n', b's', b'-', b'q', b'u', b'e',
            b'r', b'y',
        ]
    );
}

#[tokio::test]
async fn reads_udp_packet_payload() {
    let target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 4, 4), 53));
    let packet = udp_packet_for_test(target, b"answer").unwrap();
    let mut reader = Cursor::new(packet);

    let payload = read_udp_for_test(&mut reader).await.unwrap();

    assert_eq!(payload, b"answer");
}

#[tokio::test]
async fn rejects_bad_udp_delimiter() {
    let mut packet = udp_packet_for_test(
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53)),
        b"x",
    )
    .unwrap();
    packet[9] = b'x';
    let mut reader = Cursor::new(packet);

    let error = read_udp_for_test(&mut reader).await.unwrap_err();

    assert_eq!(error.stage(), "outbound-protocol");
    assert!(error.to_string().contains("delimiter"));
}

fn hex_sha224(input: &str) -> String {
    let digest = Sha224::digest(input.as_bytes());
    let mut output = String::new();
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").unwrap();
    }
    output
}
