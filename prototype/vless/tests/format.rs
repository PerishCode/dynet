use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::AsyncWriteExt;
use vless_prototype::{
    read_udp_frame, tcp_header_for_test, udp_frame, udp_header_for_test, TargetAddress, TargetHost,
};

const UUID: &str = "00112233-4455-6677-8899-aabbccddeeff";
const USER_ID: &[u8] = &[
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];

#[test]
fn tcp_header_vision_ipv4() {
    let target = TargetAddress::socket(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 80));
    let header = tcp_header_for_test(UUID, target).expect("header");
    let flow = b"xtls-rprx-vision";
    let addon_len = 2 + flow.len();

    assert_eq!(header[0], 0);
    assert_eq!(&header[1..17], USER_ID);
    assert_eq!(header[17], addon_len as u8);
    assert_eq!(header[18], 0x0a);
    assert_eq!(header[19], flow.len() as u8);
    assert_eq!(&header[20..20 + flow.len()], flow);

    let offset = 18 + addon_len;
    assert_eq!(header[offset], 0x01);
    assert_eq!(&header[offset + 1..offset + 3], &80_u16.to_be_bytes());
    assert_eq!(header[offset + 3], 0x01);
    assert_eq!(&header[offset + 4..offset + 8], &[1, 1, 1, 1]);
    assert_eq!(header.len(), offset + 8);
}

#[test]
fn udp_header_ipv6() {
    let target = TargetAddress::socket(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 53));
    let header = udp_header_for_test(UUID, target).expect("header");

    assert_eq!(header[0], 0);
    assert_eq!(&header[1..17], USER_ID);
    assert_eq!(header[17], 0);
    assert_eq!(header[18], 0x02);
    assert_eq!(&header[19..21], &53_u16.to_be_bytes());
    assert_eq!(header[21], 0x03);
    assert_eq!(&header[22..38], &Ipv6Addr::LOCALHOST.octets());
    assert_eq!(header.len(), 38);
}

#[test]
fn header_domain() {
    let target = TargetAddress::new(TargetHost::Domain("example.com".to_string()), 443);
    let header = udp_header_for_test(UUID, target).expect("header");

    assert_eq!(header[18], 0x02);
    assert_eq!(&header[19..21], &443_u16.to_be_bytes());
    assert_eq!(header[21], 0x02);
    assert_eq!(header[22], "example.com".len() as u8);
    assert_eq!(&header[23..], b"example.com");
}

#[tokio::test]
async fn udp_frame_roundtrip() {
    let frame = udp_frame(b"hello").expect("frame");
    assert_eq!(&frame, b"\x00\x05hello");

    let (mut tx, mut rx) = tokio::io::duplex(16);
    tx.write_all(&frame).await.expect("write frame");
    drop(tx);

    let payload = read_udp_frame(&mut rx).await.expect("payload");
    assert_eq!(payload, b"hello");
}

#[test]
fn udp_frame_oversize() {
    let payload = vec![0_u8; 65536];
    let error = udp_frame(&payload).expect_err("oversized");
    assert_eq!(error.stage(), "outbound-protocol");
}
