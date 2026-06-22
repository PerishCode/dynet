mod support;

use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use dynet_ingress::{run_socks5, Socks5IngressConfig};
use dynet_runtime::IngressEventKind;
use support::{event_field, local_addr, unused_tcp_addr, wait_for_count};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time,
};

#[tokio::test]
async fn udp_restores_observed_dns() {
    let upstream = UdpSocket::bind(local_addr()).await.expect("bind upstream");
    let upstream_addr = upstream.local_addr().expect("upstream addr");
    tokio::spawn(async move {
        let mut buffer = [0_u8; 1024];
        let (size, peer) = upstream.recv_from(&mut buffer).await.expect("recv request");
        upstream
            .send_to(&buffer[..size], peer)
            .await
            .expect("send response");
    });

    let fake_ip = Ipv4Addr::new(198, 18, 0, 10);
    let fake_target = SocketAddr::from((fake_ip, upstream_addr.port()));
    let dns_addr = support::spawn_dns_a_sequence(vec![fake_ip, Ipv4Addr::LOCALHOST]).await;
    let runtime = support::runtime_with_dns(dns_addr);
    let observed = runtime
        .resolve_domain_a("restored.example", upstream_addr.port())
        .await
        .expect("initial fake DNS resolves");
    assert_eq!(observed, fake_target);

    let bind = unused_tcp_addr().await;
    let events = runtime.events().clone();
    tokio::spawn(run_socks5(
        Socks5IngressConfig {
            bind,
            udp_advertise_ip: None,
            idle_timeout: Duration::from_secs(2),
            max_sessions: 16,
        },
        runtime,
    ));
    time::sleep(Duration::from_millis(25)).await;

    let mut control = socks_udp_associate(bind).await;
    let udp_bind = read_socks_reply(&mut control).await;
    let udp_client = UdpSocket::bind(local_addr()).await.expect("bind client");
    udp_client
        .send_to(&socks_udp_packet(fake_target, b"restore-udp"), udp_bind)
        .await
        .expect("send socks udp");
    let mut response = [0_u8; 1024];
    let (size, _) = time::timeout(Duration::from_secs(2), udp_client.recv_from(&mut response))
        .await
        .expect("response timeout")
        .expect("recv socks udp");

    let (source, payload) = parse_socks_udp(&response[..size]);
    assert_eq!(source, fake_target);
    assert_eq!(payload, b"restore-udp");
    let _ = wait_for_count(&events, IngressEventKind::UdpDatagram, 2).await;
    assert_eq!(
        event_field(&events, IngressEventKind::UdpDatagram, "targetIp"),
        Ipv4Addr::LOCALHOST.to_string()
    );
}

async fn socks_udp_associate(bind: SocketAddr) -> TcpStream {
    let mut client = TcpStream::connect(bind).await.expect("connect socks");
    write_greeting(&mut client).await;
    write_request(&mut client, SocketAddr::from(([0, 0, 0, 0], 0))).await;
    client
}

async fn write_greeting(client: &mut TcpStream) {
    client.write_all(&[5, 1, 0]).await.expect("write greeting");
    let mut response = [0_u8; 2];
    client
        .read_exact(&mut response)
        .await
        .expect("read greeting");
    assert_eq!(response, [5, 0]);
}

async fn write_request(client: &mut TcpStream, target: SocketAddr) {
    let mut request = vec![5, 3, 0, 1];
    let SocketAddr::V4(address) = target else {
        panic!("test helper only writes IPv4 targets");
    };
    request.extend_from_slice(&address.ip().octets());
    request.extend_from_slice(&address.port().to_be_bytes());
    client.write_all(&request).await.expect("write request");
}

async fn read_socks_reply(client: &mut TcpStream) -> SocketAddr {
    let mut header = [0_u8; 4];
    client
        .read_exact(&mut header)
        .await
        .expect("read reply header");
    assert_eq!(header[0], 5);
    assert_eq!(header[1], 0);
    assert_eq!(header[3], 1);
    let mut rest = [0_u8; 6];
    client.read_exact(&mut rest).await.expect("read ipv4 reply");
    SocketAddr::from((
        [rest[0], rest[1], rest[2], rest[3]],
        u16::from_be_bytes([rest[4], rest[5]]),
    ))
}

fn socks_udp_packet(target: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0, 0, 0, 1];
    let SocketAddr::V4(address) = target else {
        panic!("test helper only writes IPv4 targets");
    };
    packet.extend_from_slice(&address.ip().octets());
    packet.extend_from_slice(&address.port().to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

fn parse_socks_udp(packet: &[u8]) -> (SocketAddr, Vec<u8>) {
    assert_eq!(&packet[..4], &[0, 0, 0, 1]);
    let address = [packet[4], packet[5], packet[6], packet[7]];
    let port = u16::from_be_bytes([packet[8], packet[9]]);
    (SocketAddr::from((address, port)), packet[10..].to_vec())
}
