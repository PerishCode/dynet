mod support;

use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use dynet_ingress::{
    run_socks5, run_socks5_graph, EgressNodeConfig, ShadowsocksConfig, ShadowsocksMethod,
    Socks5IngressConfig, TrojanConfig,
};
use dynet_runtime::{IngressEventKind, RuntimeState};
use support::{event_field, local_addr, unused_tcp_addr, wait_for_count, wait_for_event};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time,
};

#[tokio::test]
async fn tcp_connect() {
    let upstream = TcpListener::bind(local_addr())
        .await
        .expect("bind upstream");
    let upstream_addr = upstream.local_addr().expect("upstream addr");
    tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.expect("accept upstream");
        let mut request = Vec::new();
        stream
            .read_to_end(&mut request)
            .await
            .expect("read request");
        stream.write_all(&request).await.expect("write response");
    });

    let bind = unused_tcp_addr().await;
    let runtime = RuntimeState::default();
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

    let mut client = socks_connect(bind, upstream_addr).await;
    client.write_all(b"socks-tcp").await.expect("write payload");
    client.shutdown().await.expect("shutdown payload");
    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .await
        .expect("read response");

    assert_eq!(response, b"socks-tcp");
    let kinds = wait_for_event(&events, IngressEventKind::TcpClose).await;
    assert!(kinds.contains(&IngressEventKind::TcpAccept));
    assert!(kinds.contains(&IngressEventKind::TcpClose));
    assert_eq!(
        event_field(&events, IngressEventKind::TcpAccept, "inbound"),
        "socks5"
    );
    assert_eq!(
        event_field(&events, IngressEventKind::TcpAccept, "targetIp"),
        upstream_addr.ip().to_string()
    );
    assert_eq!(
        event_field(&events, IngressEventKind::TcpAccept, "targetPort"),
        upstream_addr.port().to_string()
    );
}

#[tokio::test]
async fn domain_connect_uses_dns() {
    let upstream = TcpListener::bind(local_addr())
        .await
        .expect("bind upstream");
    let upstream_addr = upstream.local_addr().expect("upstream addr");
    tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.expect("accept upstream");
        let mut request = Vec::new();
        stream
            .read_to_end(&mut request)
            .await
            .expect("read request");
        stream.write_all(&request).await.expect("write response");
    });

    let dns_addr = support::spawn_dns_a(Ipv4Addr::LOCALHOST).await;

    let bind = unused_tcp_addr().await;
    let runtime = support::runtime_with_dns(dns_addr);
    let events = runtime.events().clone();
    tokio::spawn(run_socks5(
        Socks5IngressConfig {
            bind,
            udp_advertise_ip: None,
            idle_timeout: Duration::from_secs(2),
            max_sessions: 16,
        },
        runtime.clone(),
    ));
    time::sleep(Duration::from_millis(25)).await;

    let mut client = socks_connect_domain(bind, "example.test", upstream_addr.port()).await;
    client
        .write_all(b"socks-domain")
        .await
        .expect("write payload");
    client.shutdown().await.expect("shutdown payload");
    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .await
        .expect("read response");

    assert_eq!(response, b"socks-domain");
    let _ = wait_for_event(&events, IngressEventKind::TcpClose).await;
    assert_eq!(
        event_field(&events, IngressEventKind::TcpAccept, "targetDomain"),
        "example.test"
    );
    assert_eq!(
        runtime.dns_map().snapshot()["example.test"],
        vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]
    );
}

#[tokio::test]
async fn graph_routes_node() {
    let upstream = TcpListener::bind(local_addr())
        .await
        .expect("bind upstream");
    let upstream_addr = upstream.local_addr().expect("upstream addr");
    tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.expect("accept upstream");
        let mut request = Vec::new();
        stream
            .read_to_end(&mut request)
            .await
            .expect("read request");
        stream.write_all(&request).await.expect("write response");
    });

    let dns_addr = support::spawn_dns_a(Ipv4Addr::LOCALHOST).await;

    let bind = unused_tcp_addr().await;
    let runtime = support::runtime_from_seed(support::route_selected_seed(dns_addr)).await;
    let events = runtime.events().clone();
    let mut egress_nodes = BTreeMap::new();
    egress_nodes.insert("routed-node".to_string(), EgressNodeConfig::Direct);
    tokio::spawn(run_socks5_graph(
        Socks5IngressConfig {
            bind,
            udp_advertise_ip: None,
            idle_timeout: Duration::from_secs(2),
            max_sessions: 16,
        },
        egress_nodes,
        runtime,
    ));
    time::sleep(Duration::from_millis(25)).await;

    let mut client = socks_connect_domain(bind, "routed.example", upstream_addr.port()).await;
    client
        .write_all(b"graph-route")
        .await
        .expect("write payload");
    client.shutdown().await.expect("shutdown payload");
    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .await
        .expect("read response");

    assert_eq!(response, b"graph-route");
    let _ = wait_for_event(&events, IngressEventKind::TcpClose).await;
    assert_eq!(
        event_field(&events, IngressEventKind::TcpAccept, "nodeId"),
        "routed-node"
    );
    assert_eq!(
        event_field(&events, IngressEventKind::TcpAccept, "selectionGroups"),
        "routed"
    );
}

#[tokio::test]
async fn graph_chains_shadowsocks_direct() {
    let (ss_addr, ss_task) = support::spawn_ss_header_server("fake-password").await;
    let dns_addr = support::spawn_dns_a(Ipv4Addr::LOCALHOST).await;

    let bind = unused_tcp_addr().await;
    let runtime = support::runtime_from_seed(support::route_selected_seed(dns_addr)).await;
    let mut egress_nodes = BTreeMap::new();
    egress_nodes.insert(
        "routed-node".to_string(),
        EgressNodeConfig::Shadowsocks(ShadowsocksConfig {
            server: ss_addr.ip().to_string(),
            port: ss_addr.port(),
            method: ShadowsocksMethod::Aes256Gcm,
            password: "fake-password".to_string(),
        }),
    );
    tokio::spawn(run_socks5_graph(
        Socks5IngressConfig {
            bind,
            udp_advertise_ip: None,
            idle_timeout: Duration::from_secs(2),
            max_sessions: 16,
        },
        egress_nodes,
        runtime,
    ));
    time::sleep(Duration::from_millis(25)).await;

    let mut client = socks_connect_domain(bind, "routed.example", 80).await;
    client.write_all(b"chain").await.expect("write payload");

    let header = time::timeout(Duration::from_secs(2), ss_task)
        .await
        .expect("ss server timeout")
        .expect("ss task");
    assert_eq!(header, vec![1, 127, 0, 0, 1, 0, 80]);
}

#[tokio::test]
async fn graph_chains_trojan_direct() {
    let (trojan_addr, tls_task) = support::spawn_tcp_prefix_server::<1>().await;
    let dns_addr = support::spawn_dns_a(Ipv4Addr::LOCALHOST).await;

    let bind = unused_tcp_addr().await;
    let runtime = support::runtime_from_seed(support::route_selected_seed(dns_addr)).await;
    let mut egress_nodes = BTreeMap::new();
    egress_nodes.insert(
        "routed-node".to_string(),
        EgressNodeConfig::Trojan(TrojanConfig {
            server: trojan_addr.ip().to_string(),
            port: trojan_addr.port(),
            password: "secret".to_string(),
            sni: None,
            skip_cert_verify: true,
        }),
    );
    tokio::spawn(run_socks5_graph(
        Socks5IngressConfig {
            bind,
            udp_advertise_ip: None,
            idle_timeout: Duration::from_secs(2),
            max_sessions: 16,
        },
        egress_nodes,
        runtime,
    ));
    time::sleep(Duration::from_millis(25)).await;

    let mut client = socks_connect_domain(bind, "routed.example", 80).await;
    client.write_all(b"chain").await.expect("write payload");

    let prefix = time::timeout(Duration::from_secs(2), tls_task)
        .await
        .expect("trojan server timeout")
        .expect("trojan task");
    assert_eq!(prefix[0], 0x16);
}

#[tokio::test]
async fn udp_associate() {
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

    let bind = unused_tcp_addr().await;
    let runtime = RuntimeState::default();
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
    let request = socks_udp_packet(upstream_addr, b"socks-udp");
    udp_client
        .send_to(&request, udp_bind)
        .await
        .expect("send socks udp");
    let mut response = [0_u8; 1024];
    let (size, _) = time::timeout(Duration::from_secs(2), udp_client.recv_from(&mut response))
        .await
        .expect("response timeout")
        .expect("recv socks udp");

    let (source, payload) = parse_socks_udp(&response[..size]);
    assert_eq!(source, upstream_addr);
    assert_eq!(payload, b"socks-udp");
    let kinds = wait_for_count(&events, IngressEventKind::UdpDatagram, 2).await;
    assert!(kinds.contains(&IngressEventKind::UdpSessionStart));
    assert!(kinds.contains(&IngressEventKind::UdpDatagram));
    assert_eq!(
        event_field(&events, IngressEventKind::UdpDatagram, "inbound"),
        "socks5"
    );
    assert_eq!(
        event_field(&events, IngressEventKind::UdpDatagram, "targetIp"),
        upstream_addr.ip().to_string()
    );
}

async fn socks_connect(bind: SocketAddr, target: SocketAddr) -> TcpStream {
    let mut client = TcpStream::connect(bind).await.expect("connect socks");
    write_greeting(&mut client).await;
    write_request(&mut client, 1, target).await;
    let reply = read_socks_reply(&mut client).await;
    assert_eq!(reply.port(), 0);
    client
}

async fn socks_connect_domain(bind: SocketAddr, domain: &str, port: u16) -> TcpStream {
    let mut client = TcpStream::connect(bind).await.expect("connect socks");
    write_greeting(&mut client).await;
    write_domain_request(&mut client, 1, domain, port).await;
    let reply = read_socks_reply(&mut client).await;
    assert_eq!(reply.port(), 0);
    client
}

async fn socks_udp_associate(bind: SocketAddr) -> TcpStream {
    let mut client = TcpStream::connect(bind).await.expect("connect socks");
    write_greeting(&mut client).await;
    write_request(&mut client, 3, SocketAddr::from(([0, 0, 0, 0], 0))).await;
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

async fn write_request(client: &mut TcpStream, command: u8, target: SocketAddr) {
    let mut request = vec![5, command, 0];
    match target {
        SocketAddr::V4(address) => {
            request.push(1);
            request.extend_from_slice(&address.ip().octets());
            request.extend_from_slice(&address.port().to_be_bytes());
        }
        SocketAddr::V6(address) => {
            request.push(4);
            request.extend_from_slice(&address.ip().octets());
            request.extend_from_slice(&address.port().to_be_bytes());
        }
    }
    client.write_all(&request).await.expect("write request");
}

async fn write_domain_request(client: &mut TcpStream, command: u8, domain: &str, port: u16) {
    let mut request = vec![5, command, 0, 3, domain.len() as u8];
    request.extend_from_slice(domain.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
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
    match header[3] {
        1 => {
            let mut rest = [0_u8; 6];
            client.read_exact(&mut rest).await.expect("read ipv4 reply");
            SocketAddr::from((
                [rest[0], rest[1], rest[2], rest[3]],
                u16::from_be_bytes([rest[4], rest[5]]),
            ))
        }
        4 => {
            let mut rest = [0_u8; 18];
            client.read_exact(&mut rest).await.expect("read ipv6 reply");
            let mut address = [0_u8; 16];
            address.copy_from_slice(&rest[..16]);
            SocketAddr::from((address, u16::from_be_bytes([rest[16], rest[17]])))
        }
        _ => panic!("unexpected reply address type"),
    }
}

fn socks_udp_packet(target: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0, 0, 0];
    match target {
        SocketAddr::V4(address) => {
            packet.push(1);
            packet.extend_from_slice(&address.ip().octets());
            packet.extend_from_slice(&address.port().to_be_bytes());
        }
        SocketAddr::V6(address) => {
            packet.push(4);
            packet.extend_from_slice(&address.ip().octets());
            packet.extend_from_slice(&address.port().to_be_bytes());
        }
    }
    packet.extend_from_slice(payload);
    packet
}

fn parse_socks_udp(packet: &[u8]) -> (SocketAddr, Vec<u8>) {
    assert_eq!(&packet[..3], &[0, 0, 0]);
    match packet[3] {
        1 => {
            let address = [packet[4], packet[5], packet[6], packet[7]];
            let port = u16::from_be_bytes([packet[8], packet[9]]);
            (SocketAddr::from((address, port)), packet[10..].to_vec())
        }
        4 => {
            let mut address = [0_u8; 16];
            address.copy_from_slice(&packet[4..20]);
            let port = u16::from_be_bytes([packet[20], packet[21]]);
            (SocketAddr::from((address, port)), packet[22..].to_vec())
        }
        _ => panic!("unexpected udp address type"),
    }
}
