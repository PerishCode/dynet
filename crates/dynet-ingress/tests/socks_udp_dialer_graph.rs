mod support;

use std::{collections::BTreeMap, net::Ipv4Addr, time::Duration};

use dynet_ingress::{
    run_socks5_graph, EgressNodeConfig, Socks5IngressConfig, TrojanConfig, VlessConfig, VmessConfig,
};
use dynet_runtime::IngressEventKind;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time,
};

#[tokio::test]
async fn vmess_udp_dialer() {
    let prefix = run_udp_prefix_probe(
        EgressNodeConfig::Vmess(VmessConfig {
            server: "127.0.0.1".to_string(),
            port: 0,
            uuid: "11111111-2222-3333-4444-555555555555".to_string(),
        }),
        16,
    )
    .await;

    assert_ne!(prefix, vec![0_u8; 16]);
}

#[tokio::test]
async fn trojan_udp_dialer() {
    let prefix = run_udp_prefix_probe(
        EgressNodeConfig::Trojan(TrojanConfig {
            server: "127.0.0.1".to_string(),
            port: 0,
            password: "fake-password".to_string(),
            sni: Some("example.com".to_string()),
            skip_cert_verify: true,
        }),
        1,
    )
    .await;

    assert_eq!(prefix, vec![0x16]);
}

#[tokio::test]
async fn vless_udp_dialer() {
    let prefix = run_udp_prefix_probe(
        EgressNodeConfig::Vless(VlessConfig {
            server: "127.0.0.1".to_string(),
            port: 0,
            uuid: "00112233-4455-6677-8899-aabbccddeeff".to_string(),
            server_name: "example.com".to_string(),
            public_key: "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI".to_string(),
            short_id: "0123456789abcdef".to_string(),
        }),
        1,
    )
    .await;

    assert_eq!(prefix, vec![0x16]);
}

async fn run_udp_prefix_probe(mut final_node: EgressNodeConfig, prefix_len: usize) -> Vec<u8> {
    let (final_addr, final_task) = support::spawn_prefix_vec(prefix_len).await;
    match &mut final_node {
        EgressNodeConfig::Trojan(config) => {
            config.server = final_addr.ip().to_string();
            config.port = final_addr.port();
        }
        EgressNodeConfig::Vless(config) => {
            config.server = final_addr.ip().to_string();
            config.port = final_addr.port();
        }
        EgressNodeConfig::Vmess(config) => {
            config.server = final_addr.ip().to_string();
            config.port = final_addr.port();
        }
        EgressNodeConfig::Direct | EgressNodeConfig::Shadowsocks(_) => {
            panic!("unexpected final node")
        }
    }
    let dns_addr = support::spawn_dns_a(Ipv4Addr::LOCALHOST).await;
    let bind = support::unused_tcp_addr().await;
    let runtime = support::runtime_from_seed(support::chained_route_seed(dns_addr)).await;
    let events = runtime.events().clone();
    let mut egress_nodes = BTreeMap::new();
    egress_nodes.insert("routed-node".to_string(), EgressNodeConfig::Direct);
    egress_nodes.insert("egress-node".to_string(), final_node);
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

    let mut control = socks_udp_associate(bind).await;
    let udp_bind = read_socks_reply(&mut control).await;
    let udp_client = UdpSocket::bind(support::local_addr())
        .await
        .expect("bind socks udp client");
    let request = socks_udp_domain_packet("routed.example", 443, b"h3-probe");
    udp_client
        .send_to(&request, udp_bind)
        .await
        .expect("send socks udp");

    let _ = support::wait_for_event(&events, IngressEventKind::UdpDatagram).await;
    assert_eq!(
        support::event_field(&events, IngressEventKind::UdpDatagram, "selectionGroups"),
        "routed,egress"
    );
    time::timeout(Duration::from_secs(2), final_task)
        .await
        .expect("final server timeout")
        .expect("final server")
}

async fn socks_udp_associate(bind: std::net::SocketAddr) -> TcpStream {
    let mut client = TcpStream::connect(bind).await.expect("connect socks");
    client.write_all(&[5, 1, 0]).await.expect("write greeting");
    let mut response = [0_u8; 2];
    client
        .read_exact(&mut response)
        .await
        .expect("read greeting");
    assert_eq!(response, [5, 0]);
    client
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .expect("write udp associate");
    client
}

async fn read_socks_reply(client: &mut TcpStream) -> std::net::SocketAddr {
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
            std::net::SocketAddr::from((
                [rest[0], rest[1], rest[2], rest[3]],
                u16::from_be_bytes([rest[4], rest[5]]),
            ))
        }
        4 => {
            let mut rest = [0_u8; 18];
            client.read_exact(&mut rest).await.expect("read ipv6 reply");
            let mut address = [0_u8; 16];
            address.copy_from_slice(&rest[..16]);
            std::net::SocketAddr::from((address, u16::from_be_bytes([rest[16], rest[17]])))
        }
        _ => panic!("unexpected reply address type"),
    }
}

fn socks_udp_domain_packet(domain: &str, port: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0, 0, 0, 3, domain.len() as u8];
    packet.extend_from_slice(domain.as_bytes());
    packet.extend_from_slice(&port.to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}
