mod support;

use std::{collections::BTreeMap, net::Ipv4Addr, time::Duration};

use dynet_ingress::{
    run_socks5_graph, OutboundConfig, ShadowsocksConfig, ShadowsocksMethod, Socks5IngressConfig,
    VlessConfig, VmessConfig,
};
use dynet_runtime::IngressEventKind;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time,
};

#[tokio::test]
async fn graph_chains_vmess_direct() {
    let (vmess_addr, vmess_task) = support::spawn_tcp_prefix_server::<16>().await;
    let dns_addr = support::spawn_dns_a(Ipv4Addr::LOCALHOST).await;

    let bind = support::unused_tcp_addr().await;
    let runtime = support::runtime_from_seed(support::chained_route_seed(dns_addr)).await;
    let mut outbounds = BTreeMap::new();
    outbounds.insert(
        "routed-node".to_string(),
        OutboundConfig::Vmess(VmessConfig {
            server: vmess_addr.ip().to_string(),
            port: vmess_addr.port(),
            uuid: "11111111-2222-3333-4444-555555555555".to_string(),
        }),
    );
    outbounds.insert("egress-node".to_string(), OutboundConfig::Direct);
    tokio::spawn(run_socks5_graph(
        Socks5IngressConfig {
            bind,
            udp_advertise_ip: None,
            idle_timeout: Duration::from_secs(2),
            max_sessions: 16,
        },
        outbounds,
        runtime,
    ));
    time::sleep(Duration::from_millis(25)).await;

    let mut client = socks_connect_domain(bind, "routed.example", 80).await;
    client.write_all(b"chain").await.expect("write payload");

    let prefix = time::timeout(Duration::from_secs(2), vmess_task)
        .await
        .expect("vmess server timeout")
        .expect("vmess task");
    assert_ne!(prefix, [0_u8; 16]);
}

#[tokio::test]
async fn graph_chains_vless_direct() {
    let (vless_addr, reality_task) = support::spawn_tcp_prefix_server::<1>().await;
    let dns_addr = support::spawn_dns_a(Ipv4Addr::LOCALHOST).await;

    let bind = support::unused_tcp_addr().await;
    let runtime = support::runtime_from_seed(support::chained_route_seed(dns_addr)).await;
    let mut outbounds = BTreeMap::new();
    outbounds.insert(
        "routed-node".to_string(),
        OutboundConfig::Vless(VlessConfig {
            server: vless_addr.ip().to_string(),
            port: vless_addr.port(),
            uuid: "00112233-4455-6677-8899-aabbccddeeff".to_string(),
            server_name: "example.com".to_string(),
            public_key: "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI".to_string(),
            short_id: "0123456789abcdef".to_string(),
        }),
    );
    outbounds.insert("egress-node".to_string(), OutboundConfig::Direct);
    tokio::spawn(run_socks5_graph(
        Socks5IngressConfig {
            bind,
            udp_advertise_ip: None,
            idle_timeout: Duration::from_secs(2),
            max_sessions: 16,
        },
        outbounds,
        runtime,
    ));
    time::sleep(Duration::from_millis(25)).await;

    let mut client = socks_connect_domain(bind, "routed.example", 80).await;
    client.write_all(b"chain").await.expect("write payload");

    let prefix = time::timeout(Duration::from_secs(2), reality_task)
        .await
        .expect("vless server timeout")
        .expect("vless task");
    assert_eq!(prefix[0], 0x16);
}

#[tokio::test]
async fn rejects_protocol_tail() {
    let dns_addr = support::spawn_dns_a(Ipv4Addr::LOCALHOST).await;

    let bind = support::unused_tcp_addr().await;
    let runtime = support::runtime_from_seed(support::chained_route_seed(dns_addr)).await;
    let events = runtime.events().clone();
    let mut outbounds = BTreeMap::new();
    for node_id in ["routed-node", "egress-node"] {
        outbounds.insert(
            node_id.to_string(),
            OutboundConfig::Shadowsocks(ShadowsocksConfig {
                server: "127.0.0.1".to_string(),
                port: 9,
                method: ShadowsocksMethod::Aes256Gcm,
                password: "fake-password".to_string(),
            }),
        );
    }
    tokio::spawn(run_socks5_graph(
        Socks5IngressConfig {
            bind,
            udp_advertise_ip: None,
            idle_timeout: Duration::from_secs(2),
            max_sessions: 16,
        },
        outbounds,
        runtime,
    ));
    time::sleep(Duration::from_millis(25)).await;

    let mut client = socks_connect_domain(bind, "routed.example", 80).await;
    client.write_all(b"chain").await.expect("write payload");
    let mut response = Vec::new();
    let read = time::timeout(Duration::from_secs(2), client.read_to_end(&mut response))
        .await
        .expect("read timeout")
        .expect("read response");

    assert_eq!(read, 0);
    let _ = support::wait_for_event(&events, IngressEventKind::TcpError).await;
    assert_eq!(
        support::event_field(&events, IngressEventKind::TcpError, "selectionGroups"),
        "routed,egress"
    );
    assert!(
        support::event_field(&events, IngressEventKind::TcpError, "error")
            .contains("non-direct node egress-node")
    );
}

async fn socks_connect_domain(bind: std::net::SocketAddr, domain: &str, port: u16) -> TcpStream {
    let mut client = TcpStream::connect(bind).await.expect("connect socks");
    write_greeting(&mut client).await;
    write_domain_request(&mut client, 1, domain, port).await;
    let reply = read_socks_reply(&mut client).await;
    assert_eq!(reply.port(), 0);
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

async fn write_domain_request(client: &mut TcpStream, command: u8, domain: &str, port: u16) {
    let mut request = vec![5, command, 0, 3, domain.len() as u8];
    request.extend_from_slice(domain.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    client.write_all(&request).await.expect("write request");
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
