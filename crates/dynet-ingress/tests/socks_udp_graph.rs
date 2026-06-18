mod support;

use std::{collections::BTreeMap, net::Ipv4Addr, time::Duration};

use dynet_ingress::{
    run_socks5_graph, EgressNodeConfig, ShadowsocksConfig, ShadowsocksMethod, Socks5IngressConfig,
};
use dynet_runtime::IngressEventKind;
use shadowsocks_prototype::{
    Client as ShadowsocksClient, ClientConfig as ShadowsocksClientConfig,
    Method as ShadowsocksPrototypeMethod,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time,
};

#[tokio::test]
async fn ss_udp_double_hop() {
    let outer_password = "airport-password";
    let inner_password = "private-password";
    let outer_socket = UdpSocket::bind(support::local_addr())
        .await
        .expect("bind outer ss udp");
    let outer_addr = outer_socket.local_addr().expect("outer addr");
    let private_addr = support::unused_udp_addr().await;
    let target = std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, 443));
    let outer_task = tokio::spawn(async move {
        let outer_client = ss_client(outer_addr, outer_password);
        let inner_client = ss_client(private_addr, inner_password);
        let mut outer_session = outer_client.udp_session();
        let mut inner_session = inner_client.udp_session();
        let mut buffer = vec![0_u8; 65_535];
        let (size, peer) = outer_socket
            .recv_from(&mut buffer)
            .await
            .expect("recv outer packet");
        let inner_packet = outer_session
            .decode_udp_datagram(&buffer[..size])
            .expect("decode outer packet");
        let payload = inner_session
            .decode_udp_datagram(&inner_packet)
            .expect("decode inner packet");
        assert_eq!(payload, b"chain-udp");
        let inner_response = inner_session
            .encode_udp_datagram(target, b"udp-reply")
            .expect("encode inner response");
        let outer_response = outer_session
            .encode_udp_datagram(private_addr, &inner_response)
            .expect("encode outer response");
        outer_socket
            .send_to(&outer_response, peer)
            .await
            .expect("send outer response");
    });
    let dns_addr = support::spawn_dns_a(Ipv4Addr::LOCALHOST).await;

    let bind = support::unused_tcp_addr().await;
    let runtime = support::runtime_from_seed(support::chained_route_seed(dns_addr)).await;
    let events = runtime.events().clone();
    let mut egress_nodes = BTreeMap::new();
    egress_nodes.insert(
        "routed-node".to_string(),
        EgressNodeConfig::Shadowsocks(ShadowsocksConfig {
            server: outer_addr.ip().to_string(),
            port: outer_addr.port(),
            method: ShadowsocksMethod::Aes256Gcm,
            password: outer_password.to_string(),
        }),
    );
    egress_nodes.insert(
        "egress-node".to_string(),
        EgressNodeConfig::Shadowsocks(ShadowsocksConfig {
            server: private_addr.ip().to_string(),
            port: private_addr.port(),
            method: ShadowsocksMethod::Aes256Gcm,
            password: inner_password.to_string(),
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

    let mut control = socks_udp_associate(bind).await;
    let udp_bind = read_socks_reply(&mut control).await;
    let udp_client = UdpSocket::bind(support::local_addr())
        .await
        .expect("bind socks udp client");
    let request = socks_udp_domain_packet("routed.example", target.port(), b"chain-udp");
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
    assert_eq!(source, target);
    assert_eq!(payload, b"udp-reply");
    outer_task.await.expect("outer task");
    let _ = support::wait_for_count(&events, IngressEventKind::UdpDatagram, 2).await;
    assert_eq!(
        support::event_field(&events, IngressEventKind::UdpDatagram, "selectionGroups"),
        "routed,egress"
    );
    assert_eq!(
        support::event_field(&events, IngressEventKind::UdpDatagram, "selectionNodes"),
        "routed-node,egress-node"
    );
}

fn ss_client(address: std::net::SocketAddr, password: &str) -> ShadowsocksClient {
    ShadowsocksClient::new(ShadowsocksClientConfig {
        server: address.ip().to_string(),
        port: address.port(),
        method: ShadowsocksPrototypeMethod::Aes256Gcm,
        password: password.to_string(),
    })
}

async fn socks_udp_associate(bind: std::net::SocketAddr) -> TcpStream {
    let mut client = TcpStream::connect(bind).await.expect("connect socks");
    write_greeting(&mut client).await;
    write_request(
        &mut client,
        3,
        std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
    )
    .await;
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

async fn write_request(client: &mut TcpStream, command: u8, target: std::net::SocketAddr) {
    let mut request = vec![5, command, 0];
    match target {
        std::net::SocketAddr::V4(address) => {
            request.push(1);
            request.extend_from_slice(&address.ip().octets());
            request.extend_from_slice(&address.port().to_be_bytes());
        }
        std::net::SocketAddr::V6(address) => {
            request.push(4);
            request.extend_from_slice(&address.ip().octets());
            request.extend_from_slice(&address.port().to_be_bytes());
        }
    }
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

fn socks_udp_domain_packet(domain: &str, port: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0, 0, 0, 3, domain.len() as u8];
    packet.extend_from_slice(domain.as_bytes());
    packet.extend_from_slice(&port.to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

fn parse_socks_udp(packet: &[u8]) -> (std::net::SocketAddr, Vec<u8>) {
    assert_eq!(&packet[..3], &[0, 0, 0]);
    match packet[3] {
        1 => {
            let address = [packet[4], packet[5], packet[6], packet[7]];
            let port = u16::from_be_bytes([packet[8], packet[9]]);
            (
                std::net::SocketAddr::from((address, port)),
                packet[10..].to_vec(),
            )
        }
        4 => {
            let mut address = [0_u8; 16];
            address.copy_from_slice(&packet[4..20]);
            let port = u16::from_be_bytes([packet[20], packet[21]]);
            (
                std::net::SocketAddr::from((address, port)),
                packet[22..].to_vec(),
            )
        }
        _ => panic!("unexpected udp address type"),
    }
}
