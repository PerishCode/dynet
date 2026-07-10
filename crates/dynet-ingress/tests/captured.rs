mod support;

use std::{collections::BTreeMap, net::SocketAddr, time::Duration};

use dynet_ingress::{
    relay_captured_tcp_graph, relay_captured_udp_graph, EgressNodeConfig, ReloadableEgress,
    ShadowsocksConfig, ShadowsocksMethod,
};
use dynet_runtime::{
    GroupId, IngressEventKind, Ipv6RulePolicy, RouteMatcher, RouteRule, RuleId, RuntimeSeed,
    RuntimeState,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};

#[tokio::test]
async fn captured_tcp_graph() {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind tcp target");
    let target = listener.local_addr().expect("target addr");
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept tcp target");
        let mut request = [0_u8; 4];
        stream.read_exact(&mut request).await.expect("read request");
        assert_eq!(&request, b"ping");
        stream.write_all(b"pong").await.expect("write response");
        stream.shutdown().await.expect("shutdown response");
    });

    let runtime = RuntimeState::from_seed(RuntimeSeed::single_node("direct"));
    let (mut client, captured) = tokio::io::duplex(1024);
    let relay = tokio::spawn(relay_captured_tcp_graph(
        captured,
        SocketAddr::from(([127, 0, 0, 1], 40_000)),
        target,
        direct_nodes(),
        runtime.clone(),
        Duration::from_millis(200),
    ));

    client.write_all(b"ping").await.expect("write captured");
    let mut response = [0_u8; 4];
    client
        .read_exact(&mut response)
        .await
        .expect("read captured response");
    assert_eq!(&response, b"pong");
    drop(client);

    let outcome = relay.await.expect("relay task").expect("relay succeeds");
    assert_eq!(outcome.target, target);
    assert_eq!(outcome.client_to_upstream_bytes, 4);
    assert_eq!(outcome.upstream_to_client_bytes, 4);

    let events = runtime.events().snapshot();
    assert!(events
        .iter()
        .any(|event| event.kind == IngressEventKind::TcpAccept
            && event.fields.get("inbound").map(String::as_str) == Some("tun")));
    assert!(events
        .iter()
        .any(|event| event.kind == IngressEventKind::TcpClose
            && event.fields.get("inbound").map(String::as_str) == Some("tun")));
}

#[tokio::test]
async fn captured_tcp_protocol_idle() {
    let upstream = support::spawn_ss_open_reply("password", b"pong").await;
    let runtime = RuntimeState::from_seed(RuntimeSeed::single_node("ss"));
    let (mut client, captured) = tokio::io::duplex(1024);
    let relay = tokio::spawn(relay_captured_tcp_graph(
        captured,
        SocketAddr::from(([127, 0, 0, 1], 40_002)),
        SocketAddr::from(([127, 0, 0, 1], 80)),
        ss_nodes(upstream),
        runtime.clone(),
        Duration::from_millis(25),
    ));

    client.write_all(b"ping").await.expect("write captured");
    let mut response = [0_u8; 4];
    client
        .read_exact(&mut response)
        .await
        .expect("read captured response");
    assert_eq!(&response, b"pong");

    let outcome = relay.await.expect("relay task").expect("relay succeeds");
    assert_eq!(outcome.client_to_upstream_bytes, 4);
    assert_eq!(outcome.upstream_to_client_bytes, 4);
    assert_eq!(outcome.close_reason, "idle-timeout");

    let events = runtime.events().snapshot();
    assert!(events.iter().any(|event| {
        event.kind == IngressEventKind::TcpClose
            && event.fields.get("nodeProtocol").map(String::as_str) == Some("ss")
            && event.fields.get("closeReason").map(String::as_str) == Some("idle-timeout")
    }));
}

#[tokio::test]
async fn captured_ipv6_tcp_direct() {
    let listener = TcpListener::bind("[::1]:0")
        .await
        .expect("bind IPv6 tcp target");
    let target = listener.local_addr().expect("IPv6 target addr");
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept IPv6 target");
        let mut request = [0_u8; 4];
        stream.read_exact(&mut request).await.expect("read request");
        stream.write_all(b"pong").await.expect("write response");
    });
    let mut seed = RuntimeSeed::single_node("direct");
    seed.ipv6_enabled = true;
    let runtime = RuntimeState::from_seed(seed);
    let (mut client, captured) = tokio::io::duplex(1024);
    let relay = tokio::spawn(relay_captured_tcp_graph(
        captured,
        "[::1]:40002".parse().expect("IPv6 peer"),
        target,
        direct_nodes(),
        runtime,
        Duration::from_millis(200),
    ));

    client.write_all(b"ping").await.expect("write captured");
    let mut response = [0_u8; 4];
    client
        .read_exact(&mut response)
        .await
        .expect("read response");

    assert_eq!(&response, b"pong");
    assert_eq!(
        relay
            .await
            .expect("relay task")
            .expect("relay succeeds")
            .target,
        target
    );
}

#[tokio::test]
async fn captured_udp_graph() {
    let upstream = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind udp target");
    let target = upstream.local_addr().expect("udp target addr");
    tokio::spawn(async move {
        let mut buffer = [0_u8; 64];
        let (size, peer) = upstream.recv_from(&mut buffer).await.expect("udp request");
        assert_eq!(&buffer[..size], b"query");
        upstream
            .send_to(b"answer", peer)
            .await
            .expect("udp response");
    });

    let runtime = RuntimeState::from_seed(RuntimeSeed::single_node("direct"));
    let (mut client, captured) = tokio::io::duplex(1024);
    let relay = tokio::spawn(relay_captured_udp_graph(
        captured,
        SocketAddr::from(([127, 0, 0, 1], 40_001)),
        target,
        direct_nodes(),
        runtime.clone(),
        Duration::from_millis(200),
        Duration::from_secs(1),
    ));

    client.write_all(b"query").await.expect("write udp query");
    let mut response = [0_u8; 6];
    client
        .read_exact(&mut response)
        .await
        .expect("read udp response");
    assert_eq!(&response, b"answer");

    let outcome = relay.await.expect("relay task").expect("relay succeeds");
    assert_eq!(outcome.target, target);
    assert_eq!(outcome.request_bytes, 5);
    assert_eq!(outcome.response_bytes, 6);

    let events = runtime.events().snapshot();
    assert!(events
        .iter()
        .any(|event| event.kind == IngressEventKind::UdpDatagram
            && event.fields.get("inbound").map(String::as_str) == Some("tun")));
    assert!(events
        .iter()
        .any(|event| event.kind == IngressEventKind::UdpSessionClose
            && event.fields.get("inbound").map(String::as_str) == Some("tun")));
}

#[tokio::test]
async fn captured_ipv6_udp_direct() {
    let upstream = UdpSocket::bind("[::1]:0")
        .await
        .expect("bind IPv6 udp target");
    let target = upstream.local_addr().expect("IPv6 udp target");
    tokio::spawn(async move {
        let mut buffer = [0_u8; 64];
        let (size, peer) = upstream.recv_from(&mut buffer).await.expect("udp request");
        assert_eq!(&buffer[..size], b"query");
        upstream
            .send_to(b"answer", peer)
            .await
            .expect("udp response");
    });
    let mut seed = RuntimeSeed::single_node("direct");
    seed.ipv6_enabled = true;
    let runtime = RuntimeState::from_seed(seed);
    let (mut client, captured) = tokio::io::duplex(1024);
    let relay = tokio::spawn(relay_captured_udp_graph(
        captured,
        "[::1]:40003".parse().expect("IPv6 peer"),
        target,
        direct_nodes(),
        runtime,
        Duration::from_millis(200),
        Duration::from_secs(1),
    ));

    client.write_all(b"query").await.expect("write query");
    let mut response = [0_u8; 6];
    client
        .read_exact(&mut response)
        .await
        .expect("read response");

    assert_eq!(&response, b"answer");
    assert_eq!(
        relay
            .await
            .expect("relay task")
            .expect("relay succeeds")
            .target,
        target
    );
}

#[tokio::test]
async fn captured_ipv6_deny_observable() {
    let target: SocketAddr = "[2001:db8::10]:443".parse().expect("IPv6 target");
    let mut seed = RuntimeSeed::single_node("direct");
    seed.ipv6_enabled = true;
    seed.route_rules = vec![RouteRule {
        id: RuleId::new("deny-v6-target"),
        priority: 100,
        enabled: true,
        matcher: RouteMatcher::IpExact(target.ip()),
        group_id: GroupId::new("default"),
        ipv6: Ipv6RulePolicy::Deny,
    }];
    let runtime = RuntimeState::from_seed(seed);
    let (_client, captured) = tokio::io::duplex(1024);

    let error = relay_captured_tcp_graph(
        captured,
        "[2001:db8::20]:40000".parse().expect("IPv6 peer"),
        target,
        direct_nodes(),
        runtime.clone(),
        Duration::from_millis(200),
    )
    .await
    .expect_err("IPv6 rule denies selection");

    assert!(error.contains("deny-v6-target"));
    let event = runtime
        .events()
        .snapshot()
        .into_iter()
        .find(|event| event.kind == IngressEventKind::TcpError)
        .expect("selection error event");
    assert_eq!(
        event.fields.get("errorCode").map(String::as_str),
        Some("ipv6-policy-deny")
    );
    assert_eq!(
        event.fields.get("matchedRuleId").map(String::as_str),
        Some("deny-v6-target")
    );
    assert_eq!(
        event.fields.get("ipFamily").map(String::as_str),
        Some("ipv6")
    );
}

fn direct_nodes() -> BTreeMap<String, EgressNodeConfig> {
    BTreeMap::from([("default-node".to_string(), EgressNodeConfig::Direct)])
}

#[test]
fn installs_generations() {
    let egress = ReloadableEgress::new(1, direct_nodes()).expect("initial graph");
    egress.install(2, direct_nodes()).expect("next graph");

    assert_eq!(egress.generations(), [1, 2]);
}

#[test]
fn bounds_generations() {
    let egress = ReloadableEgress::new(1, direct_nodes()).expect("initial graph");
    for generation in 2..=12 {
        egress
            .install(generation, direct_nodes())
            .expect("generation installs");
    }

    assert_eq!(egress.generations(), (5..=12).collect::<Vec<_>>());
}

fn ss_nodes(upstream: SocketAddr) -> BTreeMap<String, EgressNodeConfig> {
    BTreeMap::from([(
        "default-node".to_string(),
        EgressNodeConfig::Shadowsocks(ShadowsocksConfig {
            server: upstream.ip().to_string(),
            port: upstream.port(),
            method: ShadowsocksMethod::Aes256Gcm,
            password: "password".to_string(),
        }),
    )])
}
