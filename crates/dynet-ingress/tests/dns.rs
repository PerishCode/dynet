mod support;

use std::{net::SocketAddr, time::Duration};

use dynet_ingress::{run_dns, DnsRelayConfig};
use dynet_runtime::{
    DnsRacePolicy, DnsRaceStrategy, DnsUpstream, DnsUpstreamId, DnsUpstreamTransport, GroupId,
    IngressEventKind, Ipv6RulePolicy, RouteMatcher, RouteRule, RuleId, RuntimeSeed, RuntimeState,
};
use support::{event_field, event_kinds, local_addr, unused_udp_addr, wait_for_event};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time,
};

#[tokio::test]
async fn relay_loop() {
    let upstream = UdpSocket::bind(local_addr()).await.expect("bind upstream");
    let upstream_addr = upstream.local_addr().expect("upstream addr");
    tokio::spawn(async move {
        let mut buffer = [0_u8; 1024];
        let (size, peer) = upstream.recv_from(&mut buffer).await.expect("recv query");
        upstream
            .send_to(&buffer[..size], peer)
            .await
            .expect("send response");
    });

    let bind = unused_udp_addr().await;
    let runtime = runtime_with_dns(upstream_addr);
    let events = runtime.events().clone();
    tokio::spawn(run_dns(
        DnsRelayConfig {
            bind,
            ..DnsRelayConfig::default()
        },
        runtime,
    ));
    time::sleep(Duration::from_millis(25)).await;

    let client = UdpSocket::bind(local_addr()).await.expect("bind client");
    client
        .send_to(b"dns-query", bind)
        .await
        .expect("send query");
    let mut buffer = [0_u8; 1024];
    let (size, _) = time::timeout(Duration::from_secs(2), client.recv_from(&mut buffer))
        .await
        .expect("response timeout")
        .expect("receive response");

    assert_eq!(&buffer[..size], b"dns-query");
    let kinds = event_kinds(&events);
    assert!(kinds.contains(&IngressEventKind::DnsQuery));
    assert!(kinds.contains(&IngressEventKind::DnsResponse));
}

#[tokio::test]
async fn filters_denied_ipv6_aaaa() {
    let query = dns_aaaa_query();
    let response = dns_aaaa_response();
    let upstream = UdpSocket::bind(local_addr()).await.expect("bind upstream");
    let upstream_addr = upstream.local_addr().expect("upstream addr");
    tokio::spawn(async move {
        let mut buffer = [0_u8; 1024];
        let (_, peer) = upstream.recv_from(&mut buffer).await.expect("recv query");
        upstream
            .send_to(&response, peer)
            .await
            .expect("send response");
    });

    let bind = unused_udp_addr().await;
    let runtime = runtime_with_ipv6_deny(upstream_addr);
    let events = runtime.events().clone();
    tokio::spawn(run_dns(
        DnsRelayConfig {
            bind,
            ..DnsRelayConfig::default()
        },
        runtime,
    ));
    time::sleep(Duration::from_millis(25)).await;

    let client = UdpSocket::bind(local_addr()).await.expect("bind client");
    client.send_to(&query, bind).await.expect("send query");
    let mut buffer = [0_u8; 1024];
    let (size, _) = time::timeout(Duration::from_secs(2), client.recv_from(&mut buffer))
        .await
        .expect("response timeout")
        .expect("receive response");

    assert_eq!(u16::from_be_bytes([buffer[6], buffer[7]]), 0);
    assert_eq!(size, query.len());
    assert_eq!(
        event_field(&events, IngressEventKind::DnsResponse, "ipv6Policy"),
        "deny"
    );
    assert_eq!(
        event_field(&events, IngressEventKind::DnsResponse, "matchedRuleId"),
        "deny-v6-example"
    );
}

#[tokio::test]
async fn tcp_honors_ipv6_policy() {
    let query = dns_aaaa_query();
    let response = dns_aaaa_response();
    let upstream = UdpSocket::bind(local_addr()).await.expect("bind upstream");
    let upstream_addr = upstream.local_addr().expect("upstream addr");
    tokio::spawn(async move {
        let mut buffer = [0_u8; 1024];
        let (_, peer) = upstream.recv_from(&mut buffer).await.expect("recv query");
        upstream
            .send_to(&response, peer)
            .await
            .expect("send response");
    });

    let bind = unused_udp_addr().await;
    let runtime = runtime_with_ipv6_deny(upstream_addr);
    let events = runtime.events().clone();
    tokio::spawn(run_dns(
        DnsRelayConfig {
            bind,
            max_sessions: 4,
        },
        runtime,
    ));
    time::sleep(Duration::from_millis(25)).await;

    let mut client = TcpStream::connect(bind).await.expect("connect TCP DNS");
    client
        .write_all(
            &u16::try_from(query.len())
                .expect("query length")
                .to_be_bytes(),
        )
        .await
        .expect("write DNS length");
    client.write_all(&query).await.expect("write DNS query");
    let response_length = client.read_u16().await.expect("read DNS length");
    let mut response = vec![0_u8; usize::from(response_length)];
    client
        .read_exact(&mut response)
        .await
        .expect("read DNS response");

    assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
    assert_eq!(response.len(), query.len());
    assert_eq!(
        event_field(&events, IngressEventKind::DnsResponse, "transport"),
        "tcp"
    );
    assert_eq!(
        event_field(&events, IngressEventKind::DnsResponse, "matchedRuleId"),
        "deny-v6-example"
    );
}

#[tokio::test]
async fn sniffs_answer_ip() {
    let query = dns_query();
    let response = dns_a_response();
    let upstream = UdpSocket::bind(local_addr()).await.expect("bind upstream");
    let upstream_addr = upstream.local_addr().expect("upstream addr");
    tokio::spawn(async move {
        let mut buffer = [0_u8; 1024];
        let (_, peer) = upstream.recv_from(&mut buffer).await.expect("recv query");
        upstream
            .send_to(&response, peer)
            .await
            .expect("send response");
    });

    let bind = unused_udp_addr().await;
    let runtime = runtime_with_dns(upstream_addr);
    let events = runtime.events().clone();
    tokio::spawn(run_dns(
        DnsRelayConfig {
            bind,
            ..DnsRelayConfig::default()
        },
        runtime,
    ));
    time::sleep(Duration::from_millis(25)).await;

    let client = UdpSocket::bind(local_addr()).await.expect("bind client");
    client.send_to(&query, bind).await.expect("send query");
    let mut buffer = [0_u8; 1024];
    let _ = time::timeout(Duration::from_secs(2), client.recv_from(&mut buffer))
        .await
        .expect("response timeout")
        .expect("receive response");

    assert_eq!(
        event_field(&events, IngressEventKind::DnsQuery, "queryName"),
        "example.test"
    );
    assert_eq!(
        event_field(&events, IngressEventKind::DnsQuery, "queryType"),
        "A"
    );
    assert_eq!(
        event_field(&events, IngressEventKind::DnsResponse, "answerIps"),
        "203.0.113.7"
    );
}

#[tokio::test]
async fn preserves_wire() {
    let query = dns_query();
    let upstream = UdpSocket::bind(local_addr()).await.expect("bind upstream");
    let upstream_addr = upstream.local_addr().expect("upstream addr");
    let upstream_query = query.clone();
    tokio::spawn(async move {
        let mut buffer = [0_u8; 1024];
        let (size, peer) = upstream.recv_from(&mut buffer).await.expect("recv query");
        assert_eq!(&buffer[..size], upstream_query);
        upstream
            .send_to(&buffer[..size], peer)
            .await
            .expect("send response");
    });

    let bind = unused_udp_addr().await;
    let runtime = runtime_with_dns(upstream_addr);
    let events = runtime.events().clone();
    tokio::spawn(run_dns(
        DnsRelayConfig {
            bind,
            ..DnsRelayConfig::default()
        },
        runtime,
    ));
    time::sleep(Duration::from_millis(25)).await;

    let client = UdpSocket::bind(local_addr()).await.expect("bind client");
    client.send_to(&query, bind).await.expect("send query");
    let mut buffer = [0_u8; 1024];
    let (size, _) = time::timeout(Duration::from_secs(2), client.recv_from(&mut buffer))
        .await
        .expect("response timeout")
        .expect("receive response");

    assert_eq!(&buffer[..size], query);
    assert_eq!(
        event_field(&events, IngressEventKind::DnsQuery, "bytes"),
        "30"
    );
    assert_eq!(
        event_field(&events, IngressEventKind::DnsResponse, "bytes"),
        "30"
    );
}

fn dns_query() -> Vec<u8> {
    vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x04, b't', b'e', b's', b't', 0x00, 0x00, 0x01, 0x00, 0x01,
    ]
}

fn dns_a_response() -> Vec<u8> {
    vec![
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x04, b't', b'e', b's', b't', 0x00, 0x00, 0x01, 0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 203, 0, 113, 7,
    ]
}

fn dns_aaaa_query() -> Vec<u8> {
    let mut query = dns_query();
    let len = query.len();
    query[len - 4..len - 2].copy_from_slice(&28_u16.to_be_bytes());
    query
}

fn dns_aaaa_response() -> Vec<u8> {
    let mut response = dns_aaaa_query();
    response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
    response[6..8].copy_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&[
        0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x10,
    ]);
    response.extend_from_slice(
        &"2001:db8::53"
            .parse::<std::net::Ipv6Addr>()
            .expect("IPv6 answer")
            .octets(),
    );
    response
}

fn runtime_with_dns(upstream: SocketAddr) -> RuntimeState {
    runtime_with_dns_timeout(upstream, Duration::from_secs(2))
}

fn runtime_with_dns_timeout(upstream: SocketAddr, timeout: Duration) -> RuntimeState {
    RuntimeState::single_node_dns_policy(
        "direct",
        vec![DnsUpstream {
            id: DnsUpstreamId::new("test"),
            address: upstream,
            transport: DnsUpstreamTransport::Udp,
            enabled: true,
            priority: 0,
        }],
        DnsRacePolicy {
            timeout,
            strategy: DnsRaceStrategy::Parallel,
        },
    )
}

fn runtime_with_ipv6_deny(upstream: SocketAddr) -> RuntimeState {
    let mut seed = RuntimeSeed::single_node("direct");
    seed.ipv6_enabled = true;
    seed.dns_upstreams = vec![DnsUpstream {
        id: DnsUpstreamId::new("test"),
        address: upstream,
        transport: DnsUpstreamTransport::Udp,
        enabled: true,
        priority: 0,
    }];
    seed.route_rules = vec![RouteRule {
        id: RuleId::new("deny-v6-example"),
        priority: 100,
        enabled: true,
        matcher: RouteMatcher::DomainExact("example.test".to_string()),
        group_id: GroupId::new("default"),
        ipv6: Ipv6RulePolicy::Deny,
    }];
    RuntimeState::from_seed(seed)
}

#[tokio::test]
async fn timeout_event() {
    let bind = unused_udp_addr().await;
    let runtime = runtime_with_dns_timeout(unused_udp_addr().await, Duration::from_millis(25));
    let events = runtime.events().clone();
    tokio::spawn(run_dns(
        DnsRelayConfig {
            bind,
            ..DnsRelayConfig::default()
        },
        runtime,
    ));
    time::sleep(Duration::from_millis(25)).await;

    let client = UdpSocket::bind(local_addr()).await.expect("bind client");
    client
        .send_to(b"dns-timeout", bind)
        .await
        .expect("send query");
    let kinds = wait_for_event(&events, IngressEventKind::DnsError).await;

    assert!(kinds.contains(&IngressEventKind::DnsQuery));
    assert!(kinds.contains(&IngressEventKind::DnsError));
}

#[tokio::test]
async fn recovers_after_timeout() {
    let upstream_addr = unused_udp_addr().await;
    let bind = unused_udp_addr().await;
    let runtime = runtime_with_dns_timeout(upstream_addr, Duration::from_millis(25));
    let events = runtime.events().clone();
    tokio::spawn(run_dns(
        DnsRelayConfig {
            bind,
            ..DnsRelayConfig::default()
        },
        runtime,
    ));
    time::sleep(Duration::from_millis(25)).await;

    let client = UdpSocket::bind(local_addr()).await.expect("bind client");
    client
        .send_to(b"first-timeout", bind)
        .await
        .expect("send timeout query");
    let _ = wait_for_event(&events, IngressEventKind::DnsError).await;

    let upstream = UdpSocket::bind(upstream_addr)
        .await
        .expect("bind upstream after timeout");
    tokio::spawn(async move {
        let mut buffer = [0_u8; 1024];
        let (size, peer) = upstream.recv_from(&mut buffer).await.expect("recv query");
        upstream
            .send_to(&buffer[..size], peer)
            .await
            .expect("send response");
    });

    client
        .send_to(b"second-success", bind)
        .await
        .expect("send recovery query");
    let mut buffer = [0_u8; 1024];
    let (size, _) = time::timeout(Duration::from_secs(2), client.recv_from(&mut buffer))
        .await
        .expect("response timeout")
        .expect("receive response");
    let kinds = wait_for_event(&events, IngressEventKind::DnsResponse).await;

    assert_eq!(&buffer[..size], b"second-success");
    assert!(kinds.contains(&IngressEventKind::DnsError));
    assert!(kinds.contains(&IngressEventKind::DnsResponse));
}
