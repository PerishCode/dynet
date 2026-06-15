mod support;

use std::time::Duration;

use dynet_ingress::{run_dns, DnsRelayConfig, EventStore, IngressEventKind};
use support::{event_field, event_kinds, local_addr, unused_udp_addr, wait_for_event};
use tokio::{net::UdpSocket, time};

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
    let events = EventStore::default();
    tokio::spawn(run_dns(
        DnsRelayConfig {
            bind,
            upstream: upstream_addr,
            timeout: Duration::from_secs(2),
        },
        events.clone(),
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
    let events = EventStore::default();
    tokio::spawn(run_dns(
        DnsRelayConfig {
            bind,
            upstream: upstream_addr,
            timeout: Duration::from_secs(2),
        },
        events.clone(),
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
    let events = EventStore::default();
    tokio::spawn(run_dns(
        DnsRelayConfig {
            bind,
            upstream: upstream_addr,
            timeout: Duration::from_secs(2),
        },
        events.clone(),
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

#[tokio::test]
async fn timeout_event() {
    let bind = unused_udp_addr().await;
    let events = EventStore::default();
    tokio::spawn(run_dns(
        DnsRelayConfig {
            bind,
            upstream: unused_udp_addr().await,
            timeout: Duration::from_millis(25),
        },
        events.clone(),
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
    let events = EventStore::default();
    tokio::spawn(run_dns(
        DnsRelayConfig {
            bind,
            upstream: upstream_addr,
            timeout: Duration::from_millis(25),
        },
        events.clone(),
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
