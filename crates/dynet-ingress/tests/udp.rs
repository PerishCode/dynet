mod support;

use std::time::Duration;

use dynet_ingress::{run_udp, EventStore, IngressEventKind, UdpRelayConfig};
use support::{
    count_kind, event_field, event_fields, event_kinds, local_addr, udp_roundtrip,
    udp_roundtrip_with, unused_udp_addr, wait_for_count, wait_for_event,
};
use tokio::{net::UdpSocket, time};

#[tokio::test]
async fn relay_loop() {
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

    let bind = unused_udp_addr().await;
    let events = EventStore::default();
    tokio::spawn(run_udp(
        UdpRelayConfig {
            bind,
            upstream: upstream_addr,
            idle_timeout: Duration::from_secs(2),
            ..UdpRelayConfig::default()
        },
        events.clone(),
    ));
    time::sleep(Duration::from_millis(25)).await;

    let client = UdpSocket::bind(local_addr()).await.expect("bind client");
    client
        .send_to(b"udp-packet", bind)
        .await
        .expect("send packet");
    let mut buffer = [0_u8; 1024];
    let (size, _) = time::timeout(Duration::from_secs(2), client.recv_from(&mut buffer))
        .await
        .expect("response timeout")
        .expect("receive response");

    assert_eq!(&buffer[..size], b"udp-packet");
    let kinds = event_kinds(&events);
    assert!(kinds.contains(&IngressEventKind::UdpSessionStart));
    assert!(kinds.contains(&IngressEventKind::UdpDatagram));
    assert_eq!(
        event_field(&events, IngressEventKind::UdpSessionStart, "upstreamIp"),
        upstream_addr.ip().to_string()
    );
    assert_eq!(
        event_field(&events, IngressEventKind::UdpSessionStart, "upstreamPort"),
        upstream_addr.port().to_string()
    );
    assert_eq!(
        event_field(&events, IngressEventKind::UdpSessionStart, "inbound"),
        "udp"
    );
    assert_eq!(
        event_field(&events, IngressEventKind::UdpSessionStart, "outbound"),
        "direct"
    );
    assert_eq!(
        event_field(&events, IngressEventKind::UdpSessionStart, "targetIp"),
        upstream_addr.ip().to_string()
    );
    assert!(!event_field(&events, IngressEventKind::UdpDatagram, "sessionId").is_empty());
}

#[tokio::test]
async fn multi_client_isolation() {
    let upstream = UdpSocket::bind(local_addr()).await.expect("bind upstream");
    let upstream_addr = upstream.local_addr().expect("upstream addr");
    tokio::spawn(async move {
        for _ in 0..2 {
            let mut buffer = [0_u8; 1024];
            let (size, peer) = upstream.recv_from(&mut buffer).await.expect("recv request");
            upstream
                .send_to(&buffer[..size], peer)
                .await
                .expect("send response");
        }
    });

    let bind = unused_udp_addr().await;
    let events = EventStore::default();
    tokio::spawn(run_udp(
        UdpRelayConfig {
            bind,
            upstream: upstream_addr,
            idle_timeout: Duration::from_secs(2),
            ..UdpRelayConfig::default()
        },
        events.clone(),
    ));
    time::sleep(Duration::from_millis(25)).await;

    let first = tokio::spawn(udp_roundtrip(bind, b"first-client".to_vec()));
    let second = tokio::spawn(udp_roundtrip(bind, b"second-client".to_vec()));

    assert_eq!(first.await.expect("first client"), b"first-client");
    assert_eq!(second.await.expect("second client"), b"second-client");
    let kinds = wait_for_count(&events, IngressEventKind::UdpSessionStart, 2).await;
    assert_eq!(count_kind(&kinds, IngressEventKind::UdpSessionStart), 2);
}

#[tokio::test]
async fn same_client_reuse() {
    let upstream = UdpSocket::bind(local_addr()).await.expect("bind upstream");
    let upstream_addr = upstream.local_addr().expect("upstream addr");
    tokio::spawn(async move {
        let mut upstream_peer = None;
        for _ in 0..2 {
            let mut buffer = [0_u8; 1024];
            let (size, peer) = upstream.recv_from(&mut buffer).await.expect("recv request");
            if let Some(previous) = upstream_peer {
                assert_eq!(previous, peer);
            }
            upstream_peer = Some(peer);
            upstream
                .send_to(&buffer[..size], peer)
                .await
                .expect("send response");
        }
    });

    let bind = unused_udp_addr().await;
    let events = EventStore::default();
    tokio::spawn(run_udp(
        UdpRelayConfig {
            bind,
            upstream: upstream_addr,
            idle_timeout: Duration::from_secs(2),
            ..UdpRelayConfig::default()
        },
        events.clone(),
    ));
    time::sleep(Duration::from_millis(25)).await;

    let client = UdpSocket::bind(local_addr()).await.expect("bind client");
    assert_eq!(udp_roundtrip_with(&client, bind, b"first").await, b"first");
    assert_eq!(
        udp_roundtrip_with(&client, bind, b"second").await,
        b"second"
    );
    let kinds = wait_for_count(&events, IngressEventKind::UdpDatagram, 4).await;

    assert_eq!(count_kind(&kinds, IngressEventKind::UdpSessionStart), 1);
    let session_ids = event_fields(&events, IngressEventKind::UdpDatagram)
        .into_iter()
        .map(|fields| fields.get("sessionId").cloned().unwrap_or_default())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(session_ids.len(), 1);
}

#[tokio::test]
async fn idle_close_event() {
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

    let bind = unused_udp_addr().await;
    let events = EventStore::default();
    tokio::spawn(run_udp(
        UdpRelayConfig {
            bind,
            upstream: upstream_addr,
            idle_timeout: Duration::from_millis(25),
            ..UdpRelayConfig::default()
        },
        events.clone(),
    ));
    time::sleep(Duration::from_millis(25)).await;

    assert_eq!(
        udp_roundtrip(bind, b"idle-close".to_vec()).await,
        b"idle-close"
    );
    let kinds = wait_for_event(&events, IngressEventKind::UdpSessionClose).await;

    assert!(kinds.contains(&IngressEventKind::UdpSessionStart));
    assert!(kinds.contains(&IngressEventKind::UdpSessionClose));
    assert_eq!(
        event_field(&events, IngressEventKind::UdpSessionClose, "closeReason"),
        "idle-timeout"
    );
}

#[tokio::test]
async fn max_sessions_capacity_error() {
    let upstream = UdpSocket::bind(local_addr()).await.expect("bind upstream");
    let upstream_addr = upstream.local_addr().expect("upstream addr");
    tokio::spawn(async move {
        let mut buffer = [0_u8; 1024];
        let _ = upstream.recv_from(&mut buffer).await.expect("recv request");
    });

    let bind = unused_udp_addr().await;
    let events = EventStore::default();
    tokio::spawn(run_udp(
        UdpRelayConfig {
            bind,
            upstream: upstream_addr,
            idle_timeout: Duration::from_secs(2),
            max_sessions: 1,
        },
        events.clone(),
    ));
    time::sleep(Duration::from_millis(25)).await;

    let first = UdpSocket::bind(local_addr()).await.expect("bind first");
    first.send_to(b"first", bind).await.expect("send first");
    let _ = wait_for_event(&events, IngressEventKind::UdpSessionStart).await;
    let second = UdpSocket::bind(local_addr()).await.expect("bind second");
    second.send_to(b"second", bind).await.expect("send second");
    let kinds = wait_for_event(&events, IngressEventKind::UdpError).await;

    assert!(kinds.contains(&IngressEventKind::UdpError));
    assert_eq!(
        event_field(&events, IngressEventKind::UdpError, "errorStage"),
        "inbound-capacity"
    );
    assert_eq!(
        event_field(&events, IngressEventKind::UdpError, "maxSessions"),
        "1"
    );
}
