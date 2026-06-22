mod support;

use std::time::Duration;

use dynet_ingress::{run_tcp, TcpRelayConfig};
use dynet_runtime::{IngressEventKind, RuntimeState};
use support::{
    count_kind, event_field, event_fields, local_addr, unused_tcp_addr, wait_for_count,
    wait_for_event,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time,
};

#[tokio::test]
async fn relay_loop() {
    let upstream = TcpListener::bind(local_addr())
        .await
        .expect("bind upstream");
    let upstream_addr = upstream.local_addr().expect("upstream addr");
    tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.expect("accept upstream");
        let mut buffer = [0_u8; 1024];
        let _ = stream.read(&mut buffer).await.expect("read request");
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
            .await
            .expect("write response");
    });

    let bind = unused_tcp_addr().await;
    let runtime = RuntimeState::default();
    let events = runtime.events().clone();
    tokio::spawn(run_tcp(
        TcpRelayConfig {
            bind,
            upstream: upstream_addr,
            ..TcpRelayConfig::default()
        },
        runtime,
    ));
    time::sleep(Duration::from_millis(25)).await;

    let mut client = TcpStream::connect(bind).await.expect("connect relay");
    client
        .write_all(b"GET / HTTP/1.1\r\nhost: example.test\r\n\r\n")
        .await
        .expect("write request");
    client.shutdown().await.expect("shutdown request");
    let mut response = Vec::new();
    time::timeout(Duration::from_secs(2), client.read_to_end(&mut response))
        .await
        .expect("response timeout")
        .expect("read response");

    assert!(String::from_utf8_lossy(&response).contains("200 OK"));
    let kinds = wait_for_event(&events, IngressEventKind::TcpClose).await;
    assert!(kinds.contains(&IngressEventKind::TcpAccept));
    assert!(kinds.contains(&IngressEventKind::TcpClose));
    assert_eq!(
        event_field(&events, IngressEventKind::TcpAccept, "upstreamIp"),
        upstream_addr.ip().to_string()
    );
    assert_eq!(
        event_field(&events, IngressEventKind::TcpAccept, "upstreamPort"),
        upstream_addr.port().to_string()
    );
    assert_eq!(
        event_field(&events, IngressEventKind::TcpAccept, "inbound"),
        "tcp"
    );
    assert_eq!(
        event_field(&events, IngressEventKind::TcpAccept, "nodeProtocol"),
        "direct"
    );
    assert_eq!(
        event_field(&events, IngressEventKind::TcpAccept, "targetIp"),
        upstream_addr.ip().to_string()
    );
    assert_eq!(
        event_field(&events, IngressEventKind::TcpAccept, "nodeId"),
        "default-node"
    );
    assert_eq!(
        event_field(&events, IngressEventKind::TcpAccept, "selectionTrace"),
        "default:default-node->direct"
    );
    assert_eq!(
        event_field(&events, IngressEventKind::TcpAccept, "terminalEgress"),
        "direct"
    );
    assert_eq!(
        event_field(&events, IngressEventKind::TcpAccept, "terminalKind"),
        "direct"
    );
    assert_eq!(
        event_field(&events, IngressEventKind::TcpAccept, "selectionReason"),
        "single-node"
    );
    assert!(!event_field(&events, IngressEventKind::TcpAccept, "decisionId").is_empty());
    let accept_session = event_field(&events, IngressEventKind::TcpAccept, "sessionId");
    let close_session = event_field(&events, IngressEventKind::TcpClose, "sessionId");
    assert!(!accept_session.is_empty());
    assert_eq!(accept_session, close_session);
}

#[tokio::test]
async fn payload_transparency() {
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
    tokio::spawn(run_tcp(
        TcpRelayConfig {
            bind,
            upstream: upstream_addr,
            ..TcpRelayConfig::default()
        },
        runtime,
    ));
    time::sleep(Duration::from_millis(25)).await;

    let payload = b"opaque tcp bytes\0with binary tail".to_vec();
    let mut client = TcpStream::connect(bind).await.expect("connect relay");
    client.write_all(&payload).await.expect("write payload");
    client.shutdown().await.expect("shutdown payload");
    let mut response = Vec::new();
    time::timeout(Duration::from_secs(2), client.read_to_end(&mut response))
        .await
        .expect("response timeout")
        .expect("read response");

    assert_eq!(response, payload);
    assert_eq!(
        event_field(&events, IngressEventKind::TcpClose, "clientToUpstreamBytes"),
        payload.len().to_string()
    );
    assert_eq!(
        event_field(&events, IngressEventKind::TcpClose, "upstreamToClientBytes"),
        payload.len().to_string()
    );
    assert_eq!(
        event_field(&events, IngressEventKind::TcpClose, "closeReason"),
        "normal"
    );
}

#[tokio::test]
async fn concurrent_clients() {
    let upstream = TcpListener::bind(local_addr())
        .await
        .expect("bind upstream");
    let upstream_addr = upstream.local_addr().expect("upstream addr");
    tokio::spawn(async move {
        for _ in 0..4 {
            let (mut stream, _) = upstream.accept().await.expect("accept upstream");
            tokio::spawn(async move {
                let mut request = Vec::new();
                stream
                    .read_to_end(&mut request)
                    .await
                    .expect("read request");
                stream.write_all(&request).await.expect("write response");
            });
        }
    });

    let bind = unused_tcp_addr().await;
    let runtime = RuntimeState::default();
    let events = runtime.events().clone();
    tokio::spawn(run_tcp(
        TcpRelayConfig {
            bind,
            upstream: upstream_addr,
            ..TcpRelayConfig::default()
        },
        runtime,
    ));
    time::sleep(Duration::from_millis(25)).await;

    let mut clients = Vec::new();
    for index in 0..4 {
        clients.push(tokio::spawn(async move {
            let payload = format!("client-{index}").into_bytes();
            let mut client = TcpStream::connect(bind).await.expect("connect relay");
            client.write_all(&payload).await.expect("write payload");
            client.shutdown().await.expect("shutdown payload");
            let mut response = Vec::new();
            client
                .read_to_end(&mut response)
                .await
                .expect("read response");
            assert_eq!(response, payload);
        }));
    }
    for client in clients {
        client.await.expect("client task");
    }
    let kinds = wait_for_count(&events, IngressEventKind::TcpClose, 4).await;

    assert_eq!(count_kind(&kinds, IngressEventKind::TcpAccept), 4);
    assert_eq!(count_kind(&kinds, IngressEventKind::TcpClose), 4);
    let session_ids = event_fields(&events, IngressEventKind::TcpAccept)
        .into_iter()
        .map(|fields| fields.get("sessionId").cloned().unwrap_or_default())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(session_ids.len(), 4);
}

#[tokio::test]
async fn upstream_error_event() {
    let bind = unused_tcp_addr().await;
    let runtime = RuntimeState::default();
    let events = runtime.events().clone();
    tokio::spawn(run_tcp(
        TcpRelayConfig {
            bind,
            upstream: unused_tcp_addr().await,
            ..TcpRelayConfig::default()
        },
        runtime,
    ));
    time::sleep(Duration::from_millis(25)).await;

    let mut client = TcpStream::connect(bind).await.expect("connect relay");
    client.write_all(b"hello").await.expect("write payload");
    let kinds = wait_for_event(&events, IngressEventKind::TcpError).await;

    assert!(kinds.contains(&IngressEventKind::TcpAccept));
    assert!(kinds.contains(&IngressEventKind::TcpError));
    assert_eq!(
        event_field(&events, IngressEventKind::TcpError, "errorStage"),
        "egress-connect"
    );
    assert_eq!(
        event_field(&events, IngressEventKind::TcpError, "nodeProtocol"),
        "direct"
    );
    assert_eq!(
        event_field(&events, IngressEventKind::TcpError, "errorCode"),
        "connect-failed"
    );
    assert_eq!(
        event_field(&events, IngressEventKind::TcpError, "errorClass"),
        "connect-failed"
    );
    assert_eq!(
        event_field(&events, IngressEventKind::TcpError, "errorPhase"),
        "connect"
    );
    assert_eq!(
        event_field(&events, IngressEventKind::TcpError, "errorScoreImpact"),
        "hard-failure"
    );
}

#[tokio::test]
async fn max_sessions_capacity_error() {
    let upstream = TcpListener::bind(local_addr())
        .await
        .expect("bind upstream");
    let upstream_addr = upstream.local_addr().expect("upstream addr");
    let (release_tx, release_rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        let (_stream, _) = upstream.accept().await.expect("accept upstream");
        let _ = release_rx.await;
    });

    let bind = unused_tcp_addr().await;
    let runtime = RuntimeState::default();
    let events = runtime.events().clone();
    tokio::spawn(run_tcp(
        TcpRelayConfig {
            bind,
            upstream: upstream_addr,
            max_sessions: 1,
        },
        runtime,
    ));
    time::sleep(Duration::from_millis(25)).await;

    let _first = TcpStream::connect(bind).await.expect("connect first");
    let _ = wait_for_event(&events, IngressEventKind::TcpAccept).await;
    let mut second = TcpStream::connect(bind).await.expect("connect second");
    let _ = second.write_all(b"over-limit").await;
    let kinds = wait_for_event(&events, IngressEventKind::TcpError).await;
    let _ = release_tx.send(());

    assert!(kinds.contains(&IngressEventKind::TcpError));
    assert_eq!(
        event_field(&events, IngressEventKind::TcpError, "errorStage"),
        "inbound-capacity"
    );
    assert_eq!(
        event_field(&events, IngressEventKind::TcpError, "maxSessions"),
        "1"
    );
}
