mod support;

use std::time::Duration;

use dynet_ingress::{run_tcp, EventStore, IngressEventKind, TcpRelayConfig};
use support::{
    count_kind, event_field, local_addr, unused_tcp_addr, wait_for_count, wait_for_event,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
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
    let events = EventStore::default();
    tokio::spawn(run_tcp(
        TcpRelayConfig {
            bind,
            upstream: upstream_addr,
        },
        events.clone(),
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
    let events = EventStore::default();
    tokio::spawn(run_tcp(
        TcpRelayConfig {
            bind,
            upstream: upstream_addr,
        },
        events.clone(),
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
    let events = EventStore::default();
    tokio::spawn(run_tcp(
        TcpRelayConfig {
            bind,
            upstream: upstream_addr,
        },
        events.clone(),
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
}

#[tokio::test]
async fn upstream_error_event() {
    let bind = unused_tcp_addr().await;
    let events = EventStore::default();
    tokio::spawn(run_tcp(
        TcpRelayConfig {
            bind,
            upstream: unused_tcp_addr().await,
        },
        events.clone(),
    ));
    time::sleep(Duration::from_millis(25)).await;

    let mut client = TcpStream::connect(bind).await.expect("connect relay");
    client.write_all(b"hello").await.expect("write payload");
    let kinds = wait_for_event(&events, IngressEventKind::TcpError).await;

    assert!(kinds.contains(&IngressEventKind::TcpAccept));
    assert!(kinds.contains(&IngressEventKind::TcpError));
}
