use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use tokio::{io::AsyncReadExt, net::TcpListener};
use vmess_prototype::{request_for_test, Client, ClientConfig};

const UUID: &str = "11111111-2222-3333-4444-555555555555";

#[test]
fn rejects_bad_uuid() {
    let error = Client::try_new(ClientConfig {
        server: "127.0.0.1".to_string(),
        port: 10086,
        uuid: "not-a-uuid".to_string(),
    })
    .unwrap_err();

    assert_eq!(error.stage(), "outbound-config");
}

#[test]
fn aead_request_shape() {
    let target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 80));
    let (request, _) = request_for_test(UUID, 0x01, target).unwrap();

    assert!(request.len() > 16 + 18 + 8 + 16);
    assert_eq!(request[16..34].len(), 18);
    assert_ne!(&request[..16], &[0_u8; 16]);
    assert_ne!(&request[34..42], &[0_u8; 8]);
}

#[tokio::test]
async fn tcp_request_preconnected() {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind server");
    let upstream_addr = listener.local_addr().expect("server addr");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept server");
        let mut prefix = [0_u8; 16];
        stream
            .read_exact(&mut prefix)
            .await
            .expect("read request prefix");
        prefix
    });

    let downstream_listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind downstream");
    let downstream_addr = downstream_listener.local_addr().expect("downstream addr");
    let downstream_client = tokio::net::TcpStream::connect(downstream_addr)
        .await
        .expect("connect downstream");
    let (downstream_server, _) = downstream_listener
        .accept()
        .await
        .expect("accept downstream");

    let client = Client::try_new(ClientConfig {
        server: upstream_addr.ip().to_string(),
        port: upstream_addr.port(),
        uuid: UUID.to_string(),
    })
    .expect("client");
    let upstream = tokio::net::TcpStream::connect(upstream_addr)
        .await
        .expect("connect upstream");
    let relay = tokio::spawn(async move {
        client
            .relay_tcp_with_stream(downstream_server, upstream_addr, upstream)
            .await
    });
    drop(downstream_client);

    let prefix = server.await.expect("server task");
    assert_ne!(prefix, [0_u8; 16]);
    let _ = relay.await.expect("relay task");
}
