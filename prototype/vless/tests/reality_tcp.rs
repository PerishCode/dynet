use std::{env, net::SocketAddr, time::Duration};

use native_tls::TlsConnector as NativeTlsConnector;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time;
use tokio_native_tls::TlsConnector;
use vless_prototype::{Client, ClientConfig};

#[tokio::test]
#[ignore = "requires live VLESS Reality node credentials in DYNET_VLESS_* env vars"]
async fn live_tcp_smoke() {
    let client = Client::try_new(ClientConfig {
        server: env_required("DYNET_VLESS_SERVER"),
        port: env_required("DYNET_VLESS_PORT").parse().expect("port"),
        uuid: env_required("DYNET_VLESS_UUID"),
        server_name: env_required("DYNET_VLESS_SERVER_NAME"),
        public_key: env_required("DYNET_VLESS_PUBLIC_KEY"),
        short_id: env_required("DYNET_VLESS_SHORT_ID"),
    })
    .expect("client");
    let target: SocketAddr = "1.1.1.1:443".parse().expect("target");
    let (_parts, stream) = client
        .connect_tcp_stream(target)
        .await
        .expect("connect tcp");
    let connector = TlsConnector::from(NativeTlsConnector::new().expect("tls connector"));
    let mut tls = time::timeout(
        Duration::from_secs(10),
        connector.connect("cloudflare-dns.com", stream),
    )
    .await
    .expect("tls timeout")
    .expect("tls connect");
    tls.write_all(b"GET / HTTP/1.0\r\nHost: cloudflare-dns.com\r\nConnection: close\r\n\r\n")
        .await
        .expect("write request");

    let mut response = vec![0_u8; 1024];
    let read = time::timeout(Duration::from_secs(10), tls.read(&mut response))
        .await
        .expect("read timeout")
        .expect("read response");
    assert!(read > 0);
    assert!(
        response[..read].starts_with(b"HTTP/"),
        "unexpected response prefix: {:?}",
        &response[..read.min(16)]
    );
}

fn env_required(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("{name} is required"))
}
