use std::{env, net::SocketAddr, time::Duration};

use tokio::time;
use vless_prototype::{Client, ClientConfig};

#[tokio::test]
#[ignore = "requires live VLESS Reality node credentials in DYNET_VLESS_* env vars"]
async fn live_udp_smoke() {
    let client = Client::try_new(ClientConfig {
        server: env_required("DYNET_VLESS_SERVER"),
        port: env_required("DYNET_VLESS_PORT").parse().expect("port"),
        uuid: env_required("DYNET_VLESS_UUID"),
        server_name: env_required("DYNET_VLESS_SERVER_NAME"),
        public_key: env_required("DYNET_VLESS_PUBLIC_KEY"),
        short_id: env_required("DYNET_VLESS_SHORT_ID"),
    })
    .expect("client");
    let target: SocketAddr = "1.1.1.1:53".parse().expect("target");
    let (_parts, mut reader, mut writer) = client.connect_udp(target).await.expect("connect udp");
    writer
        .write_datagram(&dns_query_example_a())
        .await
        .expect("write dns");
    let response = time::timeout(Duration::from_secs(10), reader.read_datagram())
        .await
        .expect("dns timeout")
        .expect("read dns");
    assert!(response.len() >= 12);
    assert_eq!(&response[0..2], &[0x12, 0x34]);
}

fn env_required(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("{name} is required"))
}

fn dns_query_example_a() -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&0x1234_u16.to_be_bytes());
    packet.extend_from_slice(&0x0100_u16.to_be_bytes());
    packet.extend_from_slice(&1_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.push(7);
    packet.extend_from_slice(b"example");
    packet.push(3);
    packet.extend_from_slice(b"com");
    packet.push(0);
    packet.extend_from_slice(&1_u16.to_be_bytes());
    packet.extend_from_slice(&1_u16.to_be_bytes());
    packet
}
