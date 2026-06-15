#![allow(dead_code)]

use std::{collections::BTreeMap, net::SocketAddr, time::Duration};

use dynet_ingress::{EventStore, IngressEvent, IngressEventKind};
use tokio::{
    net::{TcpListener, UdpSocket},
    time,
};

pub fn local_addr() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 0))
}

pub async fn unused_tcp_addr() -> SocketAddr {
    let listener = TcpListener::bind(local_addr())
        .await
        .expect("bind tcp port");
    listener.local_addr().expect("tcp addr")
}

pub async fn unused_udp_addr() -> SocketAddr {
    let socket = UdpSocket::bind(local_addr()).await.expect("bind udp port");
    socket.local_addr().expect("udp addr")
}

pub fn event_kinds(events: &EventStore) -> Vec<IngressEventKind> {
    events
        .snapshot()
        .into_iter()
        .map(|event| event.kind)
        .collect()
}

pub fn event_field(events: &EventStore, kind: IngressEventKind, field: &str) -> String {
    events
        .snapshot()
        .into_iter()
        .find(|event| event.kind == kind)
        .and_then(|event| event.fields.get(field).cloned())
        .unwrap_or_default()
}

pub fn events_of_kind(events: &EventStore, kind: IngressEventKind) -> Vec<IngressEvent> {
    events
        .snapshot()
        .into_iter()
        .filter(|event| event.kind == kind)
        .collect()
}

pub fn event_fields(events: &EventStore, kind: IngressEventKind) -> Vec<BTreeMap<String, String>> {
    events_of_kind(events, kind)
        .into_iter()
        .map(|event| event.fields)
        .collect()
}

pub fn count_kind(kinds: &[IngressEventKind], kind: IngressEventKind) -> usize {
    kinds.iter().filter(|candidate| **candidate == kind).count()
}

pub async fn udp_roundtrip(bind: SocketAddr, payload: Vec<u8>) -> Vec<u8> {
    let client = UdpSocket::bind(local_addr()).await.expect("bind client");
    udp_roundtrip_with(&client, bind, &payload).await
}

pub async fn udp_roundtrip_with(client: &UdpSocket, bind: SocketAddr, payload: &[u8]) -> Vec<u8> {
    client.send_to(payload, bind).await.expect("send packet");
    let mut buffer = [0_u8; 1024];
    let (size, _) = time::timeout(Duration::from_secs(2), client.recv_from(&mut buffer))
        .await
        .expect("response timeout")
        .expect("receive response");
    buffer[..size].to_vec()
}

pub async fn wait_for_event(events: &EventStore, kind: IngressEventKind) -> Vec<IngressEventKind> {
    for _ in 0..20 {
        let kinds = event_kinds(events);
        if kinds.contains(&kind) {
            return kinds;
        }
        time::sleep(Duration::from_millis(10)).await;
    }
    event_kinds(events)
}

pub async fn wait_for_count(
    events: &EventStore,
    kind: IngressEventKind,
    expected: usize,
) -> Vec<IngressEventKind> {
    for _ in 0..20 {
        let kinds = event_kinds(events);
        if count_kind(&kinds, kind) >= expected {
            return kinds;
        }
        time::sleep(Duration::from_millis(10)).await;
    }
    event_kinds(events)
}
