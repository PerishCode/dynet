#![allow(dead_code)]

use std::{
    collections::BTreeMap,
    env,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use dynet_runtime::{
    DnsUpstream, DnsUpstreamId, EventStore, GroupId, GroupMember, IngressEvent, IngressEventKind,
    NodeId, OutboundGroup, OutboundNode, OutboundRef, RouteMatcher, RouteRule, RuleId, RuntimeSeed,
    RuntimeState, RuntimeStore, SchedulerPolicy,
};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, UdpSocket},
    task::JoinHandle,
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

pub async fn spawn_dns_a(address: Ipv4Addr) -> SocketAddr {
    let dns = UdpSocket::bind(local_addr()).await.expect("bind dns");
    let dns_addr = dns.local_addr().expect("dns addr");
    tokio::spawn(async move {
        let mut buffer = [0_u8; 1024];
        let (size, peer) = dns.recv_from(&mut buffer).await.expect("recv query");
        let response = dns_a_response(&buffer[..size], address);
        dns.send_to(&response, peer).await.expect("send response");
    });
    dns_addr
}

pub async fn spawn_ss_salt_server() -> (SocketAddr, JoinHandle<[u8; 32]>) {
    let listener = TcpListener::bind(local_addr())
        .await
        .expect("bind ss server");
    let address = listener.local_addr().expect("ss server addr");
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept ss server");
        let mut salt = [0_u8; 32];
        stream.read_exact(&mut salt).await.expect("read ss salt");
        salt
    });
    (address, task)
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

pub async fn runtime_from_seed(seed: RuntimeSeed) -> RuntimeState {
    let store = RuntimeStore::open(temp_db_path("runtime-seed"))
        .await
        .expect("runtime store");
    RuntimeState::from_store_seed(store, seed)
        .await
        .expect("runtime from seed")
}

pub fn route_selected_seed(dns_addr: SocketAddr) -> RuntimeSeed {
    RuntimeSeed {
        nodes: vec![
            OutboundNode {
                id: NodeId::new("default-node"),
                tag: "direct".to_string(),
                enabled: true,
            },
            OutboundNode {
                id: NodeId::new("routed-node"),
                tag: "direct".to_string(),
                enabled: true,
            },
        ],
        default_group_id: GroupId::new("default"),
        groups: vec![
            OutboundGroup {
                id: GroupId::new("default"),
                enabled: true,
                scheduler: SchedulerPolicy::SingleFirstEnabled,
                outbound: OutboundRef::direct_audit_outlet(),
            },
            OutboundGroup {
                id: GroupId::new("routed"),
                enabled: true,
                scheduler: SchedulerPolicy::SingleFirstEnabled,
                outbound: OutboundRef::direct_audit_outlet(),
            },
        ],
        group_members: vec![
            GroupMember {
                group_id: GroupId::new("default"),
                node_id: NodeId::new("default-node"),
                enabled: true,
                priority: 0,
            },
            GroupMember {
                group_id: GroupId::new("routed"),
                node_id: NodeId::new("routed-node"),
                enabled: true,
                priority: 0,
            },
        ],
        route_rules: vec![RouteRule {
            id: RuleId::new("routed-example"),
            priority: 100,
            enabled: true,
            matcher: RouteMatcher::DomainExact("routed.example".to_string()),
            group_id: GroupId::new("routed"),
        }],
        dns_upstreams: vec![DnsUpstream {
            id: DnsUpstreamId::new("test"),
            address: dns_addr,
            enabled: true,
            priority: 0,
        }],
        dns_policy: RuntimeSeed::single_node("direct").dns_policy,
    }
}

pub fn chained_route_seed(dns_addr: SocketAddr) -> RuntimeSeed {
    let mut seed = route_selected_seed(dns_addr);
    for group in &mut seed.groups {
        if group.id.as_str() == "routed" {
            group.outbound = OutboundRef::named("egress");
        }
    }
    seed.nodes.push(OutboundNode {
        id: NodeId::new("egress-node"),
        tag: "direct".to_string(),
        enabled: true,
    });
    seed.groups.push(OutboundGroup {
        id: GroupId::new("egress"),
        enabled: true,
        scheduler: SchedulerPolicy::SingleFirstEnabled,
        outbound: OutboundRef::direct_audit_outlet(),
    });
    seed.group_members.push(GroupMember {
        group_id: GroupId::new("egress"),
        node_id: NodeId::new("egress-node"),
        enabled: true,
        priority: 0,
    });
    seed
}

fn temp_db_path(name: &str) -> PathBuf {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    env::temp_dir().join(format!(
        "dynet-ingress-{name}-{}-{now}.sqlite",
        std::process::id()
    ))
}

fn dns_a_response(query: &[u8], address: Ipv4Addr) -> Vec<u8> {
    let question_end = query
        .iter()
        .enumerate()
        .skip(12)
        .find_map(|(index, byte)| (*byte == 0).then_some(index + 5))
        .expect("question end");
    let mut response = Vec::new();
    response.extend_from_slice(&query[..2]);
    response.extend_from_slice(&0x8180_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&query[12..question_end]);
    response.extend_from_slice(&[0xc0, 0x0c]);
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&60_u32.to_be_bytes());
    response.extend_from_slice(&4_u16.to_be_bytes());
    response.extend_from_slice(&address.octets());
    response
}
