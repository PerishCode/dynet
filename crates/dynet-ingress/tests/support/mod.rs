#![allow(dead_code)]

use std::{
    collections::BTreeMap,
    env,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use dynet_runtime::{
    DnsUpstream, DnsUpstreamId, DnsUpstreamTransport, EventStore, ForwardGroup, ForwardNode,
    GroupId, GroupMember, GroupThresholds, IngressEvent, IngressEventKind, Ipv6RulePolicy, NextRef,
    NodeId, RouteMatcher, RouteRule, RuleId, RuntimeSeed, RuntimeState, RuntimeStore,
    SchedulerPolicy,
};
use hkdf::Hkdf;
use md5::{Digest, Md5};
use sha1::Sha1;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    task::JoinHandle,
    time,
};

const SS_AES_256_GCM_KEY_SIZE: usize = 32;
const SS_AES_256_GCM_SALT_SIZE: usize = 32;
const SS_AEAD_NONCE_SIZE: usize = 12;
const SS_AEAD_TAG_SIZE: usize = 16;
const SS_SUBKEY_INFO: &[u8] = b"ss-subkey";

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
    spawn_dns_a_sequence(vec![address]).await
}

pub async fn spawn_dns_a_sequence(addresses: Vec<Ipv4Addr>) -> SocketAddr {
    assert!(
        !addresses.is_empty(),
        "DNS answer sequence must not be empty"
    );
    let dns = UdpSocket::bind(local_addr()).await.expect("bind dns");
    let dns_addr = dns.local_addr().expect("dns addr");
    let next_index = AtomicUsize::new(0);
    tokio::spawn(async move {
        let mut buffer = [0_u8; 1024];
        loop {
            let (size, peer) = dns.recv_from(&mut buffer).await.expect("recv query");
            let index = next_index.fetch_add(1, Ordering::SeqCst);
            let address = addresses
                .get(index)
                .or_else(|| addresses.last())
                .copied()
                .expect("DNS answer sequence is not empty");
            let response = dns_a_response(&buffer[..size], address);
            dns.send_to(&response, peer).await.expect("send response");
        }
    });
    dns_addr
}

pub async fn spawn_ss_header_server(password: &'static str) -> (SocketAddr, JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind(local_addr())
        .await
        .expect("bind ss server");
    let address = listener.local_addr().expect("ss server addr");
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept ss server");
        let mut salt = [0_u8; SS_AES_256_GCM_SALT_SIZE];
        stream.read_exact(&mut salt).await.expect("read ss salt");

        let mut encrypted_length = [0_u8; 2 + SS_AEAD_TAG_SIZE];
        stream
            .read_exact(&mut encrypted_length)
            .await
            .expect("read ss header length");
        let mut reader = SsAeadReader::new(password, &salt);
        let length = reader.decrypt(&encrypted_length);
        let length = u16::from_be_bytes([length[0], length[1]]) as usize;

        let mut encrypted_header = vec![0_u8; length + SS_AEAD_TAG_SIZE];
        stream
            .read_exact(&mut encrypted_header)
            .await
            .expect("read ss header");
        reader.decrypt(&encrypted_header)
    });
    (address, task)
}

pub async fn spawn_ss_open_reply(password: &'static str, response: &'static [u8]) -> SocketAddr {
    let listener = TcpListener::bind(local_addr())
        .await
        .expect("bind ss server");
    let address = listener.local_addr().expect("ss server addr");
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept ss server");
        let mut request_salt = [0_u8; SS_AES_256_GCM_SALT_SIZE];
        stream
            .read_exact(&mut request_salt)
            .await
            .expect("read ss request salt");
        let mut reader = SsAeadReader::new(password, &request_salt);
        let _target = read_ss_chunk(&mut stream, &mut reader).await;
        let _request = read_ss_chunk(&mut stream, &mut reader).await;

        let response_salt = [0x44_u8; SS_AES_256_GCM_SALT_SIZE];
        let mut writer = SsAeadWriter::new(password, &response_salt);
        let mut packet = response_salt.to_vec();
        writer.encrypt_chunk(response, &mut packet);
        stream.write_all(&packet).await.expect("write ss response");
        time::sleep(Duration::from_secs(5)).await;
    });
    address
}

pub async fn spawn_tcp_prefix_server<const N: usize>() -> (SocketAddr, JoinHandle<[u8; N]>) {
    let listener = TcpListener::bind(local_addr())
        .await
        .expect("bind prefix server");
    let address = listener.local_addr().expect("prefix server addr");
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept prefix server");
        let mut prefix = [0_u8; N];
        stream.read_exact(&mut prefix).await.expect("read prefix");
        prefix
    });
    (address, task)
}

pub async fn spawn_prefix_vec(size: usize) -> (SocketAddr, JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind(local_addr())
        .await
        .expect("bind prefix server");
    let address = listener.local_addr().expect("prefix server addr");
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept prefix server");
        let mut prefix = vec![0_u8; size];
        stream.read_exact(&mut prefix).await.expect("read prefix");
        prefix
    });
    (address, task)
}

struct SsAeadReader {
    cipher: Aes256Gcm,
    nonce: [u8; SS_AEAD_NONCE_SIZE],
}

impl SsAeadReader {
    fn new(password: &str, salt: &[u8]) -> Self {
        Self {
            cipher: Aes256Gcm::new_from_slice(&ss_derive_subkey(password, salt)).unwrap(),
            nonce: [0_u8; SS_AEAD_NONCE_SIZE],
        }
    }

    fn decrypt(&mut self, ciphertext: &[u8]) -> Vec<u8> {
        let nonce = self.nonce;
        let plaintext = self
            .cipher
            .decrypt(Nonce::from_slice(&nonce), ciphertext)
            .unwrap();
        increment_ss_nonce(&mut self.nonce);
        plaintext
    }
}

struct SsAeadWriter {
    cipher: Aes256Gcm,
    nonce: [u8; SS_AEAD_NONCE_SIZE],
}

impl SsAeadWriter {
    fn new(password: &str, salt: &[u8]) -> Self {
        Self {
            cipher: Aes256Gcm::new_from_slice(&ss_derive_subkey(password, salt)).unwrap(),
            nonce: [0_u8; SS_AEAD_NONCE_SIZE],
        }
    }

    fn encrypt_chunk(&mut self, plaintext: &[u8], out: &mut Vec<u8>) {
        let length = (plaintext.len() as u16).to_be_bytes();
        out.extend_from_slice(&self.encrypt(&length));
        out.extend_from_slice(&self.encrypt(plaintext));
    }

    fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let nonce = self.nonce;
        let ciphertext = self
            .cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .unwrap();
        increment_ss_nonce(&mut self.nonce);
        ciphertext
    }
}

async fn read_ss_chunk(stream: &mut tokio::net::TcpStream, reader: &mut SsAeadReader) -> Vec<u8> {
    let mut encrypted_length = [0_u8; 2 + SS_AEAD_TAG_SIZE];
    stream
        .read_exact(&mut encrypted_length)
        .await
        .expect("read ss chunk length");
    let length = reader.decrypt(&encrypted_length);
    let length = u16::from_be_bytes([length[0], length[1]]) as usize;
    let mut encrypted_payload = vec![0_u8; length + SS_AEAD_TAG_SIZE];
    stream
        .read_exact(&mut encrypted_payload)
        .await
        .expect("read ss chunk payload");
    reader.decrypt(&encrypted_payload)
}

fn ss_derive_subkey(password: &str, salt: &[u8]) -> Vec<u8> {
    let mut subkey = vec![0_u8; SS_AES_256_GCM_KEY_SIZE];
    Hkdf::<Sha1>::new(Some(salt), &ss_evp_key(password))
        .expand(SS_SUBKEY_INFO, &mut subkey)
        .unwrap();
    subkey
}

fn ss_evp_key(password: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(SS_AES_256_GCM_KEY_SIZE);
    let mut previous = Vec::<u8>::new();
    while key.len() < SS_AES_256_GCM_KEY_SIZE {
        let mut hasher = Md5::new();
        hasher.update(&previous);
        hasher.update(password.as_bytes());
        previous = hasher.finalize().to_vec();
        key.extend_from_slice(&previous);
    }
    key.truncate(SS_AES_256_GCM_KEY_SIZE);
    key
}

fn increment_ss_nonce(nonce: &mut [u8; SS_AEAD_NONCE_SIZE]) {
    for byte in nonce {
        let (next, carry) = byte.overflowing_add(1);
        *byte = next;
        if !carry {
            break;
        }
    }
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

pub fn runtime_with_dns(upstream: SocketAddr) -> RuntimeState {
    RuntimeState::single_node_with_dns(
        "direct",
        vec![DnsUpstream {
            id: DnsUpstreamId::new("test"),
            address: upstream,
            transport: DnsUpstreamTransport::Udp,
            enabled: true,
            priority: 0,
        }],
    )
}

pub fn route_selected_seed(dns_addr: SocketAddr) -> RuntimeSeed {
    RuntimeSeed {
        ipv6_enabled: false,
        nodes: vec![
            ForwardNode::new("default-node", "direct", true),
            ForwardNode::new("routed-node", "direct", true),
        ],
        default_group_id: GroupId::new("default"),
        groups: vec![
            ForwardGroup {
                id: GroupId::new("default"),
                enabled: true,
                scheduler: SchedulerPolicy::SingleFirstEnabled,
                thresholds: GroupThresholds::default(),
                next: NextRef::direct_audit_outlet(),
            },
            ForwardGroup {
                id: GroupId::new("routed"),
                enabled: true,
                scheduler: SchedulerPolicy::SingleFirstEnabled,
                thresholds: GroupThresholds::default(),
                next: NextRef::direct_audit_outlet(),
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
            ipv6: Ipv6RulePolicy::Inherit,
        }],
        dns_upstreams: vec![DnsUpstream {
            id: DnsUpstreamId::new("test"),
            address: dns_addr,
            transport: DnsUpstreamTransport::Udp,
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
            group.next = NextRef::named("egress");
        }
    }
    seed.nodes
        .push(ForwardNode::new("egress-node", "direct", true));
    seed.groups.push(ForwardGroup {
        id: GroupId::new("egress"),
        enabled: true,
        scheduler: SchedulerPolicy::SingleFirstEnabled,
        thresholds: GroupThresholds::default(),
        next: NextRef::direct_audit_outlet(),
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
    static NEXT_DB_ID: AtomicU64 = AtomicU64::new(0);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let id = NEXT_DB_ID.fetch_add(1, Ordering::Relaxed);
    env::temp_dir().join(format!(
        "dynet-ingress-{name}-{}-{now}-{id}.sqlite",
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
