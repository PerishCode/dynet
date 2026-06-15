use std::{collections::BTreeMap, net::SocketAddr, sync::Arc, time::Duration};

use tokio::{
    io,
    net::{TcpListener, TcpStream, UdpSocket},
    sync::mpsc,
    time,
};

mod dns;
mod event;

pub use event::{EventStore, IngressEvent, IngressEventKind, IntoFields};

const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const UDP_CHANNEL_DEPTH: usize = 64;
const DATAGRAM_LIMIT: usize = 65_535;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct DnsRelayConfig {
    pub bind: SocketAddr,
    pub upstream: SocketAddr,
    pub timeout: Duration,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct TcpRelayConfig {
    pub bind: SocketAddr,
    pub upstream: SocketAddr,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct UdpRelayConfig {
    pub bind: SocketAddr,
    pub upstream: SocketAddr,
    pub idle_timeout: Duration,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct IngressConfig {
    pub dns: DnsRelayConfig,
    pub tcp: TcpRelayConfig,
    pub udp: UdpRelayConfig,
}

impl Default for DnsRelayConfig {
    fn default() -> Self {
        Self {
            bind: SocketAddr::from(([127, 0, 0, 1], 1053)),
            upstream: SocketAddr::from(([1, 1, 1, 1], 53)),
            timeout: DNS_TIMEOUT,
        }
    }
}

impl Default for TcpRelayConfig {
    fn default() -> Self {
        Self {
            bind: SocketAddr::from(([127, 0, 0, 1], 18080)),
            upstream: SocketAddr::from(([93, 184, 216, 34], 80)),
        }
    }
}

impl Default for UdpRelayConfig {
    fn default() -> Self {
        Self {
            bind: SocketAddr::from(([127, 0, 0, 1], 18443)),
            upstream: SocketAddr::from(([1, 1, 1, 1], 443)),
            idle_timeout: UDP_IDLE_TIMEOUT,
        }
    }
}

pub async fn run_dns(config: DnsRelayConfig, events: EventStore) -> Result<(), String> {
    let socket = UdpSocket::bind(config.bind)
        .await
        .map_err(|error| format!("failed to bind DNS relay {}: {error}", config.bind))?;
    let mut buffer = vec![0_u8; DATAGRAM_LIMIT];
    loop {
        let (size, peer) = socket
            .recv_from(&mut buffer)
            .await
            .map_err(|error| format!("failed receiving DNS datagram: {error}"))?;
        let query = buffer[..size].to_vec();
        let query_info = dns::sniff_query(&query);
        let mut fields = vec![
            ("peer", peer.to_string()),
            ("upstream", config.upstream.to_string()),
            ("bytes", size.to_string()),
        ];
        push_endpoint_fields(&mut fields, "peer", peer);
        push_endpoint_fields(&mut fields, "upstream", config.upstream);
        if let Some(info) = &query_info {
            fields.push(("transactionId", info.transaction_id.to_string()));
            fields.push(("queryName", info.query_name.clone()));
            fields.push(("queryType", info.query_type.clone()));
        }
        events.record(IngressEventKind::DnsQuery, fields);
        match resolve_dns(
            &query,
            config.upstream,
            config.timeout,
            events.clone(),
            peer,
        )
        .await
        {
            Ok(response) => {
                socket
                    .send_to(&response, peer)
                    .await
                    .map_err(|error| format!("failed sending DNS response: {error}"))?;
            }
            Err(error) => {
                let mut fields = vec![
                    ("peer", peer.to_string()),
                    ("upstream", config.upstream.to_string()),
                    ("error", error),
                ];
                push_endpoint_fields(&mut fields, "peer", peer);
                push_endpoint_fields(&mut fields, "upstream", config.upstream);
                events.record(IngressEventKind::DnsError, fields);
            }
        }
    }
}

pub async fn run_tcp(config: TcpRelayConfig, events: EventStore) -> Result<(), String> {
    let listener = TcpListener::bind(config.bind)
        .await
        .map_err(|error| format!("failed to bind TCP relay {}: {error}", config.bind))?;
    loop {
        let (client, peer) = listener
            .accept()
            .await
            .map_err(|error| format!("failed accepting TCP connection: {error}"))?;
        let events = events.clone();
        tokio::spawn(async move {
            if let Err(error) = relay_tcp(client, peer, config.upstream, events.clone()).await {
                let mut fields = vec![
                    ("peer", peer.to_string()),
                    ("upstream", config.upstream.to_string()),
                    ("error", error),
                ];
                push_endpoint_fields(&mut fields, "peer", peer);
                push_endpoint_fields(&mut fields, "upstream", config.upstream);
                events.record(IngressEventKind::TcpError, fields);
            }
        });
    }
}

pub async fn run_udp(config: UdpRelayConfig, events: EventStore) -> Result<(), String> {
    let socket = Arc::new(
        UdpSocket::bind(config.bind)
            .await
            .map_err(|error| format!("failed to bind UDP relay {}: {error}", config.bind))?,
    );
    let mut sessions = BTreeMap::<SocketAddr, mpsc::Sender<Vec<u8>>>::new();
    let mut buffer = vec![0_u8; DATAGRAM_LIMIT];
    loop {
        let (size, peer) = socket
            .recv_from(&mut buffer)
            .await
            .map_err(|error| format!("failed receiving UDP datagram: {error}"))?;
        let payload = buffer[..size].to_vec();
        let sender = if let Some(sender) = sessions.get(&peer) {
            sender.clone()
        } else {
            let (sender, receiver) = mpsc::channel(UDP_CHANNEL_DEPTH);
            sessions.insert(peer, sender.clone());
            spawn_udp_session(
                peer,
                config.upstream,
                config.idle_timeout,
                socket.clone(),
                receiver,
                events.clone(),
            );
            sender
        };
        events.record(
            IngressEventKind::UdpDatagram,
            [
                ("direction", "client-to-upstream".to_string()),
                ("peer", peer.to_string()),
                ("upstream", config.upstream.to_string()),
                ("peerIp", peer.ip().to_string()),
                ("peerPort", peer.port().to_string()),
                ("upstreamIp", config.upstream.ip().to_string()),
                ("upstreamPort", config.upstream.port().to_string()),
                ("bytes", size.to_string()),
            ],
        );
        if sender.send(payload).await.is_err() {
            sessions.remove(&peer);
        }
    }
}

async fn resolve_dns(
    query: &[u8],
    upstream: SocketAddr,
    timeout: Duration,
    events: EventStore,
    peer: SocketAddr,
) -> Result<Vec<u8>, String> {
    let socket = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0)))
        .await
        .map_err(|error| format!("failed to bind DNS upstream socket: {error}"))?;
    socket
        .send_to(query, upstream)
        .await
        .map_err(|error| format!("failed forwarding DNS query: {error}"))?;
    let mut response = vec![0_u8; DATAGRAM_LIMIT];
    let (size, source) = time::timeout(timeout, socket.recv_from(&mut response))
        .await
        .map_err(|_| "timed out waiting for DNS upstream response".to_string())?
        .map_err(|error| format!("failed receiving DNS upstream response: {error}"))?;
    events.record(
        IngressEventKind::DnsResponse,
        dns_response_fields(peer, upstream, source, &response[..size]),
    );
    response.truncate(size);
    Ok(response)
}

async fn relay_tcp(
    mut client: TcpStream,
    peer: SocketAddr,
    upstream: SocketAddr,
    events: EventStore,
) -> Result<(), String> {
    events.record(
        IngressEventKind::TcpAccept,
        [
            ("peer", peer.to_string()),
            ("upstream", upstream.to_string()),
            ("peerIp", peer.ip().to_string()),
            ("peerPort", peer.port().to_string()),
            ("upstreamIp", upstream.ip().to_string()),
            ("upstreamPort", upstream.port().to_string()),
        ],
    );
    let mut server = TcpStream::connect(upstream)
        .await
        .map_err(|error| format!("failed connecting TCP upstream {upstream}: {error}"))?;
    let (from_client, from_upstream) = io::copy_bidirectional(&mut client, &mut server)
        .await
        .map_err(|error| format!("TCP relay failed: {error}"))?;
    events.record(
        IngressEventKind::TcpClose,
        [
            ("peer", peer.to_string()),
            ("upstream", upstream.to_string()),
            ("peerIp", peer.ip().to_string()),
            ("peerPort", peer.port().to_string()),
            ("upstreamIp", upstream.ip().to_string()),
            ("upstreamPort", upstream.port().to_string()),
            ("clientToUpstreamBytes", from_client.to_string()),
            ("upstreamToClientBytes", from_upstream.to_string()),
        ],
    );
    Ok(())
}

fn spawn_udp_session(
    peer: SocketAddr,
    upstream: SocketAddr,
    idle_timeout: Duration,
    downstream: Arc<UdpSocket>,
    mut receiver: mpsc::Receiver<Vec<u8>>,
    events: EventStore,
) {
    tokio::spawn(async move {
        events.record(
            IngressEventKind::UdpSessionStart,
            [
                ("peer", peer.to_string()),
                ("upstream", upstream.to_string()),
                ("peerIp", peer.ip().to_string()),
                ("peerPort", peer.port().to_string()),
                ("upstreamIp", upstream.ip().to_string()),
                ("upstreamPort", upstream.port().to_string()),
            ],
        );
        let result = relay_udp_session(
            peer,
            upstream,
            idle_timeout,
            downstream,
            &mut receiver,
            events.clone(),
        );
        if let Err(error) = result.await {
            let mut fields = vec![
                ("peer", peer.to_string()),
                ("upstream", upstream.to_string()),
                ("error", error),
            ];
            push_endpoint_fields(&mut fields, "peer", peer);
            push_endpoint_fields(&mut fields, "upstream", upstream);
            events.record(IngressEventKind::UdpError, fields);
        }
        events.record(
            IngressEventKind::UdpSessionClose,
            [
                ("peer", peer.to_string()),
                ("upstream", upstream.to_string()),
                ("peerIp", peer.ip().to_string()),
                ("peerPort", peer.port().to_string()),
                ("upstreamIp", upstream.ip().to_string()),
                ("upstreamPort", upstream.port().to_string()),
            ],
        );
    });
}

async fn relay_udp_session(
    peer: SocketAddr,
    upstream: SocketAddr,
    idle_timeout: Duration,
    downstream: Arc<UdpSocket>,
    receiver: &mut mpsc::Receiver<Vec<u8>>,
    events: EventStore,
) -> Result<(), String> {
    let upstream_socket = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0)))
        .await
        .map_err(|error| format!("failed to bind UDP upstream socket: {error}"))?;
    upstream_socket
        .connect(upstream)
        .await
        .map_err(|error| format!("failed connecting UDP upstream {upstream}: {error}"))?;
    let mut buffer = vec![0_u8; DATAGRAM_LIMIT];
    loop {
        let step = time::timeout(
            idle_timeout,
            udp_step(receiver, &upstream_socket, &mut buffer),
        )
        .await;
        match step {
            Ok(UdpStep::Client(payload)) => {
                upstream_socket
                    .send(&payload)
                    .await
                    .map_err(|error| format!("failed sending UDP upstream datagram: {error}"))?;
            }
            Ok(UdpStep::Upstream(size)) => {
                downstream
                    .send_to(&buffer[..size], peer)
                    .await
                    .map_err(|error| format!("failed sending UDP downstream datagram: {error}"))?;
                events.record(
                    IngressEventKind::UdpDatagram,
                    [
                        ("direction", "upstream-to-client".to_string()),
                        ("peer", peer.to_string()),
                        ("upstream", upstream.to_string()),
                        ("peerIp", peer.ip().to_string()),
                        ("peerPort", peer.port().to_string()),
                        ("upstreamIp", upstream.ip().to_string()),
                        ("upstreamPort", upstream.port().to_string()),
                        ("bytes", size.to_string()),
                    ],
                );
            }
            Ok(UdpStep::Closed) | Err(_) => return Ok(()),
        }
    }
}

enum UdpStep {
    Client(Vec<u8>),
    Upstream(usize),
    Closed,
}

async fn udp_step(
    receiver: &mut mpsc::Receiver<Vec<u8>>,
    upstream_socket: &UdpSocket,
    buffer: &mut [u8],
) -> UdpStep {
    tokio::select! {
        payload = receiver.recv() => match payload {
            Some(payload) => UdpStep::Client(payload),
            None => UdpStep::Closed,
        },
        result = upstream_socket.recv(buffer) => match result {
            Ok(size) => UdpStep::Upstream(size),
            Err(_) => UdpStep::Closed,
        },
    }
}

fn dns_response_fields(
    peer: SocketAddr,
    upstream: SocketAddr,
    source: SocketAddr,
    response: &[u8],
) -> Vec<(&'static str, String)> {
    let mut fields = vec![
        ("peer", peer.to_string()),
        ("upstream", upstream.to_string()),
        ("source", source.to_string()),
        ("bytes", response.len().to_string()),
    ];
    push_endpoint_fields(&mut fields, "peer", peer);
    push_endpoint_fields(&mut fields, "upstream", upstream);
    push_endpoint_fields(&mut fields, "source", source);
    if let Some(info) = dns::sniff_response(response) {
        fields.push(("transactionId", info.transaction_id.to_string()));
        if let Some(query_name) = info.query_name {
            fields.push(("queryName", query_name));
        }
        if let Some(query_type) = info.query_type {
            fields.push(("queryType", query_type));
        }
        if !info.answer_ips.is_empty() {
            fields.push(("answerIps", info.answer_ips.join(",")));
        }
    }
    fields
}

fn push_endpoint_fields(
    fields: &mut Vec<(&'static str, String)>,
    prefix: &'static str,
    address: SocketAddr,
) {
    match prefix {
        "peer" => {
            fields.push(("peerIp", address.ip().to_string()));
            fields.push(("peerPort", address.port().to_string()));
        }
        "upstream" => {
            fields.push(("upstreamIp", address.ip().to_string()));
            fields.push(("upstreamPort", address.port().to_string()));
        }
        "source" => {
            fields.push(("sourceIp", address.ip().to_string()));
            fields.push(("sourcePort", address.port().to_string()));
        }
        _ => {}
    }
}
