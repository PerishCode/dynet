use std::net::SocketAddr;
use std::time::Duration;

use tokio::{net::UdpSocket, time};

mod dns;
mod event;
mod inbound;
mod outbound;

pub use event::{EventStore, IngressEvent, IngressEventKind, IntoFields};

const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const DATAGRAM_LIMIT: usize = 65_535;
pub const DEFAULT_TCP_MAX_SESSIONS: usize = 1024;
pub const DEFAULT_UDP_MAX_SESSIONS: usize = 1024;

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
    pub max_sessions: usize,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct UdpRelayConfig {
    pub bind: SocketAddr,
    pub upstream: SocketAddr,
    pub idle_timeout: Duration,
    pub max_sessions: usize,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct IngressConfig {
    pub dns: DnsRelayConfig,
    pub tcp: TcpRelayConfig,
    pub udp: UdpRelayConfig,
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub enum OutboundConfig {
    #[default]
    Direct,
    Shadowsocks(ShadowsocksConfig),
    Trojan(TrojanConfig),
    Vless(VlessConfig),
    Vmess(VmessConfig),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ShadowsocksConfig {
    pub server: String,
    pub port: u16,
    pub method: ShadowsocksMethod,
    pub password: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TrojanConfig {
    pub server: String,
    pub port: u16,
    pub password: String,
    pub sni: Option<String>,
    pub skip_cert_verify: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct VmessConfig {
    pub server: String,
    pub port: u16,
    pub uuid: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct VlessConfig {
    pub server: String,
    pub port: u16,
    pub uuid: String,
    pub server_name: String,
    pub public_key: String,
    pub short_id: String,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ShadowsocksMethod {
    Aes256Gcm,
    Blake3Aes128Gcm2022,
}

impl ShadowsocksMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Aes256Gcm => "aes-256-gcm",
            Self::Blake3Aes128Gcm2022 => "2022-blake3-aes-128-gcm",
        }
    }
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
            max_sessions: DEFAULT_TCP_MAX_SESSIONS,
        }
    }
}

impl Default for UdpRelayConfig {
    fn default() -> Self {
        Self {
            bind: SocketAddr::from(([127, 0, 0, 1], 18443)),
            upstream: SocketAddr::from(([1, 1, 1, 1], 443)),
            idle_timeout: UDP_IDLE_TIMEOUT,
            max_sessions: DEFAULT_UDP_MAX_SESSIONS,
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
    run_tcp_with_outbound(config, OutboundConfig::Direct, events).await
}

pub async fn run_udp(config: UdpRelayConfig, events: EventStore) -> Result<(), String> {
    run_udp_with_outbound(config, OutboundConfig::Direct, events).await
}

pub async fn run_tcp_with_outbound(
    config: TcpRelayConfig,
    outbound: OutboundConfig,
    events: EventStore,
) -> Result<(), String> {
    inbound::run_tcp(
        config,
        outbound::OutboundMedium::try_from(outbound)?,
        events,
    )
    .await
}

pub async fn run_udp_with_outbound(
    config: UdpRelayConfig,
    outbound: OutboundConfig,
    events: EventStore,
) -> Result<(), String> {
    inbound::run_udp(
        config,
        outbound::OutboundMedium::try_from(outbound)?,
        events,
    )
    .await
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

pub(crate) fn session_fields(
    session_id: u64,
    inbound: &'static str,
    outbound: &'static str,
    peer: SocketAddr,
    target: SocketAddr,
    upstream: SocketAddr,
) -> Vec<(&'static str, String)> {
    let mut fields = vec![
        ("sessionId", session_id.to_string()),
        ("inbound", inbound.to_string()),
        ("outbound", outbound.to_string()),
        ("peer", peer.to_string()),
        ("target", target.to_string()),
        ("upstream", upstream.to_string()),
    ];
    push_endpoint_fields(&mut fields, "peer", peer);
    push_endpoint_fields(&mut fields, "target", target);
    push_endpoint_fields(&mut fields, "upstream", upstream);
    fields
}

pub(crate) fn push_endpoint_fields(
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
        "target" => {
            fields.push(("targetIp", address.ip().to_string()));
            fields.push(("targetPort", address.port().to_string()));
        }
        "source" => {
            fields.push(("sourceIp", address.ip().to_string()));
            fields.push(("sourcePort", address.port().to_string()));
        }
        _ => {}
    }
}
