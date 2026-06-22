use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use tokio::{net::UdpSocket, sync::mpsc, time};

use crate::{unix_ms, DnsUpstream, DnsUpstreamTransport, RuntimeState};

mod https;

const DNS_DATAGRAM_LIMIT: usize = 65_535;
const DNS_CLASS_IN: u16 = 1;
const DNS_QTYPE_A: u16 = 1;
const DNS_QTYPE_AAAA: u16 = 28;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DnsQueryInfo {
    pub transaction_id: u16,
    pub query_name: String,
    pub query_type: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DnsResponseInfo {
    pub transaction_id: u16,
    pub query_name: Option<String>,
    pub query_type: Option<String>,
    pub answer_ips: Vec<IpAddr>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DnsResolution {
    pub response: Vec<u8>,
    pub upstream: DnsUpstream,
    pub source: SocketAddr,
    pub query_info: Option<DnsQueryInfo>,
    pub response_info: Option<DnsResponseInfo>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DnsResolveError {
    message: String,
}

impl RuntimeState {
    pub async fn resolve_dns_wire(&self, query: Vec<u8>) -> Result<DnsResolution, DnsResolveError> {
        let policy = self.dns_policy();
        let query_info = sniff_dns_query(&query);
        let upstreams = enabled_upstreams(self.dns_upstreams().snapshot());
        if upstreams.is_empty() {
            return Err(DnsResolveError::new(
                "no enabled DNS upstreams are configured",
            ));
        }

        let (tx, mut rx) = mpsc::channel(upstreams.len());
        for upstream in upstreams {
            let tx = tx.clone();
            let query = query.clone();
            let query_info = query_info.clone();
            tokio::spawn(async move {
                let result = query_upstream(upstream, query, query_info, policy.timeout).await;
                let _ = tx.send(result).await;
            });
        }
        drop(tx);

        let deadline = time::sleep(policy.timeout);
        tokio::pin!(deadline);
        let mut last_error = None;
        let mut fake_candidate = None;
        loop {
            tokio::select! {
                _ = &mut deadline => {
                    if let Some(resolution) = fake_candidate {
                        self.record_dns_resolution(&resolution);
                        return Ok(resolution);
                    }
                    return Err(DnsResolveError::new(
                        last_error.unwrap_or_else(|| "timed out waiting for DNS upstream response".to_string()),
                    ));
                }
                received = rx.recv() => {
                    let Some(result) = received else {
                        if let Some(resolution) = fake_candidate {
                            self.record_dns_resolution(&resolution);
                            return Ok(resolution);
                        }
                        return Err(DnsResolveError::new(
                            last_error.unwrap_or_else(|| "all DNS upstreams failed".to_string()),
                        ));
                    };
                    match result {
                        Ok(resolution) => {
                            if only_fake_answers(&resolution) {
                                fake_candidate.get_or_insert(resolution);
                                continue;
                            }
                            self.record_dns_resolution(&resolution);
                            return Ok(resolution);
                        }
                        Err(error) => {
                            last_error = Some(error.to_string());
                        }
                    }
                }
            }
        }
    }

    pub async fn resolve_domain_a(
        &self,
        domain: &str,
        port: u16,
    ) -> Result<SocketAddr, DnsResolveError> {
        let query = build_a_query(domain)?;
        let resolution = self.resolve_dns_wire(query).await?;
        let response_info = resolution
            .response_info
            .ok_or_else(|| DnsResolveError::new(format!("DNS response for {domain} is invalid")))?;
        response_info
            .answer_ips
            .into_iter()
            .find(|address| address.is_ipv4())
            .map(|address| SocketAddr::new(address, port))
            .ok_or_else(|| {
                DnsResolveError::new(format!("no A answer resolved for {domain}:{port}"))
            })
    }

    fn record_dns_resolution(&self, resolution: &DnsResolution) {
        if let Some(response_info) = &resolution.response_info {
            if let Some(query_name) = &response_info.query_name {
                self.dns_map()
                    .record(query_name.clone(), response_info.answer_ips.clone());
            }
        }
    }
}

pub fn sniff_dns_query(packet: &[u8]) -> Option<DnsQueryInfo> {
    let transaction_id = transaction_id(packet)?;
    let qdcount = u16_at(packet, 4)?;
    if qdcount == 0 {
        return None;
    }
    let (query_name, offset) = read_name(packet, 12)?;
    let query_type = qtype_label(u16_at(packet, offset)?);
    Some(DnsQueryInfo {
        transaction_id,
        query_name,
        query_type,
    })
}

pub fn sniff_dns_response(packet: &[u8]) -> Option<DnsResponseInfo> {
    let transaction_id = transaction_id(packet)?;
    let qdcount = u16_at(packet, 4)?;
    let ancount = u16_at(packet, 6)?;
    let mut offset = 12;
    let mut query_name = None;
    let mut query_type = None;

    for index in 0..qdcount {
        let (name, next) = read_name(packet, offset)?;
        offset = next;
        let qtype = u16_at(packet, offset)?;
        offset = offset.checked_add(4)?;
        if index == 0 {
            query_name = Some(name);
            query_type = Some(qtype_label(qtype));
        }
    }

    let mut answer_ips = Vec::new();
    for _ in 0..ancount {
        let (_, next) = read_name(packet, offset)?;
        offset = next;
        let answer_type = u16_at(packet, offset)?;
        let data_len = usize::from(u16_at(packet, offset.checked_add(8)?)?);
        offset = offset.checked_add(10)?;
        let data_end = offset.checked_add(data_len)?;
        let data = packet.get(offset..data_end)?;
        match (answer_type, data) {
            (DNS_QTYPE_A, [a, b, c, d]) => {
                answer_ips.push(IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d)))
            }
            (DNS_QTYPE_AAAA, bytes) if bytes.len() == 16 => {
                let octets: [u8; 16] = bytes.try_into().ok()?;
                answer_ips.push(IpAddr::V6(Ipv6Addr::from(octets)));
            }
            _ => {}
        }
        offset = data_end;
    }

    Some(DnsResponseInfo {
        transaction_id,
        query_name,
        query_type,
        answer_ips,
    })
}

async fn query_upstream(
    upstream: DnsUpstream,
    query: Vec<u8>,
    query_info: Option<DnsQueryInfo>,
    timeout: Duration,
) -> Result<DnsResolution, DnsResolveError> {
    match &upstream.transport {
        DnsUpstreamTransport::Udp => query_udp_upstream(upstream, query, query_info, timeout).await,
        DnsUpstreamTransport::Https(endpoint) => {
            https::query_https_upstream(
                upstream.clone(),
                endpoint.host.clone(),
                endpoint.path.clone(),
                query,
                query_info,
                timeout,
            )
            .await
        }
    }
}

async fn query_udp_upstream(
    upstream: DnsUpstream,
    query: Vec<u8>,
    query_info: Option<DnsQueryInfo>,
    timeout: Duration,
) -> Result<DnsResolution, DnsResolveError> {
    let bind = if upstream.address.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0_u16; 8], 0))
    };
    let socket = UdpSocket::bind(bind).await.map_err(|error| {
        DnsResolveError::new(format!(
            "failed to bind DNS socket for upstream {}: {error}",
            upstream.id
        ))
    })?;
    socket
        .send_to(&query, upstream.address)
        .await
        .map_err(|error| {
            DnsResolveError::new(format!(
                "failed forwarding DNS query to upstream {} ({}): {error}",
                upstream.id, upstream.address
            ))
        })?;
    let mut response = vec![0_u8; DNS_DATAGRAM_LIMIT];
    let (size, source) = time::timeout(timeout, socket.recv_from(&mut response))
        .await
        .map_err(|_| {
            DnsResolveError::new(format!(
                "timed out waiting for DNS upstream {} ({})",
                upstream.id, upstream.address
            ))
        })?
        .map_err(|error| {
            DnsResolveError::new(format!(
                "failed receiving DNS response from upstream {} ({}): {error}",
                upstream.id, upstream.address
            ))
        })?;
    response.truncate(size);
    let response_info = sniff_dns_response(&response);
    validate_response_info(&upstream, &query_info, &response_info)?;
    Ok(DnsResolution {
        response,
        upstream,
        source,
        query_info,
        response_info,
    })
}

fn validate_response_info(
    upstream: &DnsUpstream,
    query_info: &Option<DnsQueryInfo>,
    response_info: &Option<DnsResponseInfo>,
) -> Result<(), DnsResolveError> {
    if let (Some(query), Some(response)) = (query_info, response_info) {
        if query.transaction_id != response.transaction_id {
            return Err(DnsResolveError::new(format!(
                "DNS response transaction id mismatch from upstream {}",
                upstream.id
            )));
        }
    } else if query_info.is_some() {
        return Err(DnsResolveError::new(format!(
            "invalid DNS response from upstream {}",
            upstream.id
        )));
    }
    Ok(())
}

fn build_a_query(domain: &str) -> Result<Vec<u8>, DnsResolveError> {
    let domain = domain.trim_end_matches('.');
    if domain.is_empty() {
        return Err(DnsResolveError::new("domain is empty"));
    }
    let mut query = Vec::with_capacity(512);
    let transaction_id = (unix_ms() & 0xffff) as u16;
    query.extend_from_slice(&transaction_id.to_be_bytes());
    query.extend_from_slice(&0x0100_u16.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(DnsResolveError::new(format!(
                "invalid DNS label in {domain}"
            )));
        }
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&DNS_QTYPE_A.to_be_bytes());
    query.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    Ok(query)
}

fn enabled_upstreams(mut upstreams: Vec<DnsUpstream>) -> Vec<DnsUpstream> {
    upstreams.retain(|upstream| upstream.enabled);
    upstreams.sort_by(|left, right| {
        left.priority
            .cmp(&right.priority)
            .then_with(|| left.id.cmp(&right.id))
    });
    upstreams
}

fn only_fake_answers(resolution: &DnsResolution) -> bool {
    resolution
        .response_info
        .as_ref()
        .is_some_and(|info| !info.answer_ips.is_empty() && info.answer_ips.iter().all(is_fake_ip))
}

fn is_fake_ip(address: &IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let octets = address.octets();
            octets[0] == 198 && matches!(octets[1], 18 | 19)
        }
        IpAddr::V6(_) => false,
    }
}

fn transaction_id(packet: &[u8]) -> Option<u16> {
    u16_at(packet, 0)
}

fn u16_at(packet: &[u8], offset: usize) -> Option<u16> {
    let bytes = packet.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_be_bytes(bytes.try_into().ok()?))
}

fn read_name(packet: &[u8], offset: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut cursor = offset;
    let mut next_offset = None;
    let mut jumps = 0_u8;

    loop {
        let length = *packet.get(cursor)?;
        if length & 0xc0 == 0xc0 {
            let next = *packet.get(cursor.checked_add(1)?)?;
            let pointer = usize::from(u16::from_be_bytes([length & 0x3f, next]));
            next_offset.get_or_insert(cursor.checked_add(2)?);
            cursor = pointer;
            jumps = jumps.checked_add(1)?;
            if jumps > 8 {
                return None;
            }
            continue;
        }
        if length == 0 {
            let end = next_offset.unwrap_or(cursor.checked_add(1)?);
            return Some((labels.join("."), end));
        }
        let label_start = cursor.checked_add(1)?;
        let label_end = label_start.checked_add(usize::from(length))?;
        let label = packet.get(label_start..label_end)?;
        labels.push(std::str::from_utf8(label).ok()?.to_ascii_lowercase());
        cursor = label_end;
    }
}

fn qtype_label(qtype: u16) -> String {
    match qtype {
        DNS_QTYPE_A => "A".to_string(),
        DNS_QTYPE_AAAA => "AAAA".to_string(),
        5 => "CNAME".to_string(),
        65 => "HTTPS".to_string(),
        other => other.to_string(),
    }
}

impl DnsResolveError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for DnsResolveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for DnsResolveError {}
