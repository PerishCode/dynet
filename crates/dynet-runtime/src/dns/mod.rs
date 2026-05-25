use std::{
    io::{ErrorKind, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream, UdpSocket},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use tracing::{debug, warn};

use crate::{
    resolver,
    resolver::trace::{classify_runtime_error, classify_runtime_error_disposition},
    RuntimeCounters, RuntimeEvent, RuntimeEventKind, RuntimeSettings,
};

mod wire;
pub(crate) use wire::query_name_from_wire;
pub use wire::{dns_reverse_from_wire, dns_servfail_from_wire};

const DNS_BUFFER_LEN: usize = 4096;

pub(crate) struct UdpDnsServer {
    socket: UdpSocket,
}

pub(crate) struct TcpDnsServer {
    listener: TcpListener,
}

impl UdpDnsServer {
    pub(crate) fn bind(bind: SocketAddr) -> Result<Self, String> {
        let socket = UdpSocket::bind(bind)
            .map_err(|error| format!("failed to bind UDP DNS {bind}: {error}"))?;
        socket
            .set_read_timeout(Some(Duration::from_millis(250)))
            .map_err(|error| format!("failed to set UDP DNS read timeout: {error}"))?;
        Ok(Self { socket })
    }
}

impl TcpDnsServer {
    pub(crate) fn bind(bind: SocketAddr) -> Result<Self, String> {
        let listener = TcpListener::bind(bind)
            .map_err(|error| format!("failed to bind TCP DNS {bind}: {error}"))?;
        listener
            .set_nonblocking(true)
            .map_err(|error| format!("failed to set TCP DNS nonblocking: {error}"))?;
        Ok(Self { listener })
    }
}

pub(crate) fn serve_udp(
    server: UdpDnsServer,
    settings: &RuntimeSettings,
    counters: Arc<RuntimeCounters>,
    stop: Arc<AtomicBool>,
) -> Result<(), String> {
    let mut buffer = [0_u8; DNS_BUFFER_LEN];
    while !stop.load(Ordering::SeqCst) {
        match server.socket.recv_from(&mut buffer) {
            Ok((size, peer)) => {
                handle_udp_query(&server.socket, &buffer[..size], peer, settings, &counters)?;
            }
            Err(error) if timeout_or_would_block(&error) => {}
            Err(error) => return Err(format!("failed receiving UDP DNS query: {error}")),
        }
    }
    Ok(())
}

fn handle_udp_query(
    socket: &UdpSocket,
    query: &[u8],
    peer: SocketAddr,
    settings: &RuntimeSettings,
    counters: &RuntimeCounters,
) -> Result<(), String> {
    let query_id = counters.dns_queries.fetch_add(1, Ordering::SeqCst) + 1;
    let started = Instant::now();
    let query_name = query_name_from_wire(query).ok();
    emit_query_received(query_id, query, query_name.as_deref(), "udp", counters)?;
    match resolver::resolve_dns(
        query,
        &settings.dns_chain,
        settings.bypass_mark,
        settings.policy.as_ref(),
    ) {
        Ok(resolution) => {
            record_resolution(
                query_id,
                query_name.as_deref(),
                "udp",
                &resolution,
                counters,
            );
            capture_reverse_records(query_id, query, &resolution.response, counters)?;
            emit_resolution_completed(
                query_id,
                query_name.as_deref(),
                "udp",
                &resolution,
                started,
                counters,
            )?;
            socket
                .send_to(&resolution.response, peer)
                .map_err(|error| format!("failed to send UDP DNS response: {error}"))?;
        }
        Err(error) => {
            let failure_response = dns_servfail_from_wire(query).ok();
            record_resolution_failure(
                query_id,
                query_name.as_deref(),
                "udp",
                &error,
                started,
                failure_response.as_ref().map(Vec::len),
                counters,
            )?;
            if let Some(response) = failure_response {
                socket
                    .send_to(&response, peer)
                    .map_err(|error| format!("failed to send UDP DNS failure response: {error}"))?;
            }
            warn!(%peer, error = %error.message, "dns.udp.forward_failed");
        }
    }
    Ok(())
}

pub(crate) fn serve_tcp(
    server: TcpDnsServer,
    settings: &RuntimeSettings,
    counters: Arc<RuntimeCounters>,
    stop: Arc<AtomicBool>,
) -> Result<(), String> {
    while !stop.load(Ordering::SeqCst) {
        match server.listener.accept() {
            Ok((stream, peer)) => {
                let query_id = counters.dns_queries.fetch_add(1, Ordering::SeqCst) + 1;
                if let Err(error) = handle_tcp_query(stream, settings, &counters, query_id) {
                    warn!(%peer, %error, "dns.tcp.forward_failed");
                }
            }
            Err(error) if timeout_or_would_block(&error) => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(error) => return Err(format!("failed accepting TCP DNS query: {error}")),
        }
    }
    Ok(())
}

fn handle_tcp_query(
    mut stream: TcpStream,
    settings: &RuntimeSettings,
    counters: &RuntimeCounters,
    query_id: usize,
) -> Result<(), String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|error| format!("failed to set TCP DNS read timeout: {error}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .map_err(|error| format!("failed to set TCP DNS write timeout: {error}"))?;
    let mut len = [0_u8; 2];
    stream
        .read_exact(&mut len)
        .map_err(|error| format!("failed to read TCP DNS length: {error}"))?;
    let query_len = usize::from(u16::from_be_bytes(len));
    if query_len == 0 || query_len > DNS_BUFFER_LEN {
        return Err(format!("unsupported TCP DNS query length: {query_len}"));
    }
    let mut query = vec![0_u8; query_len];
    stream
        .read_exact(&mut query)
        .map_err(|error| format!("failed to read TCP DNS query: {error}"))?;
    let started = Instant::now();
    let query_name = query_name_from_wire(&query).ok();
    emit_query_received(query_id, &query, query_name.as_deref(), "tcp", counters)?;
    let resolution = match resolver::resolve_dns(
        &query,
        &settings.dns_chain,
        settings.bypass_mark,
        settings.policy.as_ref(),
    ) {
        Ok(resolution) => resolution,
        Err(error) => {
            let failure_response = dns_servfail_from_wire(&query).ok();
            record_resolution_failure(
                query_id,
                query_name.as_deref(),
                "tcp",
                &error,
                started,
                failure_response.as_ref().map(Vec::len),
                counters,
            )?;
            if let Some(response) = failure_response {
                write_tcp_dns_response(&mut stream, &response)?;
            }
            return Err(error.message);
        }
    };
    record_resolution(
        query_id,
        query_name.as_deref(),
        "tcp",
        &resolution,
        counters,
    );
    capture_reverse_records(query_id, &query, &resolution.response, counters)?;
    emit_resolution_completed(
        query_id,
        query_name.as_deref(),
        "tcp",
        &resolution,
        started,
        counters,
    )?;
    write_tcp_dns_response(&mut stream, &resolution.response)
}

fn write_tcp_dns_response(stream: &mut TcpStream, response: &[u8]) -> Result<(), String> {
    let response_len = u16::try_from(response.len())
        .map_err(|_| format!("TCP DNS response too large: {}", response.len()))?;
    stream
        .write_all(&response_len.to_be_bytes())
        .and_then(|_| stream.write_all(response))
        .map_err(|error| format!("failed to write TCP DNS response: {error}"))
}

fn record_resolution(
    query_id: usize,
    query_name: Option<&str>,
    listener: &str,
    resolution: &resolver::ResolvedDns,
    counters: &RuntimeCounters,
) {
    if resolution.route_decision {
        counters.route_decisions.fetch_add(1, Ordering::SeqCst);
    }
    if resolution.proxied {
        counters.proxied_dns_queries.fetch_add(1, Ordering::SeqCst);
    }
    for event in &resolution.events {
        let _ = counters.emit(dns_context_event(
            event.clone(),
            query_id,
            query_name,
            listener,
        ));
    }
}

fn emit_query_received(
    query_id: usize,
    query: &[u8],
    query_name: Option<&str>,
    listener: &str,
    counters: &RuntimeCounters,
) -> Result<(), String> {
    counters.emit(
        RuntimeEvent::new(RuntimeEventKind::DnsQueryReceived)
            .field("dnsQueryId", query_id)
            .field("flowId", format!("dns-query-{query_id}"))
            .field("listener", listener)
            .field("query", query_name.unwrap_or("<unparsed>"))
            .field("queryBytes", query.len()),
    )
}

fn emit_resolution_completed(
    query_id: usize,
    query_name: Option<&str>,
    listener: &str,
    resolution: &resolver::ResolvedDns,
    started: Instant,
    counters: &RuntimeCounters,
) -> Result<(), String> {
    counters.emit(
        RuntimeEvent::new(RuntimeEventKind::DnsResolveCompleted)
            .field("dnsQueryId", query_id)
            .field("flowId", format!("dns-query-{query_id}"))
            .field("listener", listener)
            .field("query", query_name.unwrap_or("<unparsed>"))
            .field("elapsedMs", started.elapsed().as_millis())
            .field("routeDecision", resolution.route_decision)
            .field("proxied", resolution.proxied)
            .field("responseBytes", resolution.response.len()),
    )
}

fn record_resolution_failure(
    query_id: usize,
    query_name: Option<&str>,
    listener: &str,
    error: &resolver::ResolveError,
    started: Instant,
    failure_response_bytes: Option<usize>,
    counters: &RuntimeCounters,
) -> Result<(), String> {
    for event in &error.events {
        counters.emit(dns_context_event(
            event.clone(),
            query_id,
            query_name,
            listener,
        ))?;
    }
    let mut event = RuntimeEvent::new(RuntimeEventKind::DnsResolveFailed)
        .field("dnsQueryId", query_id)
        .field("flowId", format!("dns-query-{query_id}"))
        .field("listener", listener)
        .field("query", query_name.unwrap_or("<unparsed>"))
        .field("elapsedMs", started.elapsed().as_millis())
        .field("errorType", classify_runtime_error(&error.message))
        .field(
            "errorDisposition",
            classify_runtime_error_disposition(&error.message),
        )
        .field("error", &error.message);
    if let Some(bytes) = failure_response_bytes {
        event = event
            .field("failureResponseCode", "SERVFAIL")
            .field("failureResponseBytes", bytes);
    }
    counters.emit(event)
}

fn capture_reverse_records(
    query_id: usize,
    query: &[u8],
    response: &[u8],
    counters: &RuntimeCounters,
) -> Result<(), String> {
    let captured = dns_reverse_from_wire(query, response, now_secs())?;
    let inserted = captured.records.len();
    for record in &captured.records {
        debug!(
            query = %record.query,
            canonical = ?record.canonical,
            address = %record.address,
            ttl = record.ttl_secs,
            "dns.reverse_record"
        );
        counters.emit(
            RuntimeEvent::new(RuntimeEventKind::DnsReverseRecord)
                .field("dnsQueryId", query_id)
                .field("flowId", format!("dns-query-{query_id}"))
                .field("query", &record.query)
                .field("address", record.address)
                .field("ttl", record.ttl_secs),
        )?;
    }
    let mut reverse = counters
        .dns_reverse
        .lock()
        .map_err(|_| "dns reverse index lock poisoned".to_string())?;
    reverse.now_secs = captured.now_secs;
    reverse.records.extend(captured.records);
    debug!(records = inserted, "dns.query");
    Ok(())
}

fn dns_context_event(
    mut event: RuntimeEvent,
    query_id: usize,
    query_name: Option<&str>,
    listener: &str,
) -> RuntimeEvent {
    event
        .fields
        .entry("dnsQueryId".to_string())
        .or_insert_with(|| query_id.to_string());
    event
        .fields
        .entry("flowId".to_string())
        .or_insert_with(|| format!("dns-query-{query_id}"));
    event
        .fields
        .entry("listener".to_string())
        .or_insert_with(|| listener.to_string());
    if let Some(query_name) = query_name {
        event
            .fields
            .entry("query".to_string())
            .or_insert_with(|| query_name.to_string());
    }
    event
}

fn timeout_or_would_block(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
    )
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
