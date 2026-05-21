use std::{
    io::{Read, Write},
    net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs},
    time::{Duration, Instant},
};

pub(crate) mod buffered_read;
mod dialer;
mod shadowsocks;
mod stream;
mod trojan;
#[cfg(target_os = "linux")]
mod udp;
mod vmess_adapter;

use dynet_core::{InboundContext, NetworkNode};
use tracing::debug;

use crate::{
    resolver::trace::classify_runtime_error, settings::RuntimePolicy, socket, vmess, RuntimeEvent,
    RuntimeEventKind,
};

#[cfg(target_os = "linux")]
pub(crate) use udp::{connect_udp_policy, ProxiedUdpSocket};
pub(super) use vmess_adapter::{vmess_server_target, vmess_spec_from_node, vmess_target};

const DNS_TCP_BUFFER_LIMIT: usize = 4096;
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(8);

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum TcpTarget {
    Socket(SocketAddr),
    Domain { host: String, port: u16 },
}

pub(crate) enum ProxiedTcpStream {
    Direct(TcpStream),
    Shadowsocks(Box<shadowsocks::ShadowsocksTcpStream>),
    Trojan(Box<trojan::TrojanTcpStream>),
    Vmess(Box<vmess::VmessTcpStream>),
}

pub(crate) fn resolve_dns_over_tcp(
    query: &[u8],
    upstream_dns: SocketAddr,
    outbound: &NetworkNode,
    mark: u32,
    events: &mut Vec<RuntimeEvent>,
) -> Result<Vec<u8>, String> {
    match outbound.kind.as_str() {
        "vmess" => observed_outbound_attempt(query, upstream_dns, outbound, mark, events),
        kind => Err(format!(
            "DNS-over-TCP proxy egress does not support outbound type `{kind}`"
        )),
    }
}

pub(crate) fn resolve_dns_policy(
    query: &[u8],
    upstream_dns: SocketAddr,
    outbound: &NetworkNode,
    mark: u32,
    policy: &RuntimePolicy,
    context: &InboundContext,
    events: &mut Vec<RuntimeEvent>,
) -> Result<Vec<u8>, String> {
    let started = Instant::now();
    events.push(
        RuntimeEvent::new(RuntimeEventKind::OutboundAttemptStarted)
            .field("outbound", &outbound.tag)
            .field("kind", &outbound.kind)
            .field("transport", "dns")
            .field("protocol", "dns-over-tcp")
            .field("upstream", upstream_dns)
            .field("queryBytes", query.len()),
    );
    let result = dns_over_tcp_stream(query, upstream_dns, outbound, mark, policy, context, events);
    match result {
        Ok(response) => {
            events.push(
                RuntimeEvent::new(RuntimeEventKind::OutboundAttemptFinished)
                    .field("outbound", &outbound.tag)
                    .field("kind", &outbound.kind)
                    .field("transport", "dns")
                    .field("protocol", "dns-over-tcp")
                    .field("status", "success")
                    .field("elapsedMs", started.elapsed().as_millis())
                    .field("responseBytes", response.len()),
            );
            Ok(response)
        }
        Err(error) => {
            events.push(
                RuntimeEvent::new(RuntimeEventKind::OutboundAttemptFinished)
                    .field("outbound", &outbound.tag)
                    .field("kind", &outbound.kind)
                    .field("transport", "dns")
                    .field("protocol", "dns-over-tcp")
                    .field("status", "failed")
                    .field("errorType", classify_runtime_error(&error))
                    .field("error", &error)
                    .field("elapsedMs", started.elapsed().as_millis()),
            );
            Err(error)
        }
    }
}

fn observed_outbound_attempt(
    query: &[u8],
    upstream_dns: SocketAddr,
    outbound: &NetworkNode,
    mark: u32,
    events: &mut Vec<RuntimeEvent>,
) -> Result<Vec<u8>, String> {
    let started = Instant::now();
    events.push(
        RuntimeEvent::new(RuntimeEventKind::OutboundAttemptStarted)
            .field("outbound", &outbound.tag)
            .field("kind", &outbound.kind)
            .field("transport", "dns")
            .field("protocol", "dns-over-tcp")
            .field("upstream", upstream_dns)
            .field("queryBytes", query.len()),
    );
    match vmess_tcp_dns(query, upstream_dns, outbound, mark, events) {
        Ok(response) => {
            events.push(
                RuntimeEvent::new(RuntimeEventKind::OutboundAttemptFinished)
                    .field("outbound", &outbound.tag)
                    .field("kind", &outbound.kind)
                    .field("transport", "dns")
                    .field("protocol", "dns-over-tcp")
                    .field("status", "success")
                    .field("elapsedMs", started.elapsed().as_millis())
                    .field("responseBytes", response.len()),
            );
            Ok(response)
        }
        Err(error) => {
            events.push(
                RuntimeEvent::new(RuntimeEventKind::OutboundAttemptFinished)
                    .field("outbound", &outbound.tag)
                    .field("kind", &outbound.kind)
                    .field("transport", "dns")
                    .field("protocol", "dns-over-tcp")
                    .field("status", "failed")
                    .field("errorType", classify_runtime_error(&error))
                    .field("error", &error)
                    .field("elapsedMs", started.elapsed().as_millis()),
            );
            Err(error)
        }
    }
}

fn vmess_tcp_dns(
    query: &[u8],
    upstream_dns: SocketAddr,
    outbound: &NetworkNode,
    mark: u32,
    events: &mut Vec<RuntimeEvent>,
) -> Result<Vec<u8>, String> {
    let spec = observe_stage(events, outbound, "payload-decode", || {
        vmess_spec_from_node(outbound)
    })?;
    let mut stream = observe_stage(events, outbound, "vmess-connect", || {
        vmess::connect_tcp(&spec, upstream_dns.into(), mark)
    })?;
    write_dns_tcp_query(&mut stream, query, outbound, events)?;
    let response = read_dns_tcp_response(&mut stream, outbound, events)?;
    debug!(
        outbound = %outbound.tag,
        upstream = %upstream_dns,
        bytes = response.len(),
        "dns.vmess.query"
    );
    Ok(response)
}

fn dns_over_tcp_stream(
    query: &[u8],
    upstream_dns: SocketAddr,
    outbound: &NetworkNode,
    mark: u32,
    policy: &RuntimePolicy,
    context: &InboundContext,
    events: &mut Vec<RuntimeEvent>,
) -> Result<Vec<u8>, String> {
    let mut stream = connect_tcp_policy(
        &upstream_dns.into(),
        outbound,
        policy,
        context,
        mark,
        events,
    )?;
    write_dns_tcp_query(&mut stream, query, outbound, events)?;
    let response = read_dns_tcp_response(&mut stream, outbound, events)?;
    debug!(
        outbound = %outbound.tag,
        upstream = %upstream_dns,
        bytes = response.len(),
        "dns.proxied.tcp.query"
    );
    Ok(response)
}

fn write_dns_tcp_query(
    stream: &mut impl Write,
    query: &[u8],
    outbound: &NetworkNode,
    events: &mut Vec<RuntimeEvent>,
) -> Result<(), String> {
    let query_len = u16::try_from(query.len())
        .map_err(|_| format!("DNS query too large for TCP framing: {}", query.len()))?;
    let mut framed_query = Vec::with_capacity(query.len() + 2);
    framed_query.extend_from_slice(&query_len.to_be_bytes());
    framed_query.extend_from_slice(query);
    observe_stage(events, outbound, "dns-tcp-write", || {
        stream
            .write_all(&framed_query)
            .map_err(|error| format!("failed to write proxied DNS TCP query: {error}"))?;
        stream
            .flush()
            .map_err(|error| format!("failed to flush proxied DNS TCP query: {error}"))
    })
}

fn read_dns_tcp_response(
    stream: &mut impl Read,
    outbound: &NetworkNode,
    events: &mut Vec<RuntimeEvent>,
) -> Result<Vec<u8>, String> {
    let mut len = [0_u8; 2];
    observe_stage(events, outbound, "dns-tcp-read-length", || {
        stream
            .read_exact(&mut len)
            .map_err(|error| format!("failed to read proxied DNS TCP length: {error}"))
    })?;
    let response_len = usize::from(u16::from_be_bytes(len));
    if response_len == 0 || response_len > DNS_TCP_BUFFER_LIMIT {
        return Err(format!(
            "proxied DNS TCP response length is unsupported: {response_len}"
        ));
    }
    let mut response = vec![0_u8; response_len];
    observe_stage(events, outbound, "dns-tcp-read-response", || {
        stream
            .read_exact(&mut response)
            .map_err(|error| format!("failed to read proxied DNS TCP response: {error}"))
    })?;
    Ok(response)
}

pub(crate) fn connect_tcp_target(
    target: &TcpTarget,
    outbound: &NetworkNode,
    mark: u32,
    events: &mut Vec<RuntimeEvent>,
) -> Result<ProxiedTcpStream, String> {
    let started = Instant::now();
    events.push(
        RuntimeEvent::new(RuntimeEventKind::OutboundAttemptStarted)
            .field("outbound", &outbound.tag)
            .field("kind", &outbound.kind)
            .field("transport", "tcp")
            .field("protocol", "tcp-connect")
            .field("target", target),
    );
    let result = connect_tcp_target_inner(target, outbound, mark, events);
    match &result {
        Ok(_) => events.push(
            RuntimeEvent::new(RuntimeEventKind::OutboundAttemptFinished)
                .field("outbound", &outbound.tag)
                .field("kind", &outbound.kind)
                .field("transport", "tcp")
                .field("protocol", "tcp-connect")
                .field("target", target)
                .field("status", "success")
                .field("elapsedMs", started.elapsed().as_millis()),
        ),
        Err(error) => events.push(
            RuntimeEvent::new(RuntimeEventKind::OutboundAttemptFinished)
                .field("outbound", &outbound.tag)
                .field("kind", &outbound.kind)
                .field("transport", "tcp")
                .field("protocol", "tcp-connect")
                .field("target", target)
                .field("status", "failed")
                .field("errorType", classify_runtime_error(error))
                .field("error", error)
                .field("elapsedMs", started.elapsed().as_millis()),
        ),
    }
    result
}

fn connect_tcp_target_inner(
    target: &TcpTarget,
    outbound: &NetworkNode,
    mark: u32,
    events: &mut Vec<RuntimeEvent>,
) -> Result<ProxiedTcpStream, String> {
    match outbound.kind.as_str() {
        "direct" => observe_stage(events, outbound, "tcp-connect", || {
            connect_direct_target(target, mark).map(ProxiedTcpStream::Direct)
        }),
        "vmess" => {
            let spec = observe_stage(events, outbound, "payload-decode", || {
                vmess_spec_from_node(outbound)
            })?;
            observe_stage(events, outbound, "tcp-connect", || {
                vmess::connect_tcp(&spec, vmess_target(target), mark)
                    .map(Box::new)
                    .map(ProxiedTcpStream::Vmess)
            })
        }
        "ss" => {
            let spec = observe_stage(events, outbound, "payload-decode", || {
                shadowsocks::spec_from_node(outbound)
            })?;
            observe_stage(events, outbound, "tcp-connect", || {
                shadowsocks::connect_tcp(&spec, target, mark)
                    .map(Box::new)
                    .map(ProxiedTcpStream::Shadowsocks)
            })
        }
        "trojan" => {
            let spec = observe_stage(events, outbound, "payload-decode", || {
                trojan::spec_from_node(outbound)
            })?;
            observe_stage(events, outbound, "tcp-connect", || {
                trojan::connect_tcp(&spec, target, mark)
                    .map(Box::new)
                    .map(ProxiedTcpStream::Trojan)
            })
        }
        kind => Err(format!(
            "TCP probe egress does not support outbound type `{kind}`"
        )),
    }
}

pub(crate) fn connect_tcp_policy(
    target: &TcpTarget,
    outbound: &NetworkNode,
    policy: &RuntimePolicy,
    context: &InboundContext,
    mark: u32,
    events: &mut Vec<RuntimeEvent>,
) -> Result<ProxiedTcpStream, String> {
    connect_tcp_with_bound(target, outbound, policy, context, mark, events, None)
}

pub(crate) fn connect_tcp_with_bound(
    target: &TcpTarget,
    outbound: &NetworkNode,
    policy: &RuntimePolicy,
    context: &InboundContext,
    mark: u32,
    events: &mut Vec<RuntimeEvent>,
    dialer_bound_override: Option<&str>,
) -> Result<ProxiedTcpStream, String> {
    if outbound.kind == "dialer" {
        return dialer::connect_with_bound_override(
            target,
            outbound,
            policy,
            context,
            mark,
            events,
            dialer_bound_override,
        );
    }
    connect_tcp_target(target, outbound, mark, events)
}

pub(crate) fn dialer_bound_candidate_order(
    outbound: &NetworkNode,
    policy: &RuntimePolicy,
    context: &InboundContext,
) -> Result<Vec<String>, String> {
    dialer::bound_candidate_order(outbound, policy, context)
}

fn observe_stage<T>(
    events: &mut Vec<RuntimeEvent>,
    outbound: &NetworkNode,
    stage: &str,
    run: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    let started = Instant::now();
    match run() {
        Ok(value) => {
            events.push(
                RuntimeEvent::new(RuntimeEventKind::OutboundStageFinished)
                    .field("outbound", &outbound.tag)
                    .field("kind", &outbound.kind)
                    .field("stage", stage)
                    .field("status", "success")
                    .field("elapsedMs", started.elapsed().as_millis()),
            );
            Ok(value)
        }
        Err(error) => {
            events.push(
                RuntimeEvent::new(RuntimeEventKind::OutboundStageFinished)
                    .field("outbound", &outbound.tag)
                    .field("kind", &outbound.kind)
                    .field("stage", stage)
                    .field("status", "failed")
                    .field("errorType", classify_runtime_error(&error))
                    .field("error", &error)
                    .field("elapsedMs", started.elapsed().as_millis()),
            );
            Err(error)
        }
    }
}

impl std::fmt::Display for TcpTarget {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Socket(address) => write!(formatter, "{address}"),
            Self::Domain { host, port } => write!(formatter, "{host}:{port}"),
        }
    }
}

impl From<SocketAddr> for TcpTarget {
    fn from(value: SocketAddr) -> Self {
        Self::Socket(value)
    }
}

fn connect_direct_target(target: &TcpTarget, mark: u32) -> Result<TcpStream, String> {
    let stream = match target {
        TcpTarget::Socket(address) => TcpStream::connect_timeout(address, TCP_CONNECT_TIMEOUT)
            .map_err(|error| format!("failed to connect TCP target {target}: {error}"))?,
        TcpTarget::Domain { host, port } => {
            connect_host_port(host, *port, &format!("TCP target {target}"))?
        }
    };
    socket::set_socket_mark(&stream, mark)?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(8)))
        .map_err(|error| format!("failed to set TCP target read timeout: {error}"))?;
    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(8)))
        .map_err(|error| format!("failed to set TCP target write timeout: {error}"))?;
    Ok(stream)
}

pub(crate) fn connect_tcp_socket(
    address: &str,
    port: u16,
    mark: u32,
) -> Result<std::net::TcpStream, String> {
    let stream = match address.parse::<IpAddr>() {
        Ok(ip) => {
            let socket = SocketAddr::new(ip, port);
            TcpStream::connect_timeout(&socket, TCP_CONNECT_TIMEOUT)
                .map_err(|error| format!("failed to connect outbound server {socket}: {error}"))?
        }
        Err(_) => connect_host_port(address, port, "outbound server")?,
    };
    socket::set_socket_mark(&stream, mark)?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(8)))
        .map_err(|error| format!("failed to set outbound read timeout: {error}"))?;
    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(8)))
        .map_err(|error| format!("failed to set outbound write timeout: {error}"))?;
    Ok(stream)
}

fn connect_host_port(host: &str, port: u16, context: &str) -> Result<TcpStream, String> {
    let addresses = (host, port)
        .to_socket_addrs()
        .map_err(|error| format!("failed to resolve {context} {host}:{port}: {error}"))?;
    let mut last_error = None;
    for address in addresses {
        match TcpStream::connect_timeout(&address, TCP_CONNECT_TIMEOUT) {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(format!("{address}: {error}")),
        }
    }
    Err(format!(
        "failed to connect {context} {host}:{port}: {}",
        last_error.unwrap_or_else(|| "no socket addresses resolved".to_string())
    ))
}
