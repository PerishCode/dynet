use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    time::Instant,
};

pub(crate) mod buffered_read;
mod cascade;
mod dialer;
mod shadowsocks;
mod stream;
mod tcp_socket;
mod trojan;
#[cfg(target_os = "linux")]
mod udp;
mod vmess_adapter;

use dynet_core::{InboundContext, NetworkNode};
use tracing::debug;

use crate::{
    resolver::trace::{
        annotate_runtime_error_fields, classify_runtime_error, classify_runtime_error_disposition,
    },
    settings::{OutboundTcpSettings, RuntimePolicy},
    vmess, RuntimeEvent, RuntimeEventKind,
};

pub(crate) use cascade::connect_tcp_with_fallback;
pub(crate) use tcp_socket::{connect_tcp_socket, connect_tcp_socket_bound, TcpTarget};
#[cfg(target_os = "linux")]
pub(crate) use udp::{connect_udp_policy, ProxiedUdpSocket};
pub(super) use vmess_adapter::{vmess_server_target, vmess_spec_from_node, vmess_target};

const DNS_TCP_BUFFER_LIMIT: usize = 4096;

pub(crate) enum ProxiedTcpStream {
    Direct(TcpStream),
    Shadowsocks(Box<shadowsocks::ShadowsocksTcpStream>),
    Trojan(Box<trojan::TrojanTcpStream>),
    Vmess(Box<vmess::VmessTcpStream>),
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct TcpConnectOptions {
    mark: u32,
    settings: OutboundTcpSettings,
}

impl TcpConnectOptions {
    pub(crate) fn new(mark: u32, settings: OutboundTcpSettings) -> Self {
        Self { mark, settings }
    }
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
                    .field(
                        "errorDisposition",
                        classify_runtime_error_disposition(&error),
                    )
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
                    .field(
                        "errorDisposition",
                        classify_runtime_error_disposition(&error),
                    )
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
        vmess::connect_tcp(
            &spec,
            upstream_dns.into(),
            mark,
            OutboundTcpSettings::default(),
        )
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
    let mut stream = connect_tcp_with_fallback(
        &upstream_dns.into(),
        outbound,
        policy,
        context,
        events,
        "pre-query",
        TcpConnectOptions::new(mark, OutboundTcpSettings::default()),
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
    tcp_settings: OutboundTcpSettings,
) -> Result<ProxiedTcpStream, String> {
    let started = Instant::now();
    events.push(
        RuntimeEvent::new(RuntimeEventKind::OutboundAttemptStarted)
            .field("outbound", &outbound.tag)
            .field("kind", &outbound.kind)
            .field("transport", "tcp")
            .field("protocol", "tcp-connect")
            .field("target", target)
            .field(
                "outboundTcpConnectTimeoutMs",
                tcp_settings.connect_timeout_ms,
            )
            .field(
                "outboundTcpReadWriteTimeoutMs",
                tcp_settings.read_write_timeout_ms,
            ),
    );
    let result = connect_tcp_target_inner(target, outbound, mark, events, tcp_settings);
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
        Err(error) => events.push(annotate_runtime_error_fields(
            RuntimeEvent::new(RuntimeEventKind::OutboundAttemptFinished)
                .field("outbound", &outbound.tag)
                .field("kind", &outbound.kind)
                .field("transport", "tcp")
                .field("protocol", "tcp-connect")
                .field("target", target)
                .field("status", "failed")
                .field("errorType", classify_runtime_error(error))
                .field(
                    "errorDisposition",
                    classify_runtime_error_disposition(error),
                )
                .field("error", error)
                .field("elapsedMs", started.elapsed().as_millis()),
            error,
        )),
    }
    result
}

fn connect_tcp_target_inner(
    target: &TcpTarget,
    outbound: &NetworkNode,
    mark: u32,
    events: &mut Vec<RuntimeEvent>,
    tcp_settings: OutboundTcpSettings,
) -> Result<ProxiedTcpStream, String> {
    match outbound.kind.as_str() {
        "direct" => observe_stage_with(
            events,
            outbound,
            "tcp-connect",
            |event| annotate_tcp_settings(event, tcp_settings),
            || {
                tcp_socket::connect_direct_target(target, mark, tcp_settings)
                    .map(ProxiedTcpStream::Direct)
            },
        ),
        "vmess" => {
            let spec = observe_stage(events, outbound, "payload-decode", || {
                vmess_spec_from_node(outbound)
            })?;
            observe_stage_with(
                events,
                outbound,
                "tcp-connect",
                |event| annotate_tcp_settings(event, tcp_settings),
                || {
                    vmess::connect_tcp(&spec, vmess_target(target), mark, tcp_settings)
                        .map(Box::new)
                        .map(ProxiedTcpStream::Vmess)
                },
            )
        }
        "ss" => {
            let spec = observe_stage(events, outbound, "payload-decode", || {
                shadowsocks::spec_from_node(outbound)
            })?;
            observe_stage_with(
                events,
                outbound,
                "tcp-connect",
                |event| annotate_tcp_settings(event, tcp_settings),
                || {
                    shadowsocks::connect_tcp(&spec, target, mark, tcp_settings)
                        .map(Box::new)
                        .map(ProxiedTcpStream::Shadowsocks)
                },
            )
        }
        "trojan" => trojan::adapter::connect_tcp(target, outbound, mark, events, tcp_settings),
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
    events: &mut Vec<RuntimeEvent>,
    options: TcpConnectOptions,
) -> Result<ProxiedTcpStream, String> {
    connect_tcp_with_bound(target, outbound, policy, context, events, None, options)
}

pub(crate) fn connect_tcp_with_bound(
    target: &TcpTarget,
    outbound: &NetworkNode,
    policy: &RuntimePolicy,
    context: &InboundContext,
    events: &mut Vec<RuntimeEvent>,
    dialer_bound_override: Option<&str>,
    options: TcpConnectOptions,
) -> Result<ProxiedTcpStream, String> {
    if outbound.kind == "dialer" {
        return dialer::connect_with_bound_override(
            target,
            outbound,
            policy,
            context,
            events,
            dialer_bound_override,
            options,
        );
    }
    connect_tcp_target(target, outbound, options.mark, events, options.settings)
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
    observe_stage_with(events, outbound, stage, |event| event, run)
}

fn annotate_tcp_settings(event: RuntimeEvent, settings: OutboundTcpSettings) -> RuntimeEvent {
    event
        .field("outboundTcpConnectTimeoutMs", settings.connect_timeout_ms)
        .field(
            "outboundTcpReadWriteTimeoutMs",
            settings.read_write_timeout_ms,
        )
}

fn observe_stage_with<T>(
    events: &mut Vec<RuntimeEvent>,
    outbound: &NetworkNode,
    stage: &str,
    decorate: impl Fn(RuntimeEvent) -> RuntimeEvent,
    run: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    let started = Instant::now();
    match run() {
        Ok(value) => {
            events.push(decorate(
                RuntimeEvent::new(RuntimeEventKind::OutboundStageFinished)
                    .field("outbound", &outbound.tag)
                    .field("kind", &outbound.kind)
                    .field("stage", stage)
                    .field("status", "success")
                    .field("elapsedMs", started.elapsed().as_millis()),
            ));
            Ok(value)
        }
        Err(error) => {
            events.push(decorate(annotate_runtime_error_fields(
                RuntimeEvent::new(RuntimeEventKind::OutboundStageFinished)
                    .field("outbound", &outbound.tag)
                    .field("kind", &outbound.kind)
                    .field("stage", stage)
                    .field("status", "failed")
                    .field("errorType", classify_runtime_error(&error))
                    .field(
                        "errorDisposition",
                        classify_runtime_error_disposition(&error),
                    )
                    .field("error", &error)
                    .field("elapsedMs", started.elapsed().as_millis()),
                &error,
            )));
            Err(error)
        }
    }
}
