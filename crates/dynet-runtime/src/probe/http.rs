use std::{
    io::{ErrorKind, Read, Result as IoResult, Write},
    sync::Arc,
    thread::sleep,
    time::Instant,
};

use dynet_core::NetworkNode;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

use crate::{
    event::EventBus,
    outbound::ProxiedTcpStream,
    probe::{ProbeProtocol, ProbeReadPolicy, ProbeTarget},
    resolver::trace::{classify_runtime_error, classify_runtime_error_disposition, elapsed_ms},
    RuntimeEvent, RuntimeEventKind,
};

const HTTP_HEAD_LIMIT: usize = 64 * 1024;

pub(crate) struct ProbeResponse {
    pub(crate) status_code: Option<u16>,
    pub(crate) bytes: usize,
}

pub(crate) fn execute_with_protocol(
    ebus: &EventBus,
    outbound: &NetworkNode,
    target: &ProbeTarget,
    mut stream: ProxiedTcpStream,
    protocol: ProbeProtocol,
    read_policy: ProbeReadPolicy,
) -> Result<ProbeResponse, String> {
    if protocol == ProbeProtocol::TcpConnect {
        return observe_stage(ebus, outbound, "stream-flush", || {
            stream
                .flush()
                .map_err(|error| format!("failed to flush TCP probe stream: {error}"))?;
            Ok(ProbeResponse {
                status_code: None,
                bytes: 0,
            })
        });
    }
    stream
        .set_read_timeout(Some(read_policy.poll_timeout()))
        .map_err(|error| format!("failed to set probe stream read timeout: {error}"))?;
    let mut tls = observe_stage(ebus, outbound, "tls-handshake", || {
        tls_handshake(
            ObservedProbeStream::new(
                stream,
                ebus.clone(),
                outbound,
                protocol.as_str(),
                read_policy,
            ),
            &target.host,
        )
    })?;
    if protocol == ProbeProtocol::TlsHandshake {
        return Ok(ProbeResponse {
            status_code: None,
            bytes: 0,
        });
    }
    observe_stage(ebus, outbound, "http-head-write", || {
        let request = http_head_request(target);
        tls.write_all(&request)
            .map_err(|error| format!("failed to write HTTPS HEAD request: {error}"))?;
        tls.flush()
            .map_err(|error| format!("failed to flush HTTPS HEAD request: {error}"))
    })?;
    observe_stage(ebus, outbound, "http-head-read", || {
        read_http_head(&mut tls)
    })
}

fn observe_stage<T>(
    ebus: &EventBus,
    outbound: &NetworkNode,
    stage: &str,
    run: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    let started = Instant::now();
    match run() {
        Ok(value) => {
            emit(
                ebus,
                stage_event(outbound, stage, "success", started, None::<&str>),
            )?;
            Ok(value)
        }
        Err(error) => {
            emit(
                ebus,
                stage_event(outbound, stage, "failed", started, Some(error.as_str())),
            )?;
            Err(error)
        }
    }
}

fn stage_event(
    outbound: &NetworkNode,
    stage: &str,
    status: &str,
    started: Instant,
    error: Option<&str>,
) -> RuntimeEvent {
    let mut event = RuntimeEvent::new(RuntimeEventKind::OutboundStageFinished)
        .field("outbound", &outbound.tag)
        .field("kind", &outbound.kind)
        .field("stage", stage)
        .field("status", status)
        .field("elapsedMs", elapsed_ms(started));
    if let Some(error) = error {
        event = event
            .field("errorType", classify_runtime_error(error))
            .field(
                "errorDisposition",
                classify_runtime_error_disposition(error),
            )
            .field("error", error);
    }
    event
}

fn tls_handshake(
    mut stream: ObservedProbeStream,
    host: &str,
) -> Result<StreamOwned<ClientConnection, ObservedProbeStream>, String> {
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|error| format!("invalid TLS server name `{host}`: {error}"))?;
    let mut connection = ClientConnection::new(tls_config(), server_name)
        .map_err(|error| format!("failed to create TLS connection: {error}"))?;
    while connection.is_handshaking() {
        connection
            .complete_io(&mut stream)
            .map_err(|error| format!("failed TLS handshake with `{host}`: {error}"))?;
    }
    Ok(StreamOwned::new(connection, stream))
}

fn tls_config() -> Arc<ClientConfig> {
    let root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    Arc::new(
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    )
}

fn http_head_request(target: &ProbeTarget) -> Vec<u8> {
    format!(
        "HEAD {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: dynet-probe/0.1\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        target.path,
        target.host_header()
    )
    .into_bytes()
}

fn read_http_head(
    tls: &mut StreamOwned<ClientConnection, ObservedProbeStream>,
) -> Result<ProbeResponse, String> {
    let mut response = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let size = tls
            .read(&mut buffer)
            .map_err(|error| format!("failed to read HTTPS HEAD response: {error}"))?;
        if size == 0 {
            break;
        }
        response.extend_from_slice(&buffer[..size]);
        if header_end(&response).is_some() {
            break;
        }
        if response.len() > HTTP_HEAD_LIMIT {
            return Err(format!(
                "HTTPS HEAD response headers too large: {} bytes",
                response.len()
            ));
        }
    }
    let header_end = header_end(&response)
        .ok_or_else(|| "HTTPS HEAD response ended before headers completed".to_string())?;
    let headers = std::str::from_utf8(&response[..header_end])
        .map_err(|error| format!("HTTPS HEAD response headers are not UTF-8: {error}"))?;
    let status_line = headers
        .lines()
        .next()
        .ok_or_else(|| "HTTPS HEAD response was empty".to_string())?;
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| format!("HTTPS HEAD status line has no code: `{status_line}`"))?
        .parse::<u16>()
        .map_err(|error| format!("invalid HTTPS HEAD status line `{status_line}`: {error}"))?;
    Ok(ProbeResponse {
        status_code: Some(status_code),
        bytes: response.len(),
    })
}

fn header_end(response: &[u8]) -> Option<usize> {
    response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

fn emit(ebus: &EventBus, event: RuntimeEvent) -> Result<(), String> {
    ebus.emit(event)
}

struct ObservedProbeStream {
    inner: ProxiedTcpStream,
    ebus: EventBus,
    outbound_tag: String,
    outbound_kind: String,
    protocol: &'static str,
    read_policy: ProbeReadPolicy,
    first_write_seen: bool,
    first_read_seen: bool,
}

impl ObservedProbeStream {
    fn new(
        inner: ProxiedTcpStream,
        ebus: EventBus,
        outbound: &NetworkNode,
        protocol: &'static str,
        read_policy: ProbeReadPolicy,
    ) -> Self {
        Self {
            inner,
            ebus,
            outbound_tag: outbound.tag.clone(),
            outbound_kind: outbound.kind.clone(),
            protocol,
            read_policy,
            first_write_seen: false,
            first_read_seen: false,
        }
    }

    fn emit_stream_stage(
        &self,
        stage: &str,
        status: &str,
        started: Instant,
        bytes: Option<usize>,
        error: Option<&std::io::Error>,
        pending_retries: usize,
    ) -> IoResult<()> {
        let mut event = RuntimeEvent::new(RuntimeEventKind::OutboundStageFinished)
            .field("outbound", &self.outbound_tag)
            .field("kind", &self.outbound_kind)
            .field("stage", stage)
            .field("status", status)
            .field("protocol", self.protocol)
            .field("elapsedMs", elapsed_ms(started));
        if pending_retries > 0 {
            event = event
                .field("pendingRetries", pending_retries)
                .field("pendingBudgetMs", self.read_policy.pending_budget_ms)
                .field("pendingSleepMs", self.read_policy.pending_sleep_ms);
        }
        if let Some(bytes) = bytes {
            event = event.field("bytes", bytes);
        }
        if let Some(error) = error {
            let error = error.to_string();
            let marker = protocol_read_marker(error.as_str());
            event = event
                .field("errorType", classify_runtime_error(&error))
                .field("error", &error);
            if let Some(marker) = marker {
                event = event
                    .field("protocolReadMarker", marker.key)
                    .field("protocolReadStage", marker.stage)
                    .field("protocolReadContext", marker.context)
                    .field("protocolReadDisposition", marker.disposition);
            }
        }
        self.ebus.emit(event).map_err(std::io::Error::other)
    }
}

impl Read for ObservedProbeStream {
    fn read(&mut self, output: &mut [u8]) -> IoResult<usize> {
        let observe = !self.first_read_seen;
        if observe {
            self.first_read_seen = true;
        }
        let started = Instant::now();
        let mut pending_retries = 0;
        let pending_budget = self.read_policy.pending_budget();
        let pending_sleep = self.read_policy.pending_sleep();
        let result = loop {
            match self.inner.read(output) {
                Err(error) if pending_read_error(&error) && started.elapsed() < pending_budget => {
                    pending_retries += 1;
                    if !pending_sleep.is_zero() {
                        sleep(pending_sleep);
                    }
                }
                result => break result,
            }
        };
        if observe {
            match &result {
                Ok(bytes) => self.emit_stream_stage(
                    "stream-first-read",
                    "success",
                    started,
                    Some(*bytes),
                    None,
                    pending_retries,
                )?,
                Err(error) => self.emit_stream_stage(
                    "stream-first-read",
                    "failed",
                    started,
                    None,
                    Some(error),
                    pending_retries,
                )?,
            }
        }
        result
    }
}

impl Write for ObservedProbeStream {
    fn write(&mut self, input: &[u8]) -> IoResult<usize> {
        let observe = !self.first_write_seen;
        if observe {
            self.first_write_seen = true;
        }
        let started = Instant::now();
        let result = self.inner.write(input);
        if observe {
            match &result {
                Ok(bytes) => self.emit_stream_stage(
                    "stream-first-write",
                    "success",
                    started,
                    Some(*bytes),
                    None,
                    0,
                )?,
                Err(error) => self.emit_stream_stage(
                    "stream-first-write",
                    "failed",
                    started,
                    None,
                    Some(error),
                    0,
                )?,
            }
        }
        result
    }

    fn flush(&mut self) -> IoResult<()> {
        self.inner.flush()
    }
}

fn pending_read_error(error: &std::io::Error) -> bool {
    matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
}

struct ProtocolReadMarker {
    key: &'static str,
    stage: &'static str,
    context: &'static str,
    disposition: &'static str,
}

fn protocol_read_marker(error: &str) -> Option<ProtocolReadMarker> {
    if error.contains("VMess response header length is not ready") {
        return Some(ProtocolReadMarker {
            key: "vmess-response-header-length-pending",
            stage: "vmess-response-header-length",
            context: protocol_read_context(error),
            disposition: "pending-budget-exhausted",
        });
    }
    if error.contains("failed to read VMess response header length: unexpected EOF") {
        return Some(ProtocolReadMarker {
            key: "vmess-response-header-length-eof",
            stage: "vmess-response-header-length",
            context: protocol_read_context(error),
            disposition: "remote-eof",
        });
    }
    if error.contains("failed to read VMess response header length") {
        return Some(ProtocolReadMarker {
            key: "vmess-response-header-length-read",
            stage: "vmess-response-header-length",
            context: protocol_read_context(error),
            disposition: "read-error",
        });
    }
    None
}

fn protocol_read_context(error: &str) -> &'static str {
    if error.contains("Shadowsocks response salt") {
        return "shadowsocks-response-salt";
    }
    if error.contains("Shadowsocks chunk length") {
        return "shadowsocks-chunk-length";
    }
    if error.contains("Shadowsocks chunk payload") {
        return "shadowsocks-chunk-payload";
    }
    "vmess-response-header-length"
}
