use std::{
    net::SocketAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    task::{Context, Poll},
};

use tokio::io::{self, AsyncRead, AsyncWrite, ReadBuf};

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct EgressError {
    pub stage: &'static str,
    pub upstream: Option<SocketAddr>,
    pub message: String,
    pub client_to_upstream_bytes: Option<u64>,
    pub upstream_to_client_bytes: Option<u64>,
}

impl EgressError {
    pub(crate) fn new(
        stage: &'static str,
        upstream: Option<SocketAddr>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            stage,
            upstream,
            message: message.into(),
            client_to_upstream_bytes: None,
            upstream_to_client_bytes: None,
        }
    }

    pub(crate) fn with_plaintext_bytes(mut self, bytes: PlaintextByteCounts) -> Self {
        self.client_to_upstream_bytes = Some(bytes.client_to_upstream());
        self.upstream_to_client_bytes = Some(bytes.upstream_to_client());
        self
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct PlaintextByteCounts {
    client_to_upstream: Arc<AtomicU64>,
    upstream_to_client: Arc<AtomicU64>,
}

impl PlaintextByteCounts {
    pub(crate) fn client_to_upstream(&self) -> u64 {
        self.client_to_upstream.load(Ordering::Relaxed)
    }

    pub(crate) fn upstream_to_client(&self) -> u64 {
        self.upstream_to_client.load(Ordering::Relaxed)
    }
}

#[derive(Debug)]
pub(crate) struct CountingDownstream<T> {
    inner: T,
    counts: PlaintextByteCounts,
}

pub(crate) fn count_downstream<T>(inner: T) -> (CountingDownstream<T>, PlaintextByteCounts) {
    let counts = PlaintextByteCounts::default();
    (
        CountingDownstream {
            inner,
            counts: counts.clone(),
        },
        counts,
    )
}

impl<T> AsyncRead for CountingDownstream<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buffer.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buffer);
        if let Poll::Ready(Ok(())) = &result {
            let read = buffer.filled().len().saturating_sub(before);
            self.counts
                .client_to_upstream
                .fetch_add(read as u64, Ordering::Relaxed);
        }
        result
    }
}

impl<T> AsyncWrite for CountingDownstream<T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.inner).poll_write(cx, buffer) {
            Poll::Ready(Ok(written)) => {
                self.counts
                    .upstream_to_client
                    .fetch_add(written as u64, Ordering::Relaxed);
                Poll::Ready(Ok(written))
            }
            result => result,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub(crate) fn push_egress_error_fields(
    fields: &mut Vec<(&'static str, String)>,
    node_protocol: &str,
    error: &EgressError,
) {
    fields.push(("errorStage", error.stage.to_string()));
    fields.push(("error", error.message.clone()));
    if let Some(bytes) = error.client_to_upstream_bytes {
        fields.push(("clientToUpstreamBytes", bytes.to_string()));
    }
    if let Some(bytes) = error.upstream_to_client_bytes {
        fields.push(("upstreamToClientBytes", bytes.to_string()));
    }
    let signal = classify_egress_error(node_protocol, error);
    fields.push(("errorCode", signal.code.to_string()));
    fields.push(("errorClass", signal.class.to_string()));
    fields.push(("errorSide", signal.side.to_string()));
    fields.push(("errorPhase", signal.phase.to_string()));
    fields.push(("errorProtocolPhase", signal.protocol_phase.to_string()));
    fields.push(("errorScoreImpact", signal.score_impact.to_string()));
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct EgressErrorSignal {
    code: &'static str,
    class: &'static str,
    side: &'static str,
    phase: &'static str,
    protocol_phase: &'static str,
    score_impact: &'static str,
}

fn classify_egress_error(node_protocol: &str, error: &EgressError) -> EgressErrorSignal {
    let message = error.message.to_ascii_lowercase();
    if error.stage == "egress-resolve" {
        return signal(
            "resolve-failed",
            "connect-failed",
            "local",
            "resolve",
            "resolve",
            "hard-failure",
        );
    }
    if error.stage == "egress-connect" {
        return signal(
            "connect-failed",
            "connect-failed",
            "upstream",
            "connect",
            "connect",
            "hard-failure",
        );
    }
    if error.stage == "inbound-write" || message.contains("broken pipe") {
        return signal(
            "client-write-failed",
            "client-aborted",
            "client",
            "relay",
            "downstream-write",
            "neutral",
        );
    }
    if response_salt_eof(&message) {
        return signal(
            protocol_code(node_protocol, "response-salt-eof"),
            "no-response-before-first-byte",
            "upstream",
            "response-first-byte",
            "response-salt",
            "hard-failure",
        );
    }
    if error.stage == "outbound-read" && contains_eof(&message) {
        return signal(
            protocol_code(node_protocol, "response-eof"),
            "response-interrupted",
            "upstream",
            "response-frame",
            "response-read",
            "hard-failure",
        );
    }
    if error.stage == "outbound-write" {
        return signal(
            protocol_code(node_protocol, "request-write-failed"),
            "request-write-failed",
            "upstream",
            "request-write",
            "request-write",
            "hard-failure",
        );
    }
    if error.stage == "outbound-tls" && message.contains("reality handshake") {
        return signal(
            protocol_code(node_protocol, "reality-handshake-eof"),
            "handshake-failed",
            "upstream",
            "handshake",
            "reality-handshake",
            "hard-failure",
        );
    }
    if error.stage == "outbound-tls" {
        return signal(
            protocol_code(node_protocol, "tls-handshake-failed"),
            "handshake-failed",
            "upstream",
            "handshake",
            "tls-handshake",
            "hard-failure",
        );
    }
    if error.stage == "outbound-crypto" || error.stage == "outbound-protocol" {
        return signal(
            protocol_code(node_protocol, "protocol-invalid"),
            "protocol-invalid",
            "protocol",
            "response-frame",
            error.stage,
            "hard-failure",
        );
    }
    signal(
        protocol_code(node_protocol, "egress-error"),
        "unknown-failure",
        "unknown",
        error.stage,
        error.stage,
        "hard-failure",
    )
}

fn signal(
    code: &'static str,
    class: &'static str,
    side: &'static str,
    phase: &'static str,
    protocol_phase: &'static str,
    score_impact: &'static str,
) -> EgressErrorSignal {
    EgressErrorSignal {
        code,
        class,
        side,
        phase,
        protocol_phase,
        score_impact,
    }
}

fn response_salt_eof(message: &str) -> bool {
    message.contains("response salt") && contains_eof(message)
}

fn contains_eof(message: &str) -> bool {
    message.contains("early eof")
        || message.contains("unexpected eof")
        || message.contains("end of file")
}

fn protocol_code(protocol: &str, suffix: &str) -> &'static str {
    match (protocol, suffix) {
        ("ss", "response-salt-eof") => "ss-response-salt-eof",
        ("ss", "response-eof") => "ss-response-eof",
        ("ss", "request-write-failed") => "ss-request-write-failed",
        ("ss", "protocol-invalid") => "ss-protocol-invalid",
        ("trojan", "response-eof") => "trojan-response-eof",
        ("trojan", "request-write-failed") => "trojan-request-write-failed",
        ("trojan", "tls-handshake-failed") => "trojan-tls-handshake-failed",
        ("trojan", "protocol-invalid") => "trojan-protocol-invalid",
        ("vmess", "response-eof") => "vmess-response-eof",
        ("vmess", "request-write-failed") => "vmess-request-write-failed",
        ("vmess", "protocol-invalid") => "vmess-protocol-invalid",
        ("vless", "response-eof") => "vless-response-eof",
        ("vless", "request-write-failed") => "vless-request-write-failed",
        ("vless", "reality-handshake-eof") => "vless-reality-handshake-eof",
        ("vless", "tls-handshake-failed") => "vless-tls-handshake-failed",
        ("vless", "protocol-invalid") => "vless-protocol-invalid",
        ("direct", "request-write-failed") => "direct-request-write-failed",
        ("direct", "egress-error") => "direct-egress-error",
        _ => "egress-error",
    }
}
