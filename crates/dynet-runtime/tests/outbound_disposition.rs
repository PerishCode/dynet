use dynet_core::{validate_config, DynetConfig};
use dynet_runtime::{
    probe_tcp_connect, OutboundTcpSettings, ProbeFailureScope, ProbeReadPolicy, ProbeRetryPolicy,
    ProbeSettings, ProbeTarget, RuntimeEvent, RuntimeEventKind, RuntimePolicy, RuntimeStatus,
};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener},
    thread::{self, JoinHandle},
    time::Duration,
};

#[path = "support/outbound_configs.rs"]
#[allow(dead_code)]
mod outbound_configs;
#[path = "support/outbound_events.rs"]
#[allow(dead_code)]
mod outbound_events;

use outbound_configs as configs;
use outbound_events as events;

#[test]
fn trojan_downstream_eof_disposition() {
    let server = DirectEofServer::spawn();
    let report = run_tcp_probe(configs::dialer_trojan_config(server.address().port()));
    server.join();

    assert_downstream_disposition(&report, "remote-eof");
}

#[test]
fn trojan_downstream_invalid_disposition() {
    let server = DirectPlainServer::spawn(b"HTTP/1.1 400 Bad Request\r\n\r\n".to_vec());
    let report = run_tcp_probe(configs::dialer_trojan_config(server.address().port()));
    server.join();

    assert_downstream_disposition(&report, "protocol-invalid");
}

#[test]
fn trojan_tls_pending_retry() {
    let server = StalledTlsServer::spawn();
    let report = run_tcp_with_settings(
        configs::trojan_plan_config(server.address().port()),
        OutboundTcpSettings {
            connect_timeout_ms: 1_000,
            read_write_timeout_ms: 20,
        },
    );
    server.join();

    assert_eq!(report.status, RuntimeStatus::Deny);
    let stage = report
        .events
        .iter()
        .find(|event| {
            event.kind == RuntimeEventKind::OutboundStageFinished
                && field(event, "outbound") == Some("private-trojan")
                && field(event, "stage") == Some("trojan-tls-handshake")
                && field(event, "status") == Some("failed")
        })
        .expect("Trojan TLS stage failure is emitted");
    assert_eq!(field(stage, "errorDisposition"), Some("pending-timeout"));
    assert_eq!(field(stage, "pendingBudgetMs"), Some("250"));
    assert_eq!(field(stage, "pendingSleepMs"), Some("10"));
    let retries = field(stage, "pendingRetries")
        .expect("pending retries are reported")
        .parse::<usize>()
        .expect("pending retries are numeric");
    assert!(retries > 0, "pending retries should be positive");
    let error = field(stage, "error").unwrap_or_default();
    assert!(error.contains("pendingRetries="), "{error}");
    assert!(error.contains("pendingElapsedMs="), "{error}");
    assert!(!error.contains("pendingRetries=0"), "{error}");
    let elapsed = field(stage, "pendingElapsedMs")
        .expect("pending elapsed is reported")
        .parse::<usize>()
        .expect("pending elapsed is numeric");
    assert!(elapsed > 0, "pending elapsed should be positive");
    assert_eq!(
        field(stage, "pendingWaitClass"),
        Some("poll-budget-exhausted")
    );
    let attempt = report
        .events
        .iter()
        .find(|event| {
            event.kind == RuntimeEventKind::OutboundAttemptFinished
                && field(event, "outbound") == Some("private-trojan")
                && field(event, "status") == Some("failed")
        })
        .expect("Trojan outbound attempt failure is emitted");
    assert_eq!(
        field(attempt, "pendingRetries").and_then(|value| value.parse::<usize>().ok()),
        Some(retries),
    );
    assert_eq!(
        field(attempt, "pendingElapsedMs").and_then(|value| value.parse::<usize>().ok()),
        Some(elapsed),
    );
    assert_eq!(
        field(attempt, "pendingWaitClass"),
        Some("poll-budget-exhausted"),
    );
}

#[test]
fn trojan_tls_wait_class() {
    let server = StalledTlsServer::spawn();
    let report = run_tcp_with_settings(
        configs::trojan_plan_config(server.address().port()),
        OutboundTcpSettings {
            connect_timeout_ms: 1_000,
            read_write_timeout_ms: 300,
        },
    );
    server.join();

    assert_eq!(report.status, RuntimeStatus::Deny);
    let stage = report
        .events
        .iter()
        .find(|event| {
            event.kind == RuntimeEventKind::OutboundStageFinished
                && field(event, "outbound") == Some("private-trojan")
                && field(event, "stage") == Some("trojan-tls-handshake")
                && field(event, "status") == Some("failed")
        })
        .expect("Trojan TLS stage failure is emitted");
    assert_eq!(field(stage, "errorDisposition"), Some("pending-timeout"));
    assert_eq!(field(stage, "pendingRetries"), Some("0"));
    assert_eq!(
        field(stage, "pendingWaitClass"),
        Some("socket-read-timeout")
    );
    let elapsed = field(stage, "pendingElapsedMs")
        .expect("pending elapsed is reported")
        .parse::<usize>()
        .expect("pending elapsed is numeric");
    assert!(elapsed >= 250, "pending elapsed should cross budget");
}

#[test]
fn dialer_trojan_pending_retry() {
    let server = StalledTlsServer::spawn();
    let report = run_tcp_with_settings(
        configs::dialer_trojan_config(server.address().port()),
        OutboundTcpSettings {
            connect_timeout_ms: 1_000,
            read_write_timeout_ms: 20,
        },
    );
    server.join();

    assert_eq!(report.status, RuntimeStatus::Deny);
    assert_eq!(report.failure_scope, Some(ProbeFailureScope::Downstream));
    let stage = report
        .events
        .iter()
        .find(|event| {
            event.kind == RuntimeEventKind::OutboundStageFinished
                && field(event, "outbound") == Some("private-trojan")
                && field(event, "stage") == Some("private-trojan-connect")
                && field(event, "status") == Some("failed")
        })
        .expect("private Trojan connect failure is emitted");
    assert_eq!(field(stage, "errorDisposition"), Some("pending-timeout"));
    let retries = field(stage, "pendingRetries").expect("pending retries are reported");
    let wait_class = field(stage, "pendingWaitClass").expect("pending wait class is reported");

    let cascade = report
        .events
        .iter()
        .find(|event| {
            events::cascade_finished_scope(
                event,
                "private-via-bound",
                "direct",
                "failed",
                "downstream",
            )
        })
        .expect("downstream cascade stop is emitted");
    assert_eq!(field(cascade, "pendingRetries"), Some(retries));
    assert_eq!(field(cascade, "failureStagePendingRetries"), Some(retries));
    assert_eq!(field(cascade, "pendingWaitClass"), Some(wait_class));
    assert_eq!(
        field(cascade, "failureStagePendingWaitClass"),
        Some(wait_class),
    );
    assert_eq!(
        field(cascade, "failureStage"),
        Some("private-trojan-connect")
    );
    assert_eq!(field(cascade, "retryAllowed"), Some("false"));
}

fn assert_downstream_disposition(report: &dynet_runtime::ProbeReport, disposition: &str) {
    assert_eq!(report.status, RuntimeStatus::Deny);
    assert_eq!(report.failure_scope, Some(ProbeFailureScope::Downstream));
    let private_failure = report
        .events
        .iter()
        .find(|event| {
            event.kind == RuntimeEventKind::OutboundStageFinished
                && field(event, "outbound") == Some("private-trojan")
                && field(event, "stage") == Some("private-trojan-connect")
                && field(event, "status") == Some("failed")
        })
        .expect("private Trojan downstream stage failure is emitted");
    assert_eq!(
        field(private_failure, "errorDisposition"),
        Some(disposition)
    );

    let cascade_stop = report
        .events
        .iter()
        .find(|event| {
            events::cascade_finished_scope(
                event,
                "private-via-bound",
                "direct",
                "failed",
                "downstream",
            )
        })
        .expect("downstream cascade stop is emitted");
    assert_eq!(field(cascade_stop, "retryAllowed"), Some("false"));
    assert_eq!(field(cascade_stop, "errorDisposition"), Some(disposition));
    assert_eq!(
        field(cascade_stop, "failureStage"),
        Some("private-trojan-connect")
    );
    assert_eq!(
        field(cascade_stop, "failureStageOutbound"),
        Some("private-trojan")
    );
    assert_eq!(field(cascade_stop, "failureStageKind"), Some("trojan"));
    assert_eq!(
        field(cascade_stop, "failureStageDisposition"),
        Some(disposition)
    );

    let attempt = report
        .events
        .iter()
        .find(|event| {
            event.kind == RuntimeEventKind::OutboundAttemptFinished
                && field(event, "outbound") == Some("private-via-bound")
                && field(event, "status") == Some("failed")
        })
        .expect("top-level outbound attempt failure is emitted");
    assert_eq!(field(attempt, "errorDisposition"), Some(disposition));
}

fn field<'a>(event: &'a RuntimeEvent, key: &str) -> Option<&'a str> {
    event.fields.get(key).map(String::as_str)
}

fn run_tcp_probe(config: DynetConfig) -> dynet_runtime::ProbeReport {
    run_tcp_with_settings(config, OutboundTcpSettings::default())
}

fn run_tcp_with_settings(
    config: DynetConfig,
    outbound_tcp: OutboundTcpSettings,
) -> dynet_runtime::ProbeReport {
    let diagnostics = validate_config(&config);
    assert!(diagnostics.is_empty(), "{diagnostics:?}");
    probe_tcp_connect(ProbeSettings {
        target: ProbeTarget {
            host: "target.example".to_string(),
            port: 443,
            path: "/".to_string(),
        },
        inbound: None,
        bypass_mark: 0,
        policy: RuntimePolicy::from_config(config),
        outbound_tcp,
        read_policy: ProbeReadPolicy::default(),
        retry_policy: ProbeRetryPolicy::default(),
    })
    .expect("probe should run")
}

struct DirectEofServer {
    address: SocketAddr,
    handle: JoinHandle<()>,
}

impl DirectEofServer {
    fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind direct EOF server");
        let address = listener.local_addr().expect("direct EOF server address");
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept direct EOF client");
            let mut buffer = [0_u8; 2048];
            let _ = stream.read(&mut buffer);
        });
        Self { address, handle }
    }

    fn address(&self) -> SocketAddr {
        self.address
    }

    fn join(self) {
        self.handle.join().expect("direct EOF server joined");
    }
}

struct StalledTlsServer {
    address: SocketAddr,
    handle: JoinHandle<()>,
}

impl StalledTlsServer {
    fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stalled TLS server");
        let address = listener.local_addr().expect("stalled TLS server address");
        let handle = thread::spawn(move || {
            let (_stream, _) = listener.accept().expect("accept stalled TLS client");
            thread::sleep(Duration::from_millis(400));
        });
        Self { address, handle }
    }

    fn address(&self) -> SocketAddr {
        self.address
    }

    fn join(self) {
        self.handle.join().expect("stalled TLS server joined");
    }
}

struct DirectPlainServer {
    address: SocketAddr,
    handle: JoinHandle<()>,
}

impl DirectPlainServer {
    fn spawn(response: Vec<u8>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind direct plain server");
        let address = listener.local_addr().expect("direct plain server address");
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept direct plain client");
            let mut buffer = [0_u8; 2048];
            let _ = stream.read(&mut buffer);
            let _ = stream.write_all(&response);
        });
        Self { address, handle }
    }

    fn address(&self) -> SocketAddr {
        self.address
    }

    fn join(self) {
        self.handle.join().expect("direct plain server joined");
    }
}
