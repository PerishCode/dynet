use dynet_core::{validate_config, DynetConfig};
use dynet_runtime::{
    probe_tcp_connect, probe_tls_handshake, OutboundTcpSettings, ProbeFailureScope, ProbeProtocol,
    ProbeRetryPolicy, ProbeSettings, ProbeTarget, RuntimeEvent, RuntimeEventKind, RuntimePolicy,
    RuntimeStatus,
};
use std::{
    io::Read,
    net::{SocketAddr, TcpListener},
    thread::{self, JoinHandle},
};

#[path = "support/outbound_configs.rs"]
mod outbound_configs;
#[path = "support/outbound_events.rs"]
mod outbound_events;
#[path = "support/outbound_server.rs"]
mod outbound_server;
#[path = "support/vmess_crypto.rs"]
mod vmess_crypto;
#[path = "support/vmess_responder.rs"]
mod vmess_responder;

use outbound_configs as configs;
use outbound_events as events;
use outbound_server::{SsServer, Target, TrojanServer};
use vmess_responder::{VmessFrameEofServer, VmessHeaderServer, VmessResponseServer};

#[test]
fn tcp_probe_ss_candidate() {
    let server = SsServer::spawn("secret");
    let config = configs::ss_plan_config(server.address().port());
    let report = run_tcp_probe(config);

    assert_eq!(report.status, RuntimeStatus::Pass);
    assert_eq!(report.protocol, ProbeProtocol::TcpConnect);
    assert_eq!(report.reason, "TCP connect completed");
    assert!(report
        .events
        .iter()
        .any(|event| events::plan_selected(event, "private-ss")));
    assert!(report
        .events
        .iter()
        .any(|event| events::attempt_done(event, "private-ss", "ss")));
    assert!(report
        .events
        .iter()
        .any(|event| events::stream_flushed(event, "private-ss")));

    let request = server.request().expect("test server observed request");
    assert_eq!(request.target, Target::domain("target.example", 443));
    assert!(request.payload.is_empty());
}

#[test]
fn dialer_probe_ss_bound() {
    let server = SsServer::spawn("secret");
    let config = configs::dialer_config(server.address().port());
    let report = run_tcp_probe(config);

    assert_eq!(report.status, RuntimeStatus::Pass);
    assert!(report.events.iter().any(events::bound_candidate_set));
    assert!(report.events.iter().any(|event| events::cascade_selected(
        event,
        "private-via-bound",
        "private-ss"
    )));
    assert!(report.events.iter().any(|event| {
        events::cascade_finished_scope(event, "private-via-bound", "direct", "success", "none")
    }));
    assert!(report
        .events
        .iter()
        .any(|event| events::private_stage_target(
            event,
            "private-ss",
            "private-ss-connect",
            "target.example:443",
            "domain"
        )));
    assert!(report.events.iter().any(events::bound_direct_done));

    let request = server.request().expect("test server observed request");
    assert_eq!(request.target, Target::domain("target.example", 443));
    assert!(request.payload.is_empty());
}

#[test]
fn tcp_probe_vmess_candidate() {
    let server = VmessHeaderServer::spawn(configs::VMESS_UUID);
    let config = configs::vmess_plan_config(server.address().port());
    let report = run_tcp_probe(config);

    assert_eq!(report.status, RuntimeStatus::Pass);
    assert!(report
        .events
        .iter()
        .any(|event| events::plan_selected(event, "private-vmess")));
    assert!(report.events.iter().any(|event| events::attempt_done(
        event,
        "private-vmess",
        "vmess"
    )));
    assert!(report
        .events
        .iter()
        .any(|event| events::stream_flushed(event, "private-vmess")));

    let request = server.request().expect("VMess server observed request");
    assert_eq!(request.target, Target::domain("target.example", 443));
}

#[test]
fn dialer_probe_vmess_bound() {
    let server = VmessHeaderServer::spawn(configs::VMESS_UUID);
    let config = configs::dialer_vmess_config(server.address().port());
    let report = run_tcp_probe(config);

    assert_eq!(report.status, RuntimeStatus::Pass);
    assert!(report.events.iter().any(events::bound_candidate_set));
    assert!(report.events.iter().any(|event| events::cascade_selected(
        event,
        "private-via-bound",
        "private-vmess"
    )));
    assert!(report
        .events
        .iter()
        .any(|event| events::private_stage_target(
            event,
            "private-vmess",
            "private-vmess-connect",
            "target.example:443",
            "domain"
        )));
    assert!(report.events.iter().any(events::bound_direct_done));

    let request = server.request().expect("VMess server observed request");
    assert_eq!(request.target, Target::domain("target.example", 443));
}

#[test]
fn vmess_ss_reads_response() {
    let server = VmessResponseServer::spawn(configs::VMESS_UUID, "secret", b"not a TLS record");
    let config = configs::vmess_ss_config(server.address().port());
    let report = run_tls_probe(config, "localhost", 443);

    assert_eq!(report.status, RuntimeStatus::Deny);
    assert_eq!(report.failure_scope, Some(ProbeFailureScope::Downstream));
    assert!(report
        .events
        .iter()
        .any(|event| events::cascade_selected_bound(
            event,
            "private-via-bound",
            "bound-vmess",
            "private-ss"
        )));
    assert!(report
        .events
        .iter()
        .any(|event| events::private_stage_target(
            event,
            "private-ss",
            "private-ss-connect",
            "localhost:443",
            "domain"
        )));
    assert!(report
        .events
        .iter()
        .any(|event| events::stream_first_read_success(event, "private-via-bound")));
    assert!(report.events.iter().any(|event| {
        events::cascade_finished_scope(
            event,
            "private-via-bound",
            "bound-vmess",
            "failed",
            "downstream",
        )
    }));
    assert!(!report.reason.contains("not ready"), "{}", report.reason);

    let request = server
        .request()
        .expect("VMess responder observed data frame");
    assert_eq!(
        request.target,
        Target::Socket("127.0.0.1:1".parse().expect("valid fixture target"))
    );
    assert!(
        request.first_payload_len > 32,
        "nested SS request frame too small: {}",
        request.first_payload_len
    );
}

#[test]
fn vmess_read_marker_eof() {
    let server = VmessFrameEofServer::spawn(configs::VMESS_UUID);
    let config = configs::vmess_plan_config(server.address().port());
    let report = run_tls_probe(config, "target.example", 443);

    assert_eq!(report.status, RuntimeStatus::Deny);
    let first_read = report
        .events
        .iter()
        .find(|event| event.fields.get("stage").map(String::as_str) == Some("stream-first-read"))
        .expect("stream-first-read event is emitted");
    assert_eq!(field(first_read, "status"), Some("failed"));
    assert_eq!(
        field(first_read, "protocolReadMarker"),
        Some("vmess-response-header-length-eof")
    );
    assert_eq!(
        field(first_read, "protocolReadStage"),
        Some("vmess-response-header-length")
    );
    assert_eq!(
        field(first_read, "protocolReadDisposition"),
        Some("remote-eof")
    );
    assert_eq!(
        field(first_read, "protocolReadContext"),
        Some("vmess-response-header-length")
    );
    let attempt = report
        .events
        .iter()
        .find(|event| event.kind == RuntimeEventKind::ProbeAttemptFinished)
        .expect("probe-attempt-finished event is emitted");
    assert_eq!(
        field(attempt, "classification"),
        Some("protocol-read-vmess-response-header-length-eof")
    );
    assert_eq!(
        field(attempt, "protocolReadContext"),
        Some("vmess-response-header-length")
    );
    assert!(report.reason.contains("VMess response header length"));

    let request = server.request().expect("VMess EOF server observed request");
    assert_eq!(request.target, Target::domain("target.example", 443));
    assert!(
        request.first_payload_len > 32,
        "TLS request frame too small: {}",
        request.first_payload_len
    );
}

#[test]
fn bound_retry_stops_downstream() {
    let server = VmessResponseServer::spawn(configs::VMESS_UUID, "secret", b"not a TLS record");
    let config = configs::bound_then_downstream_config(server.address().port());
    let report = run_tls_probe(config, "localhost", 443);

    assert_eq!(report.status, RuntimeStatus::Deny);
    assert_eq!(report.failure_scope, Some(ProbeFailureScope::Downstream));
    assert!(report.events.iter().any(|event| {
        events::cascade_finished_scope(event, "private-via-bound", "direct", "failed", "bound")
            && field(event, "retryAllowed") == Some("true")
            && field(event, "errorDisposition") == Some("connection-refused")
            && field(event, "failureStage") == Some("tcp-connect")
            && field(event, "failureStageOutbound") == Some("direct")
            && field(event, "failureStageKind") == Some("direct")
            && field(event, "failureStageDisposition") == Some("connection-refused")
    }));
    assert!(report.events.iter().any(|event| {
        events::cascade_finished_scope(
            event,
            "private-via-bound",
            "bound-vmess",
            "failed",
            "downstream",
        ) && field(event, "retryAllowed") == Some("false")
            && field(event, "failureStage") == Some("tls-handshake")
            && field(event, "failureStageOutbound") == Some("private-via-bound")
            && field(event, "failureStageKind") == Some("dialer")
            && field(event, "failureStageDisposition") == Some("protocol-invalid")
    }));
    assert_eq!(
        report
            .events
            .iter()
            .filter(|event| event.kind == RuntimeEventKind::DialerCascadeAttemptFinished)
            .count(),
        2
    );
}

#[test]
fn probe_retry_eof() {
    let server = DirectEofServer::spawn(2);
    let config = configs::direct_config("localhost");
    let report = run_probe_with_retry(
        config,
        "localhost",
        server.address().port(),
        probe_tls_handshake,
        ProbeRetryPolicy::direct_tls_eof(2, 0),
    );
    server.join();

    assert_eq!(report.status, RuntimeStatus::Deny);
    assert_eq!(report.retry.attempts_used, 2);
    assert!(!report.retry.recovered_after_retry);
    assert!(report.retry.unresolved_direct_tls_eof);
    assert_eq!(report.retry.attempts.len(), 2);
    assert!(report
        .retry
        .attempts
        .iter()
        .all(|attempt| attempt.classification == "direct-tls-eof-after-path-complete"));
    assert_eq!(
        report
            .events
            .iter()
            .filter(|event| event.kind == dynet_runtime::RuntimeEventKind::ProbeAttemptStarted)
            .count(),
        2
    );
}

fn field<'a>(event: &'a RuntimeEvent, key: &str) -> Option<&'a str> {
    event.fields.get(key).map(String::as_str)
}

#[test]
fn tcp_probe_trojan_candidate() {
    let server = TrojanServer::spawn("secret");
    let config = configs::trojan_plan_config(server.address().port());
    let report = run_tcp_probe(config);

    assert_eq!(report.status, RuntimeStatus::Pass);
    assert!(report
        .events
        .iter()
        .any(|event| events::plan_selected(event, "private-trojan")));
    assert!(report.events.iter().any(|event| events::attempt_done(
        event,
        "private-trojan",
        "trojan"
    )));
    assert!(report
        .events
        .iter()
        .any(|event| events::stream_flushed(event, "private-trojan")));
    assert!(report.events.iter().any(|event| events::private_stage(
        event,
        "private-trojan",
        "trojan-tls-handshake"
    )));
    assert!(report.events.iter().any(|event| events::private_stage(
        event,
        "private-trojan",
        "trojan-request-write"
    )));
    let connect_stage = report
        .events
        .iter()
        .find(|event| {
            event.kind == RuntimeEventKind::OutboundStageFinished
                && field(event, "outbound") == Some("private-trojan")
                && field(event, "stage") == Some("tcp-connect")
        })
        .expect("Trojan tcp-connect stage is emitted");
    assert_eq!(
        field(connect_stage, "interfaceNameConfigured"),
        Some("false")
    );
    assert_eq!(field(connect_stage, "interfaceNameLength"), Some("0"));

    let request = server.request().expect("Trojan server observed request");
    assert_eq!(request.target, Target::domain("target.example", 443));
    assert!(request.payload.is_empty());
}

#[test]
fn dialer_probe_trojan_bound() {
    let server = TrojanServer::spawn("secret");
    let config = configs::dialer_trojan_config(server.address().port());
    let report = run_tcp_probe(config);

    assert_eq!(report.status, RuntimeStatus::Pass);
    assert!(report.events.iter().any(events::bound_candidate_set));
    assert!(report.events.iter().any(|event| events::cascade_selected(
        event,
        "private-via-bound",
        "private-trojan"
    )));
    assert!(report
        .events
        .iter()
        .any(|event| events::private_stage_target(
            event,
            "private-trojan",
            "private-trojan-connect",
            "target.example:443",
            "domain"
        )));
    assert!(report.events.iter().any(events::bound_direct_done));

    let request = server.request().expect("Trojan server observed request");
    assert_eq!(request.target, Target::domain("target.example", 443));
    assert!(request.payload.is_empty());
}

fn run_tcp_probe(config: DynetConfig) -> dynet_runtime::ProbeReport {
    run_probe(config, "target.example", 443, probe_tcp_connect)
}

fn run_tls_probe(config: DynetConfig, host: &str, port: u16) -> dynet_runtime::ProbeReport {
    run_probe(config, host, port, probe_tls_handshake)
}

fn run_probe(
    config: DynetConfig,
    host: &str,
    port: u16,
    probe: fn(ProbeSettings) -> Result<dynet_runtime::ProbeReport, String>,
) -> dynet_runtime::ProbeReport {
    run_probe_with_retry(config, host, port, probe, ProbeRetryPolicy::default())
}

fn run_probe_with_retry(
    config: DynetConfig,
    host: &str,
    port: u16,
    probe: fn(ProbeSettings) -> Result<dynet_runtime::ProbeReport, String>,
    retry_policy: ProbeRetryPolicy,
) -> dynet_runtime::ProbeReport {
    let diagnostics = validate_config(&config);
    assert!(diagnostics.is_empty(), "{diagnostics:?}");
    probe(ProbeSettings {
        target: ProbeTarget {
            host: host.to_string(),
            port,
            path: "/".to_string(),
        },
        inbound: None,
        bypass_mark: 0,
        policy: RuntimePolicy::from_config(config),
        outbound_tcp: OutboundTcpSettings::default(),
        read_policy: dynet_runtime::ProbeReadPolicy::default(),
        retry_policy,
    })
    .expect("probe should run")
}

struct DirectEofServer {
    address: SocketAddr,
    handle: JoinHandle<()>,
}

impl DirectEofServer {
    fn spawn(connections: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind direct EOF server");
        let address = listener.local_addr().expect("direct EOF server address");
        let handle = thread::spawn(move || {
            for _ in 0..connections {
                let (mut stream, _) = listener.accept().expect("accept direct EOF client");
                let mut buffer = [0_u8; 2048];
                let _ = stream.read(&mut buffer);
            }
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
