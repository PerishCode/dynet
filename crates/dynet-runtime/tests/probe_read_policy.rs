use std::{net::SocketAddr, time::Duration};

use dynet_core::{validate_config, DynetConfig};
use dynet_runtime::{
    probe_tls_handshake, OutboundTcpSettings, ProbeFailureScope, ProbeReadPolicy, ProbeRetryPolicy,
    ProbeSettings, ProbeTarget, RuntimeEvent, RuntimeEventKind, RuntimePolicy, RuntimeStatus,
};

#[allow(dead_code)]
#[path = "support/outbound_configs.rs"]
mod outbound_configs;
#[allow(dead_code)]
#[path = "support/outbound_events.rs"]
mod outbound_events;
mod outbound_server {
    use super::SocketAddr;

    #[derive(Debug, Eq, PartialEq)]
    pub(crate) enum Target {
        Socket(SocketAddr),
        Domain { host: String, port: u16 },
    }
}
#[allow(dead_code)]
#[path = "support/vmess_crypto.rs"]
mod vmess_crypto;
#[allow(dead_code)]
#[path = "support/vmess_responder.rs"]
mod vmess_responder;

use outbound_configs as configs;
use outbound_events as events;
use outbound_server::Target;
use vmess_responder::VmessResponseServer;

#[test]
fn pending_read_recovers() {
    let server = VmessResponseServer::spawn_delayed(
        configs::VMESS_UUID,
        "secret",
        b"not a TLS record",
        Duration::from_millis(600),
    );
    let config = configs::vmess_ss_config(server.address().port());
    let report = run_tls_probe(config, ProbeReadPolicy::default());

    assert_eq!(report.status, RuntimeStatus::Deny);
    assert_eq!(report.failure_scope, Some(ProbeFailureScope::Downstream));
    assert!(report
        .events
        .iter()
        .any(|event| events::stream_first_read_success(event, "private-via-bound")));
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
    let first_read = first_read(&report.events);
    let retries = field(first_read, "pendingRetries")
        .expect("pending retries are reported")
        .parse::<usize>()
        .expect("pending retries are numeric");
    assert!(retries > 0, "{first_read:?}");
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
fn read_budget_override() {
    let read_policy = ProbeReadPolicy {
        poll_timeout_ms: 5,
        pending_budget_ms: 20,
        pending_sleep_ms: 1,
    };
    let server = VmessResponseServer::spawn_delayed(
        configs::VMESS_UUID,
        "secret",
        b"not a TLS record",
        Duration::from_millis(200),
    );
    let config = configs::vmess_ss_config(server.address().port());
    let report = run_tls_probe(config, read_policy);

    assert_eq!(report.status, RuntimeStatus::Deny);
    assert_eq!(report.read_policy, read_policy);
    assert!(report.reason.contains("not ready"), "{}", report.reason);
    let started = report
        .events
        .iter()
        .find(|event| event.kind == RuntimeEventKind::ProbeStarted)
        .expect("probe-started event is emitted");
    assert_eq!(field(started, "readPollTimeoutMs"), Some("5"));
    assert_eq!(field(started, "readPendingBudgetMs"), Some("20"));
    assert_eq!(field(started, "readPendingSleepMs"), Some("1"));

    let first_read = first_read(&report.events);
    assert_eq!(field(first_read, "status"), Some("failed"));
    assert_eq!(field(first_read, "pendingBudgetMs"), Some("20"));
    assert_eq!(field(first_read, "pendingSleepMs"), Some("1"));
    assert_eq!(
        field(first_read, "protocolReadMarker"),
        Some("vmess-response-header-length-pending")
    );
    assert_eq!(
        field(first_read, "protocolReadDisposition"),
        Some("pending-budget-exhausted")
    );
    assert_eq!(
        field(first_read, "protocolReadContext"),
        Some("shadowsocks-response-salt")
    );
    let attempt = report
        .events
        .iter()
        .find(|event| event.kind == RuntimeEventKind::ProbeAttemptFinished)
        .expect("probe-attempt-finished event is emitted");
    assert_eq!(
        field(attempt, "classification"),
        Some("protocol-read-vmess-response-header-length-pending-budget-exhausted")
    );
    assert_eq!(
        field(attempt, "protocolReadMarker"),
        Some("vmess-response-header-length-pending")
    );
    assert_eq!(
        field(attempt, "protocolReadContext"),
        Some("shadowsocks-response-salt")
    );
    let retries = field(first_read, "pendingRetries")
        .expect("pending retries are reported")
        .parse::<usize>()
        .expect("pending retries are numeric");
    assert!(retries > 0, "{first_read:?}");

    let _ = server.request();
}

fn run_tls_probe(config: DynetConfig, read_policy: ProbeReadPolicy) -> dynet_runtime::ProbeReport {
    run_probe_with_policy(config, "localhost", 443, read_policy)
}

fn run_probe_with_policy(
    config: DynetConfig,
    host: &str,
    port: u16,
    read_policy: ProbeReadPolicy,
) -> dynet_runtime::ProbeReport {
    let diagnostics = validate_config(&config);
    assert!(diagnostics.is_empty(), "{diagnostics:?}");
    probe_tls_handshake(ProbeSettings {
        target: ProbeTarget {
            host: host.to_string(),
            port,
            path: "/".to_string(),
        },
        inbound: None,
        bypass_mark: 0,
        policy: RuntimePolicy::from_config(config),
        outbound_tcp: OutboundTcpSettings::default(),
        read_policy,
        retry_policy: ProbeRetryPolicy::default(),
    })
    .expect("probe should run")
}

fn first_read(events: &[RuntimeEvent]) -> &RuntimeEvent {
    events
        .iter()
        .find(|event| event.fields.get("stage").map(String::as_str) == Some("stream-first-read"))
        .expect("stream-first-read event is emitted")
}

fn field<'a>(event: &'a RuntimeEvent, key: &str) -> Option<&'a str> {
    event.fields.get(key).map(String::as_str)
}
