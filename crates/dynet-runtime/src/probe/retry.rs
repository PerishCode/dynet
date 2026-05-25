use std::{
    thread,
    time::{Duration, Instant},
};

use serde::Serialize;

use crate::{
    event::EventBus,
    probe::{
        scope::{latest_event_sequence, probe_failure_scope},
        ProbeFailureScope, ProbeProtocol, ProbeSettings,
    },
    resolver::trace::{classify_runtime_error, elapsed_ms},
    RuntimeEvent, RuntimeEventKind, RuntimeStatus,
};

pub(super) const DIRECT_TLS_EOF: &str = "direct-tls-eof-after-path-complete";

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeRetryPolicy {
    pub max_attempts: usize,
    pub retry_sleep_ms: u64,
}

impl Default for ProbeRetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 1,
            retry_sleep_ms: 250,
        }
    }
}

impl ProbeRetryPolicy {
    pub fn direct_tls_eof(max_attempts: usize, retry_sleep_ms: u64) -> Self {
        Self {
            max_attempts: max_attempts.max(1),
            retry_sleep_ms,
        }
    }

    pub(super) fn enabled(self) -> bool {
        self.max_attempts > 1
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeRetryReport {
    pub enabled: bool,
    pub policy: ProbeRetryPolicy,
    pub attempts_used: usize,
    pub recovered_after_retry: bool,
    pub unresolved_direct_tls_eof: bool,
    pub attempts: Vec<ProbeAttemptReport>,
}

impl ProbeRetryReport {
    pub(super) fn is_default(&self) -> bool {
        !self.enabled
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeAttemptReport {
    pub attempt: usize,
    pub status: RuntimeStatus,
    pub classification: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_scope: Option<ProbeFailureScope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_outbound: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed_stage: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_marker: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_read_marker: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_read_stage: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_read_context: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_read_disposition: Option<String>,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_sequence: Option<u64>,
}

struct ProtocolReadAttempt {
    classification: String,
    marker: String,
    stage: Option<String>,
    context: Option<String>,
    disposition: Option<String>,
}

pub(super) fn run_attempts(
    settings: &ProbeSettings,
    ebus: &EventBus,
    protocol: ProbeProtocol,
) -> Result<(Result<String, String>, Vec<ProbeAttemptReport>), String> {
    let mut attempts = Vec::new();
    let mut result = Err("probe did not run".to_string());
    let retry_policy = settings.retry_policy;
    for attempt in 1..=retry_policy.max_attempts.max(1) {
        if attempt > 1 && retry_policy.retry_sleep_ms > 0 {
            thread::sleep(Duration::from_millis(retry_policy.retry_sleep_ms));
        }
        let started = Instant::now();
        emit(
            ebus,
            RuntimeEvent::new(RuntimeEventKind::ProbeAttemptStarted)
                .field("attempt", attempt)
                .field("maxAttempts", retry_policy.max_attempts.max(1))
                .field("retryPolicy", "direct-tls-eof-only")
                .field("protocol", protocol.as_str())
                .field("target", settings.target.address()),
        )?;
        let start_sequence = latest_event_sequence(ebus)?;
        result = super::probe_inner(settings, ebus, protocol);
        let events = ebus.snapshot()?;
        let attempt_report = summarize_attempt(attempt, start_sequence, &result, &events);
        let should_retry = result.is_err()
            && retry_policy.enabled()
            && attempt < retry_policy.max_attempts
            && attempt_report.classification == DIRECT_TLS_EOF;
        emit(
            ebus,
            attempt_finished_event(
                protocol,
                settings,
                &attempt_report,
                retry_policy.max_attempts.max(1),
                should_retry,
                started,
            ),
        )?;
        attempts.push(attempt_report);
        if result.is_ok() || !should_retry {
            break;
        }
    }
    Ok((result, attempts))
}

fn summarize_attempt(
    attempt: usize,
    start_sequence: Option<u64>,
    result: &Result<String, String>,
    events: &[RuntimeEvent],
) -> ProbeAttemptReport {
    let status = if result.is_ok() {
        RuntimeStatus::Pass
    } else {
        RuntimeStatus::Deny
    };
    let attempt_events = attempt_events(events, start_sequence);
    let failure_scope = probe_failure_scope(status, &attempt_events);
    let selected_outbound = selected_outbound_since(events, start_sequence);
    let failed_stage = failed_stage_since(events, start_sequence);
    let reason = match result {
        Ok(reason) | Err(reason) => reason.clone(),
    };
    let reason_marker = failed_stage_error_since(events, start_sequence).map(reason_marker);
    let protocol_read = protocol_read_since(events, start_sequence);
    let classification = classify_attempt(
        status,
        failure_scope,
        selected_outbound.as_deref(),
        failed_stage.as_deref(),
        protocol_read.as_ref(),
        events,
        start_sequence,
    );
    ProbeAttemptReport {
        attempt,
        status,
        classification,
        failure_scope,
        selected_outbound,
        failed_stage,
        reason_marker,
        protocol_read_marker: protocol_read.as_ref().map(|item| item.marker.clone()),
        protocol_read_stage: protocol_read.as_ref().and_then(|item| item.stage.clone()),
        protocol_read_context: protocol_read.as_ref().and_then(|item| item.context.clone()),
        protocol_read_disposition: protocol_read
            .as_ref()
            .and_then(|item| item.disposition.clone()),
        reason,
        start_sequence,
    }
}

fn attempt_finished_event(
    protocol: ProbeProtocol,
    settings: &ProbeSettings,
    attempt: &ProbeAttemptReport,
    max_attempts: usize,
    retry_planned: bool,
    started: Instant,
) -> RuntimeEvent {
    let mut event = RuntimeEvent::new(RuntimeEventKind::ProbeAttemptFinished)
        .field("attempt", attempt.attempt)
        .field("maxAttempts", max_attempts)
        .field("retryPolicy", "direct-tls-eof-only")
        .field("protocol", protocol.as_str())
        .field("target", settings.target.address())
        .field(
            "status",
            if attempt.status == RuntimeStatus::Pass {
                "success"
            } else {
                "failed"
            },
        )
        .field("classification", &attempt.classification)
        .field("retryPlanned", retry_planned)
        .field("elapsedMs", elapsed_ms(started));
    if let Some(scope) = attempt.failure_scope {
        event = event.field("failureScope", scope.as_str());
    }
    if let Some(outbound) = &attempt.selected_outbound {
        event = event.field("selectedOutbound", outbound);
    }
    if let Some(stage) = &attempt.failed_stage {
        event = event.field("failedStage", stage);
    }
    if let Some(marker) = &attempt.reason_marker {
        event = event.field("reasonMarker", marker);
    }
    if let Some(marker) = &attempt.protocol_read_marker {
        event = event.field("protocolReadMarker", marker);
    }
    if let Some(stage) = &attempt.protocol_read_stage {
        event = event.field("protocolReadStage", stage);
    }
    if let Some(context) = &attempt.protocol_read_context {
        event = event.field("protocolReadContext", context);
    }
    if let Some(disposition) = &attempt.protocol_read_disposition {
        event = event.field("protocolReadDisposition", disposition);
    }
    event
}

fn classify_attempt(
    status: RuntimeStatus,
    failure_scope: Option<ProbeFailureScope>,
    selected_outbound: Option<&str>,
    failed_stage: Option<&str>,
    protocol_read: Option<&ProtocolReadAttempt>,
    events: &[RuntimeEvent],
    start_sequence: Option<u64>,
) -> String {
    if status == RuntimeStatus::Pass {
        return "not-dynet-failure".to_string();
    }
    if direct_tls_eof(
        failure_scope,
        selected_outbound,
        failed_stage,
        events,
        start_sequence,
    ) {
        return DIRECT_TLS_EOF.to_string();
    }
    if let Some(read) = protocol_read {
        return read.classification.clone();
    }
    "dynet-failure-with-partial-evidence".to_string()
}

fn direct_tls_eof(
    failure_scope: Option<ProbeFailureScope>,
    selected_outbound: Option<&str>,
    failed_stage: Option<&str>,
    events: &[RuntimeEvent],
    start_sequence: Option<u64>,
) -> bool {
    failure_scope == Some(ProbeFailureScope::Direct)
        && selected_outbound == Some("direct")
        && failed_stage == Some("tls-handshake")
        && route_outbound_since(events, start_sequence) == Some("direct".to_string())
        && stage_status_since(events, start_sequence, "tcp-connect") == Some("success".to_string())
        && stage_status_since(events, start_sequence, "stream-first-write")
            == Some("success".to_string())
        && stream_first_read_zero(events, start_sequence)
        && failed_stage_error_since(events, start_sequence)
            .is_some_and(|error| reason_marker(error) == "tls-eof")
}

fn attempt_events(events: &[RuntimeEvent], start_sequence: Option<u64>) -> Vec<RuntimeEvent> {
    events
        .iter()
        .filter(|event| after_sequence(event, start_sequence))
        .cloned()
        .collect()
}

fn selected_outbound_since(events: &[RuntimeEvent], start_sequence: Option<u64>) -> Option<String> {
    events
        .iter()
        .filter(|event| after_sequence(event, start_sequence))
        .find(|event| event.kind == RuntimeEventKind::OutboundGraphSelected)
        .and_then(|event| field(event, "selected"))
        .or_else(|| route_outbound_since(events, start_sequence))
}

fn route_outbound_since(events: &[RuntimeEvent], start_sequence: Option<u64>) -> Option<String> {
    events
        .iter()
        .filter(|event| after_sequence(event, start_sequence))
        .find(|event| {
            event.kind == RuntimeEventKind::RouteMatched
                || event.kind == RuntimeEventKind::RuleMatched
        })
        .and_then(|event| field(event, "outbound"))
}

fn failed_stage_since(events: &[RuntimeEvent], start_sequence: Option<u64>) -> Option<String> {
    events
        .iter()
        .filter(|event| after_sequence(event, start_sequence))
        .filter(|event| event.kind == RuntimeEventKind::OutboundStageFinished)
        .find(|event| field(event, "status").as_deref() == Some("failed"))
        .and_then(|event| field(event, "stage"))
}

fn failed_stage_error_since(
    events: &[RuntimeEvent],
    start_sequence: Option<u64>,
) -> Option<String> {
    events
        .iter()
        .filter(|event| after_sequence(event, start_sequence))
        .filter(|event| event.kind == RuntimeEventKind::OutboundStageFinished)
        .find(|event| field(event, "status").as_deref() == Some("failed"))
        .and_then(|event| field(event, "error"))
}

fn protocol_read_since(
    events: &[RuntimeEvent],
    start_sequence: Option<u64>,
) -> Option<ProtocolReadAttempt> {
    let event = events
        .iter()
        .filter(|event| after_sequence(event, start_sequence))
        .filter(|event| event.kind == RuntimeEventKind::OutboundStageFinished)
        .find(|event| field(event, "status").as_deref() == Some("failed"))?;
    let marker = field(event, "protocolReadMarker")?;
    let disposition = field(event, "protocolReadDisposition");
    Some(ProtocolReadAttempt {
        classification: protocol_read_classification(&marker, disposition.as_deref()),
        marker,
        stage: field(event, "protocolReadStage"),
        context: field(event, "protocolReadContext"),
        disposition,
    })
}

fn protocol_read_classification(marker: &str, disposition: Option<&str>) -> String {
    if marker == "vmess-response-header-length-pending" {
        if let Some(disposition) = disposition {
            return format!("protocol-read-vmess-response-header-length-{disposition}");
        }
    }
    format!("protocol-read-{marker}")
}

fn stage_status_since(
    events: &[RuntimeEvent],
    start_sequence: Option<u64>,
    stage: &str,
) -> Option<String> {
    events
        .iter()
        .filter(|event| after_sequence(event, start_sequence))
        .filter(|event| event.kind == RuntimeEventKind::OutboundStageFinished)
        .find(|event| field(event, "stage").as_deref() == Some(stage))
        .and_then(|event| field(event, "status"))
}

fn stream_first_read_zero(events: &[RuntimeEvent], start_sequence: Option<u64>) -> bool {
    events
        .iter()
        .filter(|event| after_sequence(event, start_sequence))
        .filter(|event| event.kind == RuntimeEventKind::OutboundStageFinished)
        .filter(|event| field(event, "stage").as_deref() == Some("stream-first-read"))
        .any(|event| {
            field(event, "status").as_deref() == Some("success")
                && field(event, "bytes").as_deref() == Some("0")
        })
}

fn reason_marker(error: String) -> String {
    let text = error.to_ascii_lowercase();
    if text.contains("unexpected end of file") || text.contains("eof") {
        "tls-eof".to_string()
    } else if text.contains("temporarily unavailable") || text.contains("not ready") {
        "pending-read".to_string()
    } else {
        classify_runtime_error(&error).to_string()
    }
}

fn field(event: &RuntimeEvent, key: &str) -> Option<String> {
    event.fields.get(key).cloned()
}

fn after_sequence(event: &RuntimeEvent, start_sequence: Option<u64>) -> bool {
    match (event.sequence, start_sequence) {
        (Some(sequence), Some(start)) => sequence > start,
        (Some(_), None) => true,
        _ => false,
    }
}

fn emit(ebus: &EventBus, event: RuntimeEvent) -> Result<(), String> {
    ebus.emit(event)
}
