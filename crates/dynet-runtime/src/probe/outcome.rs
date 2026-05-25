use std::time::Instant;

use dynet_core::NetworkNode;

use crate::{
    resolver::trace::{
        annotate_runtime_error_fields, classify_runtime_error, classify_runtime_error_disposition,
        elapsed_ms,
    },
    RuntimeEvent, RuntimeEventKind,
};

use super::{
    http::ProbeResponse, scope::CascadeFailureStage, ProbeFailureScope, ProbeProtocol,
    ProbeSettings,
};

pub(super) fn outbound_attempt_finished(
    outbound: &NetworkNode,
    protocol: ProbeProtocol,
    status: &str,
    started: Instant,
    response: &ProbeResponse,
) -> RuntimeEvent {
    let mut event = RuntimeEvent::new(RuntimeEventKind::OutboundAttemptFinished)
        .field("outbound", &outbound.tag)
        .field("kind", &outbound.kind)
        .field("transport", "tcp")
        .field("protocol", protocol.as_str())
        .field("status", status)
        .field("elapsedMs", elapsed_ms(started))
        .field("responseBytes", response.bytes);
    if let Some(status_code) = response.status_code {
        event = event.field("httpStatus", status_code);
    }
    event
}

pub(super) fn cascade_attempt_finished(
    outbound: &NetworkNode,
    candidate: &str,
    index: usize,
    candidate_count: usize,
    settings: &ProbeSettings,
    started: Instant,
    response: &ProbeResponse,
) -> RuntimeEvent {
    let mut event = RuntimeEvent::new(RuntimeEventKind::DialerCascadeAttemptFinished)
        .field("dialer", &outbound.tag)
        .field("boundSelected", candidate)
        .field("attempt", index + 1)
        .field("candidateCount", candidate_count)
        .field("target", settings.target.address())
        .field("status", "success")
        .field("failureScope", ProbeFailureScope::None.as_str())
        .field("elapsedMs", elapsed_ms(started))
        .field("responseBytes", response.bytes);
    if let Some(status_code) = response.status_code {
        event = event.field("httpStatus", status_code);
    }
    event
}

pub(super) struct CascadeAttemptFailure<'a> {
    pub(super) outbound: &'a NetworkNode,
    pub(super) candidate: &'a str,
    pub(super) index: usize,
    pub(super) candidate_count: usize,
    pub(super) settings: &'a ProbeSettings,
    pub(super) failure_scope: ProbeFailureScope,
    pub(super) failure_stage: Option<CascadeFailureStage>,
    pub(super) error: &'a str,
    pub(super) started: Instant,
    pub(super) can_retry: bool,
}

pub(super) fn cascade_attempt_failed(args: CascadeAttemptFailure<'_>) -> RuntimeEvent {
    let mut event = annotate_runtime_error_fields(
        RuntimeEvent::new(RuntimeEventKind::DialerCascadeAttemptFinished)
            .field("dialer", &args.outbound.tag)
            .field("boundSelected", args.candidate)
            .field("attempt", args.index + 1)
            .field("candidateCount", args.candidate_count)
            .field("target", args.settings.target.address())
            .field("status", "failed")
            .field("failureScope", args.failure_scope.as_str())
            .field("errorType", classify_runtime_error(args.error))
            .field(
                "errorDisposition",
                classify_runtime_error_disposition(args.error),
            )
            .field("error", args.error)
            .field("elapsedMs", elapsed_ms(args.started))
            .field("retryAllowed", args.can_retry)
            .field(
                "retryStopReason",
                retry_stop_reason(args.failure_scope, args.can_retry),
            ),
        args.error,
    );
    if let Some(stage) = args.failure_stage {
        event = event
            .field("failureStage", stage.stage)
            .field("failureStageOutbound", stage.outbound)
            .field("failureStageKind", stage.kind)
            .field("failureStageErrorType", stage.error_type)
            .field("failureStageDisposition", stage.error_disposition);
        if let Some(pending_retries) = stage.pending_retries {
            event = event.field("failureStagePendingRetries", pending_retries);
        }
        if let Some(pending_wait_class) = stage.pending_wait_class {
            event = event.field("failureStagePendingWaitClass", pending_wait_class);
        }
    }
    event
}

fn retry_stop_reason(failure_scope: ProbeFailureScope, can_retry: bool) -> &'static str {
    if can_retry {
        "retry-bound-failure-before-replay"
    } else if failure_scope == ProbeFailureScope::Bound {
        "bound-candidates-exhausted"
    } else {
        "non-bound-failure"
    }
}

pub(super) fn success_reason(protocol: ProbeProtocol, response: &ProbeResponse) -> String {
    match (protocol, response.status_code) {
        (ProbeProtocol::TcpConnect, _) => "TCP connect completed".to_string(),
        (ProbeProtocol::HttpsHead, Some(status_code)) => {
            format!("HTTPS HEAD completed with HTTP {status_code}")
        }
        (ProbeProtocol::HttpsHead, None) => "HTTPS HEAD completed".to_string(),
        (ProbeProtocol::TlsHandshake, _) => "TLS handshake completed".to_string(),
    }
}
