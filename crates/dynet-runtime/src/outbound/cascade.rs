use std::time::Instant;

use dynet_core::{InboundContext, NetworkNode};

use crate::{
    resolver::trace::{
        annotate_runtime_error_fields, classify_runtime_error, classify_runtime_error_disposition,
    },
    RuntimeEvent, RuntimeEventKind, RuntimePolicy,
};

use super::{connect_tcp_policy, connect_tcp_with_bound, dialer_bound_candidate_order};
use super::{ProxiedTcpStream, TcpConnectOptions, TcpTarget};

pub(crate) fn connect_tcp_with_fallback(
    target: &TcpTarget,
    outbound: &NetworkNode,
    policy: &RuntimePolicy,
    context: &InboundContext,
    events: &mut Vec<RuntimeEvent>,
    replay_safe: &'static str,
    options: TcpConnectOptions,
) -> Result<ProxiedTcpStream, String> {
    if outbound.kind != "dialer" {
        return connect_tcp_policy(target, outbound, policy, context, events, options);
    }
    connect_dialer_with_fallback(
        target,
        outbound,
        policy,
        context,
        events,
        replay_safe,
        options,
    )
}

fn connect_dialer_with_fallback(
    target: &TcpTarget,
    outbound: &NetworkNode,
    policy: &RuntimePolicy,
    context: &InboundContext,
    events: &mut Vec<RuntimeEvent>,
    replay_safe: &'static str,
    options: TcpConnectOptions,
) -> Result<ProxiedTcpStream, String> {
    let candidates = dialer_bound_candidate_order(outbound, policy, context)?;
    let mut failures = Vec::new();
    for (index, candidate) in candidates.iter().enumerate() {
        let started = Instant::now();
        events.push(
            RuntimeEvent::new(RuntimeEventKind::DialerCascadeAttemptStarted)
                .field("dialer", &outbound.tag)
                .field("boundSelected", candidate)
                .field("attempt", index + 1)
                .field("candidateCount", candidates.len())
                .field("target", target)
                .field("replaySafe", replay_safe),
        );
        let attempt_start = events.len();
        match connect_tcp_with_bound(
            target,
            outbound,
            policy,
            context,
            events,
            Some(candidate),
            options,
        ) {
            Ok(stream) => {
                events.push(
                    RuntimeEvent::new(RuntimeEventKind::DialerCascadeAttemptFinished)
                        .field("dialer", &outbound.tag)
                        .field("boundSelected", candidate)
                        .field("attempt", index + 1)
                        .field("candidateCount", candidates.len())
                        .field("target", target)
                        .field("status", "success")
                        .field("failureScope", "none")
                        .field("elapsedMs", started.elapsed().as_millis()),
                );
                return Ok(stream);
            }
            Err(error) => {
                let failure_context = cascade_failure_context(events, attempt_start, candidate);
                let failure_scope = failure_context.scope;
                let can_retry = failure_scope == "bound" && index + 1 < candidates.len();
                events.push(cascade_failure_event(CascadeFailure {
                    outbound,
                    candidate,
                    index,
                    candidate_count: candidates.len(),
                    target,
                    failure_scope,
                    stage: failure_context.stage,
                    error: &error,
                    started,
                    can_retry,
                }));
                failures.push(format!("{candidate}: {error}"));
                if failure_scope != "bound" {
                    return Err(format!(
                        "dialer `{}` stopped after non-retry-safe {} failure on bound candidate `{candidate}` before replay point: {error}",
                        outbound.tag, failure_scope,
                    ));
                }
            }
        }
    }
    Err(format!(
        "dialer `{}` failed all {} bound candidates before replay point: {}",
        outbound.tag,
        candidates.len(),
        failures.join(" | ")
    ))
}

struct CascadeFailure<'a> {
    outbound: &'a NetworkNode,
    candidate: &'a str,
    index: usize,
    candidate_count: usize,
    target: &'a TcpTarget,
    failure_scope: &'a str,
    stage: Option<CascadeFailureStage>,
    error: &'a str,
    started: Instant,
    can_retry: bool,
}

fn cascade_failure_event(args: CascadeFailure<'_>) -> RuntimeEvent {
    let mut event = annotate_runtime_error_fields(
        RuntimeEvent::new(RuntimeEventKind::DialerCascadeAttemptFinished)
            .field("dialer", &args.outbound.tag)
            .field("boundSelected", args.candidate)
            .field("attempt", args.index + 1)
            .field("candidateCount", args.candidate_count)
            .field("target", args.target)
            .field("status", "failed")
            .field("failureScope", args.failure_scope)
            .field("errorType", classify_runtime_error(args.error))
            .field(
                "errorDisposition",
                classify_runtime_error_disposition(args.error),
            )
            .field("error", args.error)
            .field("elapsedMs", args.started.elapsed().as_millis())
            .field("retryAllowed", args.can_retry)
            .field(
                "retryStopReason",
                retry_stop_reason(args.failure_scope, args.can_retry),
            ),
        args.error,
    );
    if let Some(stage) = args.stage {
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

fn retry_stop_reason(failure_scope: &str, can_retry: bool) -> &'static str {
    if can_retry {
        "retry-bound-failure-before-replay"
    } else if failure_scope == "bound" {
        "bound-candidates-exhausted"
    } else {
        "non-bound-failure"
    }
}

struct CascadeFailureContext {
    scope: &'static str,
    stage: Option<CascadeFailureStage>,
}

struct CascadeFailureStage {
    stage: String,
    outbound: String,
    kind: String,
    error_type: String,
    error_disposition: String,
    pending_retries: Option<String>,
    pending_wait_class: Option<String>,
}

fn cascade_failure_context(
    events: &[RuntimeEvent],
    attempt_start: usize,
    bound: &str,
) -> CascadeFailureContext {
    let failed_stages: Vec<&RuntimeEvent> = events
        .iter()
        .skip(attempt_start)
        .filter(|event| event.kind == RuntimeEventKind::OutboundStageFinished)
        .filter(|event| field(event, "status") == Some("failed"))
        .collect();
    let mut saw_failed_stage = false;
    for event in failed_stages.iter().rev() {
        saw_failed_stage = true;
        if field(event, "outbound") == Some(bound) {
            return CascadeFailureContext {
                scope: "bound",
                stage: Some(stage_context(event)),
            };
        }
    }
    if saw_failed_stage {
        return CascadeFailureContext {
            scope: "downstream",
            stage: failed_stages.last().map(|event| stage_context(event)),
        };
    }
    CascadeFailureContext {
        scope: "unknown",
        stage: None,
    }
}

fn stage_context(event: &RuntimeEvent) -> CascadeFailureStage {
    CascadeFailureStage {
        stage: field(event, "stage").unwrap_or("unknown").to_string(),
        outbound: field(event, "outbound").unwrap_or("unknown").to_string(),
        kind: field(event, "kind").unwrap_or("unknown").to_string(),
        error_type: field(event, "errorType").unwrap_or("unknown").to_string(),
        error_disposition: field(event, "errorDisposition")
            .unwrap_or("unknown")
            .to_string(),
        pending_retries: field(event, "pendingRetries").map(ToOwned::to_owned),
        pending_wait_class: field(event, "pendingWaitClass").map(ToOwned::to_owned),
    }
}

fn field<'a>(event: &'a RuntimeEvent, key: &str) -> Option<&'a str> {
    event.fields.get(key).map(String::as_str)
}
