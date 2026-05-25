use std::time::Instant;

use dynet_core::{InboundContext, NetworkNode};

use crate::{event::EventBus, outbound, RuntimeEvent, RuntimeEventKind};

use super::{
    execute_probe_once,
    http::ProbeResponse,
    outcome,
    scope::{cascade_failure_scope, cascade_failure_stage, latest_event_sequence},
    ProbeFailureScope, ProbeProtocol, ProbeSettings,
};

pub(super) fn execute_with_fallback(
    settings: &ProbeSettings,
    ebus: &EventBus,
    context: &InboundContext,
    outbound: &NetworkNode,
    protocol: ProbeProtocol,
) -> Result<ProbeResponse, String> {
    let candidates = outbound::dialer_bound_candidate_order(outbound, &settings.policy, context)?;
    let mut failures = Vec::new();
    for (index, candidate) in candidates.iter().enumerate() {
        let started = Instant::now();
        ebus.emit(cascade_attempt_started(
            outbound,
            candidate,
            index,
            candidates.len(),
            settings,
        ))?;
        let attempt_start_sequence = latest_event_sequence(ebus)?;
        match execute_probe_once(settings, ebus, context, outbound, Some(candidate), protocol) {
            Ok(response) => {
                ebus.emit(outcome::cascade_attempt_finished(
                    outbound,
                    candidate,
                    index,
                    candidates.len(),
                    settings,
                    started,
                    &response,
                ))?;
                return Ok(response);
            }
            Err(error) => {
                let failure_scope = cascade_failure_scope(ebus, attempt_start_sequence, candidate)?;
                let failure_stage =
                    cascade_failure_stage(ebus, attempt_start_sequence, candidate, failure_scope)?;
                handle_cascade_failure(
                    CascadeAttemptFailure {
                        ebus,
                        outbound,
                        candidate,
                        index,
                        candidate_count: candidates.len(),
                        settings,
                        failure_scope,
                        failure_stage,
                        error,
                        started,
                    },
                    &mut failures,
                )?;
            }
        }
    }
    Err(format!(
        "dialer `{}` failed all {} bound candidates: {}",
        outbound.tag,
        candidates.len(),
        failures.join(" | ")
    ))
}

fn cascade_attempt_started(
    outbound: &NetworkNode,
    candidate: &str,
    index: usize,
    candidate_count: usize,
    settings: &ProbeSettings,
) -> RuntimeEvent {
    RuntimeEvent::new(RuntimeEventKind::DialerCascadeAttemptStarted)
        .field("dialer", &outbound.tag)
        .field("boundSelected", candidate)
        .field("attempt", index + 1)
        .field("candidateCount", candidate_count)
        .field("target", settings.target.address())
}

struct CascadeAttemptFailure<'a> {
    ebus: &'a EventBus,
    outbound: &'a NetworkNode,
    candidate: &'a str,
    index: usize,
    candidate_count: usize,
    settings: &'a ProbeSettings,
    failure_scope: ProbeFailureScope,
    failure_stage: Option<super::scope::CascadeFailureStage>,
    error: String,
    started: Instant,
}

fn handle_cascade_failure(
    args: CascadeAttemptFailure<'_>,
    failures: &mut Vec<String>,
) -> Result<(), String> {
    let can_retry =
        args.failure_scope == ProbeFailureScope::Bound && args.index + 1 < args.candidate_count;
    args.ebus.emit(outcome::cascade_attempt_failed(
        outcome::CascadeAttemptFailure {
            outbound: args.outbound,
            candidate: args.candidate,
            index: args.index,
            candidate_count: args.candidate_count,
            settings: args.settings,
            failure_scope: args.failure_scope,
            failure_stage: args.failure_stage,
            error: &args.error,
            started: args.started,
            can_retry,
        },
    ))?;
    failures.push(format!("{}: {}", args.candidate, args.error));
    if args.failure_scope == ProbeFailureScope::Bound {
        return Ok(());
    }
    Err(format!(
        "dialer `{}` stopped after non-retry-safe {} failure on bound candidate `{}`: {}",
        args.outbound.tag,
        args.failure_scope.as_str(),
        args.candidate,
        args.error,
    ))
}
