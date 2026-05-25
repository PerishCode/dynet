use std::net::SocketAddr;

use dynet_core::InboundContext;

use crate::{
    outbound::{self, ProxiedTcpStream},
    RuntimeCounters, RuntimeEvent, RuntimeEventKind, RuntimePolicy, RuntimeSettings,
};

use super::super::event_context;
use super::{start_failure::SessionStartFailureStage, target_select, SessionStartFailure};

pub(super) struct ConnectArgs<'a> {
    pub(super) id: usize,
    pub(super) target: SocketAddr,
    pub(super) client: SocketAddr,
    pub(super) domains: &'a [String],
    pub(super) decision_domain: Option<&'a str>,
    pub(super) route_selected: &'a str,
    pub(super) candidates: &'a [String],
    pub(super) policy: &'a RuntimePolicy,
    pub(super) context: &'a InboundContext,
    pub(super) settings: &'a RuntimeSettings,
    pub(super) counters: &'a RuntimeCounters,
}

pub(super) struct ConnectedCandidate {
    pub(super) outbound: String,
    pub(super) stream: ProxiedTcpStream,
    pub(super) forward_target: target_select::SelectedTcpTarget,
}

pub(super) fn connect(args: ConnectArgs<'_>) -> Result<ConnectedCandidate, SessionStartFailure> {
    let mut last_error = None;
    let mut last_stage = None;
    for (index, candidate) in args.candidates.iter().enumerate() {
        let outbound = args.policy.outbound(candidate).ok_or_else(|| {
            SessionStartFailure::outbound_scoped(
                format!("TUN TCP route fallback selected missing outbound `{candidate}`"),
                args.id,
                args.target,
                args.client,
                candidate.clone(),
            )
        })?;
        let forward_target =
            target_select::select(args.target, args.domains, args.decision_domain, outbound);
        args.counters
            .emit(target_select::annotate(
                RuntimeEvent::new(RuntimeEventKind::TcpSessionOutboundConnecting)
                    .field("session", args.id)
                    .field("flowId", format!("tcp-session-{}", args.id))
                    .field("target", args.target)
                    .field("outbound", &outbound.tag)
                    .field("kind", &outbound.kind)
                    .field("routeSelected", args.route_selected)
                    .field("routeFallbackAttempt", index + 1)
                    .field("routeFallbackCandidateCount", args.candidates.len())
                    .field("replaySafe", "pre-payload")
                    .field(
                        "outboundTcpConnectTimeoutMs",
                        args.settings.outbound_tcp.connect_timeout_ms,
                    )
                    .field(
                        "outboundTcpReadWriteTimeoutMs",
                        args.settings.outbound_tcp.read_write_timeout_ms,
                    ),
                &forward_target,
            ))
            .map_err(|error| {
                SessionStartFailure::outbound_scoped(
                    error,
                    args.id,
                    args.target,
                    args.client,
                    candidate.clone(),
                )
            })?;
        let mut events = Vec::new();
        let stream = outbound::connect_tcp_with_fallback(
            &forward_target.target,
            outbound,
            args.policy,
            args.context,
            &mut events,
            "pre-payload",
            outbound::TcpConnectOptions::new(args.settings.bypass_mark, args.settings.outbound_tcp),
        );
        let failure_context = stream
            .as_ref()
            .err()
            .map(|_| route_failure_context(&events, candidate));
        event_context::emit_session_events(
            args.counters,
            &event_context::SessionEventContext::tcp(args.id, args.target, args.client),
            events,
        )
        .map_err(|error| {
            SessionStartFailure::outbound_scoped(
                error,
                args.id,
                args.target,
                args.client,
                candidate.clone(),
            )
        })?;
        match stream {
            Ok(stream) => {
                return Ok(ConnectedCandidate {
                    outbound: candidate.clone(),
                    stream,
                    forward_target,
                });
            }
            Err(error) => {
                let has_next = index + 1 < args.candidates.len();
                let retry = can_retry_candidate(failure_context.as_ref(), candidate, has_next);
                last_error = Some((candidate.clone(), error));
                last_stage = failure_context.and_then(|context| context.stage);
                if retry {
                    continue;
                }
                break;
            }
        }
    }
    let (outbound, error) = last_error.unwrap_or_else(|| {
        (
            args.route_selected.to_string(),
            "TUN TCP route fallback had no candidates".to_string(),
        )
    });
    Err(
        SessionStartFailure::outbound_scoped(error, args.id, args.target, args.client, outbound)
            .with_stage(last_stage),
    )
}

fn can_retry_candidate(
    context: Option<&RouteFailureContext>,
    candidate: &str,
    has_next: bool,
) -> bool {
    has_next
        && context.is_some_and(|context| {
            context.route_candidate_retryable
                || context
                    .stage
                    .as_ref()
                    .is_some_and(|stage| stage.outbound == candidate)
        })
}

struct RouteFailureContext {
    stage: Option<SessionStartFailureStage>,
    route_candidate_retryable: bool,
}

fn route_failure_context(events: &[RuntimeEvent], candidate: &str) -> RouteFailureContext {
    RouteFailureContext {
        stage: stage_failure_context(events),
        route_candidate_retryable: bound_cascade_exhausted(events, candidate),
    }
}

fn bound_cascade_exhausted(events: &[RuntimeEvent], candidate: &str) -> bool {
    events.iter().rev().any(|event| {
        event.kind == RuntimeEventKind::DialerCascadeAttemptFinished
            && field(event, "dialer") == Some(candidate)
            && field(event, "status") == Some("failed")
            && field(event, "failureScope") == Some("bound")
            && field(event, "retryAllowed") == Some("false")
            && field(event, "retryStopReason") == Some("bound-candidates-exhausted")
    })
}

fn stage_failure_context(events: &[RuntimeEvent]) -> Option<SessionStartFailureStage> {
    events.iter().rev().find_map(|event| {
        if event.kind != RuntimeEventKind::OutboundStageFinished {
            return None;
        }
        if event.fields.get("status").map(String::as_str) != Some("failed") {
            return None;
        }
        Some(SessionStartFailureStage {
            stage: event.fields.get("stage")?.clone(),
            outbound: event.fields.get("outbound")?.clone(),
            kind: event.fields.get("kind").cloned().unwrap_or_default(),
            error_type: event.fields.get("errorType").cloned().unwrap_or_default(),
            error_disposition: event
                .fields
                .get("errorDisposition")
                .cloned()
                .unwrap_or_else(|| "unknown".to_string()),
        })
    })
}

fn field<'a>(event: &'a RuntimeEvent, key: &str) -> Option<&'a str> {
    event.fields.get(key).map(String::as_str)
}
