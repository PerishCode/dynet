use dynet_runtime::{RuntimeEvent, RuntimeEventKind};

pub(crate) fn plan_selected(event: &RuntimeEvent, selected: &str) -> bool {
    has(
        event,
        RuntimeEventKind::OutboundCandidateSet,
        "scope",
        "plan-candidate",
    ) && field(event, "selected") == Some(selected)
        && field(event, "candidatesJson").is_some_and(|value| value.contains(selected))
}

pub(crate) fn attempt_done(event: &RuntimeEvent, outbound: &str, kind: &str) -> bool {
    has(
        event,
        RuntimeEventKind::OutboundAttemptFinished,
        "outbound",
        outbound,
    ) && field(event, "kind") == Some(kind)
        && field(event, "protocol") == Some("tcp-connect")
        && field(event, "status") == Some("success")
}

pub(crate) fn stream_flushed(event: &RuntimeEvent, outbound: &str) -> bool {
    has(
        event,
        RuntimeEventKind::OutboundStageFinished,
        "outbound",
        outbound,
    ) && field(event, "stage") == Some("stream-flush")
        && field(event, "status") == Some("success")
}

pub(crate) fn stream_first_read_success(event: &RuntimeEvent, outbound: &str) -> bool {
    has(
        event,
        RuntimeEventKind::OutboundStageFinished,
        "outbound",
        outbound,
    ) && field(event, "stage") == Some("stream-first-read")
        && field(event, "status") == Some("success")
        && field(event, "bytes").is_some_and(|value| value != "0")
}

pub(crate) fn bound_candidate_set(event: &RuntimeEvent) -> bool {
    has(
        event,
        RuntimeEventKind::OutboundCandidateSet,
        "scope",
        "dialer-bound",
    ) && field(event, "selected") == Some("direct")
        && field(event, "candidatesJson").is_some_and(|value| value.contains("direct"))
}

pub(crate) fn cascade_selected(event: &RuntimeEvent, dialer: &str, private: &str) -> bool {
    cascade_selected_bound(event, dialer, "direct", private)
}

pub(crate) fn cascade_selected_bound(
    event: &RuntimeEvent,
    dialer: &str,
    bound: &str,
    private: &str,
) -> bool {
    has(
        event,
        RuntimeEventKind::DialerCascadeSelected,
        "dialer",
        dialer,
    ) && field(event, "boundSelected") == Some(bound)
        && field(event, "private") == Some(private)
}

pub(crate) fn cascade_finished_scope(
    event: &RuntimeEvent,
    dialer: &str,
    bound: &str,
    status: &str,
    failure_scope: &str,
) -> bool {
    has(
        event,
        RuntimeEventKind::DialerCascadeAttemptFinished,
        "dialer",
        dialer,
    ) && field(event, "boundSelected") == Some(bound)
        && field(event, "status") == Some(status)
        && field(event, "failureScope") == Some(failure_scope)
}

pub(crate) fn private_stage(event: &RuntimeEvent, outbound: &str, stage: &str) -> bool {
    has(
        event,
        RuntimeEventKind::OutboundStageFinished,
        "outbound",
        outbound,
    ) && field(event, "stage") == Some(stage)
        && field(event, "status") == Some("success")
}

pub(crate) fn private_stage_target(
    event: &RuntimeEvent,
    outbound: &str,
    stage: &str,
    target: &str,
    target_kind: &str,
) -> bool {
    private_stage(event, outbound, stage)
        && field(event, "adapterTarget") == Some(target)
        && field(event, "adapterTargetKind") == Some(target_kind)
}

pub(crate) fn bound_direct_done(event: &RuntimeEvent) -> bool {
    has(
        event,
        RuntimeEventKind::OutboundAttemptFinished,
        "outbound",
        "direct",
    ) && field(event, "status") == Some("success")
}

fn has(event: &RuntimeEvent, kind: RuntimeEventKind, key: &str, value: &str) -> bool {
    event.kind == kind && field(event, key) == Some(value)
}

fn field<'a>(event: &'a RuntimeEvent, key: &str) -> Option<&'a str> {
    event.fields.get(key).map(String::as_str)
}
