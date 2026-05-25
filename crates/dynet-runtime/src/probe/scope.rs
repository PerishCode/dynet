use serde::Serialize;

use crate::{event::EventBus, RuntimeEvent, RuntimeEventKind, RuntimeStatus};

#[derive(Debug, Clone)]
pub(super) struct CascadeFailureStage {
    pub(super) stage: String,
    pub(super) outbound: String,
    pub(super) kind: String,
    pub(super) error_type: String,
    pub(super) error_disposition: String,
    pub(super) pending_retries: Option<String>,
    pub(super) pending_wait_class: Option<String>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProbeFailureScope {
    None,
    Direct,
    Bound,
    Downstream,
    Unknown,
}

impl ProbeFailureScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Direct => "direct",
            Self::Bound => "bound",
            Self::Downstream => "downstream",
            Self::Unknown => "unknown",
        }
    }

    fn from_field(value: &str) -> Option<Self> {
        match value {
            "none" => Some(Self::None),
            "direct" => Some(Self::Direct),
            "bound" => Some(Self::Bound),
            "downstream" => Some(Self::Downstream),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }
}

pub(super) fn latest_event_sequence(ebus: &EventBus) -> Result<Option<u64>, String> {
    Ok(ebus.snapshot()?.last().and_then(|event| event.sequence))
}

pub(super) fn cascade_failure_scope(
    ebus: &EventBus,
    attempt_start_sequence: Option<u64>,
    bound: &str,
) -> Result<ProbeFailureScope, String> {
    let events = ebus.snapshot()?;
    let failed_stages: Vec<&RuntimeEvent> = events
        .iter()
        .filter(|event| event.kind == RuntimeEventKind::OutboundStageFinished)
        .filter(|event| event.sequence > attempt_start_sequence)
        .filter(|event| field(event, "status") == Some("failed"))
        .collect();
    if failed_stages
        .iter()
        .any(|event| field(event, "outbound") == Some(bound))
    {
        return Ok(ProbeFailureScope::Bound);
    }
    if !failed_stages.is_empty() {
        return Ok(ProbeFailureScope::Downstream);
    }
    Ok(ProbeFailureScope::Unknown)
}

pub(super) fn cascade_failure_stage(
    ebus: &EventBus,
    attempt_start_sequence: Option<u64>,
    bound: &str,
    scope: ProbeFailureScope,
) -> Result<Option<CascadeFailureStage>, String> {
    let events = ebus.snapshot()?;
    let failed_stages: Vec<&RuntimeEvent> = events
        .iter()
        .filter(|event| event.kind == RuntimeEventKind::OutboundStageFinished)
        .filter(|event| event.sequence > attempt_start_sequence)
        .filter(|event| field(event, "status") == Some("failed"))
        .collect();
    let stage = match scope {
        ProbeFailureScope::Bound => failed_stages
            .iter()
            .rev()
            .find(|event| field(event, "outbound") == Some(bound)),
        ProbeFailureScope::Downstream => failed_stages.last(),
        _ => None,
    };
    Ok(stage.map(|event| CascadeFailureStage {
        stage: field(event, "stage").unwrap_or("unknown").to_string(),
        outbound: field(event, "outbound").unwrap_or("unknown").to_string(),
        kind: field(event, "kind").unwrap_or("unknown").to_string(),
        error_type: field(event, "errorType").unwrap_or("unknown").to_string(),
        error_disposition: field(event, "errorDisposition")
            .unwrap_or("unknown")
            .to_string(),
        pending_retries: field(event, "pendingRetries").map(ToOwned::to_owned),
        pending_wait_class: field(event, "pendingWaitClass").map(ToOwned::to_owned),
    }))
}

pub(super) fn probe_failure_scope(
    status: RuntimeStatus,
    events: &[RuntimeEvent],
) -> Option<ProbeFailureScope> {
    if status == RuntimeStatus::Pass {
        return None;
    }
    let scopes: Vec<ProbeFailureScope> = events
        .iter()
        .filter(|event| event.kind == RuntimeEventKind::DialerCascadeAttemptFinished)
        .filter_map(|event| field(event, "failureScope"))
        .filter_map(ProbeFailureScope::from_field)
        .collect();
    if scopes.is_empty() {
        return Some(ProbeFailureScope::Direct);
    }
    if scopes.contains(&ProbeFailureScope::Downstream) {
        return Some(ProbeFailureScope::Downstream);
    }
    if scopes.contains(&ProbeFailureScope::Bound) {
        return Some(ProbeFailureScope::Bound);
    }
    if scopes.contains(&ProbeFailureScope::Unknown) {
        return Some(ProbeFailureScope::Unknown);
    }
    None
}

fn field<'a>(event: &'a RuntimeEvent, key: &str) -> Option<&'a str> {
    event.fields.get(key).map(String::as_str)
}
