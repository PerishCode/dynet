use std::time::{Duration, Instant};

mod fallback;
mod http;
mod outcome;
mod retry;
mod scope;
mod target;

use dynet_core::{
    evaluate_rules, resolve_outbound_path, InboundContext, NetworkNode, PlanAction, Transport,
    VerdictStatus,
};
use serde::Serialize;

use crate::{
    event::EventBus,
    outbound::{self, TcpTarget},
    probe::http::ProbeResponse,
    resolver::trace::{
        annotate_runtime_error_fields, candidate_tags, classify_runtime_error,
        classify_runtime_error_disposition, elapsed_ms, hop_kinds, hop_tags, json_field,
    },
    RuntimeEvent, RuntimeEventKind, RuntimePolicy, RuntimeStatus,
};

pub use retry::{ProbeAttemptReport, ProbeRetryPolicy, ProbeRetryReport};
use scope::probe_failure_scope;
pub use scope::ProbeFailureScope;
pub use target::ProbeTarget;

#[derive(Debug)]
pub struct ProbeSettings {
    pub target: ProbeTarget,
    pub inbound: Option<String>,
    pub bypass_mark: u32,
    pub policy: RuntimePolicy,
    pub outbound_tcp: crate::OutboundTcpSettings,
    pub read_policy: ProbeReadPolicy,
    pub retry_policy: ProbeRetryPolicy,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeReadPolicy {
    pub poll_timeout_ms: u64,
    pub pending_budget_ms: u64,
    pub pending_sleep_ms: u64,
}

impl Default for ProbeReadPolicy {
    fn default() -> Self {
        Self {
            poll_timeout_ms: 250,
            pending_budget_ms: 8_000,
            pending_sleep_ms: 10,
        }
    }
}

impl ProbeReadPolicy {
    pub(crate) fn poll_timeout(self) -> Duration {
        Duration::from_millis(self.poll_timeout_ms.max(1))
    }

    pub(crate) fn pending_budget(self) -> Duration {
        Duration::from_millis(self.pending_budget_ms)
    }

    pub(crate) fn pending_sleep(self) -> Duration {
        Duration::from_millis(self.pending_sleep_ms)
    }

    pub fn is_default(self) -> bool {
        self == Self::default()
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProbeProtocol {
    TcpConnect,
    HttpsHead,
    TlsHandshake,
}

impl ProbeProtocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TcpConnect => "tcp-connect",
            Self::HttpsHead => "https-head",
            Self::TlsHandshake => "tls-handshake",
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeReport {
    pub schema: String,
    pub status: RuntimeStatus,
    pub reason: String,
    pub protocol: ProbeProtocol,
    pub target: ProbeTarget,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inbound: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_scope: Option<ProbeFailureScope>,
    pub route_decisions: usize,
    pub outbound_attempts: usize,
    pub read_policy: ProbeReadPolicy,
    #[serde(default, skip_serializing_if = "ProbeRetryReport::is_default")]
    pub retry: ProbeRetryReport,
    pub events: Vec<RuntimeEvent>,
}

pub fn probe_https_head(settings: ProbeSettings) -> Result<ProbeReport, String> {
    probe_with_protocol(settings, ProbeProtocol::HttpsHead)
}

pub fn probe_tcp_connect(settings: ProbeSettings) -> Result<ProbeReport, String> {
    probe_with_protocol(settings, ProbeProtocol::TcpConnect)
}

pub fn probe_tls_handshake(settings: ProbeSettings) -> Result<ProbeReport, String> {
    probe_with_protocol(settings, ProbeProtocol::TlsHandshake)
}

fn probe_with_protocol(
    settings: ProbeSettings,
    protocol: ProbeProtocol,
) -> Result<ProbeReport, String> {
    settings.target.validate()?;
    let retry_policy = settings.retry_policy;
    let ebus = EventBus::default();
    let started = Instant::now();
    emit(
        &ebus,
        RuntimeEvent::new(RuntimeEventKind::ProbeStarted)
            .field("protocol", protocol.as_str())
            .field("target", settings.target.address())
            .field("host", &settings.target.host)
            .field("port", settings.target.port)
            .field("path", &settings.target.path)
            .field("readPollTimeoutMs", settings.read_policy.poll_timeout_ms)
            .field(
                "readPendingBudgetMs",
                settings.read_policy.pending_budget_ms,
            )
            .field("readPendingSleepMs", settings.read_policy.pending_sleep_ms),
    )?;
    let (result, attempts) = retry::run_attempts(&settings, &ebus, protocol)?;
    let (status, reason) = match result {
        Ok(reason) => (RuntimeStatus::Pass, reason),
        Err(error) => (RuntimeStatus::Deny, error),
    };
    let recovered_after_retry = status == RuntimeStatus::Pass
        && attempts
            .first()
            .is_some_and(|attempt| attempt.status == RuntimeStatus::Deny)
        && attempts.len() > 1;
    emit(
        &ebus,
        RuntimeEvent::new(RuntimeEventKind::ProbeCompleted)
            .field("protocol", protocol.as_str())
            .field("target", settings.target.address())
            .field(
                "status",
                if status == RuntimeStatus::Pass {
                    "success"
                } else {
                    "failed"
                },
            )
            .field("elapsedMs", elapsed_ms(started))
            .field("attemptsUsed", attempts.len())
            .field("retryEnabled", retry_policy.enabled())
            .field("recoveredAfterRetry", recovered_after_retry)
            .field("reason", &reason),
    )?;
    let events = ebus.snapshot()?;
    let failure_scope = probe_failure_scope(status, &events);
    let unresolved_direct_tls_eof = status == RuntimeStatus::Deny
        && attempts
            .last()
            .is_some_and(|attempt| attempt.classification == retry::DIRECT_TLS_EOF);
    let retry = if retry_policy.enabled() {
        ProbeRetryReport {
            enabled: true,
            policy: retry_policy,
            attempts_used: attempts.len(),
            recovered_after_retry,
            unresolved_direct_tls_eof,
            attempts,
        }
    } else {
        ProbeRetryReport::default()
    };
    Ok(ProbeReport {
        schema: "dynet-probe/v1alpha1".to_string(),
        status,
        reason,
        protocol,
        target: settings.target,
        inbound: settings.inbound,
        failure_scope,
        route_decisions: count_kind(&events, RuntimeEventKind::RouteMatched)
            + count_kind(&events, RuntimeEventKind::RuleMatched),
        outbound_attempts: count_kind(&events, RuntimeEventKind::OutboundAttemptFinished),
        read_policy: settings.read_policy,
        retry,
        events,
    })
}

fn probe_inner(
    settings: &ProbeSettings,
    ebus: &EventBus,
    protocol: ProbeProtocol,
) -> Result<String, String> {
    let mut context = settings
        .inbound
        .as_ref()
        .map(InboundContext::from_inbound)
        .unwrap_or_else(InboundContext::any)
        .with_transport(Transport::Tcp)
        .with_destination_domain(settings.target.host.clone())
        .with_destination_port(settings.target.port);
    if let Ok(address) = settings.target.host.parse() {
        context = context.with_destination_ip(address);
    }
    if let Some(decision) = evaluate_rules(&settings.policy.state, &context) {
        emit(
            ebus,
            RuntimeEvent::new(RuntimeEventKind::RuleMatched)
                .field("rule", &decision.tag)
                .field("order", decision.order)
                .field("transport", "tcp")
                .field("target", settings.target.address())
                .field("outbound", &decision.outbound)
                .field("bypassesPlan", decision.bypasses_plan)
                .field("reason", &decision.reason),
        )?;
        emit(
            ebus,
            RuntimeEvent::new(RuntimeEventKind::PlanBypassed)
                .field("rule", &decision.tag)
                .field("outbound", &decision.outbound)
                .field("target", settings.target.address())
                .field("reason", "user hard rule matched before route plan"),
        )?;
        return probe_selected_outbound(settings, ebus, &context, &decision.outbound, protocol);
    }
    let verdict = settings
        .policy
        .plan
        .evaluate(&context, &settings.policy.state);
    let outbound_tag = verdict
        .outbound
        .as_ref()
        .map(|outbound| outbound.tag.as_str());
    emit(
        ebus,
        RuntimeEvent::new(RuntimeEventKind::RouteMatched)
            .field("transport", "tcp")
            .field("target", settings.target.address())
            .field("status", format!("{:?}", verdict.status))
            .field("outbound", outbound_tag.unwrap_or("<none>"))
            .field("reason", &verdict.reason),
    )?;
    match (&verdict.status, &verdict.action) {
        (VerdictStatus::Accept, PlanAction::UseOutbound { tag }) => {
            probe_selected_outbound(settings, ebus, &context, tag, protocol)
        }
        (VerdictStatus::Deny, PlanAction::Reject) => Err(format!(
            "probe target rejected by rule {:?}: {}",
            verdict.matched_rule, verdict.reason
        )),
        (VerdictStatus::Deny, _) => Err(verdict.reason),
        _ => Err("probe target did not match a usable outbound route".to_string()),
    }
}

fn probe_selected_outbound(
    settings: &ProbeSettings,
    ebus: &EventBus,
    context: &InboundContext,
    tag: &str,
    protocol: ProbeProtocol,
) -> Result<String, String> {
    let path = resolve_outbound_path(&settings.policy.state, context, tag)?;
    emit(
        ebus,
        RuntimeEvent::new(RuntimeEventKind::OutboundAdmissionPassed)
            .field("scope", "plan-candidate")
            .field("outbound", tag)
            .field("gate", "admission")
            .field("transport", "tcp"),
    )?;
    for decision in &path.decisions {
        emit(
            ebus,
            RuntimeEvent::new(RuntimeEventKind::OutboundCandidateSet)
                .field("scope", "plan-candidate")
                .field("plan", &decision.plan)
                .field("strategySource", &decision.strategy.source)
                .field("strategyKey", &decision.strategy.key)
                .field("strategyVersion", &decision.strategy.version)
                .field("selector", format!("{:?}", decision.strategy.selector))
                .field("candidateCount", decision.candidates.len())
                .field("selected", &decision.selected)
                .field(
                    "selectedEdgeType",
                    format!("{:?}", decision.selected_edge_type),
                )
                .field("candidates", candidate_tags(decision))
                .field("candidatesJson", json_field(&decision.candidates)),
        )?;
    }
    emit(
        ebus,
        RuntimeEvent::new(RuntimeEventKind::OutboundGraphSelected)
            .field("scope", "plan-candidate")
            .field("requested", &path.requested)
            .field("selected", &path.selected)
            .field("hops", path.hops.len())
            .field("hopTags", hop_tags(&path))
            .field("hopKinds", hop_kinds(&path))
            .field("decisions", path.decisions.len()),
    )?;
    emit(
        ebus,
        RuntimeEvent::new(RuntimeEventKind::OutboundEgressPassed)
            .field("scope", "plan-candidate")
            .field("gate", "egress")
            .field("requested", &path.requested)
            .field("selected", &path.selected)
            .field("transport", "tcp"),
    )?;
    let outbound = settings.policy.outbound(&path.selected).ok_or_else(|| {
        format!(
            "outbound graph selected missing outbound `{}`",
            path.selected
        )
    })?;
    probe_over_outbound(settings, ebus, context, outbound, protocol)
}

fn probe_over_outbound(
    settings: &ProbeSettings,
    ebus: &EventBus,
    context: &InboundContext,
    outbound: &NetworkNode,
    protocol: ProbeProtocol,
) -> Result<String, String> {
    let started = Instant::now();
    emit(
        ebus,
        RuntimeEvent::new(RuntimeEventKind::OutboundAttemptStarted)
            .field("outbound", &outbound.tag)
            .field("kind", &outbound.kind)
            .field("transport", "tcp")
            .field("protocol", protocol.as_str())
            .field("target", settings.target.address()),
    )?;
    match execute_probe(settings, ebus, context, outbound, protocol) {
        Ok(response) => {
            emit(
                ebus,
                outcome::outbound_attempt_finished(
                    outbound, protocol, "success", started, &response,
                ),
            )?;
            Ok(outcome::success_reason(protocol, &response))
        }
        Err(error) => {
            emit(
                ebus,
                annotate_runtime_error_fields(
                    RuntimeEvent::new(RuntimeEventKind::OutboundAttemptFinished)
                        .field("outbound", &outbound.tag)
                        .field("kind", &outbound.kind)
                        .field("transport", "tcp")
                        .field("protocol", protocol.as_str())
                        .field("status", "failed")
                        .field("errorType", classify_runtime_error(&error))
                        .field(
                            "errorDisposition",
                            classify_runtime_error_disposition(&error),
                        )
                        .field("error", &error)
                        .field("elapsedMs", elapsed_ms(started)),
                    &error,
                ),
            )?;
            Err(error)
        }
    }
}

fn execute_probe(
    settings: &ProbeSettings,
    ebus: &EventBus,
    context: &InboundContext,
    outbound: &NetworkNode,
    protocol: ProbeProtocol,
) -> Result<ProbeResponse, String> {
    if outbound.kind == "dialer" {
        return fallback::execute_with_fallback(settings, ebus, context, outbound, protocol);
    }
    execute_probe_once(settings, ebus, context, outbound, None, protocol)
}

fn execute_probe_once(
    settings: &ProbeSettings,
    ebus: &EventBus,
    context: &InboundContext,
    outbound: &NetworkNode,
    dialer_bound_override: Option<&str>,
    protocol: ProbeProtocol,
) -> Result<ProbeResponse, String> {
    let target = TcpTarget::Domain {
        host: settings.target.host.clone(),
        port: settings.target.port,
    };
    let mut events = Vec::new();
    let stream = outbound::connect_tcp_with_bound(
        &target,
        outbound,
        &settings.policy,
        context,
        &mut events,
        dialer_bound_override,
        outbound::TcpConnectOptions::new(settings.bypass_mark, settings.outbound_tcp),
    );
    emit_events(ebus, events)?;
    let stream = stream?;
    http::execute_with_protocol(
        ebus,
        outbound,
        &settings.target,
        stream,
        protocol,
        settings.read_policy,
    )
}

fn emit(ebus: &EventBus, event: RuntimeEvent) -> Result<(), String> {
    ebus.emit(event)
}

fn emit_events(ebus: &EventBus, events: Vec<RuntimeEvent>) -> Result<(), String> {
    for event in events {
        emit(ebus, event)?;
    }
    Ok(())
}

fn count_kind(events: &[RuntimeEvent], kind: RuntimeEventKind) -> usize {
    events.iter().filter(|event| event.kind == kind).count()
}
