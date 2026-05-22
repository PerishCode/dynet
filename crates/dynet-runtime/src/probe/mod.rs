use std::time::Instant;

mod http;

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
        candidate_tags, classify_runtime_error, elapsed_ms, hop_kinds, hop_tags, json_field,
    },
    RuntimeEvent, RuntimeEventKind, RuntimePolicy, RuntimeStatus,
};

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeTarget {
    pub host: String,
    pub port: u16,
    pub path: String,
}

#[derive(Debug)]
pub struct ProbeSettings {
    pub target: ProbeTarget,
    pub inbound: Option<String>,
    pub bypass_mark: u32,
    pub policy: RuntimePolicy,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProbeProtocol {
    HttpsHead,
    TlsHandshake,
}

impl ProbeProtocol {
    pub fn as_str(self) -> &'static str {
        match self {
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
    pub route_decisions: usize,
    pub outbound_attempts: usize,
    pub events: Vec<RuntimeEvent>,
}

pub fn probe_https_head(settings: ProbeSettings) -> Result<ProbeReport, String> {
    probe_with_protocol(settings, ProbeProtocol::HttpsHead)
}

pub fn probe_tls_handshake(settings: ProbeSettings) -> Result<ProbeReport, String> {
    probe_with_protocol(settings, ProbeProtocol::TlsHandshake)
}

fn probe_with_protocol(
    settings: ProbeSettings,
    protocol: ProbeProtocol,
) -> Result<ProbeReport, String> {
    settings.target.validate()?;
    let ebus = EventBus::default();
    let started = Instant::now();
    emit(
        &ebus,
        RuntimeEvent::new(RuntimeEventKind::ProbeStarted)
            .field("protocol", protocol.as_str())
            .field("target", settings.target.address())
            .field("host", &settings.target.host)
            .field("port", settings.target.port)
            .field("path", &settings.target.path),
    )?;
    let result = probe_inner(&settings, &ebus, protocol);
    let (status, reason) = match result {
        Ok(reason) => (RuntimeStatus::Pass, reason),
        Err(error) => (RuntimeStatus::Deny, error),
    };
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
            .field("reason", &reason),
    )?;
    let events = ebus.snapshot()?;
    Ok(ProbeReport {
        schema: "dynet-probe/v1alpha1".to_string(),
        status,
        reason,
        protocol,
        target: settings.target,
        inbound: settings.inbound,
        route_decisions: count_kind(&events, RuntimeEventKind::RouteMatched)
            + count_kind(&events, RuntimeEventKind::RuleMatched),
        outbound_attempts: count_kind(&events, RuntimeEventKind::OutboundAttemptFinished),
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
            .field("outbound", tag)
            .field("gate", "admission")
            .field("transport", "tcp"),
    )?;
    for decision in &path.decisions {
        emit(
            ebus,
            RuntimeEvent::new(RuntimeEventKind::OutboundCandidateSet)
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
                outbound_attempt_finished(outbound, protocol, "success", started, &response),
            )?;
            Ok(success_reason(protocol, &response))
        }
        Err(error) => {
            emit(
                ebus,
                RuntimeEvent::new(RuntimeEventKind::OutboundAttemptFinished)
                    .field("outbound", &outbound.tag)
                    .field("kind", &outbound.kind)
                    .field("transport", "tcp")
                    .field("protocol", protocol.as_str())
                    .field("status", "failed")
                    .field("errorType", classify_runtime_error(&error))
                    .field("error", &error)
                    .field("elapsedMs", elapsed_ms(started)),
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
        return execute_with_fallback(settings, ebus, context, outbound, protocol);
    }
    execute_probe_once(settings, ebus, context, outbound, None, protocol)
}

fn execute_with_fallback(
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
        emit(
            ebus,
            RuntimeEvent::new(RuntimeEventKind::DialerCascadeAttemptStarted)
                .field("dialer", &outbound.tag)
                .field("boundSelected", candidate)
                .field("attempt", index + 1)
                .field("candidateCount", candidates.len())
                .field("target", settings.target.address()),
        )?;
        match execute_probe_once(settings, ebus, context, outbound, Some(candidate), protocol) {
            Ok(response) => {
                let event = cascade_attempt_finished(
                    outbound,
                    candidate,
                    index,
                    candidates.len(),
                    settings,
                    started,
                    &response,
                );
                emit(ebus, event)?;
                return Ok(response);
            }
            Err(error) => {
                emit(
                    ebus,
                    RuntimeEvent::new(RuntimeEventKind::DialerCascadeAttemptFinished)
                        .field("dialer", &outbound.tag)
                        .field("boundSelected", candidate)
                        .field("attempt", index + 1)
                        .field("candidateCount", candidates.len())
                        .field("target", settings.target.address())
                        .field("status", "failed")
                        .field("errorType", classify_runtime_error(&error))
                        .field("error", &error)
                        .field("elapsedMs", elapsed_ms(started)),
                )?;
                failures.push(format!("{candidate}: {error}"));
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
        settings.bypass_mark,
        &mut events,
        dialer_bound_override,
    );
    emit_events(ebus, events)?;
    let stream = stream?;
    http::execute_with_protocol(ebus, outbound, &settings.target, stream, protocol)
}

fn outbound_attempt_finished(
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

fn cascade_attempt_finished(
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
        .field("elapsedMs", elapsed_ms(started))
        .field("responseBytes", response.bytes);
    if let Some(status_code) = response.status_code {
        event = event.field("httpStatus", status_code);
    }
    event
}

fn success_reason(protocol: ProbeProtocol, response: &ProbeResponse) -> String {
    match (protocol, response.status_code) {
        (ProbeProtocol::HttpsHead, Some(status_code)) => {
            format!("HTTPS HEAD completed with HTTP {status_code}")
        }
        (ProbeProtocol::HttpsHead, None) => "HTTPS HEAD completed".to_string(),
        (ProbeProtocol::TlsHandshake, _) => "TLS handshake completed".to_string(),
    }
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

impl ProbeTarget {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.host.trim() != self.host || self.host.is_empty() {
            return Err("probe host must not be empty or padded".to_string());
        }
        if self.port == 0 {
            return Err("probe port must not be zero".to_string());
        }
        if !self.path.starts_with('/') {
            return Err("probe path must start with `/`".to_string());
        }
        Ok(())
    }

    pub(crate) fn address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    pub(crate) fn host_header(&self) -> String {
        if self.port == 443 {
            self.host.clone()
        } else {
            self.address()
        }
    }
}
