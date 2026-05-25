use std::path::{Path, PathBuf};

use dynet_core::{
    build_plan, dialer_payload, resolve_outbound_path, validate_config, AppState, ConfigDiagnostic,
    ConfigSummary, DnsModel, DnsReverseIndex, DynetConfig, InboundContext, NetworkModel,
    OutboundPath, OutboundQualityPlannerFeedback, OutboundQualitySignal, OutboundQualityState,
    Plan, PlanAction, PlanSummary, QualityScope, Severity, Verdict,
};
use serde::Serialize;

use crate::config::ConfigSource;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ReportMode {
    Check,
    Run,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum DoctorStatus {
    Pass,
    Warn,
    Deny,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DoctorCheck {
    pub(crate) status: DoctorStatus,
    pub(crate) name: String,
    pub(crate) message: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Report {
    pub(crate) mode: ReportMode,
    pub(crate) root: String,
    pub(crate) config_source: String,
    pub(crate) summary: ConfigSummary,
    pub(crate) network: NetworkModel,
    pub(crate) dns: DnsModel,
    pub(crate) diagnostics: Vec<ConfigDiagnostic>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DoctorReport {
    pub(crate) root: String,
    pub(crate) config_source: String,
    pub(crate) summary: ConfigSummary,
    pub(crate) network: NetworkModel,
    pub(crate) dns: DnsModel,
    pub(crate) diagnostics: Vec<ConfigDiagnostic>,
    pub(crate) checks: Vec<DoctorCheck>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PlanReport {
    pub(crate) root: String,
    pub(crate) config_source: String,
    pub(crate) summary: ConfigSummary,
    pub(crate) plan_summary: PlanSummary,
    pub(crate) diagnostics: Vec<ConfigDiagnostic>,
    pub(crate) plan: Plan,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) verdict: Option<Verdict>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) outbound_path: Option<OutboundPath>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) dialer_bound_path: Option<OutboundPath>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) quality_feedback: Option<PlanQualityFeedback>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) quality_signals: Vec<PlanQualitySignal>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PlanQualityFeedback {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) requested_mode: Option<String>,
    pub(crate) penalty_observations: u32,
    pub(crate) fallback_signals: u32,
    pub(crate) recovered_fallback_signals: u32,
    pub(crate) non_retry_safe_fallback_signals: u32,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PlanQualitySignal {
    #[serde(rename = "type")]
    pub(crate) signal_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) fallback_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) failed_bound: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) recovered_bound: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) replay_safe: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) flow_id: Option<String>,
}

pub(crate) struct PlanEvaluationInput {
    pub(crate) context: InboundContext,
    pub(crate) dns_reverse: DnsReverseIndex,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ApiCapabilityReport {
    pub(crate) schema: String,
    pub(crate) default_bind: String,
    pub(crate) capabilities: Vec<ApiCapability>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ApiCapability {
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) purpose: String,
}

impl Report {
    pub(crate) fn from_config(
        mode: ReportMode,
        root: PathBuf,
        source: &ConfigSource,
        config: &DynetConfig,
    ) -> Self {
        Self {
            mode,
            root: root.display().to_string(),
            config_source: source_label(source),
            summary: config.summary(),
            network: config.network_model(),
            dns: config.dns_model(),
            diagnostics: validate_config(config),
        }
    }

    pub(crate) fn deny_count(&self) -> usize {
        self.diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.severity == Severity::Deny)
            .count()
    }

    pub(crate) fn warning_count(&self) -> usize {
        self.diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.severity == Severity::Warning)
            .count()
    }

    pub(crate) fn exit_code(&self) -> i32 {
        if self.deny_count() > 0 {
            1
        } else {
            0
        }
    }
}

impl DoctorReport {
    pub(crate) fn from_config(
        root: impl AsRef<Path>,
        source: &ConfigSource,
        config: &DynetConfig,
    ) -> Self {
        let diagnostics = validate_config(config);
        let mut checks = Vec::new();
        checks.push(DoctorCheck {
            status: if diagnostics
                .iter()
                .any(|diagnostic| diagnostic.severity == Severity::Deny)
            {
                DoctorStatus::Deny
            } else {
                DoctorStatus::Pass
            },
            name: "config".to_string(),
            message: format!(
                "{} deny issue(s), {} warning(s)",
                diagnostics
                    .iter()
                    .filter(|diagnostic| diagnostic.severity == Severity::Deny)
                    .count(),
                diagnostics
                    .iter()
                    .filter(|diagnostic| diagnostic.severity == Severity::Warning)
                    .count()
            ),
        });
        checks.push(DoctorCheck {
            status: if matches!(source, ConfigSource::BuiltIn) {
                DoctorStatus::Warn
            } else {
                DoctorStatus::Pass
            },
            name: "config-source".to_string(),
            message: source_label(source),
        });
        checks.push(DoctorCheck {
            status: if config.routes.is_empty() {
                DoctorStatus::Warn
            } else {
                DoctorStatus::Pass
            },
            name: "plan".to_string(),
            message: if config.routes.is_empty() {
                "no explicit route rules yet".to_string()
            } else {
                format!("{} explicit route rule(s)", config.routes.len())
            },
        });
        let network = config.network_model();
        let dns = config.dns_model();
        checks.push(DoctorCheck {
            status: DoctorStatus::Pass,
            name: "network-model".to_string(),
            message: format!(
                "{} inbound model(s), {} outbound model(s)",
                network.inbounds.len(),
                network.outbounds.len()
            ),
        });
        checks.push(DoctorCheck {
            status: DoctorStatus::Pass,
            name: "dns-model".to_string(),
            message: format!("{} DNS chain(s)", dns.chains.len()),
        });
        checks.extend(environment_checks());

        Self {
            root: root.as_ref().display().to_string(),
            config_source: source_label(source),
            summary: config.summary(),
            network,
            dns,
            diagnostics,
            checks,
        }
    }

    pub(crate) fn exit_code(&self) -> i32 {
        if self
            .checks
            .iter()
            .any(|check| check.status == DoctorStatus::Deny)
        {
            1
        } else {
            0
        }
    }

    pub(crate) fn status_count(&self, status: DoctorStatus) -> usize {
        self.checks
            .iter()
            .filter(|check| check.status == status)
            .count()
    }
}

impl PlanReport {
    pub(crate) fn from_config(
        root: impl AsRef<Path>,
        source: &ConfigSource,
        config: &DynetConfig,
        evaluation: Option<PlanEvaluationInput>,
        quality: Option<OutboundQualityState>,
    ) -> Self {
        let mut state = AppState::from_config(config.clone());
        let quality_feedback = quality
            .as_ref()
            .and_then(|quality| quality.planner_feedback.as_ref())
            .map(PlanQualityFeedback::from);
        let quality_signals = quality
            .as_ref()
            .map(|quality| {
                quality
                    .signals
                    .iter()
                    .map(PlanQualitySignal::from)
                    .collect()
            })
            .unwrap_or_default();
        if let Some(quality) = quality {
            state = state.with_quality(quality);
        }
        if let Some(evaluation) = &evaluation {
            state = state.with_dns_reverse(evaluation.dns_reverse.clone());
        }
        let plan = build_plan(&state);
        let verdict = evaluation
            .as_ref()
            .map(|evaluation| plan.evaluate(&evaluation.context, &state));
        let outbound_path = evaluation
            .as_ref()
            .and_then(|evaluation| outbound_path(&state, &evaluation.context, &verdict));
        let dialer_bound_path = evaluation
            .as_ref()
            .and_then(|evaluation| dialer_bound_path(&state, &evaluation.context, &verdict));
        Self {
            root: root.as_ref().display().to_string(),
            config_source: source_label(source),
            summary: state.summary(),
            plan_summary: plan.summary(),
            diagnostics: validate_config(config),
            plan,
            verdict,
            outbound_path,
            dialer_bound_path,
            quality_feedback,
            quality_signals,
        }
    }

    pub(crate) fn deny_count(&self) -> usize {
        self.diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.severity == Severity::Deny)
            .count()
    }

    pub(crate) fn warning_count(&self) -> usize {
        self.diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.severity == Severity::Warning)
            .count()
    }

    pub(crate) fn exit_code(&self) -> i32 {
        if self.deny_count() > 0 {
            1
        } else {
            0
        }
    }
}

impl From<&OutboundQualityPlannerFeedback> for PlanQualityFeedback {
    fn from(feedback: &OutboundQualityPlannerFeedback) -> Self {
        Self {
            mode: feedback.mode.clone(),
            requested_mode: feedback.requested_mode.clone(),
            penalty_observations: feedback.penalty_observations,
            fallback_signals: feedback.fallback_signals,
            recovered_fallback_signals: feedback.recovered_fallback_signals,
            non_retry_safe_fallback_signals: feedback.non_retry_safe_fallback_signals,
        }
    }
}

impl From<&OutboundQualitySignal> for PlanQualitySignal {
    fn from(signal: &OutboundQualitySignal) -> Self {
        Self {
            signal_type: signal.signal_type.clone(),
            action: signal.action.clone(),
            fallback_type: signal.fallback_type.clone(),
            failed_bound: signal.failed_bound.clone(),
            recovered_bound: signal.recovered_bound.clone(),
            replay_safe: signal.replay_safe.clone(),
            flow_id: signal.flow_id.clone(),
        }
    }
}

fn outbound_path(
    state: &AppState,
    context: &InboundContext,
    verdict: &Option<Verdict>,
) -> Option<OutboundPath> {
    let tag = match &verdict.as_ref()?.action {
        PlanAction::UseOutbound { tag } => tag,
        PlanAction::Reject | PlanAction::NoRoute => return None,
    };
    resolve_outbound_path(state, context, tag).ok()
}

fn dialer_bound_path(
    state: &AppState,
    context: &InboundContext,
    verdict: &Option<Verdict>,
) -> Option<OutboundPath> {
    let tag = match &verdict.as_ref()?.action {
        PlanAction::UseOutbound { tag } => tag,
        PlanAction::Reject | PlanAction::NoRoute => return None,
    };
    let outbound = state
        .config
        .outbounds
        .iter()
        .find(|outbound| outbound.tag == *tag)?;
    if outbound.kind != "dialer" {
        return None;
    }
    let payload = dialer_payload(outbound).ok()?;
    let bound_context = context
        .clone()
        .with_quality_scope(QualityScope::DialerBound);
    resolve_outbound_path(state, &bound_context, &payload.bound).ok()
}

impl ApiCapabilityReport {
    pub(crate) fn current() -> Self {
        Self {
            schema: "dynet-api/v1alpha1".to_string(),
            default_bind: "127.0.0.1:9977".to_string(),
            capabilities: vec![
                ApiCapability {
                    method: "GET".to_string(),
                    path: "/health".to_string(),
                    purpose: "local process health".to_string(),
                },
                ApiCapability {
                    method: "GET".to_string(),
                    path: "/v1/capabilities".to_string(),
                    purpose: "API capability discovery".to_string(),
                },
            ],
        }
    }
}

fn environment_checks() -> Vec<DoctorCheck> {
    let os = std::env::consts::OS;
    let mut checks = vec![
        DoctorCheck {
            status: if os == "linux" {
                DoctorStatus::Pass
            } else {
                DoctorStatus::Warn
            },
            name: "platform".to_string(),
            message: if os == "linux" {
                "linux platform detected".to_string()
            } else {
                format!("tun/dns experiments should run inside a linux VM, current OS is {os}")
            },
        },
        DoctorCheck {
            status: DoctorStatus::Pass,
            name: "api-bind".to_string(),
            message: "default API bind is loopback-only at 127.0.0.1:9977".to_string(),
        },
    ];

    if os == "linux" {
        checks.push(DoctorCheck {
            status: if Path::new("/dev/net/tun").exists() {
                DoctorStatus::Pass
            } else {
                DoctorStatus::Warn
            },
            name: "tun".to_string(),
            message: if Path::new("/dev/net/tun").exists() {
                "/dev/net/tun is present".to_string()
            } else {
                "/dev/net/tun is missing or not visible".to_string()
            },
        });
        checks.push(DoctorCheck {
            status: if Path::new("/etc/resolv.conf").exists() {
                DoctorStatus::Pass
            } else {
                DoctorStatus::Warn
            },
            name: "resolver".to_string(),
            message: if Path::new("/etc/resolv.conf").exists() {
                "/etc/resolv.conf is present; DNS ownership still needs explicit runtime plan"
                    .to_string()
            } else {
                "/etc/resolv.conf is missing or not visible".to_string()
            },
        });
    }

    checks
}

fn source_label(source: &ConfigSource) -> String {
    match source {
        ConfigSource::Explicit(path) => format!("explicit:{}", path.display()),
        ConfigSource::Discovered(path) => format!("discovered:{}", path.display()),
        ConfigSource::BuiltIn => "built-in".to_string(),
    }
}
