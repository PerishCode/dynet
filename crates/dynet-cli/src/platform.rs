#[path = "platform/command.rs"]
mod command;
#[path = "platform/desired.rs"]
mod desired;
#[path = "platform/probes.rs"]
mod probes;
#[path = "platform/resources.rs"]
mod resources;
#[path = "platform/takeover.rs"]
mod takeover;

use std::path::Path;

use dynet_core::{validate_config, ConfigDiagnostic, ConfigSummary, DynetConfig, Severity};
use serde::Serialize;

use crate::config::ConfigSource;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum LifecycleAction {
    Install,
    Status,
    Verify,
    Repair,
    Uninstall,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum LifecycleStatus {
    Pass,
    Warn,
    Deny,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LifecycleCheck {
    pub(crate) status: LifecycleStatus,
    pub(crate) name: String,
    pub(crate) message: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OwnedResource {
    pub(crate) kind: String,
    pub(crate) name: String,
    pub(crate) owned: bool,
    pub(crate) present: bool,
    pub(crate) detail: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DesiredState {
    pub(crate) schema: String,
    pub(crate) mutation_mode: String,
    pub(crate) takeover: takeover::TakeoverPlan,
    pub(crate) resources: Vec<DesiredResource>,
    pub(crate) artifacts: Vec<DesiredArtifact>,
    pub(crate) validations: Vec<DesiredValidation>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DesiredResource {
    pub(crate) kind: String,
    pub(crate) name: String,
    pub(crate) operation: String,
    pub(crate) detail: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DesiredArtifact {
    pub(crate) kind: String,
    pub(crate) name: String,
    pub(crate) target: String,
    pub(crate) content: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DesiredValidation {
    pub(crate) status: LifecycleStatus,
    pub(crate) name: String,
    pub(crate) artifact: String,
    pub(crate) message: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LifecycleReport {
    pub(crate) action: LifecycleAction,
    pub(crate) check_only: bool,
    pub(crate) root: Option<String>,
    pub(crate) config_source: Option<String>,
    pub(crate) summary: Option<ConfigSummary>,
    pub(crate) diagnostics: Vec<ConfigDiagnostic>,
    pub(crate) checks: Vec<LifecycleCheck>,
    pub(crate) resources: Vec<OwnedResource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) desired_state: Option<DesiredState>,
}

impl LifecycleReport {
    pub(crate) fn deny_count(&self) -> usize {
        self.checks
            .iter()
            .filter(|check| check.status == LifecycleStatus::Deny)
            .count()
            + self
                .diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.severity == Severity::Deny)
                .count()
    }

    pub(crate) fn warning_count(&self) -> usize {
        self.checks
            .iter()
            .filter(|check| check.status == LifecycleStatus::Warn)
            .count()
            + self
                .diagnostics
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

pub(crate) fn install_report(
    root: &Path,
    source: &ConfigSource,
    config: &DynetConfig,
    check_only: bool,
) -> LifecycleReport {
    let diagnostics = validate_config(config);
    let (takeover_config, takeover_checks) = takeover::load_config();
    let desired_state = desired::desired_state(&takeover_config);
    let mut checks = probes::install_checks(&diagnostics);
    checks.extend(takeover_checks);
    checks.push(LifecycleCheck {
        status: LifecycleStatus::Pass,
        name: "desired-state".to_string(),
        message: format!(
            "rendered {} owned resource target(s) and {} audit artifact(s); mutation disabled",
            desired_state.resources.len(),
            desired_state.artifacts.len()
        ),
    });
    checks.extend(
        desired_state
            .validations
            .iter()
            .map(|validation| LifecycleCheck {
                status: validation.status,
                name: format!("artifact:{}", validation.name),
                message: format!("{} - {}", validation.artifact, validation.message),
            }),
    );
    checks.push(apply_engine_check(check_only));

    LifecycleReport {
        action: LifecycleAction::Install,
        check_only,
        root: Some(root.display().to_string()),
        config_source: Some(source_label(source)),
        summary: Some(config.summary()),
        diagnostics,
        checks,
        resources: resources::owned_resources(&takeover_config),
        desired_state: Some(desired_state),
    }
}

pub(crate) fn status_report(action: LifecycleAction) -> LifecycleReport {
    let (takeover_config, takeover_checks) = takeover::load_config();
    let resources = resources::owned_resources(&takeover_config);
    let any_present = resources.iter().any(|resource| resource.present);
    let mut checks = takeover_checks;
    checks.extend(probes::status_checks(action, any_present, &takeover_config));

    if matches!(action, LifecycleAction::Repair | LifecycleAction::Uninstall) && !any_present {
        checks.push(LifecycleCheck {
            status: LifecycleStatus::Pass,
            name: "noop".to_string(),
            message: "system is already free of dynet-owned resources".to_string(),
        });
    }

    LifecycleReport {
        action,
        check_only: true,
        root: None,
        config_source: None,
        summary: None,
        diagnostics: Vec::new(),
        checks,
        resources,
        desired_state: None,
    }
}

fn apply_engine_check(check_only: bool) -> LifecycleCheck {
    LifecycleCheck {
        status: if check_only {
            LifecycleStatus::Pass
        } else {
            LifecycleStatus::Deny
        },
        name: "apply-engine".to_string(),
        message: if check_only {
            "install --check validates desired state without mutating network paths".to_string()
        } else {
            "network apply is intentionally gated in this first platform slice; run install --check"
                .to_string()
        },
    }
}

fn source_label(source: &ConfigSource) -> String {
    match source {
        ConfigSource::Explicit(path) => format!("explicit:{}", path.display()),
        ConfigSource::Discovered(path) => format!("discovered:{}", path.display()),
        ConfigSource::BuiltIn => "built-in".to_string(),
    }
}
