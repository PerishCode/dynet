use std::path::PathBuf;

use std::path::Path;

use dynet_core::{
    build_plan, validate_config, AppState, ConfigDiagnostic, ConfigSummary, DynetConfig,
    NetworkModel, Plan, PlanSummary, Severity,
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
    pub(crate) diagnostics: Vec<ConfigDiagnostic>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DoctorReport {
    pub(crate) root: String,
    pub(crate) config_source: String,
    pub(crate) summary: ConfigSummary,
    pub(crate) network: NetworkModel,
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
        checks.push(DoctorCheck {
            status: DoctorStatus::Pass,
            name: "network-model".to_string(),
            message: format!(
                "{} inbound model(s), {} outbound model(s)",
                network.inbounds.len(),
                network.outbounds.len()
            ),
        });
        checks.extend(environment_checks());

        Self {
            root: root.as_ref().display().to_string(),
            config_source: source_label(source),
            summary: config.summary(),
            network,
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
    ) -> Self {
        let state = AppState::from_config(config.clone());
        let plan = build_plan(&state);
        Self {
            root: root.as_ref().display().to_string(),
            config_source: source_label(source),
            summary: state.summary(),
            plan_summary: plan.summary(),
            diagnostics: validate_config(config),
            plan,
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
