use std::path::PathBuf;

use dynet_core::{validate_config, ConfigDiagnostic, ConfigSummary, DynetConfig, Severity};
use serde::Serialize;

use crate::config::ConfigSource;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ReportMode {
    Check,
    Run,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Report {
    pub(crate) mode: ReportMode,
    pub(crate) root: String,
    pub(crate) config_source: String,
    pub(crate) summary: ConfigSummary,
    pub(crate) diagnostics: Vec<ConfigDiagnostic>,
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

fn source_label(source: &ConfigSource) -> String {
    match source {
        ConfigSource::Explicit(path) => format!("explicit:{}", path.display()),
        ConfigSource::Discovered(path) => format!("discovered:{}", path.display()),
        ConfigSource::BuiltIn => "built-in".to_string(),
    }
}
