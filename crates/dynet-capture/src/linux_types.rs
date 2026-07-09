use std::{path::PathBuf, process::Command};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TakeoverReport {
    pub checks: Vec<TakeoverCheck>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TakeoverStatus {
    pub doctor: TakeoverReport,
    pub runtime: Vec<TakeoverCheck>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TakeoverPlan {
    pub items: Vec<TakeoverPlanItem>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TakeoverPlanItem {
    pub id: &'static str,
    pub phase: PlanPhase,
    pub action: String,
    pub safety: PlanSafety,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PlanPhase {
    IsolatedFragments,
    RuntimeSkeleton,
    VmOnlyCapture,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PlanSafety {
    LocalSafe,
    VmOnly,
    DecisionBlocked,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TakeoverCheck {
    pub id: &'static str,
    pub label: &'static str,
    pub path: Option<PathBuf>,
    pub state: CheckState,
    pub auto_action: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CheckState {
    Ready,
    MissingAutoCreatable,
    MissingHardFail,
    InvalidHardFail,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ApplyOptions {
    pub auto: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ApplyReport {
    pub status: TakeoverReport,
    pub created: Vec<PathBuf>,
    pub runtime_actions: Vec<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CleanupReport {
    pub removed: Vec<PathBuf>,
    pub runtime_actions: Vec<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CommandOutput {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

pub trait SystemRunner {
    fn run(&self, command: &str, args: &[&str]) -> Result<CommandOutput, String>;
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct HostRunner;

impl SystemRunner for HostRunner {
    fn run(&self, command: &str, args: &[&str]) -> Result<CommandOutput, String> {
        let output = Command::new(command)
            .args(args)
            .output()
            .map_err(|error| format!("failed running {command}: {error}"))?;
        Ok(CommandOutput {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }
}

impl TakeoverReport {
    pub fn ready(&self) -> bool {
        self.checks
            .iter()
            .all(|check| matches!(check.state, CheckState::Ready))
    }

    pub fn has_hard_failures(&self) -> bool {
        self.checks.iter().any(TakeoverCheck::is_hard_failure)
    }

    pub fn needs_auto(&self) -> bool {
        self.checks
            .iter()
            .any(|check| matches!(check.state, CheckState::MissingAutoCreatable))
    }

    pub fn failure_summary(&self) -> String {
        let failures = self
            .checks
            .iter()
            .filter(|check| check.is_hard_failure())
            .map(TakeoverCheck::summary)
            .collect::<Vec<_>>();
        if failures.is_empty() {
            return "dynet takeover has no hard failures".to_string();
        }
        format!("dynet takeover hard fail: {}", failures.join("; "))
    }
}

impl TakeoverStatus {
    pub fn has_hard_failures(&self) -> bool {
        self.doctor.has_hard_failures()
    }
}

impl TakeoverCheck {
    pub fn is_hard_failure(&self) -> bool {
        matches!(
            self.state,
            CheckState::MissingHardFail | CheckState::InvalidHardFail
        )
    }

    pub fn summary(&self) -> String {
        let path = self
            .path
            .as_ref()
            .map(|path| format!(" ({})", path.display()))
            .unwrap_or_default();
        format!("{}={}{}", self.id, self.state.label(), path)
    }
}

impl CheckState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::MissingAutoCreatable => "missing-auto-creatable",
            Self::MissingHardFail => "missing-hard-fail",
            Self::InvalidHardFail => "invalid-hard-fail",
        }
    }
}

impl PlanPhase {
    pub fn label(self) -> &'static str {
        match self {
            Self::IsolatedFragments => "isolated-fragments",
            Self::RuntimeSkeleton => "runtime-skeleton",
            Self::VmOnlyCapture => "vm-only-capture",
        }
    }
}

impl PlanSafety {
    pub fn label(self) -> &'static str {
        match self {
            Self::LocalSafe => "local-safe",
            Self::VmOnly => "vm-only",
            Self::DecisionBlocked => "decision-blocked",
        }
    }
}
