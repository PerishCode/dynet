use std::{
    env,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

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
    let mut checks = Vec::new();
    checks.push(config_check(&diagnostics));
    checks.push(platform_check());
    checks.push(root_check());
    checks.push(command_check("nft", "nftables atomic ruleset loading"));
    checks.push(command_check("ip", "policy route and tun visibility"));
    checks.push(tun_check());
    checks.push(resolver_check());
    checks.push(LifecycleCheck {
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
    });

    LifecycleReport {
        action: LifecycleAction::Install,
        check_only,
        root: Some(root.display().to_string()),
        config_source: Some(source_label(source)),
        summary: Some(config.summary()),
        diagnostics,
        checks,
        resources: owned_resources(),
    }
}

pub(crate) fn status_report(action: LifecycleAction) -> LifecycleReport {
    let resources = owned_resources();
    let any_present = resources.iter().any(|resource| resource.present);
    let mut checks = Vec::new();
    checks.push(LifecycleCheck {
        status: match action {
            LifecycleAction::Verify if any_present => LifecycleStatus::Deny,
            LifecycleAction::Repair | LifecycleAction::Uninstall if any_present => {
                LifecycleStatus::Deny
            }
            _ => LifecycleStatus::Pass,
        },
        name: "owned-resources".to_string(),
        message: if any_present {
            "dynet-owned resources are present; cleanup/apply reconciliation is not enabled yet"
                .to_string()
        } else {
            "no dynet-owned network resources are present".to_string()
        },
    });
    checks.push(LifecycleCheck {
        status: LifecycleStatus::Pass,
        name: "ownership-scope".to_string(),
        message: "owned scope is inet table dynet, tun dynet0, fwmark 0xd1e7, route table 61777"
            .to_string(),
    });
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
    }
}

fn config_check(diagnostics: &[ConfigDiagnostic]) -> LifecycleCheck {
    let deny_count = diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.severity == Severity::Deny)
        .count();
    let warning_count = diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.severity == Severity::Warning)
        .count();
    LifecycleCheck {
        status: if deny_count > 0 {
            LifecycleStatus::Deny
        } else if warning_count > 0 {
            LifecycleStatus::Warn
        } else {
            LifecycleStatus::Pass
        },
        name: "config".to_string(),
        message: format!("{deny_count} deny issue(s), {warning_count} warning(s)"),
    }
}

fn platform_check() -> LifecycleCheck {
    let os = std::env::consts::OS;
    LifecycleCheck {
        status: if os == "linux" {
            LifecycleStatus::Pass
        } else {
            LifecycleStatus::Warn
        },
        name: "platform".to_string(),
        message: if os == "linux" {
            "linux platform detected".to_string()
        } else {
            format!("network ownership apply must run inside a linux VM, current OS is {os}")
        },
    }
}

fn root_check() -> LifecycleCheck {
    let uid = command_stdout("id", &["-u"]).unwrap_or_default();
    LifecycleCheck {
        status: if uid.trim() == "0" {
            LifecycleStatus::Pass
        } else {
            LifecycleStatus::Warn
        },
        name: "privilege".to_string(),
        message: if uid.trim() == "0" {
            "running as root".to_string()
        } else {
            "install apply will require root; check mode can run unprivileged".to_string()
        },
    }
}

fn command_check(command: &str, purpose: &str) -> LifecycleCheck {
    let available = command_exists(command);
    LifecycleCheck {
        status: if available {
            LifecycleStatus::Pass
        } else {
            LifecycleStatus::Warn
        },
        name: format!("tool:{command}"),
        message: if available {
            format!("{command} available for {purpose}")
        } else {
            format!("{command} missing; required for {purpose}")
        },
    }
}

fn tun_check() -> LifecycleCheck {
    let present = Path::new("/dev/net/tun").exists();
    LifecycleCheck {
        status: if present {
            LifecycleStatus::Pass
        } else {
            LifecycleStatus::Warn
        },
        name: "tun".to_string(),
        message: if present {
            "/dev/net/tun is present".to_string()
        } else {
            "/dev/net/tun is missing or not visible".to_string()
        },
    }
}

fn resolver_check() -> LifecycleCheck {
    let present = Path::new("/etc/resolv.conf").exists();
    LifecycleCheck {
        status: if present {
            LifecycleStatus::Pass
        } else {
            LifecycleStatus::Warn
        },
        name: "resolver".to_string(),
        message: if present {
            "/etc/resolv.conf is present".to_string()
        } else {
            "/etc/resolv.conf is missing or not visible".to_string()
        },
    }
}

fn owned_resources() -> Vec<OwnedResource> {
    vec![
        OwnedResource {
            kind: "nft-table".to_string(),
            name: "inet dynet".to_string(),
            owned: true,
            present: command_status("nft", &["list", "table", "inet", "dynet"]),
            detail: "exclusive dynet nftables table".to_string(),
        },
        OwnedResource {
            kind: "tun".to_string(),
            name: "dynet0".to_string(),
            owned: true,
            present: Path::new("/sys/class/net/dynet0").exists(),
            detail: "dynet-owned tun interface".to_string(),
        },
        OwnedResource {
            kind: "ip-rule".to_string(),
            name: "fwmark 0xd1e7".to_string(),
            owned: true,
            present: command_stdout("ip", &["rule", "show"])
                .map(|output| output.contains("0xd1e7"))
                .unwrap_or(false),
            detail: "dynet-owned outbound bypass mark".to_string(),
        },
        OwnedResource {
            kind: "route-table".to_string(),
            name: "61777".to_string(),
            owned: true,
            present: command_stdout("ip", &["route", "show", "table", "61777"])
                .map(|output| !output.trim().is_empty())
                .unwrap_or(false),
            detail: "dynet policy route table".to_string(),
        },
        OwnedResource {
            kind: "runtime-dir".to_string(),
            name: "/run/dynet".to_string(),
            owned: true,
            present: Path::new("/run/dynet").exists(),
            detail: "runtime state directory".to_string(),
        },
        OwnedResource {
            kind: "state-dir".to_string(),
            name: "/var/lib/dynet".to_string(),
            owned: true,
            present: Path::new("/var/lib/dynet").exists(),
            detail: "persistent dynet state directory".to_string(),
        },
    ]
}

fn command_exists(command: &str) -> bool {
    if command.contains(std::path::MAIN_SEPARATOR) {
        return Path::new(command).is_file();
    }
    env::var_os("PATH")
        .map(|paths| {
            env::split_paths(&paths)
                .map(|path| path.join(command))
                .any(|candidate: PathBuf| candidate.is_file())
        })
        .unwrap_or(false)
}

fn command_status(command: &str, args: &[&str]) -> bool {
    Command::new(command)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn command_stdout(command: &str, args: &[&str]) -> Option<String> {
    Command::new(command)
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
}

fn source_label(source: &ConfigSource) -> String {
    match source {
        ConfigSource::Explicit(path) => format!("explicit:{}", path.display()),
        ConfigSource::Discovered(path) => format!("discovered:{}", path.display()),
        ConfigSource::BuiltIn => "built-in".to_string(),
    }
}
