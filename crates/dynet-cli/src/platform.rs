use std::{
    env,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use dynet_core::{validate_config, ConfigDiagnostic, ConfigSummary, DynetConfig, Severity};
use serde::Serialize;

use crate::config::ConfigSource;

const NFT_TABLE: &str = "inet dynet";
const TUN_NAME: &str = "dynet0";
const ROUTE_MARK: &str = "0xd1e7";
const ROUTE_TABLE: &str = "61777";
const DNS_PORT: &str = "1053";
const DNS_LISTEN: &str = "127.0.0.1:1053";
const RUNTIME_DIR: &str = "/run/dynet";
const STATE_DIR: &str = "/var/lib/dynet";

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
    pub(crate) resources: Vec<DesiredResource>,
    pub(crate) artifacts: Vec<DesiredArtifact>,
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
    let mut checks = vec![
        config_check(&diagnostics),
        platform_check(),
        root_check(),
        command_check("nft", "nftables atomic ruleset loading"),
        command_check("ip", "policy route and tun visibility"),
        tun_check(),
        resolver_check(),
    ];
    let desired_state = desired_state();
    checks.push(LifecycleCheck {
        status: LifecycleStatus::Pass,
        name: "desired-state".to_string(),
        message: format!(
            "rendered {} owned resource target(s) and {} audit artifact(s); mutation disabled",
            desired_state.resources.len(),
            desired_state.artifacts.len()
        ),
    });
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
        desired_state: Some(desired_state),
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
        message: format!(
            "owned scope is {nft_table}, tun {tun_name}, fwmark {route_mark}, route table {route_table}",
            nft_table = NFT_TABLE,
            route_mark = ROUTE_MARK,
            route_table = ROUTE_TABLE,
            tun_name = TUN_NAME
        ),
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
        desired_state: None,
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
            name: NFT_TABLE.to_string(),
            owned: true,
            present: command_status("nft", &["list", "table", "inet", "dynet"]),
            detail: "exclusive dynet nftables table".to_string(),
        },
        OwnedResource {
            kind: "tun".to_string(),
            name: TUN_NAME.to_string(),
            owned: true,
            present: Path::new("/sys/class/net").join(TUN_NAME).exists(),
            detail: "dynet-owned tun interface".to_string(),
        },
        OwnedResource {
            kind: "ip-rule".to_string(),
            name: format!("fwmark {ROUTE_MARK}"),
            owned: true,
            present: command_stdout("ip", &["rule", "show"])
                .map(|output| output.contains(ROUTE_MARK))
                .unwrap_or(false),
            detail: "dynet-owned packet mark".to_string(),
        },
        OwnedResource {
            kind: "route-table".to_string(),
            name: ROUTE_TABLE.to_string(),
            owned: true,
            present: command_stdout("ip", &["route", "show", "table", ROUTE_TABLE])
                .map(|output| !output.trim().is_empty())
                .unwrap_or(false),
            detail: "dynet policy route table".to_string(),
        },
        OwnedResource {
            kind: "runtime-dir".to_string(),
            name: RUNTIME_DIR.to_string(),
            owned: true,
            present: Path::new(RUNTIME_DIR).exists(),
            detail: "runtime state directory".to_string(),
        },
        OwnedResource {
            kind: "state-dir".to_string(),
            name: STATE_DIR.to_string(),
            owned: true,
            present: Path::new(STATE_DIR).exists(),
            detail: "persistent dynet state directory".to_string(),
        },
    ]
}

fn desired_state() -> DesiredState {
    DesiredState {
        schema: "dynet-platform/v1alpha1".to_string(),
        mutation_mode: "render-only".to_string(),
        resources: vec![
            DesiredResource {
                kind: "nft-table".to_string(),
                name: NFT_TABLE.to_string(),
                operation: "create-or-replace".to_string(),
                detail: "exclusive dynet nftables table for DNS interception hooks".to_string(),
            },
            DesiredResource {
                kind: "tun".to_string(),
                name: TUN_NAME.to_string(),
                operation: "create-or-reuse-owned".to_string(),
                detail: "tun-only packet ingress owned by dynet runtime".to_string(),
            },
            DesiredResource {
                kind: "dns-listener".to_string(),
                name: DNS_LISTEN.to_string(),
                operation: "bind-loopback".to_string(),
                detail: "local DNS ingress target for nft redirect templates".to_string(),
            },
            DesiredResource {
                kind: "ip-rule".to_string(),
                name: format!("fwmark {ROUTE_MARK}"),
                operation: "reserve".to_string(),
                detail: format!("policy rule priority {ROUTE_TABLE} for dynet-marked traffic"),
            },
            DesiredResource {
                kind: "route-table".to_string(),
                name: ROUTE_TABLE.to_string(),
                operation: "reserve".to_string(),
                detail: format!("route table for {TUN_NAME} policy routing"),
            },
            DesiredResource {
                kind: "runtime-dir".to_string(),
                name: RUNTIME_DIR.to_string(),
                operation: "create-owned".to_string(),
                detail: "ephemeral runtime state".to_string(),
            },
            DesiredResource {
                kind: "state-dir".to_string(),
                name: STATE_DIR.to_string(),
                operation: "create-owned".to_string(),
                detail: "persistent dynet state".to_string(),
            },
        ],
        artifacts: vec![
            DesiredArtifact {
                kind: "nftables".to_string(),
                name: "dynet.nft".to_string(),
                target: "nft -f -".to_string(),
                content: nftables_template(),
            },
            DesiredArtifact {
                kind: "iproute2".to_string(),
                name: "dynet-link-route.sh".to_string(),
                target: "root shell".to_string(),
                content: link_route_template(),
            },
            DesiredArtifact {
                kind: "resolver".to_string(),
                name: "dynet-resolver-ownership.txt".to_string(),
                target: "/etc/resolv.conf and local resolver manager".to_string(),
                content: resolver_template(),
            },
        ],
    }
}

fn nftables_template() -> String {
    format!(
        r#"table inet dynet {{
  chain prerouting_dns {{
    type nat hook prerouting priority dstnat; policy accept;
    meta mark {route_mark} accept comment "dynet-owned bypass"
    udp dport 53 redirect to :{dns_port} comment "dynet DNS hijack"
    tcp dport 53 redirect to :{dns_port} comment "dynet DNS hijack"
  }}

  chain output_dns {{
    type nat hook output priority dstnat; policy accept;
    meta mark {route_mark} accept comment "dynet-owned bypass"
    udp dport 53 redirect to :{dns_port} comment "dynet local DNS hijack"
    tcp dport 53 redirect to :{dns_port} comment "dynet local DNS hijack"
  }}
}}
"#,
        dns_port = DNS_PORT,
        route_mark = ROUTE_MARK
    )
}

fn link_route_template() -> String {
    format!(
        r#"#!/bin/sh
set -eu

if ! ip link show dev {tun_name} >/dev/null 2>&1; then
  ip tuntap add dev {tun_name} mode tun
fi
ip link set dev {tun_name} up
if ! ip rule show | grep -q 'fwmark {route_mark}.*lookup {route_table}'; then
  ip rule add fwmark {route_mark} lookup {route_table} priority {route_table}
fi
ip route replace default dev {tun_name} table {route_table}
"#,
        route_mark = ROUTE_MARK,
        route_table = ROUTE_TABLE,
        tun_name = TUN_NAME
    )
}

fn resolver_template() -> String {
    format!(
        r#"dynet DNS ownership contract

- dynet owns normal TCP/UDP port 53 interception through nft table {nft_table}.
- redirected DNS traffic lands on {dns_listen}.
- dynet must snapshot the previous resolver state before any future mutation.
- dynet uninstall must restore only the resolver state that dynet previously owned.
- mutation is disabled in this render-only slice.
"#,
        dns_listen = DNS_LISTEN,
        nft_table = NFT_TABLE
    )
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
