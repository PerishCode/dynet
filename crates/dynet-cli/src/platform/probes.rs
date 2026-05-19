use std::path::Path;

use dynet_core::{ConfigDiagnostic, Severity};

use super::{
    command::{command_exists, current_uid},
    LifecycleAction, LifecycleCheck, LifecycleStatus, NFT_TABLE, ROUTE_MARK, ROUTE_TABLE, TUN_NAME,
};

pub(super) fn install_checks(diagnostics: &[ConfigDiagnostic]) -> Vec<LifecycleCheck> {
    vec![
        config_check(diagnostics),
        platform_check(),
        root_check(),
        command_check("nft", "nftables atomic ruleset loading"),
        command_check("ip", "policy route and tun visibility"),
        tun_check(),
        resolver_check(),
    ]
}

pub(super) fn status_checks(action: LifecycleAction, any_present: bool) -> Vec<LifecycleCheck> {
    vec![
        LifecycleCheck {
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
        },
        LifecycleCheck {
            status: LifecycleStatus::Pass,
            name: "ownership-scope".to_string(),
            message: format!(
                "owned scope is {NFT_TABLE}, tun {TUN_NAME}, fwmark {ROUTE_MARK}, route table {ROUTE_TABLE}"
            ),
        },
    ]
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
    let uid = current_uid().unwrap_or_default();
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
