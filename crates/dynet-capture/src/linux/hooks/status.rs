use super::*;

#[derive(Debug, Clone, Copy)]
pub(crate) enum IpVersion {
    V4,
    V6,
}

impl IpVersion {
    pub(super) fn flag(self) -> &'static str {
        match self {
            Self::V4 => "-4",
            Self::V6 => "-6",
        }
    }

    pub(super) fn label(self) -> &'static str {
        match self {
            Self::V4 => "IPv4",
            Self::V6 => "IPv6",
        }
    }

    fn route_check_id(self) -> &'static str {
        match self {
            Self::V4 => "route.table.ipv4.default",
            Self::V6 => "route.table.ipv6.default",
        }
    }

    fn rule_check_id(self) -> &'static str {
        match self {
            Self::V4 => "route.rule.ipv4.mark",
            Self::V6 => "route.rule.ipv6.mark",
        }
    }
}

pub(crate) fn family_status(runner: &impl SystemRunner, family: IpVersion) -> Vec<TakeoverCheck> {
    vec![route_status(runner, family), rule_status(runner, family)]
}

pub(crate) fn route_status(runner: &impl SystemRunner, family: IpVersion) -> TakeoverCheck {
    let output = runner.run(
        "ip",
        &[family.flag(), "route", "show", "table", ROUTE_TABLE],
    );
    owned_command_check(
        family.route_check_id(),
        match family {
            IpVersion::V4 => "dynet IPv4 policy route default",
            IpVersion::V6 => "dynet IPv6 policy route default",
        },
        output,
        |stdout| {
            let lines = stdout.lines().collect::<Vec<_>>();
            lines.len() == 1 && lines[0].starts_with("default dev dynet0")
        },
        "route marked traffic to dynet0",
    )
}

pub(crate) fn rule_status(runner: &impl SystemRunner, family: IpVersion) -> TakeoverCheck {
    let output = runner.run(
        "ip",
        &[family.flag(), "rule", "show", "pref", RULE_PRIORITY],
    );
    owned_command_check(
        family.rule_check_id(),
        match family {
            IpVersion::V4 => "dynet IPv4 fwmark policy rule",
            IpVersion::V6 => "dynet IPv6 fwmark policy rule",
        },
        output,
        |stdout| {
            stdout.lines().count() == 1
                && stdout.contains(&format!("fwmark {MARK_WITH_MASK}"))
                && (stdout.contains("lookup dynet") || stdout.contains("lookup 51880"))
        },
        "route the masked dynet mark through the dynet table",
    )
}

pub(super) fn legacy_rule_status(runner: &impl SystemRunner) -> TakeoverCheck {
    let output = runner.run("ip", &["rule", "show", "pref", LEGACY_RULE_PRIORITY]);
    owned_command_check(
        "route.rule.mark.legacy",
        "legacy dynet fwmark policy rule",
        output,
        |stdout| {
            stdout.lines().count() == 1
                && stdout.contains(&format!("fwmark {LEGACY_MARK_HEX}"))
                && (stdout.contains("lookup dynet") || stdout.contains("lookup 51880"))
        },
        "remove the legacy dynet fwmark rule",
    )
}

pub(crate) fn output_chain_status(
    runner: &impl SystemRunner,
    options: Option<HookOptions>,
) -> TakeoverCheck {
    let output = runner.run(
        "nft",
        &["list", "chain", NFT_FAMILY, NFT_TABLE, OUTPUT_CHAIN],
    );
    owned_command_check(
        "nft.chain.output",
        "dynet-owned output capture hook",
        output,
        |stdout| {
            if !stdout.contains(OUTPUT_OWNER_MARKER) {
                return false;
            }
            let Some(options) = options else {
                return true;
            };
            let expected_uid = format!("meta skuid {} return", options.service_uid);
            let expected_ipv6 = if options.ipv6_enabled {
                "ip6 daddr ::1 return"
            } else {
                "meta nfproto ipv6 return"
            };
            let mark_guard = stdout.contains(&format!("meta mark & {MARK_MASK_HEX} != 0 return"))
                || stdout.contains(&format!("meta mark & {MARK_MASK_HEX} != 0x00000000 return"));
            let expected_priority = stdout.contains("type route hook output priority mangle;")
                || stdout.contains(&format!(
                    "type route hook output priority {DYNET_NFT_OUTPUT_PRIORITY};"
                ));
            stdout.contains(&expected_uid)
                && stdout.contains(expected_ipv6)
                && mark_guard
                && expected_priority
                && stdout.contains(&format!(
                    "meta l4proto tcp meta mark set meta mark | {MARK_VALUE_HEX}"
                ))
                && stdout.contains(&format!(
                    "meta l4proto udp meta mark set meta mark | {MARK_VALUE_HEX}"
                ))
        },
        "create the owned output capture hook",
    )
}

fn owned_command_check(
    id: &'static str,
    label: &'static str,
    output: Result<crate::CommandOutput, String>,
    is_owned: impl FnOnce(&str) -> bool,
    action: &'static str,
) -> TakeoverCheck {
    match output {
        Ok(output) if output.success && output.stdout.is_empty() => {
            missing_check(id, label, action)
        }
        Ok(output) if output.success && is_owned(&output.stdout) => TakeoverCheck {
            id,
            label,
            path: None,
            state: CheckState::Ready,
            auto_action: None,
        },
        Ok(output) if !output.success => missing_check(id, label, action),
        Ok(_) | Err(_) => TakeoverCheck {
            id,
            label,
            path: None,
            state: CheckState::InvalidHardFail,
            auto_action: None,
        },
    }
}

fn missing_check(id: &'static str, label: &'static str, action: &'static str) -> TakeoverCheck {
    TakeoverCheck {
        id,
        label,
        path: None,
        state: CheckState::MissingAutoCreatable,
        auto_action: Some(action),
    }
}

pub(crate) fn reject_hook_collisions(checks: &[TakeoverCheck]) -> Result<(), String> {
    let collisions = checks
        .iter()
        .filter(|check| check.state == CheckState::InvalidHardFail)
        .map(TakeoverCheck::summary)
        .collect::<Vec<_>>();
    if collisions.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "dynet hooks found foreign or drifted artifacts and refuse to overwrite them: {}",
            collisions.join("; ")
        ))
    }
}

pub(super) fn reject_cleanup_collisions(runner: &impl SystemRunner) -> Result<(), String> {
    let mut checks = family_status(runner, IpVersion::V4);
    checks.extend(family_status(runner, IpVersion::V6));
    checks.push(output_chain_status(runner, None));
    checks.push(crate::linux_router_ingress::router_chain_status(
        runner, None,
    ));
    checks.push(legacy_rule_status(runner));
    reject_hook_collisions(&checks)
}
