use crate::linux_nft::run_required;
use crate::{CheckState, LinuxTakeover, SystemRunner, TakeoverCheck};

#[path = "hooks/status.rs"]
mod status;
use status::*;

pub const DYNET_CAPTURE_MARK_VALUE: u32 = 0x4000_0000;
pub const DYNET_CAPTURE_MARK_MASK: u32 = 0x4000_0000;
pub const DYNET_ROUTE_RULE_PRIORITY: u32 = 10_000;
pub const DYNET_ROUTE_TABLE_ID: u32 = 51_880;
pub const DYNET_NFT_OUTPUT_PRIORITY: i32 = -150;

const MARK_VALUE_HEX: &str = "0x40000000";
const MARK_MASK_HEX: &str = "0x40000000";
const MARK_WITH_MASK: &str = "0x40000000/0x40000000";
const RULE_PRIORITY: &str = "10000";
const LEGACY_RULE_PRIORITY: &str = "51880";
const LEGACY_MARK_HEX: &str = "0x51880";
const TUN_INTERFACE: &str = "dynet0";
const ROUTE_TABLE: &str = "51880";
const NFT_FAMILY: &str = "inet";
const NFT_TABLE: &str = "dynet";
const OUTPUT_CHAIN: &str = "dynet_output";
const OUTPUT_OWNER_MARKER: &str = "dynet-owned: capture-output:v1";

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct HookOptions {
    pub service_uid: u32,
    pub ipv6_enabled: bool,
}

impl LinuxTakeover {
    pub fn hooks_status(&self) -> Vec<TakeoverCheck> {
        self.hooks_status_with_runner(&crate::HostRunner)
    }

    pub fn hooks_status_for(&self, service_uid: u32) -> Vec<TakeoverCheck> {
        self.hooks_status_for_options(HookOptions {
            service_uid,
            ipv6_enabled: false,
        })
    }

    pub fn hooks_status_for_options(&self, options: HookOptions) -> Vec<TakeoverCheck> {
        self.hooks_status_with(&crate::HostRunner, options)
    }

    pub fn hooks_status_with_runner(&self, runner: &impl SystemRunner) -> Vec<TakeoverCheck> {
        let mut checks = family_status(runner, IpVersion::V4);
        checks.extend(family_status(runner, IpVersion::V6));
        checks.push(output_chain_status(runner, None));
        checks
    }

    pub fn hooks_status_for_with(
        &self,
        runner: &impl SystemRunner,
        service_uid: u32,
    ) -> Vec<TakeoverCheck> {
        self.hooks_status_with(
            runner,
            HookOptions {
                service_uid,
                ipv6_enabled: false,
            },
        )
    }

    pub fn hooks_status_with(
        &self,
        runner: &impl SystemRunner,
        options: HookOptions,
    ) -> Vec<TakeoverCheck> {
        let mut checks = family_status(runner, IpVersion::V4);
        if options.ipv6_enabled {
            checks.extend(family_status(runner, IpVersion::V6));
        }
        checks.push(output_chain_status(runner, Some(options)));
        checks
    }

    pub fn hooks_apply(&self, service_uid: u32) -> Result<Vec<String>, String> {
        self.hooks_apply_for(HookOptions {
            service_uid,
            ipv6_enabled: false,
        })
    }

    pub fn hooks_apply_for(&self, options: HookOptions) -> Result<Vec<String>, String> {
        self.hooks_apply_options_with(&crate::HostRunner, options)
    }

    pub fn hooks_apply_with_runner(
        &self,
        runner: &impl SystemRunner,
        service_uid: u32,
    ) -> Result<Vec<String>, String> {
        self.hooks_apply_options_with(
            runner,
            HookOptions {
                service_uid,
                ipv6_enabled: false,
            },
        )
    }

    pub fn hooks_apply_options_with(
        &self,
        runner: &impl SystemRunner,
        options: HookOptions,
    ) -> Result<Vec<String>, String> {
        if options.service_uid == 0 {
            return Err("dynet hooks refuse uid 0 as the service bypass identity".to_string());
        }
        let status = self.status_with_runner(runner);
        if status.has_hard_failures() {
            return Err(status.doctor.failure_summary());
        }
        for runtime in &status.runtime {
            if runtime.state != CheckState::Ready {
                return Err(format!(
                    "dynet hook apply requires ready runtime skeleton: {}",
                    runtime.summary()
                ));
            }
        }
        reject_hook_collisions(&self.hooks_status_with(runner, options))?;

        let mut actions = Vec::new();
        self.ensure_family_hooks(runner, &mut actions, IpVersion::V4)?;
        if options.ipv6_enabled {
            self.ensure_family_hooks(runner, &mut actions, IpVersion::V6)?;
        }
        self.ensure_output_chain(runner, &mut actions, options)?;
        Ok(actions)
    }

    pub fn hooks_cleanup(&self) -> Result<Vec<String>, String> {
        self.hooks_cleanup_with_runner(&crate::HostRunner)
    }

    pub fn hooks_cleanup_with_runner(
        &self,
        runner: &impl SystemRunner,
    ) -> Result<Vec<String>, String> {
        reject_cleanup_collisions(runner)?;
        let mut actions = Vec::new();
        self.delete_output_chain(runner, &mut actions)?;
        self.delete_family_hooks(runner, &mut actions, IpVersion::V6)?;
        self.delete_family_hooks(runner, &mut actions, IpVersion::V4)?;
        self.delete_legacy_rule(runner, &mut actions)?;
        Ok(actions)
    }

    fn ensure_family_hooks(
        &self,
        runner: &impl SystemRunner,
        actions: &mut Vec<String>,
        family: IpVersion,
    ) -> Result<(), String> {
        if route_status(runner, family).state != CheckState::Ready {
            let args = [
                family.flag(),
                "route",
                "add",
                "default",
                "dev",
                TUN_INTERFACE,
                "table",
                ROUTE_TABLE,
            ];
            run_required(runner, "ip", &args)?;
            actions.push(format!(
                "created {} route table {ROUTE_TABLE} default dev {TUN_INTERFACE}",
                family.label()
            ));
        }
        if rule_status(runner, family).state != CheckState::Ready {
            let args = [
                family.flag(),
                "rule",
                "add",
                "pref",
                RULE_PRIORITY,
                "fwmark",
                MARK_WITH_MASK,
                "lookup",
                ROUTE_TABLE,
            ];
            run_required(runner, "ip", &args)?;
            actions.push(format!(
                "created {} fwmark {MARK_WITH_MASK} policy rule pref {RULE_PRIORITY}",
                family.label()
            ));
        }
        Ok(())
    }

    fn ensure_output_chain(
        &self,
        runner: &impl SystemRunner,
        actions: &mut Vec<String>,
        options: HookOptions,
    ) -> Result<(), String> {
        if output_chain_status(runner, Some(options)).state == CheckState::Ready {
            return Ok(());
        }
        run_required(
            runner,
            "nft",
            &[
                "add",
                "chain",
                NFT_FAMILY,
                NFT_TABLE,
                OUTPUT_CHAIN,
                "{",
                "type",
                "route",
                "hook",
                "output",
                "priority",
                "-150;",
                "policy",
                "accept;",
                "comment",
                "\"dynet-owned: capture-output:v1\";",
                "}",
            ],
        )?;
        actions.push(format!(
            "created owned nft output hook {NFT_FAMILY} {NFT_TABLE} {OUTPUT_CHAIN} priority {DYNET_NFT_OUTPUT_PRIORITY}"
        ));
        for rule in output_rules(options) {
            let args = rule.iter().map(String::as_str).collect::<Vec<_>>();
            run_required(runner, "nft", &args)?;
        }
        actions.push(format!(
            "installed dual-stack-safe output capture rules preserving marks outside {MARK_MASK_HEX}"
        ));
        Ok(())
    }

    fn delete_output_chain(
        &self,
        runner: &impl SystemRunner,
        actions: &mut Vec<String>,
    ) -> Result<(), String> {
        if output_chain_status(runner, None).state != CheckState::Ready {
            return Ok(());
        }
        run_required(
            runner,
            "nft",
            &["delete", "chain", NFT_FAMILY, NFT_TABLE, OUTPUT_CHAIN],
        )?;
        actions.push(format!(
            "deleted owned nft output hook {NFT_FAMILY} {NFT_TABLE} {OUTPUT_CHAIN}"
        ));
        Ok(())
    }

    fn delete_family_hooks(
        &self,
        runner: &impl SystemRunner,
        actions: &mut Vec<String>,
        family: IpVersion,
    ) -> Result<(), String> {
        if rule_status(runner, family).state == CheckState::Ready {
            run_required(
                runner,
                "ip",
                &[
                    family.flag(),
                    "rule",
                    "del",
                    "pref",
                    RULE_PRIORITY,
                    "fwmark",
                    MARK_WITH_MASK,
                    "lookup",
                    ROUTE_TABLE,
                ],
            )?;
            actions.push(format!(
                "deleted {} fwmark {MARK_WITH_MASK} policy rule pref {RULE_PRIORITY}",
                family.label()
            ));
        }
        if route_status(runner, family).state == CheckState::Ready {
            run_required(
                runner,
                "ip",
                &[
                    family.flag(),
                    "route",
                    "del",
                    "default",
                    "dev",
                    TUN_INTERFACE,
                    "table",
                    ROUTE_TABLE,
                ],
            )?;
            actions.push(format!(
                "deleted {} route table {ROUTE_TABLE} default dev {TUN_INTERFACE}",
                family.label()
            ));
        }
        Ok(())
    }

    fn delete_legacy_rule(
        &self,
        runner: &impl SystemRunner,
        actions: &mut Vec<String>,
    ) -> Result<(), String> {
        if legacy_rule_status(runner).state != CheckState::Ready {
            return Ok(());
        }
        run_required(
            runner,
            "ip",
            &[
                "rule",
                "del",
                "pref",
                LEGACY_RULE_PRIORITY,
                "fwmark",
                LEGACY_MARK_HEX,
                "lookup",
                ROUTE_TABLE,
            ],
        )?;
        actions.push(format!(
            "deleted legacy fwmark {LEGACY_MARK_HEX} policy rule pref {LEGACY_RULE_PRIORITY}"
        ));
        Ok(())
    }
}

fn output_rules(options: HookOptions) -> Vec<Vec<String>> {
    let mut rules = vec![
        nft_rule(&[
            "meta".to_string(),
            "skuid".to_string(),
            options.service_uid.to_string(),
            "return".to_string(),
        ]),
        nft_rule_strings(&["meta", "mark", "&", MARK_MASK_HEX, "!=", "0", "return"]),
    ];
    if options.ipv6_enabled {
        rules.extend([
            nft_rule_strings(&["ip6", "daddr", "::1", "return"]),
            nft_rule_strings(&["ip6", "daddr", "fe80::/10", "return"]),
            nft_rule_strings(&["ip6", "daddr", "ff00::/8", "return"]),
        ]);
    } else {
        rules.push(nft_rule_strings(&["meta", "nfproto", "ipv6", "return"]));
    }
    rules.extend([
        nft_rule_strings(&["ip", "daddr", "127.0.0.0/8", "return"]),
        nft_rule_strings(&["ip", "daddr", "169.254.0.0/16", "return"]),
        nft_rule_strings(&["ip", "daddr", "224.0.0.0/4", "return"]),
        nft_rule_strings(&["ip", "daddr", "255.255.255.255", "return"]),
        nft_rule_strings(&["tcp", "sport", "22", "return"]),
        nft_rule_strings(&["tcp", "dport", "22", "return"]),
        nft_rule_strings(&[
            "meta",
            "l4proto",
            "tcp",
            "meta",
            "mark",
            "set",
            "meta",
            "mark",
            "|",
            MARK_VALUE_HEX,
        ]),
        nft_rule_strings(&[
            "meta",
            "l4proto",
            "udp",
            "meta",
            "mark",
            "set",
            "meta",
            "mark",
            "|",
            MARK_VALUE_HEX,
        ]),
    ]);
    rules
}

fn nft_rule(rule: &[String]) -> Vec<String> {
    let mut args = ["add", "rule", NFT_FAMILY, NFT_TABLE, OUTPUT_CHAIN]
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
    args.extend_from_slice(rule);
    args
}

fn nft_rule_strings(rule: &[&str]) -> Vec<String> {
    nft_rule(
        &rule
            .iter()
            .map(|value| (*value).to_string())
            .collect::<Vec<_>>(),
    )
}
