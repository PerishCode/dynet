use crate::linux_nft::run_required;
use crate::{CheckState, LinuxTakeover, SystemRunner, TakeoverCheck};

pub(crate) const DYN_MARK_HEX: &str = "0x51880";
const RULE_PRIORITY: &str = "10000";
const LEGACY_RULE_PRIORITY: &str = "51880";
const TUN_INTERFACE: &str = "dynet0";
const ROUTE_TABLE: &str = "dynet";
const NFT_FAMILY: &str = "inet";
const NFT_TABLE: &str = "dynet";
const OUTPUT_CHAIN: &str = "dynet_output";
const SERVICE_UID: &str = "1000";
const BYPASS_IPV4_CIDRS: &[&str] = &["192.168.1.0/24", "192.168.20.0/24", "10.199.0.0/24"];

impl LinuxTakeover {
    pub fn hooks_status(&self) -> Vec<TakeoverCheck> {
        self.hooks_status_with_runner(&crate::HostRunner)
    }

    pub fn hooks_status_with_runner(&self, runner: &impl SystemRunner) -> Vec<TakeoverCheck> {
        vec![
            hook_check(
                "route.table.default",
                "dynet policy route default",
                route_query(runner),
                "route marked traffic to dynet0",
            ),
            hook_check(
                "route.rule.mark",
                "dynet fwmark policy rule",
                rule_query(runner, RULE_PRIORITY),
                "route dynet fwmark through dynet table",
            ),
            hook_check(
                "nft.chain.output",
                "dynet output capture hook",
                runner.run(
                    "nft",
                    &["list", "chain", NFT_FAMILY, NFT_TABLE, OUTPUT_CHAIN],
                ),
                "create output capture hook",
            ),
        ]
    }

    pub fn hooks_apply(&self) -> Result<Vec<String>, String> {
        self.hooks_apply_with_runner(&crate::HostRunner)
    }

    pub fn hooks_apply_with_runner(
        &self,
        runner: &impl SystemRunner,
    ) -> Result<Vec<String>, String> {
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

        let mut actions = Vec::new();
        self.ensure_hook_route(runner, &mut actions)?;
        self.ensure_hook_rule(runner, &mut actions)?;
        self.ensure_output_chain(runner, &mut actions)?;
        Ok(actions)
    }

    pub fn hooks_cleanup(&self) -> Result<Vec<String>, String> {
        self.hooks_cleanup_with_runner(&crate::HostRunner)
    }

    pub fn hooks_cleanup_with_runner(
        &self,
        runner: &impl SystemRunner,
    ) -> Result<Vec<String>, String> {
        let mut actions = Vec::new();
        self.delete_output_chain(runner, &mut actions)?;
        self.delete_hook_rule(runner, &mut actions)?;
        self.delete_hook_route(runner, &mut actions)?;
        Ok(actions)
    }

    fn ensure_hook_route(
        &self,
        runner: &impl SystemRunner,
        actions: &mut Vec<String>,
    ) -> Result<(), String> {
        if route_status(runner).state == CheckState::Ready {
            return Ok(());
        }
        run_required(
            runner,
            "ip",
            &[
                "route",
                "add",
                "default",
                "dev",
                TUN_INTERFACE,
                "table",
                ROUTE_TABLE,
            ],
        )?;
        actions.push(format!(
            "created route table {ROUTE_TABLE} default dev {TUN_INTERFACE}"
        ));
        Ok(())
    }

    fn ensure_hook_rule(
        &self,
        runner: &impl SystemRunner,
        actions: &mut Vec<String>,
    ) -> Result<(), String> {
        if rule_status(runner).state == CheckState::Ready {
            return Ok(());
        }
        run_required(
            runner,
            "ip",
            &[
                "rule",
                "add",
                "pref",
                RULE_PRIORITY,
                "fwmark",
                DYN_MARK_HEX,
                "lookup",
                ROUTE_TABLE,
            ],
        )?;
        actions.push(format!("created fwmark {DYN_MARK_HEX} policy rule"));
        Ok(())
    }

    fn ensure_output_chain(
        &self,
        runner: &impl SystemRunner,
        actions: &mut Vec<String>,
    ) -> Result<(), String> {
        if output_chain_status(runner).state == CheckState::Ready {
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
                "mangle;",
                "policy",
                "accept;",
                "}",
            ],
        )?;
        actions.push(format!(
            "created nft output hook {NFT_FAMILY} {NFT_TABLE} {OUTPUT_CHAIN}"
        ));
        for rule in output_rules() {
            run_required(runner, "nft", &rule)?;
        }
        actions.push("installed output capture marking rules".to_string());
        Ok(())
    }

    fn delete_output_chain(
        &self,
        runner: &impl SystemRunner,
        actions: &mut Vec<String>,
    ) -> Result<(), String> {
        if output_chain_status(runner).state != CheckState::Ready {
            return Ok(());
        }
        run_required(
            runner,
            "nft",
            &["delete", "chain", NFT_FAMILY, NFT_TABLE, OUTPUT_CHAIN],
        )?;
        actions.push(format!(
            "deleted nft output hook {NFT_FAMILY} {NFT_TABLE} {OUTPUT_CHAIN}"
        ));
        Ok(())
    }

    fn delete_hook_rule(
        &self,
        runner: &impl SystemRunner,
        actions: &mut Vec<String>,
    ) -> Result<(), String> {
        if rule_status(runner).state == CheckState::Ready {
            delete_rule_pref(runner, RULE_PRIORITY)?;
            actions.push(format!(
                "deleted fwmark {DYN_MARK_HEX} policy rule pref {RULE_PRIORITY}"
            ));
        }
        if legacy_rule_status(runner).state == CheckState::Ready {
            delete_rule_pref(runner, LEGACY_RULE_PRIORITY)?;
            actions.push(format!(
                "deleted legacy fwmark {DYN_MARK_HEX} policy rule pref {LEGACY_RULE_PRIORITY}"
            ));
        }
        Ok(())
    }

    fn delete_hook_route(
        &self,
        runner: &impl SystemRunner,
        actions: &mut Vec<String>,
    ) -> Result<(), String> {
        if route_status(runner).state != CheckState::Ready {
            return Ok(());
        }
        run_required(
            runner,
            "ip",
            &[
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
            "deleted route table {ROUTE_TABLE} default dev {TUN_INTERFACE}"
        ));
        Ok(())
    }
}

fn route_status(runner: &impl SystemRunner) -> TakeoverCheck {
    hook_check(
        "route.table.default",
        "dynet policy route default",
        route_query(runner),
        "route marked traffic to dynet0",
    )
}

fn rule_status(runner: &impl SystemRunner) -> TakeoverCheck {
    hook_check(
        "route.rule.mark",
        "dynet fwmark policy rule",
        rule_query(runner, RULE_PRIORITY),
        "route dynet fwmark through dynet table",
    )
}

fn legacy_rule_status(runner: &impl SystemRunner) -> TakeoverCheck {
    hook_check(
        "route.rule.mark.legacy",
        "legacy dynet fwmark policy rule",
        rule_query(runner, LEGACY_RULE_PRIORITY),
        "remove legacy dynet fwmark rule",
    )
}

fn output_chain_status(runner: &impl SystemRunner) -> TakeoverCheck {
    hook_check(
        "nft.chain.output",
        "dynet output capture hook",
        runner.run(
            "nft",
            &["list", "chain", NFT_FAMILY, NFT_TABLE, OUTPUT_CHAIN],
        ),
        "create output capture hook",
    )
}

fn hook_check(
    id: &'static str,
    label: &'static str,
    output: Result<crate::CommandOutput, String>,
    action: &'static str,
) -> TakeoverCheck {
    match output {
        Ok(output) if output.success && output.stdout_required_ready() => TakeoverCheck {
            id,
            label,
            path: None,
            state: CheckState::Ready,
            auto_action: None,
        },
        Ok(_) | Err(_) => TakeoverCheck {
            id,
            label,
            path: None,
            state: CheckState::MissingAutoCreatable,
            auto_action: Some(action),
        },
    }
}

fn route_query(runner: &impl SystemRunner) -> Result<crate::CommandOutput, String> {
    runner.run(
        "ip",
        &[
            "route",
            "show",
            "table",
            ROUTE_TABLE,
            "default",
            "dev",
            TUN_INTERFACE,
        ],
    )
}

fn rule_query(
    runner: &impl SystemRunner,
    priority: &'static str,
) -> Result<crate::CommandOutput, String> {
    runner.run("ip", &["rule", "show", "pref", priority])
}

fn delete_rule_pref(runner: &impl SystemRunner, priority: &'static str) -> Result<(), String> {
    run_required(
        runner,
        "ip",
        &[
            "rule",
            "del",
            "pref",
            priority,
            "fwmark",
            DYN_MARK_HEX,
            "lookup",
            ROUTE_TABLE,
        ],
    )
}

trait HookOutputReady {
    fn stdout_required_ready(&self) -> bool;
}

impl HookOutputReady for crate::CommandOutput {
    fn stdout_required_ready(&self) -> bool {
        !self.stdout.is_empty()
    }
}

fn output_rules() -> Vec<Vec<&'static str>> {
    let mut rules = vec![
        nft_rule(&["meta", "skuid", SERVICE_UID, "return"]),
        nft_rule(&["ip", "daddr", "127.0.0.0/8", "return"]),
        nft_rule(&["tcp", "sport", "22", "return"]),
        nft_rule(&["tcp", "dport", "22", "return"]),
    ];
    for cidr in BYPASS_IPV4_CIDRS {
        rules.push(nft_rule(&["ip", "daddr", cidr, "return"]));
    }
    rules.extend([
        nft_rule(&["udp", "dport", "53", "meta", "mark", "set", DYN_MARK_HEX]),
        nft_rule(&["ip", "protocol", "tcp", "meta", "mark", "set", DYN_MARK_HEX]),
        nft_rule(&["ip", "protocol", "udp", "meta", "mark", "set", DYN_MARK_HEX]),
    ]);
    rules
}

fn nft_rule(rule: &[&'static str]) -> Vec<&'static str> {
    let mut args = vec!["add", "rule", NFT_FAMILY, NFT_TABLE, OUTPUT_CHAIN];
    args.extend(rule);
    args
}
