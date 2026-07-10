use crate::linux_hooks::{
    family_status, output_chain_status, reject_hook_collisions, IpVersion, MARK_MASK_HEX,
    MARK_VALUE_HEX, NFT_FAMILY, NFT_TABLE,
};
use crate::linux_nft::run_required;
use crate::{CheckState, LinuxTakeover, SystemRunner, TakeoverCheck, TrafficScope};

pub const DYNET_NFT_ROUTER_INGRESS_PRIORITY: i32 = -151;

const ROUTER_CHAIN: &str = "dynet_router_ingress";
const ROUTER_OWNER_MARKER: &str = "dynet-owned: router-ingress:v1";

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RouterHookOptions {
    pub scope: TrafficScope,
    pub ipv6_enabled: bool,
}

impl RouterHookOptions {
    fn validate(&self) -> Result<(), String> {
        self.scope.validate(self.ipv6_enabled)
    }
}

impl LinuxTakeover {
    pub fn router_hooks_plan(&self, options: &RouterHookOptions) -> Result<Vec<String>, String> {
        options.validate()?;
        Ok(vec![
            format!(
                "capture only caller-selected TCP/UDP arriving on {} from {} IPv4 and {} active IPv6 CIDRs",
                options.scope.interface,
                options.scope.ipv4_sources.len(),
                if options.ipv6_enabled {
                    options.scope.ipv6_sources.len()
                } else {
                    0
                }
            ),
            format!(
                "create only owned nft chain {NFT_FAMILY} {NFT_TABLE} {ROUTER_CHAIN} at prerouting priority {DYNET_NFT_ROUTER_INGRESS_PRIORITY}"
            ),
            format!(
                "OR only dynet mark bit {MARK_VALUE_HEX}/{MARK_MASK_HEX}; preserve all foreign mark bits"
            ),
            "bypass local, private, link-local, multicast, non-TCP/UDP, and already dynet-marked traffic"
                .to_string(),
            "require caller-owned downstream interceptors to bypass the dynet mark".to_string(),
        ])
    }

    pub fn router_hooks_doctor_for(
        &self,
        options: &RouterHookOptions,
    ) -> Result<Vec<TakeoverCheck>, String> {
        options.validate()?;
        Ok(vec![
            self.nft_status(&crate::HostRunner),
            router_interface_status(&crate::HostRunner, options),
        ])
    }

    pub fn router_hooks_status_for(
        &self,
        options: &RouterHookOptions,
    ) -> Result<Vec<TakeoverCheck>, String> {
        options.validate()?;
        Ok(self.router_hooks_status_with(&crate::HostRunner, Some(options)))
    }

    pub fn router_hooks_status_with(
        &self,
        runner: &impl SystemRunner,
        options: Option<&RouterHookOptions>,
    ) -> Vec<TakeoverCheck> {
        let mut checks = family_status(runner, IpVersion::V4);
        if options.is_none_or(|options| options.ipv6_enabled) {
            checks.extend(family_status(runner, IpVersion::V6));
        }
        checks.push(router_chain_status(runner, options));
        checks
    }

    pub fn router_hooks_apply(&self, options: &RouterHookOptions) -> Result<Vec<String>, String> {
        self.router_hooks_apply_with(&crate::HostRunner, options)
    }

    pub fn router_hooks_apply_with(
        &self,
        runner: &impl SystemRunner,
        options: &RouterHookOptions,
    ) -> Result<Vec<String>, String> {
        options.validate()?;
        let status = self.status_with_runner(runner);
        if status.has_hard_failures() {
            return Err(status.doctor.failure_summary());
        }
        for runtime in &status.runtime {
            if runtime.state != CheckState::Ready {
                return Err(format!(
                    "dynet router hook apply requires ready runtime skeleton: {}",
                    runtime.summary()
                ));
            }
        }
        let interface = router_interface_status(runner, options);
        if interface.state != CheckState::Ready {
            return Err(format!(
                "dynet router hook apply requires its caller-selected interface: {}",
                interface.summary()
            ));
        }
        reject_hook_collisions(&self.router_hooks_status_with(runner, Some(options)))?;

        let mut actions = Vec::new();
        let result = (|| {
            self.ensure_family_hooks(runner, &mut actions, IpVersion::V4)?;
            if options.ipv6_enabled {
                self.ensure_family_hooks(runner, &mut actions, IpVersion::V6)?;
            }
            self.ensure_router_chain(runner, &mut actions, options)
        })();
        if let Err(error) = result {
            return match rollback_router_apply(runner, &actions) {
                Ok(()) => Err(format!(
                    "router hook apply failed and rolled back newly owned artifacts: {error}"
                )),
                Err(rollback) => Err(format!(
                    "router hook apply failed: {error}; rollback also failed: {rollback}"
                )),
            };
        }
        Ok(actions)
    }

    pub fn router_hooks_cleanup(&self) -> Result<Vec<String>, String> {
        self.router_hooks_cleanup_with(&crate::HostRunner)
    }

    pub fn router_hooks_cleanup_with(
        &self,
        runner: &impl SystemRunner,
    ) -> Result<Vec<String>, String> {
        reject_hook_collisions(&[
            router_chain_status(runner, None),
            output_chain_status(runner, None),
        ])?;
        let mut actions = Vec::new();
        self.delete_router_chain(runner, &mut actions)?;
        if output_chain_status(runner, None).state != CheckState::Ready {
            self.delete_family_hooks(runner, &mut actions, IpVersion::V6)?;
            self.delete_family_hooks(runner, &mut actions, IpVersion::V4)?;
        }
        self.delete_legacy_rule(runner, &mut actions)?;
        Ok(actions)
    }

    fn ensure_router_chain(
        &self,
        runner: &impl SystemRunner,
        actions: &mut Vec<String>,
        options: &RouterHookOptions,
    ) -> Result<(), String> {
        if router_chain_status(runner, Some(options)).state == CheckState::Ready {
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
                ROUTER_CHAIN,
                "{",
                "type",
                "filter",
                "hook",
                "prerouting",
                "priority",
                "-151;",
                "policy",
                "accept;",
                "comment",
                "\"dynet-owned: router-ingress:v1\";",
                "}",
            ],
        )?;
        actions.push(format!(
            "created owned nft router ingress hook {NFT_FAMILY} {NFT_TABLE} {ROUTER_CHAIN} priority {DYNET_NFT_ROUTER_INGRESS_PRIORITY}"
        ));
        for rule in router_rules(options) {
            let args = rule.iter().map(String::as_str).collect::<Vec<_>>();
            run_required(runner, "nft", &args)?;
        }
        actions.push(format!(
            "installed source-scoped dual-stack router capture rules preserving marks outside {MARK_MASK_HEX}"
        ));
        Ok(())
    }

    fn delete_router_chain(
        &self,
        runner: &impl SystemRunner,
        actions: &mut Vec<String>,
    ) -> Result<(), String> {
        if router_chain_status(runner, None).state != CheckState::Ready {
            return Ok(());
        }
        run_required(
            runner,
            "nft",
            &["delete", "chain", NFT_FAMILY, NFT_TABLE, ROUTER_CHAIN],
        )?;
        actions.push(format!(
            "deleted owned nft router ingress hook {NFT_FAMILY} {NFT_TABLE} {ROUTER_CHAIN}"
        ));
        Ok(())
    }
}

fn rollback_router_apply(runner: &impl SystemRunner, actions: &[String]) -> Result<(), String> {
    for action in actions.iter().rev() {
        if action.starts_with("created owned nft router ingress hook") {
            run_required(
                runner,
                "nft",
                &["delete", "chain", NFT_FAMILY, NFT_TABLE, ROUTER_CHAIN],
            )?;
        } else if action.starts_with("created IPv6 fwmark") {
            run_required(
                runner,
                "ip",
                &[
                    "-6",
                    "rule",
                    "del",
                    "pref",
                    "10000",
                    "fwmark",
                    "0x40000000/0x40000000",
                    "lookup",
                    "51880",
                ],
            )?;
        } else if action.starts_with("created IPv6 route table") {
            run_required(
                runner,
                "ip",
                &[
                    "-6", "route", "del", "default", "dev", "dynet0", "table", "51880",
                ],
            )?;
        } else if action.starts_with("created IPv4 fwmark") {
            run_required(
                runner,
                "ip",
                &[
                    "-4",
                    "rule",
                    "del",
                    "pref",
                    "10000",
                    "fwmark",
                    "0x40000000/0x40000000",
                    "lookup",
                    "51880",
                ],
            )?;
        } else if action.starts_with("created IPv4 route table") {
            run_required(
                runner,
                "ip",
                &[
                    "-4", "route", "del", "default", "dev", "dynet0", "table", "51880",
                ],
            )?;
        }
    }
    Ok(())
}

pub(crate) fn router_chain_status(
    runner: &impl SystemRunner,
    options: Option<&RouterHookOptions>,
) -> TakeoverCheck {
    let output = runner.run(
        "nft",
        &["list", "chain", NFT_FAMILY, NFT_TABLE, ROUTER_CHAIN],
    );
    let state = match output {
        Ok(output) if !output.success => CheckState::MissingAutoCreatable,
        Ok(output) if router_chain_is_expected(&output.stdout, options) => CheckState::Ready,
        Ok(_) => CheckState::InvalidHardFail,
        Err(_) => CheckState::MissingHardFail,
    };
    TakeoverCheck {
        id: "nft.chain.router-ingress",
        label: "dynet-owned source-scoped router ingress hook",
        path: None,
        state,
        auto_action: (state == CheckState::MissingAutoCreatable)
            .then_some("explicitly apply the source-scoped router hook"),
    }
}

fn router_chain_is_expected(stdout: &str, options: Option<&RouterHookOptions>) -> bool {
    if !stdout.contains(ROUTER_OWNER_MARKER) {
        return false;
    }
    let Some(options) = options else {
        return true;
    };
    let priority = stdout.contains("type filter hook prerouting priority -151;")
        || stdout.contains("type filter hook prerouting priority mangle - 1;")
        || stdout.contains(&format!(
            "type filter hook prerouting priority {DYNET_NFT_ROUTER_INGRESS_PRIORITY};"
        ));
    let mark_guard = stdout.contains(&format!("meta mark & {MARK_MASK_HEX} != 0 return"))
        || stdout.contains(&format!("meta mark & {MARK_MASK_HEX} != 0x00000000 return"));
    let sources = options
        .scope
        .ipv4_sources
        .iter()
        .map(|source| ("ip", source))
        .chain(
            options
                .ipv6_enabled
                .then_some(options.scope.ipv6_sources.iter())
                .into_iter()
                .flatten()
                .map(|source| ("ip6", source)),
        )
        .all(|(family, source)| {
            ["tcp", "udp"].into_iter().all(|protocol| {
                stdout.lines().any(|line| {
                    line.contains(&format!("iifname \"{}\"", options.scope.interface))
                        && source_matches(line, family, source)
                        && line.contains(&format!("meta l4proto {protocol}"))
                        && line.contains(&format!("meta mark set meta mark | {MARK_VALUE_HEX}"))
                })
            })
        });
    let expected_ipv6 = if options.ipv6_enabled {
        stdout.contains("ip6 daddr fe80::/10 return")
            && stdout.contains("ip6 daddr fc00::/7 return")
            && stdout.contains("ip6 daddr ff00::/8 return")
    } else {
        stdout.contains("meta nfproto ipv6 return")
    };
    priority
        && mark_guard
        && sources
        && expected_ipv6
        && stdout.contains("fib daddr type local return")
        && stdout.contains("ip daddr 10.0.0.0/8 return")
        && stdout.contains("ip daddr 172.16.0.0/12 return")
        && stdout.contains("ip daddr 192.168.0.0/16 return")
}

fn source_matches(line: &str, family: &str, source: &str) -> bool {
    if line.contains(&format!("{family} saddr {source}")) {
        return true;
    }
    let Some((address, prefix)) = source.split_once('/') else {
        return false;
    };
    let host_prefix = (family == "ip" && prefix == "32") || (family == "ip6" && prefix == "128");
    host_prefix && line.contains(&format!("{family} saddr {address}"))
}

fn router_interface_status(
    runner: &impl SystemRunner,
    options: &RouterHookOptions,
) -> TakeoverCheck {
    let output = runner.run("ip", &["link", "show", "dev", &options.scope.interface]);
    let state = match output {
        Ok(output) if output.success => CheckState::Ready,
        Ok(_) | Err(_) => CheckState::MissingHardFail,
    };
    TakeoverCheck {
        id: "router-ingress.interface",
        label: "caller-selected router ingress interface",
        path: None,
        state,
        auto_action: None,
    }
}

fn router_rules(options: &RouterHookOptions) -> Vec<Vec<String>> {
    let mut rules = vec![
        nft_rule_strings(&["meta", "mark", "&", MARK_MASK_HEX, "!=", "0", "return"]),
        nft_rule_strings(&["fib", "daddr", "type", "local", "return"]),
        nft_rule_strings(&["ip", "daddr", "0.0.0.0/8", "return"]),
        nft_rule_strings(&["ip", "daddr", "10.0.0.0/8", "return"]),
        nft_rule_strings(&["ip", "daddr", "127.0.0.0/8", "return"]),
        nft_rule_strings(&["ip", "daddr", "169.254.0.0/16", "return"]),
        nft_rule_strings(&["ip", "daddr", "172.16.0.0/12", "return"]),
        nft_rule_strings(&["ip", "daddr", "192.168.0.0/16", "return"]),
        nft_rule_strings(&["ip", "daddr", "224.0.0.0/4", "return"]),
        nft_rule_strings(&["ip", "daddr", "255.255.255.255", "return"]),
    ];
    if options.ipv6_enabled {
        rules.extend([
            nft_rule_strings(&["ip6", "daddr", "::1", "return"]),
            nft_rule_strings(&["ip6", "daddr", "fe80::/10", "return"]),
            nft_rule_strings(&["ip6", "daddr", "fc00::/7", "return"]),
            nft_rule_strings(&["ip6", "daddr", "ff00::/8", "return"]),
        ]);
    } else {
        rules.push(nft_rule_strings(&["meta", "nfproto", "ipv6", "return"]));
    }
    for source in &options.scope.ipv4_sources {
        rules.push(mark_rule(&options.scope.interface, "ip", source, "tcp"));
        rules.push(mark_rule(&options.scope.interface, "ip", source, "udp"));
    }
    if options.ipv6_enabled {
        for source in &options.scope.ipv6_sources {
            rules.push(mark_rule(&options.scope.interface, "ip6", source, "tcp"));
            rules.push(mark_rule(&options.scope.interface, "ip6", source, "udp"));
        }
    }
    rules
}

fn mark_rule(interface: &str, family: &str, source: &str, protocol: &str) -> Vec<String> {
    nft_rule(&[
        "iifname".to_string(),
        format!("\"{interface}\""),
        family.to_string(),
        "saddr".to_string(),
        source.to_string(),
        "meta".to_string(),
        "l4proto".to_string(),
        protocol.to_string(),
        "meta".to_string(),
        "mark".to_string(),
        "set".to_string(),
        "meta".to_string(),
        "mark".to_string(),
        "|".to_string(),
        MARK_VALUE_HEX.to_string(),
    ])
}

fn nft_rule(rule: &[String]) -> Vec<String> {
    let mut args = ["add", "rule", NFT_FAMILY, NFT_TABLE, ROUTER_CHAIN]
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
