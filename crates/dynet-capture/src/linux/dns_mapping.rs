use std::net::SocketAddr;

use crate::linux_hooks::MARK_MASK_HEX;
use crate::linux_nft::run_required;
use crate::{CheckState, LinuxTakeover, SystemRunner, TakeoverCheck, TrafficScope};

pub const DYNET_NFT_DNS_MAPPING_PRIORITY: i32 = -100;

const NFT_FAMILY: &str = "inet";
const NFT_TABLE: &str = "dynet";
const MAPPING_CHAIN: &str = "dynet_dns_mapping";
const MAPPING_OWNER_MARKER: &str = "dynet-owned: dns-mapping:v1";
const MARK_CLEAR_MASK_HEX: &str = "0xbfffffff";

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DnsMappingOptions {
    pub scope: TrafficScope,
    pub source_port: u16,
    pub target: SocketAddr,
    pub ipv6_enabled: bool,
}

impl DnsMappingOptions {
    pub fn validate(&self) -> Result<(), String> {
        self.scope.validate(self.ipv6_enabled)?;
        if self.source_port == 0 || self.target.port() == 0 {
            return Err("dns mapping ports must be between 1 and 65535".to_string());
        }
        if self.source_port == self.target.port() {
            return Err(
                "dns mapping source port must differ from the dynet DNS listener port".to_string(),
            );
        }
        if !self.target.ip().is_unspecified() {
            return Err(
                "dns mapping requires the dynet DNS listener to use an unspecified bind address"
                    .to_string(),
            );
        }
        if self.ipv6_enabled && !self.target.is_ipv6() {
            return Err(
                "IPv6 DNS mapping requires an IPv6 unspecified listener such as [::]:1053"
                    .to_string(),
            );
        }
        if !self.ipv6_enabled && !self.target.is_ipv4() {
            return Err(
                "IPv4-only DNS mapping requires an IPv4 unspecified listener such as 0.0.0.0:1053"
                    .to_string(),
            );
        }
        Ok(())
    }
}

impl LinuxTakeover {
    pub fn dns_mapping_plan(&self, options: &DnsMappingOptions) -> Result<Vec<String>, String> {
        options.validate()?;
        let families = if options.ipv6_enabled {
            "IPv4 and IPv6"
        } else {
            "IPv4 only"
        };
        Ok(vec![
            format!(
                "map {families} UDP/TCP {}:{} to dynet DNS port {}",
                options.scope.interface,
                options.source_port,
                options.target.port()
            ),
            "leave firewall admission, DHCP, dnsmasq, UCI, and fw4 policy caller-owned".to_string(),
            format!(
                "create only owned nft chain {NFT_FAMILY} {NFT_TABLE} {MAPPING_CHAIN} at priority {DYNET_NFT_DNS_MAPPING_PRIORITY}"
            ),
            "never apply this mapping from service start, hooks apply, or runtime start".to_string(),
            format!(
                "clear only dynet mark bit {MARK_MASK_HEX} before redirect so policy routing remains fail-open"
            ),
        ])
    }

    pub fn dns_mapping_doctor_for(
        &self,
        options: &DnsMappingOptions,
    ) -> Result<Vec<TakeoverCheck>, String> {
        options.validate()?;
        Ok(vec![
            self.nft_status(&crate::HostRunner),
            mapping_interface_status(&crate::HostRunner, options),
        ])
    }

    pub fn dns_mapping_status_for(
        &self,
        options: &DnsMappingOptions,
    ) -> Result<Vec<TakeoverCheck>, String> {
        self.mapping_status_with(&crate::HostRunner, options)
    }

    pub fn mapping_status_with(
        &self,
        runner: &impl SystemRunner,
        options: &DnsMappingOptions,
    ) -> Result<Vec<TakeoverCheck>, String> {
        options.validate()?;
        Ok(vec![mapping_status(runner, Some(options))])
    }

    pub fn dns_mapping_apply(&self, options: &DnsMappingOptions) -> Result<Vec<String>, String> {
        self.mapping_apply_with_runner(&crate::HostRunner, options)
    }

    pub fn mapping_apply_with_runner(
        &self,
        runner: &impl SystemRunner,
        options: &DnsMappingOptions,
    ) -> Result<Vec<String>, String> {
        options.validate()?;
        let table = self.nft_status(runner);
        if table.state != CheckState::Ready {
            return Err(format!(
                "dns mapping requires the owned dynet runtime skeleton: {}",
                table.summary()
            ));
        }
        let interface = mapping_interface_status(runner, options);
        if interface.state != CheckState::Ready {
            return Err(format!(
                "dns mapping requires its caller-selected interface: {}",
                interface.summary()
            ));
        }
        let status = mapping_status(runner, Some(options));
        match status.state {
            CheckState::Ready => return Ok(Vec::new()),
            CheckState::InvalidHardFail => {
                return Err(format!(
                    "dns mapping found a foreign or drifted chain and refuses to overwrite it: {}",
                    status.summary()
                ))
            }
            CheckState::MissingAutoCreatable => {}
            CheckState::MissingHardFail => {
                return Err(format!("dns mapping status failed: {}", status.summary()))
            }
        }

        run_required(
            runner,
            "nft",
            &[
                "add",
                "chain",
                NFT_FAMILY,
                NFT_TABLE,
                MAPPING_CHAIN,
                "{",
                "type",
                "nat",
                "hook",
                "prerouting",
                "priority",
                "-100;",
                "policy",
                "accept;",
                "comment",
                "\"dynet-owned: dns-mapping:v1\";",
                "}",
            ],
        )?;
        let mut actions = vec![format!(
            "created owned DNS mapping chain {NFT_FAMILY} {NFT_TABLE} {MAPPING_CHAIN}"
        )];
        for rule in mapping_rules(options) {
            let args = rule.iter().map(String::as_str).collect::<Vec<_>>();
            if let Err(error) = run_required(runner, "nft", &args) {
                let rollback = run_required(
                    runner,
                    "nft",
                    &["delete", "chain", NFT_FAMILY, NFT_TABLE, MAPPING_CHAIN],
                );
                return match rollback {
                    Ok(()) => Err(format!(
                        "dns mapping apply failed and rolled back its owned chain: {error}"
                    )),
                    Err(rollback) => Err(format!(
                        "dns mapping apply failed: {error}; owned-chain rollback also failed: {rollback}"
                    )),
                };
            }
        }
        actions.push(format!(
            "mapped UDP/TCP port {} on {} to dynet DNS port {}",
            options.source_port,
            options.scope.interface,
            options.target.port()
        ));
        Ok(actions)
    }

    pub fn dns_mapping_cleanup(&self) -> Result<Vec<String>, String> {
        self.mapping_cleanup_with_runner(&crate::HostRunner)
    }

    pub fn mapping_cleanup_with_runner(
        &self,
        runner: &impl SystemRunner,
    ) -> Result<Vec<String>, String> {
        let status = mapping_status(runner, None);
        match status.state {
            CheckState::MissingAutoCreatable => Ok(Vec::new()),
            CheckState::Ready => {
                run_required(
                    runner,
                    "nft",
                    &["delete", "chain", NFT_FAMILY, NFT_TABLE, MAPPING_CHAIN],
                )?;
                Ok(vec![format!(
                    "deleted owned DNS mapping chain {NFT_FAMILY} {NFT_TABLE} {MAPPING_CHAIN}"
                )])
            }
            CheckState::InvalidHardFail => Err(
                "dns mapping chain exists without the dynet owner marker; refusing cleanup"
                    .to_string(),
            ),
            CheckState::MissingHardFail => Err("dns mapping status command failed".to_string()),
        }
    }
}

fn mapping_status(
    runner: &impl SystemRunner,
    options: Option<&DnsMappingOptions>,
) -> TakeoverCheck {
    let output = runner.run(
        "nft",
        &["list", "chain", NFT_FAMILY, NFT_TABLE, MAPPING_CHAIN],
    );
    let state = match output {
        Ok(output) if !output.success => CheckState::MissingAutoCreatable,
        Ok(output) if mapping_is_expected(&output.stdout, options) => CheckState::Ready,
        Ok(_) => CheckState::InvalidHardFail,
        Err(_) => CheckState::MissingHardFail,
    };
    TakeoverCheck {
        id: "nft.chain.dns-mapping",
        label: "dynet-owned optional DNS port mapping",
        path: None,
        state,
        auto_action: (state == CheckState::MissingAutoCreatable)
            .then_some("explicitly apply the optional DNS mapping"),
    }
}

fn mapping_is_expected(stdout: &str, options: Option<&DnsMappingOptions>) -> bool {
    if !stdout.contains(MAPPING_OWNER_MARKER) {
        return false;
    }
    let Some(options) = options else {
        return true;
    };
    let priority = stdout.contains("type nat hook prerouting priority dstnat;")
        || stdout.contains(&format!(
            "type nat hook prerouting priority {DYNET_NFT_DNS_MAPPING_PRIORITY};"
        ));
    let mut families = vec![("ipv4", "ip", &options.scope.ipv4_sources)];
    if options.ipv6_enabled {
        families.push(("ipv6", "ip6", &options.scope.ipv6_sources));
    }
    let rules_ready = families.into_iter().all(|(nfproto, family, sources)| {
        sources.iter().all(|source| {
            ["udp", "tcp"].into_iter().all(|protocol| {
                stdout.lines().any(|line| {
                    line.contains(&format!("iifname \"{}\"", options.scope.interface))
                        && source_matches(line, family, source)
                        && (line.contains(&format!("meta nfproto {nfproto}"))
                            || line.contains(&format!("{family} saddr")))
                        && line.contains(&format!("{protocol} dport {}", options.source_port))
                        && line
                            .contains(&format!("meta mark set meta mark & {MARK_CLEAR_MASK_HEX}"))
                        && line.contains(&format!("redirect to :{}", options.target.port()))
                })
            })
        })
    });
    let has_unexpected_ipv6 = !options.ipv6_enabled
        && stdout
            .lines()
            .any(|line| line.contains("meta nfproto ipv6") || line.contains("ip6 saddr"));
    priority && rules_ready && !has_unexpected_ipv6
}

fn mapping_interface_status(
    runner: &impl SystemRunner,
    options: &DnsMappingOptions,
) -> TakeoverCheck {
    let output = runner.run("ip", &["link", "show", "dev", &options.scope.interface]);
    let state = match output {
        Ok(output) if output.success => CheckState::Ready,
        Ok(_) | Err(_) => CheckState::MissingHardFail,
    };
    TakeoverCheck {
        id: "dns-mapping.interface",
        label: "caller-selected DNS mapping interface",
        path: None,
        state,
        auto_action: None,
    }
}

fn mapping_rules(options: &DnsMappingOptions) -> Vec<Vec<String>> {
    let mut families = vec![("ipv4", "ip", &options.scope.ipv4_sources)];
    if options.ipv6_enabled {
        families.push(("ipv6", "ip6", &options.scope.ipv6_sources));
    }
    let mut rules = Vec::new();
    for (nfproto, family, sources) in families {
        for source in sources {
            for protocol in ["udp", "tcp"] {
                rules.push(nft_rule(&[
                    "iifname".to_string(),
                    format!("\"{}\"", options.scope.interface),
                    "meta".to_string(),
                    "nfproto".to_string(),
                    nfproto.to_string(),
                    family.to_string(),
                    "saddr".to_string(),
                    source.to_string(),
                    protocol.to_string(),
                    "dport".to_string(),
                    options.source_port.to_string(),
                    "meta".to_string(),
                    "mark".to_string(),
                    "set".to_string(),
                    "meta".to_string(),
                    "mark".to_string(),
                    "&".to_string(),
                    MARK_CLEAR_MASK_HEX.to_string(),
                    "redirect".to_string(),
                    "to".to_string(),
                    format!(":{}", options.target.port()),
                ]));
            }
        }
    }
    rules
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

fn nft_rule(rule: &[String]) -> Vec<String> {
    let mut args = ["add", "rule", NFT_FAMILY, NFT_TABLE, MAPPING_CHAIN]
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
    args.extend_from_slice(rule);
    args
}
