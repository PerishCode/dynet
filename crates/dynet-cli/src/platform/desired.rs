use super::{
    command::{command_exists, command_with_stdin},
    takeover::{self, TakeoverConfig},
    DesiredArtifact, DesiredResource, DesiredState, DesiredValidation, LifecycleStatus,
};

pub(super) fn desired_state(config: &TakeoverConfig) -> DesiredState {
    let artifacts = desired_artifacts(config);
    DesiredState {
        schema: "dynet-platform/v1alpha1".to_string(),
        mutation_mode: "render-only".to_string(),
        takeover: takeover::plan(config),
        resources: desired_resources(config),
        validations: validate_artifacts(config, &artifacts),
        artifacts,
    }
}

fn desired_artifacts(config: &TakeoverConfig) -> Vec<DesiredArtifact> {
    vec![
        DesiredArtifact {
            kind: "nftables".to_string(),
            name: "dynet.nft".to_string(),
            target: "nft -f -".to_string(),
            content: nftables_template(config),
        },
        DesiredArtifact {
            kind: "iproute2".to_string(),
            name: "dynet-link-route.sh".to_string(),
            target: "root shell".to_string(),
            content: link_route_template(config),
        },
        DesiredArtifact {
            kind: "resolver".to_string(),
            name: "dynet-resolver-ownership.txt".to_string(),
            target: "/etc/resolv.conf and local resolver manager".to_string(),
            content: resolver_template(config),
        },
    ]
}

fn desired_resources(config: &TakeoverConfig) -> Vec<DesiredResource> {
    vec![
        DesiredResource {
            kind: "nft-table".to_string(),
            name: config.nft_table.clone(),
            operation: "create-or-replace".to_string(),
            detail: "exclusive dynet nftables table for DNS interception hooks".to_string(),
        },
        DesiredResource {
            kind: "tun".to_string(),
            name: config.tun_name.clone(),
            operation: "create-or-reuse-owned".to_string(),
            detail: "tun-only packet ingress owned by dynet runtime".to_string(),
        },
        DesiredResource {
            kind: "dns-listener".to_string(),
            name: config.dns_endpoint(),
            operation: "bind-loopback".to_string(),
            detail: "local DNS ingress target for nft redirect templates".to_string(),
        },
        DesiredResource {
            kind: "ip-rule".to_string(),
            name: format!("fwmark {}", config.route_mark),
            operation: "reserve".to_string(),
            detail: format!(
                "policy rule priority {} for dynet-marked traffic",
                config.route_table
            ),
        },
        DesiredResource {
            kind: "route-table".to_string(),
            name: config.route_table.clone(),
            operation: "reserve".to_string(),
            detail: format!("route table for {} policy routing", config.tun_name),
        },
        DesiredResource {
            kind: "runtime-dir".to_string(),
            name: config.runtime_dir.clone(),
            operation: "create-owned".to_string(),
            detail: "ephemeral runtime state".to_string(),
        },
        DesiredResource {
            kind: "state-dir".to_string(),
            name: config.state_dir.clone(),
            operation: "create-owned".to_string(),
            detail: "persistent dynet state".to_string(),
        },
    ]
}

fn validate_artifacts(
    config: &TakeoverConfig,
    artifacts: &[DesiredArtifact],
) -> Vec<DesiredValidation> {
    let nft = find_artifact(artifacts, "dynet.nft");
    let link_route = find_artifact(artifacts, "dynet-link-route.sh");
    let resolver = find_artifact(artifacts, "dynet-resolver-ownership.txt");

    vec![
        required_fragments_validation(
            "nft-structure",
            "dynet.nft",
            nft,
            &[
                &format!("table {}", config.nft_table),
                "chain prerouting_dns",
                "chain output_dns",
                &format!("meta mark {} accept", config.route_mark),
                &format!("udp dport 53 redirect to :{}", config.dns_port),
                &format!("tcp dport 53 redirect to :{}", config.dns_port),
            ],
        ),
        nft_native_validation(nft),
        required_fragments_validation(
            "link-route-structure",
            "dynet-link-route.sh",
            link_route,
            &[
                &format!("ip link show dev {}", config.tun_name),
                &format!("ip tuntap add dev {} mode tun", config.tun_name),
                &format!("ip link set dev {} up", config.tun_name),
                &format!(
                    "ip rule add fwmark {} lookup {} priority {}",
                    config.route_mark, config.route_table, config.route_table
                ),
                &format!(
                    "ip route replace default dev {} table {}",
                    config.tun_name, config.route_table
                ),
            ],
        ),
        forbidden_fragments_validation(
            "link-route-safety",
            "dynet-link-route.sh",
            link_route,
            &["ip route del default", "ip route replace default\n"],
        ),
        required_fragments_validation(
            "resolver-ownership",
            "dynet-resolver-ownership.txt",
            resolver,
            &[
                "snapshot the previous resolver state",
                "restore only the resolver state that dynet previously owned",
                "mutation is disabled in this render-only slice",
            ],
        ),
    ]
}

fn find_artifact<'a>(artifacts: &'a [DesiredArtifact], name: &str) -> Option<&'a str> {
    artifacts
        .iter()
        .find(|artifact| artifact.name == name)
        .map(|artifact| artifact.content.as_str())
}

fn required_fragments_validation(
    name: &str,
    artifact: &str,
    content: Option<&str>,
    fragments: &[&str],
) -> DesiredValidation {
    let Some(content) = content else {
        return artifact_missing(name, artifact);
    };
    let missing = fragments
        .iter()
        .filter(|fragment| !content.contains(**fragment))
        .copied()
        .collect::<Vec<_>>();
    DesiredValidation {
        status: if missing.is_empty() {
            LifecycleStatus::Pass
        } else {
            LifecycleStatus::Deny
        },
        name: name.to_string(),
        artifact: artifact.to_string(),
        message: if missing.is_empty() {
            format!("all {} required fragment(s) are present", fragments.len())
        } else {
            format!("missing required fragment(s): {}", missing.join(", "))
        },
    }
}

fn forbidden_fragments_validation(
    name: &str,
    artifact: &str,
    content: Option<&str>,
    fragments: &[&str],
) -> DesiredValidation {
    let Some(content) = content else {
        return artifact_missing(name, artifact);
    };
    let present = fragments
        .iter()
        .filter(|fragment| content.contains(**fragment))
        .copied()
        .collect::<Vec<_>>();
    DesiredValidation {
        status: if present.is_empty() {
            LifecycleStatus::Pass
        } else {
            LifecycleStatus::Deny
        },
        name: name.to_string(),
        artifact: artifact.to_string(),
        message: if present.is_empty() {
            format!("no forbidden fragment(s) among {}", fragments.len())
        } else {
            format!("forbidden fragment(s) present: {}", present.join(", "))
        },
    }
}

fn nft_native_validation(content: Option<&str>) -> DesiredValidation {
    let artifact = "dynet.nft".to_string();
    let name = "nft-native-check".to_string();
    let Some(content) = content else {
        return artifact_missing(&name, &artifact);
    };
    if std::env::consts::OS != "linux" {
        return DesiredValidation {
            status: LifecycleStatus::Warn,
            name,
            artifact,
            message: format!(
                "nft native parser skipped outside linux: {}",
                std::env::consts::OS
            ),
        };
    }
    if !command_exists("nft") {
        return DesiredValidation {
            status: LifecycleStatus::Warn,
            name,
            artifact,
            message: "nft native parser skipped because nft is missing".to_string(),
        };
    }
    match command_with_stdin("nft", &["-c", "-f", "-"], content) {
        Ok(()) => DesiredValidation {
            status: LifecycleStatus::Pass,
            name,
            artifact,
            message: "nft accepted the rendered ruleset in check mode".to_string(),
        },
        Err(message) if nft_permission_error(&message) => DesiredValidation {
            status: LifecycleStatus::Warn,
            name,
            artifact,
            message: format!("nft check requires CAP_NET_ADMIN; skipped: {message}"),
        },
        Err(message) => DesiredValidation {
            status: LifecycleStatus::Deny,
            name,
            artifact,
            message: format!("nft rejected the rendered ruleset in check mode: {message}"),
        },
    }
}

fn artifact_missing(name: &str, artifact: &str) -> DesiredValidation {
    DesiredValidation {
        status: LifecycleStatus::Deny,
        name: name.to_string(),
        artifact: artifact.to_string(),
        message: "artifact is missing".to_string(),
    }
}

fn nft_permission_error(message: &str) -> bool {
    message.contains("Operation not permitted")
        || message.contains("cache initialization failed")
        || message.contains("Permission denied")
}

fn nftables_template(config: &TakeoverConfig) -> String {
    format!(
        r#"table {nft_table} {{
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
        dns_port = config.dns_port,
        nft_table = config.nft_table,
        route_mark = config.route_mark
    )
}

fn link_route_template(config: &TakeoverConfig) -> String {
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
        route_mark = config.route_mark,
        route_table = config.route_table,
        tun_name = config.tun_name
    )
}

fn resolver_template(config: &TakeoverConfig) -> String {
    format!(
        r#"dynet DNS ownership contract

- dynet owns normal TCP/UDP port 53 interception through nft table {nft_table}.
- redirected DNS traffic lands on {dns_listen}.
- dynet must snapshot the previous resolver state before any future mutation.
- dynet uninstall must restore only the resolver state that dynet previously owned.
- mutation is disabled in this render-only slice.
"#,
        dns_listen = config.dns_endpoint(),
        nft_table = config.nft_table
    )
}
