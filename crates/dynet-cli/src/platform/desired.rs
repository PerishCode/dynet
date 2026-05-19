use super::{
    command::{command_exists, command_with_stdin},
    DesiredArtifact, DesiredResource, DesiredState, DesiredValidation, LifecycleStatus, DNS_LISTEN,
    DNS_PORT, NFT_TABLE, ROUTE_MARK, ROUTE_TABLE, RUNTIME_DIR, STATE_DIR, TUN_NAME,
};

pub(super) fn desired_state() -> DesiredState {
    let artifacts = desired_artifacts();
    DesiredState {
        schema: "dynet-platform/v1alpha1".to_string(),
        mutation_mode: "render-only".to_string(),
        resources: desired_resources(),
        validations: validate_artifacts(&artifacts),
        artifacts,
    }
}

fn desired_artifacts() -> Vec<DesiredArtifact> {
    vec![
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
    ]
}

fn desired_resources() -> Vec<DesiredResource> {
    vec![
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
    ]
}

fn validate_artifacts(artifacts: &[DesiredArtifact]) -> Vec<DesiredValidation> {
    let nft = find_artifact(artifacts, "dynet.nft");
    let link_route = find_artifact(artifacts, "dynet-link-route.sh");
    let resolver = find_artifact(artifacts, "dynet-resolver-ownership.txt");

    vec![
        required_fragments_validation(
            "nft-structure",
            "dynet.nft",
            nft,
            &[
                "table inet dynet",
                "chain prerouting_dns",
                "chain output_dns",
                "meta mark 0xd1e7 accept",
                "udp dport 53 redirect to :1053",
                "tcp dport 53 redirect to :1053",
            ],
        ),
        nft_native_validation(nft),
        required_fragments_validation(
            "link-route-structure",
            "dynet-link-route.sh",
            link_route,
            &[
                "ip link show dev dynet0",
                "ip tuntap add dev dynet0 mode tun",
                "ip link set dev dynet0 up",
                "ip rule add fwmark 0xd1e7 lookup 61777 priority 61777",
                "ip route replace default dev dynet0 table 61777",
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
