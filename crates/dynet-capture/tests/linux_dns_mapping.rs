use dynet_capture::{DnsMappingOptions, LinuxTakeover, TrafficScope};

mod support;
use support::{cleanup_root, takeover_under, temp_root, FakeRunner};

#[test]
fn mapping_apply_dual_stack() {
    let root = temp_root("dns-mapping-apply");
    let takeover = takeover_under(&root);
    let mut runner = FakeRunner::with_ready_runtime();
    runner.set_output("ip link show dev br-lan", "7: br-lan: <UP>");
    let options = DnsMappingOptions {
        scope: dual_stack_scope(),
        source_port: 53,
        target: "[::]:1053".parse().expect("target"),
        ipv6_enabled: true,
    };

    let actions = takeover
        .mapping_apply_with_runner(&runner, &options)
        .expect("DNS mapping apply");

    assert_eq!(actions.len(), 2);
    assert!(runner.called(
        "nft add chain inet dynet dynet_dns_mapping { type nat hook prerouting priority -100; policy accept; comment \"dynet-owned: dns-mapping:v1\"; }"
    ));
    for command in [
        "nft add rule inet dynet dynet_dns_mapping iifname \"br-lan\" meta nfproto ipv4 ip saddr 192.168.20.12/32 udp dport 53 meta mark set meta mark & 0xbfffffff redirect to :1053",
        "nft add rule inet dynet dynet_dns_mapping iifname \"br-lan\" meta nfproto ipv4 ip saddr 192.168.20.12/32 tcp dport 53 meta mark set meta mark & 0xbfffffff redirect to :1053",
        "nft add rule inet dynet dynet_dns_mapping iifname \"br-lan\" meta nfproto ipv6 ip6 saddr fd00:20::12/128 udp dport 53 meta mark set meta mark & 0xbfffffff redirect to :1053",
        "nft add rule inet dynet dynet_dns_mapping iifname \"br-lan\" meta nfproto ipv6 ip6 saddr fd00:20::12/128 tcp dport 53 meta mark set meta mark & 0xbfffffff redirect to :1053",
    ] {
        assert!(runner.called(command), "missing {command}");
    }
    for foreign in ["uci", "fw4", "dnsmasq"] {
        assert!(!runner.has_call_containing(foreign));
    }
    cleanup_root(&root);
}

#[test]
fn mapping_cleanup_is_owned() {
    let root = temp_root("dns-mapping-cleanup");
    let takeover = takeover_under(&root);
    let mut owned = FakeRunner::default();
    owned.set_output(
        "nft list chain inet dynet dynet_dns_mapping",
        "chain dynet_dns_mapping { comment \"dynet-owned: dns-mapping:v1\"; }",
    );

    let actions = takeover
        .mapping_cleanup_with_runner(&owned)
        .expect("owned cleanup");
    assert_eq!(actions.len(), 1);
    assert!(owned.called("nft delete chain inet dynet dynet_dns_mapping"));

    let mut foreign = FakeRunner::default();
    foreign.set_output(
        "nft list chain inet dynet dynet_dns_mapping",
        "chain dynet_dns_mapping { udp dport 53 accept; }",
    );
    let error = takeover
        .mapping_cleanup_with_runner(&foreign)
        .expect_err("foreign mapping refused");
    assert!(error.contains("without the dynet owner marker"));
    assert!(!foreign.called("nft delete chain inet dynet dynet_dns_mapping"));
    cleanup_root(&root);
}

#[test]
fn mapping_rejects_unsafe_targets() {
    let takeover = LinuxTakeover::default();
    let error = takeover
        .dns_mapping_plan(&DnsMappingOptions {
            scope: TrafficScope {
                interface: "br-lan".to_string(),
                ipv4_sources: vec!["192.168.20.12/32".to_string()],
                ipv6_sources: Vec::new(),
            },
            source_port: 53,
            target: "127.0.0.1:1053".parse().expect("target"),
            ipv6_enabled: false,
        })
        .expect_err("loopback target refused");

    assert!(error.contains("unspecified bind address"));
}

#[test]
fn mapping_rejects_bad_scope() {
    let takeover = LinuxTakeover::default();
    for sources in [Vec::new(), vec!["192.168.20.12/24".to_string()]] {
        let error = takeover
            .dns_mapping_plan(&DnsMappingOptions {
                scope: TrafficScope {
                    interface: "br-lan".to_string(),
                    ipv4_sources: sources,
                    ipv6_sources: Vec::new(),
                },
                source_port: 53,
                target: "0.0.0.0:1053".parse().expect("target"),
                ipv6_enabled: false,
            })
            .expect_err("unsafe source scope refused");
        assert!(error.contains("source") || error.contains("scope"));
    }
}

#[test]
fn mapping_status_checks_scope() {
    let root = temp_root("dns-mapping-status");
    let takeover = takeover_under(&root);
    let mut runner = FakeRunner::with_ready_runtime();
    let options = DnsMappingOptions {
        scope: dual_stack_scope(),
        source_port: 53,
        target: "[::]:1053".parse().expect("target"),
        ipv6_enabled: true,
    };
    let expected = r#"chain dynet_dns_mapping {
        type nat hook prerouting priority -100; policy accept;
        comment "dynet-owned: dns-mapping:v1"
        iifname "br-lan" ip saddr 192.168.20.12 udp dport 53 meta mark set meta mark & 0xbfffffff redirect to :1053
        iifname "br-lan" ip saddr 192.168.20.12 tcp dport 53 meta mark set meta mark & 0xbfffffff redirect to :1053
        iifname "br-lan" ip6 saddr fd00:20::12 udp dport 53 meta mark set meta mark & 0xbfffffff redirect to :1053
        iifname "br-lan" ip6 saddr fd00:20::12 tcp dport 53 meta mark set meta mark & 0xbfffffff redirect to :1053
    }"#;
    runner.set_output("nft list chain inet dynet dynet_dns_mapping", expected);

    let checks = takeover
        .mapping_status_with(&runner, &options)
        .expect("mapping status");
    assert_eq!(checks[0].state, dynet_capture::CheckState::Ready);

    runner.set_output(
        "nft list chain inet dynet dynet_dns_mapping",
        &expected.replace("0xbfffffff", "0xffffffff"),
    );
    let checks = takeover
        .mapping_status_with(&runner, &options)
        .expect("mapping status");
    assert_eq!(checks[0].state, dynet_capture::CheckState::InvalidHardFail);
    cleanup_root(&root);
}

fn dual_stack_scope() -> TrafficScope {
    TrafficScope {
        interface: "br-lan".to_string(),
        ipv4_sources: vec!["192.168.20.12/32".to_string()],
        ipv6_sources: vec!["fd00:20::12/128".to_string()],
    }
}
