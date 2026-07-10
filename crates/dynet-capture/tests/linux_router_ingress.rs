use dynet_capture::{LinuxTakeover, RouterHookOptions, TrafficScope};

mod support;
use support::{cleanup_root, prepare_doctor_ready_root, takeover_under, temp_root, FakeRunner};

#[test]
fn apply_scopes_dual_stack() {
    let root = temp_root("router-hooks-apply");
    prepare_doctor_ready_root(&root);
    let takeover = takeover_under(&root);
    let mut runner = FakeRunner::with_ready_runtime();
    runner.set_output("ip link show dev eth1", "3: eth1: <UP>");

    let actions = takeover
        .router_hooks_apply_with(&runner, &dual_stack_options())
        .expect("router hooks apply");

    assert_eq!(actions.len(), 6);
    for command in [
        "ip -4 route add default dev dynet0 table 51880",
        "ip -4 rule add pref 10000 fwmark 0x40000000/0x40000000 lookup 51880",
        "ip -6 route add default dev dynet0 table 51880",
        "ip -6 rule add pref 10000 fwmark 0x40000000/0x40000000 lookup 51880",
        "nft add chain inet dynet dynet_router_ingress { type filter hook prerouting priority -151; policy accept; comment \"dynet-owned: router-ingress:v1\"; }",
        "nft add rule inet dynet dynet_router_ingress meta mark & 0x40000000 != 0 return",
        "nft add rule inet dynet dynet_router_ingress fib daddr type local return",
        "nft add rule inet dynet dynet_router_ingress ip daddr 192.168.0.0/16 return",
        "nft add rule inet dynet dynet_router_ingress ip6 daddr fc00::/7 return",
        "nft add rule inet dynet dynet_router_ingress iifname \"eth1\" ip saddr 192.168.20.12/32 meta l4proto tcp meta mark set meta mark | 0x40000000",
        "nft add rule inet dynet dynet_router_ingress iifname \"eth1\" ip saddr 192.168.20.12/32 meta l4proto udp meta mark set meta mark | 0x40000000",
        "nft add rule inet dynet dynet_router_ingress iifname \"eth1\" ip6 saddr fd00:20::12/128 meta l4proto tcp meta mark set meta mark | 0x40000000",
        "nft add rule inet dynet dynet_router_ingress iifname \"eth1\" ip6 saddr fd00:20::12/128 meta l4proto udp meta mark set meta mark | 0x40000000",
    ] {
        assert!(runner.called(command), "missing {command}");
    }
    assert!(!runner.has_call_containing("192.168.20.13"));
    assert!(!runner.has_call_containing("meta l4proto icmp"));
    cleanup_root(&root);
}

#[test]
fn apply_rejects_bad_scope() {
    let takeover = LinuxTakeover::default();
    for sources in [Vec::new(), vec!["192.168.20.12/24".to_string()]] {
        let error = takeover
            .router_hooks_plan(&RouterHookOptions {
                scope: TrafficScope {
                    interface: "eth1".to_string(),
                    ipv4_sources: sources,
                    ipv6_sources: Vec::new(),
                },
                ipv6_enabled: false,
            })
            .expect_err("invalid source scope refused");
        assert!(error.contains("source") || error.contains("scope"));
    }
}

#[test]
fn apply_rejects_collisions() {
    let root = temp_root("router-hooks-collision");
    prepare_doctor_ready_root(&root);
    let takeover = takeover_under(&root);
    let mut priority = FakeRunner::with_ready_runtime();
    priority.set_output("ip link show dev eth1", "3: eth1: <UP>");
    priority.set_output("ip -4 rule show pref 10000", "10000: from all lookup main");
    let error = takeover
        .router_hooks_apply_with(&priority, &dual_stack_options())
        .expect_err("foreign priority refused");
    assert!(error.contains("foreign or drifted"));

    let mut chain = FakeRunner::with_ready_runtime();
    chain.set_output("ip link show dev eth1", "3: eth1: <UP>");
    chain.set_output(
        "nft list chain inet dynet dynet_router_ingress",
        "chain dynet_router_ingress { meta l4proto tcp accept; }",
    );
    let error = takeover
        .router_hooks_apply_with(&chain, &dual_stack_options())
        .expect_err("foreign chain refused");
    assert!(error.contains("foreign or drifted"));
    assert!(!chain.called("nft delete chain inet dynet dynet_router_ingress"));
    cleanup_root(&root);
}

#[test]
fn partial_apply_rolls_back() {
    let root = temp_root("router-hooks-partial-rollback");
    prepare_doctor_ready_root(&root);
    let takeover = takeover_under(&root);
    let mut runner = FakeRunner::with_ready_runtime();
    runner.set_output("ip link show dev eth1", "3: eth1: <UP>");
    runner.set_ready(
        "nft add rule inet dynet dynet_router_ingress iifname \"eth1\" ip6 saddr fd00:20::12/128 meta l4proto udp meta mark set meta mark | 0x40000000",
        false,
    );

    let error = takeover
        .router_hooks_apply_with(&runner, &dual_stack_options())
        .expect_err("partial apply rejected");

    assert!(error.contains("rolled back newly owned artifacts"));
    assert!(runner.called("nft delete chain inet dynet dynet_router_ingress"));
    for command in [
        "ip -4 rule del pref 10000 fwmark 0x40000000/0x40000000 lookup 51880",
        "ip -4 route del default dev dynet0 table 51880",
        "ip -6 rule del pref 10000 fwmark 0x40000000/0x40000000 lookup 51880",
        "ip -6 route del default dev dynet0 table 51880",
    ] {
        assert!(runner.called(command), "missing rollback {command}");
    }
    cleanup_root(&root);
}

#[test]
fn cleanup_removes_last_routes() {
    let root = temp_root("router-hooks-cleanup");
    let takeover = takeover_under(&root);
    let mut runner = FakeRunner::with_ready_runtime();
    ready_router_hooks(&mut runner);

    let actions = takeover
        .router_hooks_cleanup_with(&runner)
        .expect("router hook cleanup");

    assert_eq!(actions.len(), 5);
    assert!(runner.called("nft delete chain inet dynet dynet_router_ingress"));
    assert!(runner.called("ip -4 rule del pref 10000 fwmark 0x40000000/0x40000000 lookup 51880"));
    assert!(runner.called("ip -4 route del default dev dynet0 table 51880"));
    assert!(runner.called("ip -6 rule del pref 10000 fwmark 0x40000000/0x40000000 lookup 51880"));
    assert!(runner.called("ip -6 route del default dev dynet0 table 51880"));
    cleanup_root(&root);
}

#[test]
fn cleanup_keeps_output_routes() {
    let root = temp_root("router-hooks-shared-cleanup");
    let takeover = takeover_under(&root);
    let mut runner = FakeRunner::with_ready_runtime();
    ready_router_hooks(&mut runner);
    runner.set_output(
        "nft list chain inet dynet dynet_output",
        "chain dynet_output { comment \"dynet-owned: capture-output:v1\"; }",
    );

    let actions = takeover
        .router_hooks_cleanup_with(&runner)
        .expect("router hook cleanup");

    assert_eq!(
        actions,
        vec!["deleted owned nft router ingress hook inet dynet dynet_router_ingress"]
    );
    assert!(!runner.has_call_containing("ip -4 rule del"));
    assert!(!runner.has_call_containing("ip -6 rule del"));
    cleanup_root(&root);
}

#[test]
fn status_rejects_scope_drift() {
    let root = temp_root("router-hooks-status");
    let takeover = takeover_under(&root);
    let mut runner = FakeRunner::with_ready_runtime();
    ready_router_hooks(&mut runner);
    let expected = r#"chain dynet_router_ingress {
        type filter hook prerouting priority mangle - 1; policy accept;
        comment "dynet-owned: router-ingress:v1"
        meta mark & 0x40000000 != 0 return
        fib daddr type local return
        ip daddr 10.0.0.0/8 return
        ip daddr 172.16.0.0/12 return
        ip daddr 192.168.0.0/16 return
        ip6 daddr fe80::/10 return
        ip6 daddr fc00::/7 return
        ip6 daddr ff00::/8 return
        iifname "eth1" ip saddr 192.168.20.12 meta l4proto tcp meta mark set meta mark | 0x40000000
        iifname "eth1" ip saddr 192.168.20.12 meta l4proto udp meta mark set meta mark | 0x40000000
        iifname "eth1" ip6 saddr fd00:20::12 meta l4proto tcp meta mark set meta mark | 0x40000000
        iifname "eth1" ip6 saddr fd00:20::12 meta l4proto udp meta mark set meta mark | 0x40000000
    }"#;
    runner.set_output("nft list chain inet dynet dynet_router_ingress", expected);

    let checks = takeover.router_hooks_status_with(&runner, Some(&dual_stack_options()));
    assert_eq!(
        checks
            .iter()
            .find(|check| check.id == "nft.chain.router-ingress")
            .expect("router status")
            .state,
        dynet_capture::CheckState::Ready
    );

    runner.set_output(
        "nft list chain inet dynet dynet_router_ingress",
        &expected.replace("192.168.20.12", "192.168.20.13"),
    );
    let checks = takeover.router_hooks_status_with(&runner, Some(&dual_stack_options()));
    assert_eq!(
        checks
            .iter()
            .find(|check| check.id == "nft.chain.router-ingress")
            .expect("router status")
            .state,
        dynet_capture::CheckState::InvalidHardFail
    );
    cleanup_root(&root);
}

fn dual_stack_options() -> RouterHookOptions {
    RouterHookOptions {
        scope: TrafficScope {
            interface: "eth1".to_string(),
            ipv4_sources: vec!["192.168.20.12/32".to_string()],
            ipv6_sources: vec!["fd00:20::12/128".to_string()],
        },
        ipv6_enabled: true,
    }
}

fn ready_router_hooks(runner: &mut FakeRunner) {
    runner.set_output(
        "ip -4 route show table 51880",
        "default dev dynet0 scope link",
    );
    runner.set_output(
        "ip -4 rule show pref 10000",
        "10000: from all fwmark 0x40000000/0x40000000 lookup 51880",
    );
    runner.set_output(
        "ip -6 route show table 51880",
        "default dev dynet0 metric 1024",
    );
    runner.set_output(
        "ip -6 rule show pref 10000",
        "10000: from all fwmark 0x40000000/0x40000000 lookup 51880",
    );
    runner.set_output(
        "nft list chain inet dynet dynet_router_ingress",
        "chain dynet_router_ingress { comment \"dynet-owned: router-ingress:v1\"; }",
    );
}
