use std::fs;

use dynet_capture::{ApplyOptions, HookOptions, LinuxTakeover, PlanSafety};

mod support;
use support::{cleanup_root, prepare_doctor_ready_root, takeover_under, temp_root, FakeRunner};

#[test]
fn missing_parent_fails() {
    let root = temp_root("missing-parent");
    let takeover = takeover_under(&root);

    let report = takeover.doctor_with_runner(&FakeRunner::default());

    assert!(report.has_hard_failures());
    assert!(!report.ready());
    cleanup_root(&root);
}

#[test]
fn doctor_checks_tuntap() {
    let root = temp_root("doctor-portable");
    prepare_doctor_ready_root(&root);
    fs::remove_dir_all(root.join("etc/systemd")).expect("remove systemd carrier");
    let takeover = takeover_under(&root);
    let ready = takeover.doctor_with_runner(&FakeRunner::default());
    assert!(!ready.has_hard_failures());
    assert!(!ready
        .checks
        .iter()
        .any(|check| check.id.contains("systemd")));

    let mut ip_tiny = FakeRunner::default();
    ip_tiny.set_ready("ip tuntap show", false);
    let report = takeover.doctor_with_runner(&ip_tiny);
    let check = report
        .checks
        .iter()
        .find(|check| check.id == "ip.tuntap-capability")
        .expect("tuntap capability check");
    assert_eq!(check.state, dynet_capture::CheckState::MissingHardFail);
    cleanup_root(&root);
}

#[test]
fn auto_creates_fragments() {
    let root = temp_root("auto");
    fs::create_dir_all(root.join("etc/sysctl.d")).expect("sysctl dir");
    fs::create_dir_all(root.join("etc/iproute2/rt_tables.d")).expect("rt tables dir");
    fs::create_dir_all(root.join("etc/systemd/system")).expect("systemd dir");
    fs::create_dir_all(root.join("dev/net")).expect("dev net dir");
    fs::create_dir_all(root.join("bin")).expect("bin dir");
    fs::write(root.join("dev/net/tun"), "").expect("tun placeholder");
    fs::write(root.join("bin/ip"), "").expect("ip command");
    fs::write(root.join("bin/nft"), "").expect("nft command");
    fs::write(root.join("bin/sysctl"), "").expect("sysctl command");
    let takeover = takeover_under(&root);

    let runner = FakeRunner::default();
    let report = takeover
        .apply_with_runner(ApplyOptions { auto: true }, &runner)
        .expect("apply");

    assert_eq!(report.created.len(), 2);
    assert_eq!(report.runtime_actions.len(), 8);
    assert!(root.join("etc/sysctl.d/90-dynet.conf").is_file());
    assert!(root.join("etc/iproute2/rt_tables.d/dynet.conf").is_file());
    assert!(runner.called("ip tuntap add dev dynet0 mode tun"));
    assert!(runner.called("ip link set dev dynet0 up"));
    assert!(runner.called(&format!(
        "sysctl -p {}",
        root.join("etc/sysctl.d/90-dynet.conf").display()
    )));
    assert!(
        runner.called("nft add table inet dynet { comment \"dynet-owned: runtime-skeleton:v1\"; }")
    );
    assert!(runner.called(
        "nft add chain inet dynet dynet_bypass { comment \"dynet-owned: runtime-bypass:v1\"; }"
    ));
    assert!(runner
        .called("nft add chain inet dynet dynet_dns { comment \"dynet-owned: runtime-dns:v1\"; }"));
    assert!(runner
        .called("nft add chain inet dynet dynet_tcp { comment \"dynet-owned: runtime-tcp:v1\"; }"));
    assert!(runner
        .called("nft add chain inet dynet dynet_udp { comment \"dynet-owned: runtime-udp:v1\"; }"));
    cleanup_root(&root);
}

#[test]
fn auto_creates_carriers() {
    let root = temp_root("auto-carriers");
    fs::create_dir_all(root.join("etc/systemd/system")).expect("systemd dir");
    fs::create_dir_all(root.join("dev/net")).expect("dev net dir");
    fs::create_dir_all(root.join("bin")).expect("bin dir");
    fs::write(root.join("dev/net/tun"), "").expect("tun placeholder");
    fs::write(root.join("bin/ip"), "").expect("ip command");
    fs::write(root.join("bin/nft"), "").expect("nft command");
    fs::write(root.join("bin/sysctl"), "").expect("sysctl command");
    let takeover = takeover_under(&root);

    let runner = FakeRunner::default();
    let report = takeover
        .apply_with_runner(ApplyOptions { auto: true }, &runner)
        .expect("apply");

    assert!(report.created.contains(&root.join("etc/sysctl.d")));
    assert!(report
        .created
        .contains(&root.join("etc/iproute2/rt_tables.d")));
    assert!(root.join("etc/sysctl.d/90-dynet.conf").is_file());
    assert!(root.join("etc/iproute2/rt_tables.d/dynet.conf").is_file());
    cleanup_root(&root);
}

#[test]
fn auto_sets_tun_up() {
    let root = temp_root("auto-existing-tun");
    prepare_doctor_ready_root(&root);
    let takeover = takeover_under(&root);
    let runner = FakeRunner::with_existing_down_tun();

    let report = takeover
        .apply_with_runner(ApplyOptions { auto: true }, &runner)
        .expect("apply");

    assert!(report
        .runtime_actions
        .contains(&"set dynet0 up".to_string()));
    assert!(!runner.called("ip tuntap add dev dynet0 mode tun"));
    assert!(runner.called("ip link show dev dynet0"));
    assert!(runner.called("ip link set dev dynet0 up"));
    cleanup_root(&root);
}

#[test]
fn status_reports_chains() {
    let root = temp_root("status");
    let takeover = takeover_under(&root);
    let status = takeover.status_with_runner(&FakeRunner::default());

    assert!(status
        .runtime
        .iter()
        .any(|check| check.id == "nft.chain.dns"));
    assert!(status
        .runtime
        .iter()
        .any(|check| check.id == "nft.chain.tcp"));
    assert!(status
        .runtime
        .iter()
        .any(|check| check.id == "nft.chain.udp"));
    cleanup_root(&root);
}

#[test]
fn plan_blocks_hooks() {
    let plan = LinuxTakeover::default().plan();

    let parser = plan
        .items
        .iter()
        .find(|item| item.id == "packet.parser")
        .expect("packet parser plan item");
    assert_eq!(parser.safety, PlanSafety::LocalSafe);

    let tun_io = plan
        .items
        .iter()
        .find(|item| item.id == "tun.io")
        .expect("TUN IO plan item");
    assert_eq!(tun_io.safety, PlanSafety::VmOnly);

    let hook = plan
        .items
        .iter()
        .find(|item| item.id == "capture.hooks")
        .expect("capture hooks plan item");

    assert_eq!(hook.safety, PlanSafety::VmOnly);
}

#[test]
fn hooks_require_runtime_skeleton() {
    let root = temp_root("hooks-require-runtime");
    prepare_doctor_ready_root(&root);
    let takeover = takeover_under(&root);

    let error = takeover
        .hooks_apply_with_runner(&FakeRunner::default(), 1000)
        .expect_err("missing runtime rejected");

    assert!(error.contains("requires ready runtime skeleton"));
    cleanup_root(&root);
}

#[test]
fn hooks_apply_installs_capture() {
    let root = temp_root("hooks-apply");
    prepare_doctor_ready_root(&root);
    let takeover = takeover_under(&root);
    let runner = FakeRunner::with_ready_runtime();

    let actions = takeover
        .hooks_apply_with_runner(&runner, 1000)
        .expect("hooks apply");

    assert_eq!(actions.len(), 4);
    assert!(runner.called("ip -4 route add default dev dynet0 table 51880"));
    assert!(runner.called("ip -4 rule add pref 10000 fwmark 0x40000000/0x40000000 lookup 51880"));
    assert!(runner.called(
        "nft add chain inet dynet dynet_output { type route hook output priority -150; policy accept; comment \"dynet-owned: capture-output:v1\"; }"
    ));
    assert!(runner.called("nft add rule inet dynet dynet_output meta skuid 1000 return"));
    assert!(
        runner.called("nft add rule inet dynet dynet_output meta mark & 0x40000000 != 0 return")
    );
    assert!(runner.called(
        "nft add rule inet dynet dynet_output meta l4proto tcp meta mark set meta mark | 0x40000000"
    ));
    assert!(runner.called("nft add rule inet dynet dynet_output meta nfproto ipv6 return"));
    cleanup_root(&root);
}

#[test]
fn hooks_reject_drift() {
    let root = temp_root("hooks-stale-service-identity");
    prepare_doctor_ready_root(&root);
    let takeover = takeover_under(&root);
    let runner = FakeRunner::with_ready_hooks();

    let status = takeover.hooks_status_for_with(&runner, 1000);
    assert_ne!(
        status
            .iter()
            .find(|check| check.id == "nft.chain.output")
            .expect("output status")
            .state,
        dynet_capture::CheckState::Ready
    );

    let error = takeover
        .hooks_apply_with_runner(&runner, 1000)
        .expect_err("drifted hook refused");

    assert!(error.contains("foreign or drifted artifacts"));
    assert!(!runner.called("nft delete chain inet dynet dynet_output"));
    cleanup_root(&root);
}

#[test]
fn hooks_apply_dual_stack() {
    let root = temp_root("hooks-apply-ipv6");
    prepare_doctor_ready_root(&root);
    let takeover = takeover_under(&root);
    let runner = FakeRunner::with_ready_runtime();

    takeover
        .hooks_apply_options_with(
            &runner,
            HookOptions {
                service_uid: 1000,
                ipv6_enabled: true,
            },
        )
        .expect("IPv6 hooks apply");

    assert!(runner.called("ip -6 route add default dev dynet0 table 51880"));
    assert!(runner.called("ip -6 rule add pref 10000 fwmark 0x40000000/0x40000000 lookup 51880"));
    assert!(runner.called("nft add rule inet dynet dynet_output ip6 daddr ::1 return"));
    assert!(runner.called("nft add rule inet dynet dynet_output ip6 daddr ff00::/8 return"));
    assert!(!runner.called("nft add rule inet dynet dynet_output meta nfproto ipv6 return"));
    assert!(!runner.has_call_containing("icmp"));
    assert!(!runner.has_call_containing("meta l4proto 53"));
    cleanup_root(&root);
}

#[test]
fn hooks_reject_priority_collision() {
    let root = temp_root("hooks-foreign-priority");
    prepare_doctor_ready_root(&root);
    let takeover = takeover_under(&root);
    let mut runner = FakeRunner::with_ready_runtime();
    runner.set_output("ip -4 rule show pref 10000", "10000: from all lookup main");

    let error = takeover
        .hooks_apply_with_runner(&runner, 1000)
        .expect_err("foreign priority refused");

    assert!(error.contains("foreign or drifted artifacts"));
    assert!(!runner.called("ip -4 route add default dev dynet0 table 51880"));
    cleanup_root(&root);
}

#[test]
fn hooks_cleanup_removes_capture() {
    let root = temp_root("hooks-cleanup");
    let takeover = takeover_under(&root);
    let runner = FakeRunner::with_ready_hooks();

    let actions = takeover
        .hooks_cleanup_with_runner(&runner)
        .expect("hooks cleanup");

    assert_eq!(actions.len(), 3);
    assert!(runner.called("nft delete chain inet dynet dynet_output"));
    assert!(runner.called("ip -4 rule del pref 10000 fwmark 0x40000000/0x40000000 lookup 51880"));
    assert!(runner.called("ip -4 route del default dev dynet0 table 51880"));
    cleanup_root(&root);
}

#[test]
fn cleanup_removes_legacy_rule() {
    let root = temp_root("hooks-cleanup-legacy-rule");
    let takeover = takeover_under(&root);
    let runner = FakeRunner::ready_hooks_legacy_rule();

    let actions = takeover
        .hooks_cleanup_with_runner(&runner)
        .expect("hooks cleanup");

    assert_eq!(actions.len(), 4);
    assert!(runner.called("nft delete chain inet dynet dynet_output"));
    assert!(runner.called("ip -4 rule del pref 10000 fwmark 0x40000000/0x40000000 lookup 51880"));
    assert!(runner.called("ip rule del pref 51880 fwmark 0x51880 lookup 51880"));
    assert!(runner.called("ip -4 route del default dev dynet0 table 51880"));
    cleanup_root(&root);
}

#[test]
fn cleanup_rejects_foreign() {
    let root = temp_root("cleanup-unowned");
    fs::create_dir_all(root.join("etc/sysctl.d")).expect("sysctl dir");
    fs::create_dir_all(root.join("etc/iproute2/rt_tables.d")).expect("rt tables dir");
    fs::write(root.join("etc/sysctl.d/90-dynet.conf"), "foreign").expect("foreign");
    let takeover = takeover_under(&root);

    let error = takeover
        .cleanup_with_runner(&FakeRunner::default())
        .expect_err("foreign fragment rejected");

    assert!(error.contains("not dynet-owned"));
    cleanup_root(&root);
}

#[test]
fn cleanup_deletes_runtime() {
    let root = temp_root("cleanup-runtime");
    fs::create_dir_all(root.join("etc/sysctl.d")).expect("sysctl dir");
    fs::create_dir_all(root.join("etc/iproute2/rt_tables.d")).expect("rt tables dir");
    fs::write(
        root.join("etc/sysctl.d/90-dynet.conf"),
        "# dynet-owned: full-takeover\n",
    )
    .expect("sysctl fragment");
    fs::write(
        root.join("etc/iproute2/rt_tables.d/dynet.conf"),
        "# dynet-owned: full-takeover\n",
    )
    .expect("route fragment");
    let takeover = takeover_under(&root);
    let runner = FakeRunner::with_ready_runtime();

    let report = takeover.cleanup_with_runner(&runner).expect("cleanup");

    assert_eq!(report.runtime_actions.len(), 2);
    assert!(runner.called("nft delete table inet dynet"));
    assert!(runner.called("ip link delete dev dynet0"));
    cleanup_root(&root);
}
