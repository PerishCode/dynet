use std::{
    env, fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use std::{cell::RefCell, collections::BTreeMap};

use dynet_capture::{
    ApplyOptions, CommandOutput, LinuxTakeover, LinuxTakeoverPaths, PlanSafety, SystemRunner,
};

#[test]
fn missing_parent_fails() {
    let root = temp_root("missing-parent");
    let takeover = takeover_under(&root);

    let report = takeover.doctor();

    assert!(report.has_hard_failures());
    assert!(!report.ready());
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
        "sysctl --load {}",
        root.join("etc/sysctl.d/90-dynet.conf").display()
    )));
    assert!(runner.called("nft add table inet dynet"));
    assert!(runner.called("nft add chain inet dynet dynet_bypass"));
    assert!(runner.called("nft add chain inet dynet dynet_dns"));
    assert!(runner.called("nft add chain inet dynet dynet_tcp"));
    assert!(runner.called("nft add chain inet dynet dynet_udp"));
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
        .hooks_apply_with_runner(&FakeRunner::default())
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
        .hooks_apply_with_runner(&runner)
        .expect("hooks apply");

    assert_eq!(actions.len(), 4);
    assert!(runner.called("ip route add default dev dynet0 table dynet"));
    assert!(runner.called("ip rule add pref 10000 fwmark 0x51880 lookup dynet"));
    assert!(runner.called(
        "nft add chain inet dynet dynet_output { type route hook output priority mangle; policy accept; }"
    ));
    assert!(runner.called("nft add rule inet dynet dynet_output meta skuid 1000 return"));
    assert!(runner.called("nft add rule inet dynet dynet_output ip daddr 192.168.1.0/24 return"));
    assert!(runner.called("nft add rule inet dynet dynet_output ip daddr 192.168.20.0/24 return"));
    assert!(runner.called("nft add rule inet dynet dynet_output ip daddr 10.199.0.0/24 return"));
    assert!(
        runner.called("nft add rule inet dynet dynet_output ip protocol tcp meta mark set 0x51880")
    );
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
    assert!(runner.called("ip rule del pref 10000 fwmark 0x51880 lookup dynet"));
    assert!(runner.called("ip route del default dev dynet0 table dynet"));
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
    assert!(runner.called("ip rule del pref 10000 fwmark 0x51880 lookup dynet"));
    assert!(runner.called("ip rule del pref 51880 fwmark 0x51880 lookup dynet"));
    assert!(runner.called("ip route del default dev dynet0 table dynet"));
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

fn takeover_under(root: &Path) -> LinuxTakeover {
    LinuxTakeover::with_paths(LinuxTakeoverPaths {
        sysctl_dir: root.join("etc/sysctl.d"),
        rt_tables_dir: root.join("etc/iproute2/rt_tables.d"),
        systemd_system_dir: root.join("etc/systemd/system"),
        tun_device: root.join("dev/net/tun"),
        command_dirs: vec![root.join("bin")],
    })
}

fn temp_root(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = env::temp_dir().join(format!("dynet-capture-{label}-{nanos}"));
    fs::create_dir_all(&root).expect("temp root");
    root
}

fn cleanup_root(root: &Path) {
    let _ = fs::remove_dir_all(root);
}

fn prepare_doctor_ready_root(root: &Path) {
    fs::create_dir_all(root.join("etc/sysctl.d")).expect("sysctl dir");
    fs::create_dir_all(root.join("etc/iproute2/rt_tables.d")).expect("rt tables dir");
    fs::create_dir_all(root.join("etc/systemd/system")).expect("systemd dir");
    fs::create_dir_all(root.join("dev/net")).expect("dev net dir");
    fs::create_dir_all(root.join("bin")).expect("bin dir");
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
    fs::write(root.join("dev/net/tun"), "").expect("tun placeholder");
    fs::write(root.join("bin/ip"), "").expect("ip command");
    fs::write(root.join("bin/nft"), "").expect("nft command");
    fs::write(root.join("bin/sysctl"), "").expect("sysctl command");
}

#[derive(Default)]
struct FakeRunner {
    ready: BTreeMap<String, bool>,
    calls: RefCell<Vec<String>>,
}

impl FakeRunner {
    fn with_ready_runtime() -> Self {
        let mut ready = BTreeMap::new();
        ready.insert("ip -br link show dev dynet0 up".to_string(), true);
        ready.insert("ip link show dev dynet0".to_string(), true);
        ready.insert("nft list table inet dynet".to_string(), true);
        ready.insert("nft list chain inet dynet dynet_bypass".to_string(), true);
        ready.insert("nft list chain inet dynet dynet_dns".to_string(), true);
        ready.insert("nft list chain inet dynet dynet_tcp".to_string(), true);
        ready.insert("nft list chain inet dynet dynet_udp".to_string(), true);
        Self {
            ready,
            calls: RefCell::new(Vec::new()),
        }
    }

    fn with_existing_down_tun() -> Self {
        let mut ready = BTreeMap::new();
        ready.insert("ip link show dev dynet0".to_string(), true);
        Self {
            ready,
            calls: RefCell::new(Vec::new()),
        }
    }

    fn with_ready_hooks() -> Self {
        let mut runner = Self::with_ready_runtime();
        runner.ready.insert(
            "ip route show table dynet default dev dynet0".to_string(),
            true,
        );
        runner
            .ready
            .insert("ip rule show pref 10000".to_string(), true);
        runner
            .ready
            .insert("nft list chain inet dynet dynet_output".to_string(), true);
        runner
    }

    fn ready_hooks_legacy_rule() -> Self {
        let mut runner = Self::with_ready_hooks();
        runner
            .ready
            .insert("ip rule show pref 51880".to_string(), true);
        runner
    }

    fn called(&self, command: &str) -> bool {
        self.calls.borrow().iter().any(|called| called == command)
    }
}

impl SystemRunner for FakeRunner {
    fn run(&self, command: &str, args: &[&str]) -> Result<CommandOutput, String> {
        let joined = if args.is_empty() {
            command.to_string()
        } else {
            format!("{command} {}", args.join(" "))
        };
        self.calls.borrow_mut().push(joined.clone());
        Ok(CommandOutput {
            success: self.ready.get(&joined).copied().unwrap_or_else(|| {
                joined.starts_with("ip tuntap")
                    || joined.starts_with("ip link set")
                    || joined.starts_with("ip link delete")
                    || joined.starts_with("ip route add")
                    || joined.starts_with("ip route del")
                    || joined.starts_with("ip rule add")
                    || joined.starts_with("ip rule del")
                    || joined.starts_with("sysctl --load")
                    || joined.starts_with("nft add table")
                    || joined.starts_with("nft add chain")
                    || joined.starts_with("nft add rule")
                    || joined.starts_with("nft delete chain")
                    || joined.starts_with("nft delete table")
            }),
            stdout: self
                .ready
                .get(&joined)
                .copied()
                .filter(|ready| *ready)
                .map(|_| joined.clone())
                .unwrap_or_default(),
            stderr: String::new(),
        })
    }
}
