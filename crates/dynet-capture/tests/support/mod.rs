#![allow(dead_code)]

use std::{
    cell::RefCell,
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use dynet_capture::{CommandOutput, LinuxTakeover, LinuxTakeoverPaths, SystemRunner};

pub fn takeover_under(root: &Path) -> LinuxTakeover {
    LinuxTakeover::with_paths(LinuxTakeoverPaths {
        sysctl_dir: root.join("etc/sysctl.d"),
        rt_tables_dir: root.join("etc/iproute2/rt_tables.d"),
        systemd_system_dir: root.join("etc/systemd/system"),
        tun_device: root.join("dev/net/tun"),
        command_dirs: vec![root.join("bin")],
    })
}

pub fn temp_root(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = env::temp_dir().join(format!("dynet-capture-{label}-{nanos}"));
    fs::create_dir_all(&root).expect("temp root");
    root
}

pub fn cleanup_root(root: &Path) {
    let _ = fs::remove_dir_all(root);
}

pub fn prepare_doctor_ready_root(root: &Path) {
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
pub struct FakeRunner {
    ready: BTreeMap<String, bool>,
    outputs: BTreeMap<String, String>,
    calls: RefCell<Vec<String>>,
}

impl FakeRunner {
    pub fn with_ready_runtime() -> Self {
        let mut ready = BTreeMap::new();
        ready.insert("ip -br link show dev dynet0 up".to_string(), true);
        ready.insert("ip link show dev dynet0".to_string(), true);
        let mut runner = Self {
            ready,
            outputs: BTreeMap::new(),
            calls: RefCell::new(Vec::new()),
        };
        runner.set_output(
            "nft list table inet dynet",
            "table inet dynet { comment \"dynet-owned: runtime-skeleton:v1\"; }",
        );
        for (chain, marker) in [
            ("dynet_bypass", "dynet-owned: runtime-bypass:v1"),
            ("dynet_dns", "dynet-owned: runtime-dns:v1"),
            ("dynet_tcp", "dynet-owned: runtime-tcp:v1"),
            ("dynet_udp", "dynet-owned: runtime-udp:v1"),
        ] {
            runner.set_output(
                &format!("nft list chain inet dynet {chain}"),
                &format!("chain {chain} {{ comment \"{marker}\"; }}"),
            );
        }
        runner
    }

    pub fn with_existing_down_tun() -> Self {
        let mut ready = BTreeMap::new();
        ready.insert("ip link show dev dynet0".to_string(), true);
        Self {
            ready,
            outputs: BTreeMap::new(),
            calls: RefCell::new(Vec::new()),
        }
    }

    pub fn with_ready_hooks() -> Self {
        let mut runner = Self::with_ready_runtime();
        runner.set_output(
            "ip -4 route show table 51880",
            "default dev dynet0 scope link",
        );
        runner.set_output(
            "ip -4 rule show pref 10000",
            "10000: from all fwmark 0x40000000/0x40000000 lookup 51880",
        );
        runner.set_output(
            "nft list chain inet dynet dynet_output",
            "chain dynet_output { comment \"dynet-owned: capture-output:v1\"; meta skuid 999 return; }",
        );
        runner
    }

    pub fn ready_hooks_legacy_rule() -> Self {
        let mut runner = Self::with_ready_hooks();
        runner.set_output(
            "ip rule show pref 51880",
            "51880: from all fwmark 0x51880 lookup dynet",
        );
        runner
    }

    pub fn set_ready(&mut self, command: &str, ready: bool) {
        self.ready.insert(command.to_string(), ready);
    }

    pub fn set_output(&mut self, command: &str, output: &str) {
        self.ready.insert(command.to_string(), true);
        self.outputs.insert(command.to_string(), output.to_string());
    }

    pub fn called(&self, command: &str) -> bool {
        self.calls.borrow().iter().any(|called| called == command)
    }

    pub fn has_call_containing(&self, needle: &str) -> bool {
        self.calls.borrow().iter().any(|call| call.contains(needle))
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
                    || joined.starts_with("ip -4 route add")
                    || joined.starts_with("ip -4 route del")
                    || joined.starts_with("ip -4 rule add")
                    || joined.starts_with("ip -4 rule del")
                    || joined.starts_with("ip -6 route add")
                    || joined.starts_with("ip -6 route del")
                    || joined.starts_with("ip -6 rule add")
                    || joined.starts_with("ip -6 rule del")
                    || joined.starts_with("sysctl -p")
                    || joined.starts_with("nft add table")
                    || joined.starts_with("nft add chain")
                    || joined.starts_with("nft add rule")
                    || joined.starts_with("nft delete chain")
                    || joined.starts_with("nft delete table")
            }),
            stdout: self.outputs.get(&joined).cloned().unwrap_or_else(|| {
                self.ready
                    .get(&joined)
                    .copied()
                    .filter(|ready| *ready)
                    .map(|_| joined.clone())
                    .unwrap_or_default()
            }),
            stderr: String::new(),
        })
    }
}
