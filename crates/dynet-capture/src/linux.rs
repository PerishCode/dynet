use std::{
    env, fs, io,
    path::{Path, PathBuf},
};

use crate::linux_checks::{
    command_check, device_check, directory_auto_check, directory_check, fragment_check,
    runtime_command_check,
};
use crate::linux_nft::{nft_chain_action, nft_chain_id, nft_chain_label, run_required, NFT_CHAINS};
use crate::{
    ApplyOptions, ApplyReport, CaptureBackend, CaptureBackendInfo, CapturePlatform, CheckState,
    CleanupReport, HostRunner, SystemRunner, TakeoverCheck, TakeoverKind, TakeoverReport,
    TakeoverStatus,
};

const OWNER_MARKER: &str = "# dynet-owned: full-takeover";
const SYSCTL_FRAGMENT: &str = "90-dynet.conf";
const RT_TABLES_FRAGMENT: &str = "dynet.conf";
const DYN_TABLE_ID: u16 = 51880;
const TUN_INTERFACE: &str = "dynet0";
const NFT_FAMILY: &str = "inet";
const NFT_TABLE: &str = "dynet";

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct LinuxTakeover {
    paths: LinuxTakeoverPaths,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LinuxTakeoverPaths {
    pub sysctl_dir: PathBuf,
    pub rt_tables_dir: PathBuf,
    pub systemd_system_dir: PathBuf,
    pub tun_device: PathBuf,
    pub command_dirs: Vec<PathBuf>,
}

impl Default for LinuxTakeoverPaths {
    fn default() -> Self {
        Self {
            sysctl_dir: PathBuf::from("/etc/sysctl.d"),
            rt_tables_dir: PathBuf::from("/etc/iproute2/rt_tables.d"),
            systemd_system_dir: PathBuf::from("/etc/systemd/system"),
            tun_device: PathBuf::from("/dev/net/tun"),
            command_dirs: path_dirs(),
        }
    }
}

impl LinuxTakeover {
    pub fn with_paths(paths: LinuxTakeoverPaths) -> Self {
        Self { paths }
    }

    pub fn doctor(&self) -> TakeoverReport {
        let sysctl_fragment = self.sysctl_fragment();
        let rt_tables_fragment = self.rt_tables_fragment();
        let checks = vec![
            directory_auto_check(
                "sysctl.d",
                "sysctl .d carrier",
                &self.paths.sysctl_dir,
                "create /etc/sysctl.d",
            ),
            fragment_check(
                "sysctl.fragment",
                "dynet sysctl fragment",
                &sysctl_fragment,
                "create /etc/sysctl.d/90-dynet.conf",
            ),
            directory_auto_check(
                "rt_tables.d",
                "iproute2 route-table .d carrier",
                &self.paths.rt_tables_dir,
                "create /etc/iproute2/rt_tables.d",
            ),
            fragment_check(
                "rt_tables.fragment",
                "dynet route-table fragment",
                &rt_tables_fragment,
                "create /etc/iproute2/rt_tables.d/dynet.conf",
            ),
            directory_check(
                "systemd.system",
                "systemd system unit carrier",
                &self.paths.systemd_system_dir,
            ),
            device_check("tun.device", "Linux TUN device", &self.paths.tun_device),
            command_check(
                "ip.command",
                "iproute2 command",
                "ip",
                &self.paths.command_dirs,
            ),
            command_check(
                "nft.command",
                "nftables command",
                "nft",
                &self.paths.command_dirs,
            ),
            command_check(
                "sysctl.command",
                "sysctl command",
                "sysctl",
                &self.paths.command_dirs,
            ),
        ];
        TakeoverReport { checks }
    }

    pub fn status(&self) -> TakeoverStatus {
        self.status_with_runner(&HostRunner)
    }

    pub fn status_with_runner(&self, runner: &impl SystemRunner) -> TakeoverStatus {
        let mut runtime = vec![self.tun_status(runner), self.nft_status(runner)];
        runtime.extend(
            NFT_CHAINS
                .iter()
                .map(|chain| self.nft_chain_status(runner, chain)),
        );
        TakeoverStatus {
            doctor: self.doctor(),
            runtime,
        }
    }

    pub fn apply(&self, options: ApplyOptions) -> Result<ApplyReport, String> {
        self.apply_with_runner(options, &HostRunner)
    }

    pub fn apply_with_runner(
        &self,
        options: ApplyOptions,
        runner: &impl SystemRunner,
    ) -> Result<ApplyReport, String> {
        let before = self.doctor();
        if before.has_hard_failures() {
            return Err(before.failure_summary());
        }
        if before.needs_auto() && !options.auto {
            return Err("dynet takeover requires --auto to create isolated fragments".to_string());
        }

        let mut created = Vec::new();
        if options.auto {
            self.ensure_directory(&self.paths.sysctl_dir, &mut created)?;
            self.ensure_directory(&self.paths.rt_tables_dir, &mut created)?;
            self.ensure_fragment(
                &self.sysctl_fragment(),
                sysctl_fragment_content(),
                &mut created,
            )?;
            self.ensure_fragment(
                &self.rt_tables_fragment(),
                rt_tables_fragment_content(),
                &mut created,
            )?;
        }
        let mut runtime_actions = Vec::new();
        if options.auto {
            self.ensure_tun(runner, &mut runtime_actions)?;
            self.ensure_sysctl_loaded(runner, &mut runtime_actions)?;
            self.ensure_nft_table(runner, &mut runtime_actions)?;
            self.ensure_nft_chains(runner, &mut runtime_actions)?;
        }

        Ok(ApplyReport {
            status: self.doctor(),
            created,
            runtime_actions,
        })
    }

    pub fn cleanup(&self) -> Result<CleanupReport, String> {
        self.cleanup_with_runner(&HostRunner)
    }

    pub fn cleanup_with_runner(&self, runner: &impl SystemRunner) -> Result<CleanupReport, String> {
        let mut runtime_actions = Vec::new();
        self.delete_nft_table(runner, &mut runtime_actions)?;
        self.delete_tun(runner, &mut runtime_actions)?;
        let mut removed = Vec::new();
        self.remove_owned_fragment(&self.sysctl_fragment(), &mut removed)?;
        self.remove_owned_fragment(&self.rt_tables_fragment(), &mut removed)?;
        Ok(CleanupReport {
            removed,
            runtime_actions,
        })
    }

    pub fn backend_info(&self) -> CaptureBackendInfo {
        CaptureBackendInfo {
            name: "linux-tun",
            platform: CapturePlatform::Linux,
            takeover: TakeoverKind::FullDnsUdpTcp,
        }
    }

    fn sysctl_fragment(&self) -> PathBuf {
        self.paths.sysctl_dir.join(SYSCTL_FRAGMENT)
    }

    fn rt_tables_fragment(&self) -> PathBuf {
        self.paths.rt_tables_dir.join(RT_TABLES_FRAGMENT)
    }

    fn ensure_directory(&self, path: &Path, created: &mut Vec<PathBuf>) -> Result<(), String> {
        if path.is_dir() {
            return Ok(());
        }
        if path.exists() {
            return Err(format!(
                "{} exists but is not a directory; refusing to overwrite",
                path.display()
            ));
        }
        fs::create_dir_all(path)
            .map_err(|error| format!("failed creating {}: {error}", path.display()))?;
        created.push(path.to_path_buf());
        Ok(())
    }

    fn ensure_fragment(
        &self,
        path: &Path,
        content: String,
        created: &mut Vec<PathBuf>,
    ) -> Result<(), String> {
        if path.exists() {
            let existing = fs::read_to_string(path)
                .map_err(|error| format!("failed reading {}: {error}", path.display()))?;
            if !existing.contains(OWNER_MARKER) {
                return Err(format!(
                    "{} exists but is not dynet-owned; refusing to overwrite",
                    path.display()
                ));
            }
            if existing == content {
                return Ok(());
            }
        }
        fs::write(path, content)
            .map_err(|error| format!("failed writing {}: {error}", path.display()))?;
        created.push(path.to_path_buf());
        Ok(())
    }

    fn remove_owned_fragment(&self, path: &Path, removed: &mut Vec<PathBuf>) -> Result<(), String> {
        match fs::read_to_string(path) {
            Ok(content) if content.contains(OWNER_MARKER) => {
                fs::remove_file(path)
                    .map_err(|error| format!("failed removing {}: {error}", path.display()))?;
                removed.push(path.to_path_buf());
                Ok(())
            }
            Ok(_) => Err(format!(
                "{} exists but is not dynet-owned; refusing to remove",
                path.display()
            )),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!("failed reading {}: {error}", path.display())),
        }
    }

    fn tun_status(&self, runner: &impl SystemRunner) -> TakeoverCheck {
        runtime_command_check(
            "tun.interface",
            "dynet TUN interface",
            runner.run("ip", &["link", "show", "dev", TUN_INTERFACE]),
            "create dynet0 TUN interface",
        )
    }

    fn nft_status(&self, runner: &impl SystemRunner) -> TakeoverCheck {
        runtime_command_check(
            "nft.table",
            "dynet nftables table",
            runner.run("nft", &["list", "table", NFT_FAMILY, NFT_TABLE]),
            "create inet dynet nftables table",
        )
    }

    fn nft_chain_status(&self, runner: &impl SystemRunner, chain: &'static str) -> TakeoverCheck {
        runtime_command_check(
            nft_chain_id(chain),
            nft_chain_label(chain),
            runner.run("nft", &["list", "chain", NFT_FAMILY, NFT_TABLE, chain]),
            nft_chain_action(chain),
        )
    }

    fn ensure_tun(
        &self,
        runner: &impl SystemRunner,
        actions: &mut Vec<String>,
    ) -> Result<(), String> {
        if self.tun_status(runner).state == CheckState::Ready {
            return Ok(());
        }
        run_required(
            runner,
            "ip",
            &["tuntap", "add", "dev", TUN_INTERFACE, "mode", "tun"],
        )?;
        actions.push(format!("created TUN interface {TUN_INTERFACE}"));
        run_required(runner, "ip", &["link", "set", "dev", TUN_INTERFACE, "up"])?;
        actions.push(format!("set {TUN_INTERFACE} up"));
        Ok(())
    }

    fn ensure_sysctl_loaded(
        &self,
        runner: &impl SystemRunner,
        actions: &mut Vec<String>,
    ) -> Result<(), String> {
        let fragment = self.sysctl_fragment();
        let fragment_arg = fragment.to_string_lossy().into_owned();
        run_required(runner, "sysctl", &["--load", &fragment_arg])?;
        actions.push(format!(
            "loaded dynet sysctl fragment {}",
            fragment.display()
        ));
        Ok(())
    }

    fn ensure_nft_table(
        &self,
        runner: &impl SystemRunner,
        actions: &mut Vec<String>,
    ) -> Result<(), String> {
        if self.nft_status(runner).state == CheckState::Ready {
            return Ok(());
        }
        run_required(runner, "nft", &["add", "table", NFT_FAMILY, NFT_TABLE])?;
        actions.push(format!("created nft table {NFT_FAMILY} {NFT_TABLE}"));
        Ok(())
    }

    fn ensure_nft_chains(
        &self,
        runner: &impl SystemRunner,
        actions: &mut Vec<String>,
    ) -> Result<(), String> {
        for chain in NFT_CHAINS {
            if self.nft_chain_status(runner, chain).state == CheckState::Ready {
                continue;
            }
            run_required(
                runner,
                "nft",
                &["add", "chain", NFT_FAMILY, NFT_TABLE, chain],
            )?;
            actions.push(format!(
                "created nft chain {NFT_FAMILY} {NFT_TABLE} {chain}"
            ));
        }
        Ok(())
    }

    fn delete_tun(
        &self,
        runner: &impl SystemRunner,
        actions: &mut Vec<String>,
    ) -> Result<(), String> {
        if self.tun_status(runner).state != CheckState::Ready {
            return Ok(());
        }
        run_required(runner, "ip", &["link", "delete", "dev", TUN_INTERFACE])?;
        actions.push(format!("deleted TUN interface {TUN_INTERFACE}"));
        Ok(())
    }

    fn delete_nft_table(
        &self,
        runner: &impl SystemRunner,
        actions: &mut Vec<String>,
    ) -> Result<(), String> {
        if self.nft_status(runner).state != CheckState::Ready {
            return Ok(());
        }
        run_required(runner, "nft", &["delete", "table", NFT_FAMILY, NFT_TABLE])?;
        actions.push(format!("deleted nft table {NFT_FAMILY} {NFT_TABLE}"));
        Ok(())
    }
}

impl CaptureBackend for LinuxTakeover {
    fn info(&self) -> CaptureBackendInfo {
        self.backend_info()
    }

    fn doctor(&self) -> TakeoverReport {
        LinuxTakeover::doctor(self)
    }
}

fn path_dirs() -> Vec<PathBuf> {
    env::var_os("PATH")
        .map(|paths| env::split_paths(&paths).collect())
        .unwrap_or_default()
}

fn sysctl_fragment_content() -> String {
    format!(
        "{OWNER_MARKER}\n\
         # Installed by dynet apply --auto. Loaded by sysctl tooling, not by \
         writing global sysctl files.\n\
         net.ipv4.ip_forward = 1\n\
         net.ipv4.conf.all.rp_filter = 0\n\
         net.ipv4.conf.default.rp_filter = 0\n\
         net.ipv4.conf.dynet0.rp_filter = 0\n\
         net.ipv6.conf.all.disable_ipv6 = 1\n\
         net.ipv6.conf.default.disable_ipv6 = 1\n"
    )
}

fn rt_tables_fragment_content() -> String {
    format!("{OWNER_MARKER}\n{DYN_TABLE_ID} dynet\n")
}
