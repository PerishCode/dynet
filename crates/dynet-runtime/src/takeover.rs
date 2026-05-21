use std::{
    fs,
    path::Path,
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use crate::TakeoverSettings;

const BYPASS_RULE_PRIORITY: &str = "6177";

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TakeoverApplyReport {
    pub schema: String,
    pub action: TakeoverAction,
    pub status: TakeoverStatus,
    pub steps: Vec<TakeoverStepReport>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TakeoverAction {
    Apply,
    Uninstall,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TakeoverStatus {
    Pass,
    Deny,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TakeoverStepReport {
    pub status: TakeoverStatus,
    pub name: String,
    pub message: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TakeoverManifest {
    schema: String,
    installed_at_secs: u64,
    settings: TakeoverSettings,
}

pub fn apply_takeover(settings: &TakeoverSettings) -> TakeoverApplyReport {
    let mut report = TakeoverApplyReport::new(TakeoverAction::Apply);
    if let Err(error) = apply_takeover_inner(settings, &mut report) {
        report.deny("apply", error);
    }
    report
}

pub fn uninstall_takeover(settings: &TakeoverSettings) -> TakeoverApplyReport {
    let mut report = TakeoverApplyReport::new(TakeoverAction::Uninstall);
    if let Err(error) = uninstall_takeover_inner(settings, &mut report) {
        report.deny("uninstall", error);
    }
    report
}

impl TakeoverApplyReport {
    fn new(action: TakeoverAction) -> Self {
        Self {
            schema: "dynet-takeover-apply/v1alpha1".to_string(),
            action,
            status: TakeoverStatus::Pass,
            steps: Vec::new(),
        }
    }

    fn pass(&mut self, name: impl Into<String>, message: impl Into<String>) {
        self.steps.push(TakeoverStepReport {
            status: TakeoverStatus::Pass,
            name: name.into(),
            message: message.into(),
        });
    }

    fn deny(&mut self, name: impl Into<String>, message: impl Into<String>) {
        self.status = TakeoverStatus::Deny;
        self.steps.push(TakeoverStepReport {
            status: TakeoverStatus::Deny,
            name: name.into(),
            message: message.into(),
        });
    }

    pub fn is_pass(&self) -> bool {
        self.status == TakeoverStatus::Pass
    }
}

fn apply_takeover_inner(
    settings: &TakeoverSettings,
    report: &mut TakeoverApplyReport,
) -> Result<(), String> {
    settings.validate()?;
    require_linux_root()?;
    require_dropin_include(settings)?;
    report.pass("preflight", "linux root and nft drop-in include are ready");

    fs::create_dir_all(&settings.runtime_dir)
        .map_err(|error| format!("failed to create runtime dir: {error}"))?;
    if let Some(parent) = settings.manifest_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create manifest dir: {error}"))?;
    }
    report.pass("directories", "runtime and state directories are present");

    write_manifest(settings)?;
    report.pass(
        "manifest",
        format!("wrote {}", settings.manifest_path.display()),
    );

    ensure_tun(settings)?;
    report.pass("tun", format!("{} is present and up", settings.tun_name));

    ensure_bypass_route(settings)?;
    report.pass(
        "bypass-route",
        format!(
            "fwmark {:#x} uses policy table {}",
            settings.bypass_mark, settings.route_table
        ),
    );

    write_atomic(&settings.nft_dropin_path, nft_ruleset(settings).as_bytes())?;
    let (family, name) = settings.nft_family_name();
    let _ = command_status("nft", &["delete", "table", family, name]);
    command_ok(
        "nft",
        &["-f", path_str(&settings.nft_main_config)?],
        "failed to reload nftables",
    )?;
    report.pass(
        "nftables",
        format!("loaded {}", settings.nft_dropin_path.display()),
    );
    Ok(())
}

fn uninstall_takeover_inner(
    requested: &TakeoverSettings,
    report: &mut TakeoverApplyReport,
) -> Result<(), String> {
    requested.validate()?;
    require_linux_root()?;
    let settings = read_manifest(requested).unwrap_or_else(|| requested.clone());
    settings.validate()?;
    report.pass("manifest", manifest_message(requested, &settings));

    let (family, name) = settings.nft_family_name();
    if settings.nft_dropin_path.exists() {
        fs::remove_file(&settings.nft_dropin_path)
            .map_err(|error| format!("failed to remove nft drop-in: {error}"))?;
        report.pass(
            "nft-dropin",
            format!("removed {}", settings.nft_dropin_path.display()),
        );
    } else {
        report.pass("nft-dropin", "dynet nft drop-in is already absent");
    }
    let _ = command_status("nft", &["delete", "table", family, name]);
    if settings.nft_main_config.exists() {
        let _ = command_status("nft", &["-f", path_str(&settings.nft_main_config)?]);
    }

    cleanup_bypass_route(&settings);
    report.pass(
        "bypass-route",
        format!("removed policy table {}", settings.route_table),
    );

    if command_status("ip", &["link", "show", "dev", &settings.tun_name]) {
        command_ok(
            "ip",
            &["link", "delete", "dev", &settings.tun_name],
            "failed to delete tun",
        )?;
        report.pass("tun", format!("deleted {}", settings.tun_name));
    } else {
        report.pass("tun", format!("{} is already absent", settings.tun_name));
    }

    remove_manifest_dirs(&settings)?;
    report.pass(
        "state",
        "removed manifest and empty dynet state directories",
    );
    Ok(())
}

fn require_linux_root() -> Result<(), String> {
    if std::env::consts::OS != "linux" {
        return Err(format!(
            "takeover apply requires linux, current OS is {}",
            std::env::consts::OS
        ));
    }
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::geteuid() } != 0 {
            return Err("takeover apply requires root".to_string());
        }
    }
    Ok(())
}

fn require_dropin_include(settings: &TakeoverSettings) -> Result<(), String> {
    let content = fs::read_to_string(&settings.nft_main_config).map_err(|error| {
        format!(
            "failed to read nft main config {}: {error}",
            settings.nft_main_config.display()
        )
    })?;
    let dropin_dir = settings.nft_dropin_dir.display().to_string();
    let quoted = format!("include \"{dropin_dir}/*.nft\"");
    let bare = format!("include {dropin_dir}/*.nft");
    if content
        .lines()
        .filter_map(|line| line.split('#').next())
        .map(str::trim)
        .any(|line| line == quoted || line == bare)
    {
        Ok(())
    } else {
        Err(format!(
            "{} must include {dropin_dir}/*.nft",
            settings.nft_main_config.display()
        ))
    }
}

fn ensure_tun(settings: &TakeoverSettings) -> Result<(), String> {
    if !command_status("ip", &["link", "show", "dev", &settings.tun_name]) {
        command_ok(
            "ip",
            &["tuntap", "add", "dev", &settings.tun_name, "mode", "tun"],
            "failed to create tun",
        )?;
    }
    command_ok(
        "ip",
        &["link", "set", "dev", &settings.tun_name, "up"],
        "failed to bring tun up",
    )
}

fn ensure_bypass_route(settings: &TakeoverSettings) -> Result<(), String> {
    let default = default_route()?;
    let table = settings.route_table.to_string();
    let mark = format!("{:#x}", settings.bypass_mark);
    delete_bypass_rule(&mark, &table, BYPASS_RULE_PRIORITY);
    delete_bypass_rule(&mark, &table, &table);

    let mut route_args = vec!["route", "replace", "table", &table, "default"];
    if let Some(gateway) = default.gateway.as_deref() {
        route_args.extend(["via", gateway]);
    }
    route_args.extend(["dev", &default.device]);
    command_ok("ip", &route_args, "failed to install dynet bypass route")?;
    command_ok(
        "ip",
        &[
            "rule",
            "add",
            "fwmark",
            &mark,
            "table",
            &table,
            "priority",
            BYPASS_RULE_PRIORITY,
        ],
        "failed to install dynet bypass rule",
    )
}

fn cleanup_bypass_route(settings: &TakeoverSettings) {
    let table = settings.route_table.to_string();
    let mark = format!("{:#x}", settings.bypass_mark);
    delete_bypass_rule(&mark, &table, BYPASS_RULE_PRIORITY);
    delete_bypass_rule(&mark, &table, &table);
    let _ = command_status("ip", &["route", "flush", "table", &table]);
}

fn delete_bypass_rule(mark: &str, table: &str, priority: &str) {
    let _ = command_status(
        "ip",
        &[
            "rule", "del", "fwmark", mark, "table", table, "priority", priority,
        ],
    );
}

struct DefaultRoute {
    gateway: Option<String>,
    device: String,
}

fn default_route() -> Result<DefaultRoute, String> {
    let output = command_stdout("ip", &["-4", "route", "show", "default"])?;
    let line = output
        .lines()
        .find(|line| !line.trim().is_empty())
        .ok_or_else(|| "no IPv4 default route is available for dynet bypass table".to_string())?;
    parse_default_route(line)
}

fn parse_default_route(line: &str) -> Result<DefaultRoute, String> {
    let parts = line.split_whitespace().collect::<Vec<_>>();
    if parts.first().copied() != Some("default") {
        return Err(format!("unexpected IPv4 default route: {line}"));
    }
    let gateway = value_after(&parts, "via").map(str::to_string);
    let device = value_after(&parts, "dev")
        .ok_or_else(|| format!("default route has no device: {line}"))?
        .to_string();
    Ok(DefaultRoute { gateway, device })
}

fn value_after<'a>(parts: &'a [&str], key: &str) -> Option<&'a str> {
    parts
        .windows(2)
        .find_map(|window| (window[0] == key).then_some(window[1]))
}

fn write_manifest(settings: &TakeoverSettings) -> Result<(), String> {
    let manifest = TakeoverManifest {
        schema: "dynet-takeover-manifest/v1alpha1".to_string(),
        installed_at_secs: now_secs(),
        settings: settings.clone(),
    };
    let content = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| format!("failed to serialize takeover manifest: {error}"))?;
    write_atomic(&settings.manifest_path, &content)
}

fn read_manifest(settings: &TakeoverSettings) -> Option<TakeoverSettings> {
    let content = fs::read_to_string(&settings.manifest_path).ok()?;
    serde_json::from_str::<TakeoverManifest>(&content)
        .ok()
        .map(|manifest| manifest.settings)
}

fn manifest_message(requested: &TakeoverSettings, effective: &TakeoverSettings) -> String {
    if requested.manifest_path.exists() {
        format!(
            "using installed manifest {}",
            requested.manifest_path.display()
        )
    } else {
        format!(
            "manifest absent at {}; using requested cleanup scope",
            effective.manifest_path.display()
        )
    }
}

fn remove_manifest_dirs(settings: &TakeoverSettings) -> Result<(), String> {
    if settings.manifest_path.exists() {
        fs::remove_file(&settings.manifest_path)
            .map_err(|error| format!("failed to remove manifest: {error}"))?;
    }
    remove_dir_if_empty(settings.manifest_path.parent())?;
    remove_dir_if_empty(Some(&settings.state_dir))?;
    remove_dir_if_empty(Some(&settings.runtime_dir))
}

fn remove_dir_if_empty(path: Option<&Path>) -> Result<(), String> {
    let Some(path) = path else {
        return Ok(());
    };
    match fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if matches!(error.kind(), std::io::ErrorKind::NotFound) => Ok(()),
        Err(error) if matches!(error.kind(), std::io::ErrorKind::DirectoryNotEmpty) => Ok(()),
        Err(error) => Err(format!(
            "failed to remove empty dir {}: {error}",
            path.display()
        )),
    }
}

fn write_atomic(path: &Path, content: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("path has no parent: {}", path.display()))?;
    let temporary = parent.join(format!(
        ".{}.tmp.{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("dynet"),
        std::process::id()
    ));
    fs::write(&temporary, content)
        .map_err(|error| format!("failed to write {}: {error}", temporary.display()))?;
    fs::rename(&temporary, path)
        .map_err(|error| format!("failed to install {}: {error}", path.display()))
}

fn nft_ruleset(settings: &TakeoverSettings) -> String {
    format!(
        r#"table {nft_table} {{
  chain prerouting_dns {{
    type nat hook prerouting priority dstnat; policy accept;
    meta mark {bypass_mark:#x} accept comment "dynet-owned socket bypass"
    udp dport 53 redirect to :{dns_port} comment "dynet DNS hijack"
    tcp dport 53 redirect to :{dns_port} comment "dynet DNS hijack"
  }}

  chain output_dns {{
    type nat hook output priority dstnat; policy accept;
    meta mark {bypass_mark:#x} accept comment "dynet-owned socket bypass"
    udp dport 53 redirect to :{dns_port} comment "dynet local DNS hijack"
    tcp dport 53 redirect to :{dns_port} comment "dynet local DNS hijack"
  }}
}}
"#,
        bypass_mark = settings.bypass_mark,
        dns_port = settings.dns_bind.port(),
        nft_table = settings.nft_table
    )
}

fn command_status(command: &str, args: &[&str]) -> bool {
    Command::new(command)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn command_stdout(command: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(command)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("failed to run {command}: {error}"))?;
    if output.status.success() {
        String::from_utf8(output.stdout)
            .map_err(|error| format!("{command} output was not UTF-8: {error}"))
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("{command} failed: {stderr}"))
    }
}

fn command_ok(command: &str, args: &[&str], context: &str) -> Result<(), String> {
    let output = Command::new(command)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("{context}: failed to start {command}: {error}"))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let message = if !stderr.is_empty() { stderr } else { stdout };
    Err(format!("{context}: {message}"))
}

fn path_str(path: &Path) -> Result<&str, String> {
    path.to_str()
        .ok_or_else(|| format!("path is not valid UTF-8: {}", path.display()))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
