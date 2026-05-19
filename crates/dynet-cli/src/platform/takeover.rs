use std::{
    env,
    net::IpAddr,
    path::{Component, Path, PathBuf},
};

use serde::Serialize;

use super::{LifecycleCheck, LifecycleStatus};

const DEFAULT_NFT_TABLE: &str = "inet dynet";
const DEFAULT_NFT_MAIN_CONFIG: &str = "/etc/nftables.conf";
const DEFAULT_NFT_DROPIN_DIR: &str = "/etc/nftables.d";
const DEFAULT_TUN_NAME: &str = "dynet0";
const DEFAULT_ROUTE_MARK: &str = "0xd1e7";
const DEFAULT_ROUTE_TABLE: &str = "61777";
const DEFAULT_DNS_LISTEN: &str = "127.0.0.1";
const DEFAULT_DNS_PORT: &str = "1053";
const DEFAULT_RUNTIME_DIR: &str = "/run/dynet";
const DEFAULT_STATE_DIR: &str = "/var/lib/dynet";

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TakeoverConfig {
    pub(crate) nft_table: String,
    pub(crate) nft_main_config: String,
    pub(crate) nft_dropin_dir: String,
    pub(crate) nft_dropin_path: String,
    pub(crate) tun_name: String,
    pub(crate) route_mark: String,
    pub(crate) route_table: String,
    pub(crate) dns_listen: String,
    pub(crate) dns_port: String,
    pub(crate) runtime_dir: String,
    pub(crate) state_dir: String,
    pub(crate) manifest_path: String,
    pub(crate) env_overrides: Vec<EnvOverride>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EnvOverride {
    pub(crate) name: String,
    pub(crate) value: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TakeoverPlan {
    pub(crate) schema: String,
    pub(crate) config: TakeoverConfig,
    pub(crate) manifest: TakeoverManifest,
    pub(crate) steps: Vec<TakeoverStep>,
    pub(crate) rollback_steps: Vec<TakeoverStep>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TakeoverManifest {
    pub(crate) schema: String,
    pub(crate) path: String,
    pub(crate) authority: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TakeoverStep {
    pub(crate) phase: String,
    pub(crate) name: String,
    pub(crate) operation: String,
}

#[derive(Debug, Clone)]
struct FieldSpec {
    env: &'static str,
    default: &'static str,
    kind: FieldKind,
}

#[derive(Debug, Clone, Copy)]
enum FieldKind {
    DnsListen,
    DnsPort,
    Interface,
    NftTable,
    Path,
    RouteMark,
    RouteTable,
}

impl TakeoverConfig {
    pub(super) fn nft_family_name(&self) -> (&str, &str) {
        self.nft_table
            .split_once(' ')
            .expect("validated nft table has family and name")
    }

    pub(crate) fn dns_endpoint(&self) -> String {
        match self
            .dns_listen
            .parse::<IpAddr>()
            .expect("validated dns listen is an IP address")
        {
            IpAddr::V4(address) => format!("{address}:{}", self.dns_port),
            IpAddr::V6(address) => format!("[{address}]:{}", self.dns_port),
        }
    }

    pub(crate) fn nft_main_config(&self) -> &str {
        &self.nft_main_config
    }
}

pub(super) fn load_config() -> (TakeoverConfig, Vec<LifecycleCheck>) {
    let mut checks = Vec::new();
    let mut overrides = Vec::new();

    let nft_table = load_field(
        spec("DYNET_NFT_TABLE", DEFAULT_NFT_TABLE, FieldKind::NftTable),
        &mut overrides,
        &mut checks,
    );
    let nft_main_config = load_field(
        spec(
            "DYNET_NFT_MAIN_CONFIG",
            DEFAULT_NFT_MAIN_CONFIG,
            FieldKind::Path,
        ),
        &mut overrides,
        &mut checks,
    );
    let nft_dropin_dir = load_field(
        spec(
            "DYNET_NFT_DROPIN_DIR",
            DEFAULT_NFT_DROPIN_DIR,
            FieldKind::Path,
        ),
        &mut overrides,
        &mut checks,
    );
    let tun_name = load_field(
        spec("DYNET_TUN_NAME", DEFAULT_TUN_NAME, FieldKind::Interface),
        &mut overrides,
        &mut checks,
    );
    let route_mark = load_field(
        spec("DYNET_ROUTE_MARK", DEFAULT_ROUTE_MARK, FieldKind::RouteMark),
        &mut overrides,
        &mut checks,
    );
    let route_table = load_field(
        spec(
            "DYNET_ROUTE_TABLE",
            DEFAULT_ROUTE_TABLE,
            FieldKind::RouteTable,
        ),
        &mut overrides,
        &mut checks,
    );
    let dns_listen = load_field(
        spec("DYNET_DNS_LISTEN", DEFAULT_DNS_LISTEN, FieldKind::DnsListen),
        &mut overrides,
        &mut checks,
    );
    let dns_port = load_field(
        spec("DYNET_DNS_PORT", DEFAULT_DNS_PORT, FieldKind::DnsPort),
        &mut overrides,
        &mut checks,
    );
    let runtime_dir = load_field(
        spec("DYNET_RUNTIME_DIR", DEFAULT_RUNTIME_DIR, FieldKind::Path),
        &mut overrides,
        &mut checks,
    );
    let state_dir = load_field(
        spec("DYNET_STATE_DIR", DEFAULT_STATE_DIR, FieldKind::Path),
        &mut overrides,
        &mut checks,
    );
    let manifest_path = Path::new(&state_dir)
        .join("takeover")
        .join("manifest.json")
        .display()
        .to_string();
    let nft_dropin_path = Path::new(&nft_dropin_dir)
        .join("dynet.nft")
        .display()
        .to_string();

    checks.push(LifecycleCheck {
        status: LifecycleStatus::Pass,
        name: "takeover-config".to_string(),
        message: format!(
            "effective takeover config loaded with {} env override(s); manifest will freeze values at {}",
            overrides.len(),
            manifest_path
        ),
    });
    checks.push(dropin_dir_check(&nft_dropin_dir));
    checks.push(dropin_include_check(&nft_main_config, &nft_dropin_dir));

    (
        TakeoverConfig {
            nft_table,
            nft_main_config,
            nft_dropin_dir,
            nft_dropin_path,
            tun_name,
            route_mark,
            route_table,
            dns_listen,
            dns_port,
            runtime_dir,
            state_dir,
            manifest_path,
            env_overrides: overrides,
        },
        checks,
    )
}

pub(super) fn plan(config: &TakeoverConfig) -> TakeoverPlan {
    TakeoverPlan {
        schema: "dynet-takeover/v1alpha1".to_string(),
        config: config.clone(),
        manifest: TakeoverManifest {
            schema: "dynet-takeover-manifest/v1alpha1".to_string(),
            path: config.manifest_path.clone(),
            authority: "verify, rollback, and uninstall use the installed manifest as truth; env only builds new takeover plans".to_string(),
        },
        steps: vec![
            step(
                "preflight",
                "verify-nft-dropin",
                format!(
                    "require {} to include {}/*.nft",
                    config.nft_main_config(),
                    config.nft_dropin_dir
                ),
            ),
            step("preflight", "bind-dns-listener", format!("bind {}", config.dns_endpoint())),
            step("stage", "create-tun", format!("create tun {}", config.tun_name)),
            step("stage", "write-manifest", format!("write {}", config.manifest_path)),
            step(
                "apply",
                "write-nft-dropin",
                format!("write {}", config.nft_dropin_path),
            ),
            step(
                "apply",
                "reload-nftables",
                "reload nftables through host drop-in mechanism",
            ),
            step(
                "apply",
                "install-policy-route",
                format!(
                    "install fwmark {} lookup {} for {}",
                    config.route_mark, config.route_table, config.tun_name
                ),
            ),
            step("prove", "dns-hijack", "prove normal DNS reaches dynet listener"),
        ],
        rollback_steps: vec![
            step(
                "rollback",
                "remove-nft-dropin",
                format!("delete {}", config.nft_dropin_path),
            ),
            step(
                "rollback",
                "reload-nftables",
                "reload nftables after removing dynet drop-in",
            ),
            step(
                "rollback",
                "remove-policy-route",
                format!("remove fwmark {} lookup {}", config.route_mark, config.route_table),
            ),
            step("rollback", "remove-tun", format!("delete tun {}", config.tun_name)),
            step("rollback", "restore-resolver", "restore manifest-owned resolver snapshot"),
        ],
    }
}

fn step(phase: &str, name: &str, operation: impl Into<String>) -> TakeoverStep {
    TakeoverStep {
        phase: phase.to_string(),
        name: name.to_string(),
        operation: operation.into(),
    }
}

fn spec(env: &'static str, default: &'static str, kind: FieldKind) -> FieldSpec {
    FieldSpec { env, default, kind }
}

fn load_field(
    spec: FieldSpec,
    overrides: &mut Vec<EnvOverride>,
    checks: &mut Vec<LifecycleCheck>,
) -> String {
    match env::var(spec.env) {
        Ok(value) => match validate_value(&value, spec.kind) {
            Ok(()) => {
                overrides.push(EnvOverride {
                    name: spec.env.to_string(),
                    value: value.clone(),
                });
                value
            }
            Err(message) => {
                checks.push(LifecycleCheck {
                    status: LifecycleStatus::Deny,
                    name: format!("env:{}", spec.env),
                    message: format!(
                        "{message}; using default `{}` for render-only output",
                        spec.default
                    ),
                });
                spec.default.to_string()
            }
        },
        Err(env::VarError::NotPresent) => spec.default.to_string(),
        Err(env::VarError::NotUnicode(_)) => {
            checks.push(LifecycleCheck {
                status: LifecycleStatus::Deny,
                name: format!("env:{}", spec.env),
                message: format!(
                    "override is not valid unicode; using default `{}` for render-only output",
                    spec.default
                ),
            });
            spec.default.to_string()
        }
    }
}

fn dropin_dir_check(path: &str) -> LifecycleCheck {
    let exists = Path::new(path).is_dir();
    LifecycleCheck {
        status: if exists {
            LifecycleStatus::Pass
        } else {
            LifecycleStatus::Deny
        },
        name: "nft-dropin-dir".to_string(),
        message: if exists {
            format!("nftables drop-in directory exists: {path}")
        } else {
            format!("nftables drop-in directory is required before dynet can serve: {path}")
        },
    }
}

fn dropin_include_check(main_config: &str, dropin_dir: &str) -> LifecycleCheck {
    let main = Path::new(main_config);
    let content = std::fs::read_to_string(main);
    let included = content
        .as_deref()
        .map(|content| includes_dropin_pattern(content, dropin_dir))
        .unwrap_or(false);
    LifecycleCheck {
        status: if included {
            LifecycleStatus::Pass
        } else {
            LifecycleStatus::Deny
        },
        name: "nft-dropin-include".to_string(),
        message: if included {
            format!("{} includes {dropin_dir}/*.nft", main.display())
        } else {
            format!(
                "{} must explicitly include {dropin_dir}/*.nft before dynet writes its drop-in",
                main.display()
            )
        },
    }
}

fn includes_dropin_pattern(content: &str, dropin_dir: &str) -> bool {
    let quoted = format!("include \"{dropin_dir}/*.nft\"");
    let bare = format!("include {dropin_dir}/*.nft");
    content
        .lines()
        .filter_map(|line| line.split('#').next())
        .map(str::trim)
        .any(|line| line == quoted || line == bare)
}

fn validate_value(value: &str, kind: FieldKind) -> Result<(), String> {
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err("override must be non-empty and contain no control characters".to_string());
    }
    match kind {
        FieldKind::DnsListen => value
            .parse::<IpAddr>()
            .map(|_| ())
            .map_err(|_| "DYNET_DNS_LISTEN must be an IP address without port".to_string()),
        FieldKind::DnsPort => validate_u16(value, "DYNET_DNS_PORT"),
        FieldKind::Interface => validate_name(value, 15, "interface name"),
        FieldKind::NftTable => validate_nft_table(value),
        FieldKind::Path => validate_absolute_path(value),
        FieldKind::RouteMark => validate_route_mark(value),
        FieldKind::RouteTable => validate_u32(value, "route table"),
    }
}

fn validate_name(value: &str, max: usize, label: &str) -> Result<(), String> {
    if value.len() > max {
        return Err(format!("{label} must be at most {max} bytes"));
    }
    if value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        && !value.contains("..")
    {
        Ok(())
    } else {
        Err(format!("{label} contains unsupported characters"))
    }
}

fn validate_nft_table(value: &str) -> Result<(), String> {
    let Some((family, name)) = value.split_once(' ') else {
        return Err("DYNET_NFT_TABLE must look like `inet dynet`".to_string());
    };
    if value.split_whitespace().count() != 2 {
        return Err("DYNET_NFT_TABLE must contain exactly family and table name".to_string());
    }
    match family {
        "ip" | "ip6" | "inet" | "arp" | "bridge" | "netdev" => {}
        _ => return Err("DYNET_NFT_TABLE uses unsupported nft family".to_string()),
    }
    validate_name(name, 64, "nft table name")
}

fn validate_absolute_path(value: &str) -> Result<(), String> {
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err("path override must be absolute".to_string());
    }
    for component in path.components() {
        match component {
            Component::RootDir | Component::Normal(_) => {}
            _ => return Err("path override must not contain traversal or prefixes".to_string()),
        }
    }
    Ok(())
}

fn validate_route_mark(value: &str) -> Result<(), String> {
    let parsed = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map(|hex| u32::from_str_radix(hex, 16))
        .unwrap_or_else(|| value.parse::<u32>());
    parsed
        .map(|_| ())
        .map_err(|_| "DYNET_ROUTE_MARK must be u32 decimal or 0x-prefixed hex".to_string())
}

fn validate_u16(value: &str, label: &str) -> Result<(), String> {
    match value.parse::<u16>() {
        Ok(0) | Err(_) => Err(format!("{label} must be an integer from 1 to 65535")),
        Ok(_) => Ok(()),
    }
}

fn validate_u32(value: &str, label: &str) -> Result<(), String> {
    match value.parse::<u32>() {
        Ok(0) | Err(_) => Err(format!("{label} must be a positive u32 integer")),
        Ok(_) => Ok(()),
    }
}
