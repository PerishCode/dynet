use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Component, Path, PathBuf},
    time::Duration,
};

use serde::{Deserialize, Serialize};

use dynet_core::{build_plan, AppState, DynetConfig, NetworkNode, OutboundQualityState, Plan};

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TakeoverSettings {
    pub nft_table: String,
    pub nft_main_config: PathBuf,
    pub nft_dropin_dir: PathBuf,
    pub nft_dropin_path: PathBuf,
    pub tun_name: String,
    pub bypass_mark: u32,
    pub route_table: u32,
    pub dns_bind: SocketAddr,
    pub upstream_dns: SocketAddr,
    pub runtime_dir: PathBuf,
    pub state_dir: PathBuf,
    pub manifest_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeSettings {
    pub tun_name: String,
    pub dns_bind: SocketAddr,
    pub dns_chain: DnsRuntimeChain,
    pub bypass_mark: u32,
    pub tcp_forwarding: TcpForwardingSettings,
    pub udp_forwarding: UdpForwardingSettings,
    #[serde(skip_serializing)]
    pub policy: Option<RuntimePolicy>,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TcpForwardingSettings {
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UdpForwardingSettings {
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RuntimePolicy {
    pub state: AppState,
    pub plan: Plan,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum DnsRuntimeChain {
    Udp {
        upstream_dns: SocketAddr,
    },
    Doh {
        endpoint: String,
        bootstrap_ips: Vec<IpAddr>,
    },
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct RunLimits {
    pub max_dns_queries: Option<usize>,
    pub max_tun_packets: Option<usize>,
    pub max_tcp_sessions: Option<usize>,
    pub max_udp_sessions: Option<usize>,
    pub timeout: Option<Duration>,
}

impl Default for TakeoverSettings {
    fn default() -> Self {
        Self {
            nft_table: "inet dynet".to_string(),
            nft_main_config: PathBuf::from("/etc/nftables.conf"),
            nft_dropin_dir: PathBuf::from("/etc/nftables.d"),
            nft_dropin_path: PathBuf::from("/etc/nftables.d/dynet.nft"),
            tun_name: "dynet0".to_string(),
            bypass_mark: 0xd1e7,
            route_table: 61777,
            dns_bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1053),
            upstream_dns: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53),
            runtime_dir: PathBuf::from("/run/dynet"),
            state_dir: PathBuf::from("/var/lib/dynet"),
            manifest_path: PathBuf::from("/var/lib/dynet/takeover/manifest.json"),
        }
    }
}

impl TakeoverSettings {
    pub fn validate(&self) -> Result<(), String> {
        validate_nft_table(&self.nft_table)?;
        validate_name(&self.tun_name, 15, "tun name")?;
        validate_absolute_path(&self.nft_main_config, "nft main config")?;
        validate_absolute_path(&self.nft_dropin_dir, "nft drop-in dir")?;
        validate_absolute_path(&self.nft_dropin_path, "nft drop-in path")?;
        validate_absolute_path(&self.runtime_dir, "runtime dir")?;
        validate_absolute_path(&self.state_dir, "state dir")?;
        validate_absolute_path(&self.manifest_path, "manifest path")?;
        if !self.nft_dropin_path.starts_with(&self.nft_dropin_dir) {
            return Err("nft drop-in path must stay under nft drop-in dir".to_string());
        }
        if !self.manifest_path.starts_with(&self.state_dir) {
            return Err("manifest path must stay under state dir".to_string());
        }
        if self.dns_bind.port() == 0 {
            return Err("dns bind port must not be zero".to_string());
        }
        if self.upstream_dns.port() == 0 {
            return Err("upstream DNS port must not be zero".to_string());
        }
        Ok(())
    }

    pub fn runtime_settings(&self, dns_chain: DnsRuntimeChain) -> RuntimeSettings {
        RuntimeSettings {
            tun_name: self.tun_name.clone(),
            dns_bind: self.dns_bind,
            dns_chain,
            bypass_mark: self.bypass_mark,
            tcp_forwarding: TcpForwardingSettings::default(),
            udp_forwarding: UdpForwardingSettings::default(),
            policy: None,
        }
    }

    pub fn nft_family_name(&self) -> (&str, &str) {
        self.nft_table
            .split_once(' ')
            .expect("validated nft table has family and name")
    }
}

impl RuntimeSettings {
    pub fn with_policy(mut self, policy: RuntimePolicy) -> Self {
        self.policy = Some(policy);
        self
    }

    pub fn with_tcp_forwarding(mut self, tcp_forwarding: TcpForwardingSettings) -> Self {
        self.tcp_forwarding = tcp_forwarding;
        self
    }

    pub fn with_udp_forwarding(mut self, udp_forwarding: UdpForwardingSettings) -> Self {
        self.udp_forwarding = udp_forwarding;
        self
    }

    pub fn validate(&self) -> Result<(), String> {
        validate_name(&self.tun_name, 15, "tun name")?;
        if self.dns_bind.port() == 0 {
            return Err("dns bind port must not be zero".to_string());
        }
        self.dns_chain.validate()?;
        Ok(())
    }
}

impl RuntimePolicy {
    pub fn from_config(config: DynetConfig) -> Self {
        let state = AppState::from_config(config);
        let plan = build_plan(&state);
        Self { state, plan }
    }

    pub fn from_config_with_quality(config: DynetConfig, quality: OutboundQualityState) -> Self {
        let state = AppState::from_config(config).with_quality(quality);
        let plan = build_plan(&state);
        Self { state, plan }
    }

    pub(crate) fn outbound(&self, tag: &str) -> Option<&NetworkNode> {
        self.state
            .config
            .outbounds
            .iter()
            .find(|outbound| outbound.tag == tag)
    }
}

impl DnsRuntimeChain {
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Udp { upstream_dns } => {
                if upstream_dns.port() == 0 {
                    return Err("upstream DNS port must not be zero".to_string());
                }
            }
            Self::Doh {
                endpoint,
                bootstrap_ips,
            } => {
                validate_doh_endpoint(endpoint)?;
                if bootstrap_ips.is_empty() {
                    return Err("DoH bootstrap IPs must not be empty".to_string());
                }
            }
        }
        Ok(())
    }
}

pub(crate) fn validate_doh_endpoint(endpoint: &str) -> Result<(), String> {
    if endpoint.trim() != endpoint || endpoint.is_empty() {
        return Err("DoH endpoint must not be empty or padded".to_string());
    }
    let Some(rest) = endpoint.strip_prefix("https://") else {
        return Err("DoH endpoint must use https://".to_string());
    };
    let Some((host, path)) = rest.split_once('/') else {
        return Err("DoH endpoint must include an absolute path".to_string());
    };
    if host.is_empty() || path.is_empty() || host.contains(char::is_whitespace) {
        return Err("DoH endpoint must include a non-empty host and path".to_string());
    }
    Ok(())
}

fn validate_nft_table(value: &str) -> Result<(), String> {
    let Some((family, name)) = value.split_once(' ') else {
        return Err("nft table must look like `inet dynet`".to_string());
    };
    if value.split_whitespace().count() != 2 {
        return Err("nft table must contain exactly family and table name".to_string());
    }
    match family {
        "ip" | "ip6" | "inet" | "arp" | "bridge" | "netdev" => {}
        _ => return Err("nft table uses unsupported family".to_string()),
    }
    validate_name(name, 64, "nft table name")
}

fn validate_name(value: &str, max: usize, label: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > max {
        return Err(format!("{label} must be 1..={max} bytes"));
    }
    if value.contains("..") {
        return Err(format!("{label} must not contain traversal"));
    }
    if value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        Ok(())
    } else {
        Err(format!("{label} contains unsupported characters"))
    }
}

fn validate_absolute_path(path: &Path, label: &str) -> Result<(), String> {
    if !path.is_absolute() {
        return Err(format!("{label} must be absolute"));
    }
    for component in path.components() {
        match component {
            Component::RootDir | Component::Normal(_) => {}
            _ => return Err(format!("{label} must not contain traversal or prefixes")),
        }
    }
    Ok(())
}
