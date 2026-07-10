use std::{
    collections::BTreeMap,
    env, fs, io,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use dynet_ingress::{
    DnsRelayConfig, EgressNodeConfig, IngressConfig, TcpRelayConfig, UdpRelayConfig,
};
use dynet_runtime::{PersistencePolicy, RuntimeSeed};
use serde::Deserialize;

mod env_config;
mod forwarding_config;
mod integration_config;
mod persistence_config;
mod reload;
mod service_config;
mod socks_config;
mod summary;
use env_config::apply_env;
use forwarding_config::FileForwardingConfig;
pub use integration_config::{DnsMappingConfig, RouterIngressConfig};
pub use reload::{ReloadDisposition, ReloadPlan};
pub use service_config::{ServiceConfig, ServiceManager};
use socks_config::FileSocks5IngressConfig;
pub use summary::redacted_summary_lines;

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct AppState {
    pub config: Config,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Config {
    pub control: ControlConfig,
    pub ingress: IngressConfig,
    pub capture: CaptureConfig,
    pub ipv6: Ipv6Config,
    pub dns_mapping: DnsMappingConfig,
    pub persistence: PersistencePolicy,
    pub forwarding: ForwardingConfig,
    pub service: ServiceConfig,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ControlConfig {
    pub bind: SocketAddr,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct Ipv6Config {
    pub enabled: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ForwardingConfig {
    pub seed: RuntimeSeed,
    pub execution_nodes: BTreeMap<String, EgressNodeConfig>,
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct CaptureConfig {
    pub tun: TunCaptureConfig,
    pub router_ingress: RouterIngressConfig,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TunCaptureConfig {
    pub enabled: bool,
    pub interface: String,
    pub tcp_idle_timeout: Duration,
    pub udp_idle_timeout: Duration,
    pub udp_response_timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            control: ControlConfig {
                bind: SocketAddr::from(([127, 0, 0, 1], 9977)),
            },
            ingress: IngressConfig::default(),
            capture: CaptureConfig::default(),
            ipv6: Ipv6Config::default(),
            dns_mapping: DnsMappingConfig::default(),
            persistence: PersistencePolicy::default(),
            forwarding: ForwardingConfig::default(),
            service: ServiceConfig::default(),
        }
    }
}

impl Default for TunCaptureConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interface: "dynet0".to_string(),
            tcp_idle_timeout: Duration::from_secs(2),
            udp_idle_timeout: Duration::from_secs(2),
            udp_response_timeout: Duration::from_millis(1500),
        }
    }
}

impl Default for ForwardingConfig {
    fn default() -> Self {
        let mut execution_nodes = BTreeMap::new();
        execution_nodes.insert("default-node".to_string(), EgressNodeConfig::Direct);
        Self {
            seed: RuntimeSeed::single_node("direct"),
            execution_nodes,
        }
    }
}

impl AppState {
    pub fn from_env() -> Result<Self, String> {
        Ok(Self {
            config: Config::from_env()?,
        })
    }

    pub fn from_config_path(path: Option<&Path>) -> Result<Self, String> {
        Ok(Self {
            config: Config::from_config_path(path)?,
        })
    }
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let mut config = Self::default();
        apply_env(&mut config)?;
        sync_runtime_policy(&mut config);
        Ok(config)
    }

    pub fn from_config_path(path: Option<&Path>) -> Result<Self, String> {
        let mut config = Self::default();
        apply_config_file(&mut config, path)?;
        apply_env(&mut config)?;
        sync_runtime_policy(&mut config);
        Ok(config)
    }

    pub fn fingerprint(&self) -> String {
        reload::config_fingerprint(self)
    }

    pub fn plan_reload(&self, next: &Self) -> ReloadPlan {
        reload::plan_reload(self, next)
    }
}

fn sync_runtime_policy(config: &mut Config) {
    config.forwarding.seed.ipv6_enabled = config.ipv6.enabled;
}

fn apply_config_file(config: &mut Config, path: Option<&Path>) -> Result<(), String> {
    let (path, ignore_missing) = match path {
        Some(path) => (path.to_path_buf(), false),
        None => (default_config_path()?, true),
    };
    let content = match fs::read_to_string(&path) {
        Ok(content) => content,
        Err(error) if error.kind() == io::ErrorKind::NotFound && ignore_missing => {
            return Ok(());
        }
        Err(error) => return Err(format!("failed to read config {}: {error}", path.display())),
    };
    let file = toml::from_str::<FileConfig>(&content)
        .map_err(|error| format!("failed to parse config {}: {error}", path.display()))?;
    file.apply(config)
}

fn default_config_path() -> Result<PathBuf, String> {
    env::current_dir()
        .map(|directory| directory.join("dynet.toml"))
        .map_err(|error| format!("failed to resolve current directory: {error}"))
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    control: Option<FileControlConfig>,
    ingress: Option<FileIngressConfig>,
    capture: Option<FileCaptureConfig>,
    ipv6: Option<FileIpv6Config>,
    dns_mapping: Option<integration_config::FileDnsMappingConfig>,
    persistence: Option<persistence_config::FilePersistenceConfig>,
    forwarding: Option<FileForwardingConfig>,
    service: Option<service_config::FileServiceConfig>,
}

impl FileConfig {
    fn apply(self, config: &mut Config) -> Result<(), String> {
        if let Some(control) = self.control {
            control.apply(&mut config.control)?;
        }
        if let Some(ingress) = self.ingress {
            ingress.apply(&mut config.ingress)?;
        }
        if let Some(capture) = self.capture {
            capture.apply(&mut config.capture)?;
        }
        if let Some(ipv6) = self.ipv6 {
            ipv6.apply(&mut config.ipv6);
        }
        if let Some(dns_mapping) = self.dns_mapping {
            dns_mapping.apply(&mut config.dns_mapping)?;
        }
        if let Some(persistence) = self.persistence {
            persistence.apply(&mut config.persistence)?;
        }
        if let Some(forwarding) = self.forwarding {
            config.forwarding = forwarding.load()?;
        }
        if let Some(service) = self.service {
            service.apply(&mut config.service)?;
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileIpv6Config {
    enabled: Option<bool>,
}

impl FileIpv6Config {
    fn apply(self, config: &mut Ipv6Config) {
        if let Some(enabled) = self.enabled {
            config.enabled = enabled;
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileCaptureConfig {
    tun: Option<FileTunCaptureConfig>,
    router_ingress: Option<integration_config::FileRouterIngressConfig>,
}

impl FileCaptureConfig {
    fn apply(self, config: &mut CaptureConfig) -> Result<(), String> {
        if let Some(tun) = self.tun {
            tun.apply(&mut config.tun)?;
        }
        if let Some(router_ingress) = self.router_ingress {
            router_ingress.apply(&mut config.router_ingress)?;
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileTunCaptureConfig {
    enabled: Option<bool>,
    interface: Option<String>,
    tcp_idle_timeout_ms: Option<u64>,
    udp_idle_timeout_ms: Option<u64>,
    udp_response_timeout_ms: Option<u64>,
}

impl FileTunCaptureConfig {
    fn apply(self, config: &mut TunCaptureConfig) -> Result<(), String> {
        if let Some(enabled) = self.enabled {
            config.enabled = enabled;
        }
        if let Some(interface) = self.interface {
            config.interface = non_empty_string("capture.tun.interface", interface)?;
        }
        if let Some(tcp_idle_timeout_ms) = self.tcp_idle_timeout_ms {
            config.tcp_idle_timeout = Duration::from_millis(tcp_idle_timeout_ms);
        }
        if let Some(udp_idle_timeout_ms) = self.udp_idle_timeout_ms {
            config.udp_idle_timeout = Duration::from_millis(udp_idle_timeout_ms);
        }
        if let Some(udp_response_timeout_ms) = self.udp_response_timeout_ms {
            config.udp_response_timeout = Duration::from_millis(udp_response_timeout_ms);
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileControlConfig {
    bind: Option<String>,
}

impl FileControlConfig {
    fn apply(self, config: &mut ControlConfig) -> Result<(), String> {
        if let Some(bind) = self.bind {
            config.bind = parse_socket("control.bind", &bind)?;
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileIngressConfig {
    dns: Option<FileDnsRelayConfig>,
    tcp: Option<FileTcpRelayConfig>,
    udp: Option<FileUdpRelayConfig>,
    socks5: Option<FileSocks5IngressConfig>,
}

impl FileIngressConfig {
    fn apply(self, config: &mut IngressConfig) -> Result<(), String> {
        if let Some(dns) = self.dns {
            dns.apply(&mut config.dns)?;
        }
        if let Some(tcp) = self.tcp {
            tcp.apply(&mut config.tcp)?;
        }
        if let Some(udp) = self.udp {
            udp.apply(&mut config.udp)?;
        }
        if let Some(socks5) = self.socks5 {
            socks5.apply(&mut config.socks5)?;
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileDnsRelayConfig {
    bind: Option<String>,
    max_sessions: Option<usize>,
}

impl FileDnsRelayConfig {
    fn apply(self, config: &mut DnsRelayConfig) -> Result<(), String> {
        if let Some(bind) = self.bind {
            config.bind = parse_socket("ingress.dns.bind", &bind)?;
        }
        if let Some(max_sessions) = self.max_sessions {
            config.max_sessions = positive_usize("ingress.dns.max_sessions", max_sessions)?;
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileTcpRelayConfig {
    bind: Option<String>,
    upstream: Option<String>,
    max_sessions: Option<usize>,
}

impl FileTcpRelayConfig {
    fn apply(self, config: &mut TcpRelayConfig) -> Result<(), String> {
        if let Some(bind) = self.bind {
            config.bind = parse_socket("ingress.tcp.bind", &bind)?;
        }
        if let Some(upstream) = self.upstream {
            config.upstream = parse_socket("ingress.tcp.upstream", &upstream)?;
        }
        if let Some(max_sessions) = self.max_sessions {
            config.max_sessions = positive_usize("ingress.tcp.max_sessions", max_sessions)?;
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileUdpRelayConfig {
    bind: Option<String>,
    upstream: Option<String>,
    idle_timeout_ms: Option<u64>,
    max_sessions: Option<usize>,
}

impl FileUdpRelayConfig {
    fn apply(self, config: &mut UdpRelayConfig) -> Result<(), String> {
        if let Some(bind) = self.bind {
            config.bind = parse_socket("ingress.udp.bind", &bind)?;
        }
        if let Some(upstream) = self.upstream {
            config.upstream = parse_socket("ingress.udp.upstream", &upstream)?;
        }
        if let Some(idle_timeout_ms) = self.idle_timeout_ms {
            config.idle_timeout = Duration::from_millis(idle_timeout_ms);
        }
        if let Some(max_sessions) = self.max_sessions {
            config.max_sessions = positive_usize("ingress.udp.max_sessions", max_sessions)?;
        }
        Ok(())
    }
}

fn parse_socket(name: &str, value: &str) -> Result<SocketAddr, String> {
    value
        .parse()
        .map_err(|error| format!("{name} must be a socket address: {error}"))
}

fn non_empty_string(name: &str, value: String) -> Result<String, String> {
    if value.is_empty() {
        return Err(format!("{name} requires a non-empty value"));
    }
    Ok(value)
}

fn positive_usize(name: &str, value: usize) -> Result<usize, String> {
    if value == 0 {
        return Err(format!("{name} must be a positive integer"));
    }
    Ok(value)
}
