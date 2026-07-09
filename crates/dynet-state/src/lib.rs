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
use dynet_runtime::RuntimeSeed;
use serde::Deserialize;

mod forwarding_config;
mod method_config;
mod socks_config;
use forwarding_config::FileForwardingConfig;
use socks_config::FileSocks5IngressConfig;

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct AppState {
    pub config: Config,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Config {
    pub control: ControlConfig,
    pub ingress: IngressConfig,
    pub capture: CaptureConfig,
    pub forwarding: ForwardingConfig,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ControlConfig {
    pub bind: SocketAddr,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ForwardingConfig {
    pub seed: RuntimeSeed,
    pub execution_nodes: BTreeMap<String, EgressNodeConfig>,
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct CaptureConfig {
    pub tun: TunCaptureConfig,
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
            forwarding: ForwardingConfig::default(),
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
        Ok(config)
    }

    pub fn from_config_path(path: Option<&Path>) -> Result<Self, String> {
        let mut config = Self::default();
        apply_config_file(&mut config, path)?;
        apply_env(&mut config)?;
        Ok(config)
    }
}

fn apply_env(config: &mut Config) -> Result<(), String> {
    config.control.bind = env_socket("DYNET_CONTROL_BIND", config.control.bind)?;
    config.ingress.dns.bind = env_socket("DYNET_DNS_BIND", config.ingress.dns.bind)?;
    config.ingress.tcp.bind = env_socket("DYNET_TCP_BIND", config.ingress.tcp.bind)?;
    config.ingress.tcp.upstream = env_socket("DYNET_TCP_UPSTREAM", config.ingress.tcp.upstream)?;
    config.ingress.tcp.max_sessions =
        env_positive_usize("DYNET_TCP_MAX_SESSIONS", config.ingress.tcp.max_sessions)?;
    config.ingress.udp.bind = env_socket("DYNET_UDP_BIND", config.ingress.udp.bind)?;
    config.ingress.udp.upstream = env_socket("DYNET_UDP_UPSTREAM", config.ingress.udp.upstream)?;
    config.ingress.udp.idle_timeout =
        env_duration_ms("DYNET_UDP_IDLE_TIMEOUT_MS", config.ingress.udp.idle_timeout)?;
    config.ingress.udp.max_sessions =
        env_positive_usize("DYNET_UDP_MAX_SESSIONS", config.ingress.udp.max_sessions)?;
    socks_config::apply_env(&mut config.ingress.socks5)?;
    config.capture.tun.enabled = env_bool("DYNET_CAPTURE_TUN_ENABLED", config.capture.tun.enabled)?;
    config.capture.tun.interface = env_non_empty_string(
        "DYNET_CAPTURE_TUN_INTERFACE",
        config.capture.tun.interface.clone(),
    )?;
    config.capture.tun.tcp_idle_timeout = env_duration_ms(
        "DYNET_CAPTURE_TUN_TCP_IDLE_TIMEOUT_MS",
        config.capture.tun.tcp_idle_timeout,
    )?;
    config.capture.tun.udp_idle_timeout = env_duration_ms(
        "DYNET_CAPTURE_TUN_UDP_IDLE_TIMEOUT_MS",
        config.capture.tun.udp_idle_timeout,
    )?;
    config.capture.tun.udp_response_timeout = env_duration_ms(
        "DYNET_CAPTURE_TUN_UDP_RESPONSE_TIMEOUT_MS",
        config.capture.tun.udp_response_timeout,
    )?;
    Ok(())
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

fn env_socket(name: &str, fallback: SocketAddr) -> Result<SocketAddr, String> {
    match env::var(name) {
        Ok(value) => value
            .parse()
            .map_err(|error| format!("{name} must be a socket address: {error}")),
        Err(env::VarError::NotPresent) => Ok(fallback),
        Err(error) => Err(format!("failed to read {name}: {error}")),
    }
}

fn env_duration_ms(name: &str, fallback: Duration) -> Result<Duration, String> {
    match env::var(name) {
        Ok(value) => value
            .parse::<u64>()
            .map(Duration::from_millis)
            .map_err(|error| format!("{name} must be an integer millisecond value: {error}")),
        Err(env::VarError::NotPresent) => Ok(fallback),
        Err(error) => Err(format!("failed to read {name}: {error}")),
    }
}

fn env_bool(name: &str, fallback: bool) -> Result<bool, String> {
    match env::var(name) {
        Ok(value) => parse_bool(name, &value),
        Err(env::VarError::NotPresent) => Ok(fallback),
        Err(error) => Err(format!("failed to read {name}: {error}")),
    }
}

fn env_non_empty_string(name: &str, fallback: String) -> Result<String, String> {
    match env::var(name) {
        Ok(value) => non_empty_string(name, value),
        Err(env::VarError::NotPresent) => Ok(fallback),
        Err(error) => Err(format!("failed to read {name}: {error}")),
    }
}

fn env_positive_usize(name: &str, fallback: usize) -> Result<usize, String> {
    match env::var(name) {
        Ok(value) => {
            let parsed = value
                .parse::<usize>()
                .map_err(|error| format!("{name} must be a positive integer: {error}"))?;
            if parsed == 0 {
                return Err(format!("{name} must be a positive integer"));
            }
            Ok(parsed)
        }
        Err(env::VarError::NotPresent) => Ok(fallback),
        Err(error) => Err(format!("failed to read {name}: {error}")),
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    control: Option<FileControlConfig>,
    ingress: Option<FileIngressConfig>,
    capture: Option<FileCaptureConfig>,
    forwarding: Option<FileForwardingConfig>,
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
        if let Some(forwarding) = self.forwarding {
            config.forwarding = forwarding.load()?;
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileCaptureConfig {
    tun: Option<FileTunCaptureConfig>,
}

impl FileCaptureConfig {
    fn apply(self, config: &mut CaptureConfig) -> Result<(), String> {
        if let Some(tun) = self.tun {
            tun.apply(&mut config.tun)?;
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
}

impl FileDnsRelayConfig {
    fn apply(self, config: &mut DnsRelayConfig) -> Result<(), String> {
        if let Some(bind) = self.bind {
            config.bind = parse_socket("ingress.dns.bind", &bind)?;
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

fn parse_bool(name: &str, value: &str) -> Result<bool, String> {
    if value.eq_ignore_ascii_case("true")
        || value.eq_ignore_ascii_case("yes")
        || value.eq_ignore_ascii_case("on")
        || value == "1"
    {
        return Ok(true);
    }
    if value.eq_ignore_ascii_case("false")
        || value.eq_ignore_ascii_case("no")
        || value.eq_ignore_ascii_case("off")
        || value == "0"
    {
        return Ok(false);
    }
    Err(format!("{name} must be a boolean"))
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
