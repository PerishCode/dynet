use std::{
    env, fs, io,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use dynet_ingress::{
    DnsRelayConfig, IngressConfig, OutboundConfig, ShadowsocksConfig, TcpRelayConfig, TrojanConfig,
    UdpRelayConfig, VlessConfig, VmessConfig,
};
use serde::Deserialize;

mod method_config;
mod socks_config;
use method_config::parse_shadowsocks_method;
use socks_config::FileSocks5IngressConfig;

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct AppState {
    pub config: Config,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Config {
    pub control: ControlConfig,
    pub ingress: IngressConfig,
    pub outbound: OutboundConfig,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ControlConfig {
    pub bind: SocketAddr,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            control: ControlConfig {
                bind: SocketAddr::from(([127, 0, 0, 1], 9977)),
            },
            ingress: IngressConfig::default(),
            outbound: OutboundConfig::Direct,
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
    outbound: Option<FileOutboundConfig>,
}

impl FileConfig {
    fn apply(self, config: &mut Config) -> Result<(), String> {
        if let Some(control) = self.control {
            control.apply(&mut config.control)?;
        }
        if let Some(ingress) = self.ingress {
            ingress.apply(&mut config.ingress)?;
        }
        if let Some(outbound) = self.outbound {
            config.outbound = outbound.load()?;
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileOutboundConfig {
    #[serde(rename = "type")]
    kind: String,
    server: Option<String>,
    port: Option<u16>,
    method: Option<String>,
    cipher: Option<String>,
    #[serde(rename = "alterId")]
    alter_id: Option<u16>,
    uuid: Option<String>,
    flow: Option<String>,
    network: Option<String>,
    tls: Option<bool>,
    password: Option<String>,
    sni: Option<String>,
    servername: Option<String>,
    #[serde(rename = "client-fingerprint")]
    client_fingerprint: Option<String>,
    #[serde(rename = "reality-opts")]
    reality_opts: Option<FileRealityOptions>,
    #[serde(rename = "skip-cert-verify")]
    skip_cert_verify: Option<bool>,
    udp: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileRealityOptions {
    #[serde(rename = "public-key")]
    public_key: Option<String>,
    #[serde(rename = "short-id")]
    short_id: Option<String>,
}

impl FileOutboundConfig {
    fn load(self) -> Result<OutboundConfig, String> {
        match self.kind.as_str() {
            "direct" => Ok(OutboundConfig::Direct),
            "shadowsocks" | "ss" => self.load_shadowsocks(),
            "trojan" => self.load_trojan(),
            "vless" => self.load_vless(),
            "vmess" => self.load_vmess(),
            _ => Err(format!("outbound.type unsupported: {}", self.kind)),
        }
    }

    fn load_shadowsocks(self) -> Result<OutboundConfig, String> {
        if self.udp != Some(true) {
            return Err("outbound.udp must be true for shadowsocks cold start".to_string());
        }
        let server = self
            .server
            .ok_or_else(|| "outbound.server is required for shadowsocks".to_string())?;
        let port = self
            .port
            .ok_or_else(|| "outbound.port is required for shadowsocks".to_string())?;
        let method = match (self.method, self.cipher) {
            (Some(method), None) | (None, Some(method)) => method,
            (Some(method), Some(cipher)) if method == cipher => method,
            (Some(_), Some(_)) => {
                return Err("outbound.method and outbound.cipher disagree".to_string());
            }
            (None, None) => {
                return Err("outbound.method is required for shadowsocks".to_string());
            }
        };
        let password = self
            .password
            .ok_or_else(|| "outbound.password is required for shadowsocks".to_string())?;
        Ok(OutboundConfig::Shadowsocks(ShadowsocksConfig {
            server,
            port,
            method: parse_shadowsocks_method(&method)?,
            password,
        }))
    }

    fn load_trojan(self) -> Result<OutboundConfig, String> {
        if self.udp != Some(true) {
            return Err("outbound.udp must be true for trojan cold start".to_string());
        }
        let server = self
            .server
            .ok_or_else(|| "outbound.server is required for trojan".to_string())?;
        let port = self
            .port
            .ok_or_else(|| "outbound.port is required for trojan".to_string())?;
        let password = self
            .password
            .ok_or_else(|| "outbound.password is required for trojan".to_string())?;
        let sni = match (self.sni, self.servername) {
            (Some(sni), None) | (None, Some(sni)) => Some(sni),
            (Some(sni), Some(servername)) if sni == servername => Some(sni),
            (Some(_), Some(_)) => {
                return Err("outbound.sni and outbound.servername disagree".to_string());
            }
            (None, None) => None,
        };
        Ok(OutboundConfig::Trojan(TrojanConfig {
            server,
            port,
            password,
            sni,
            skip_cert_verify: self.skip_cert_verify.unwrap_or(false),
        }))
    }

    fn load_vmess(self) -> Result<OutboundConfig, String> {
        if self.udp != Some(true) {
            return Err("outbound.udp must be true for vmess cold start".to_string());
        }
        if self.alter_id != Some(0) {
            return Err("outbound.alterId must be 0 for vmess cold start".to_string());
        }
        if self.cipher.as_deref() != Some("auto") {
            return Err("outbound.cipher must be auto for vmess cold start".to_string());
        }
        if !matches!(self.network.as_deref(), None | Some("tcp")) {
            return Err("outbound.network must be tcp for vmess cold start".to_string());
        }
        if self.tls == Some(true) {
            return Err("outbound.tls is not supported for vmess cold start".to_string());
        }
        let server = self
            .server
            .ok_or_else(|| "outbound.server is required for vmess".to_string())?;
        let port = self
            .port
            .ok_or_else(|| "outbound.port is required for vmess".to_string())?;
        let uuid = self
            .uuid
            .ok_or_else(|| "outbound.uuid is required for vmess".to_string())?;
        Ok(OutboundConfig::Vmess(VmessConfig { server, port, uuid }))
    }

    fn load_vless(self) -> Result<OutboundConfig, String> {
        if self.udp != Some(true) {
            return Err("outbound.udp must be true for vless cold start".to_string());
        }
        if self.flow.as_deref() != Some("xtls-rprx-vision") {
            return Err("outbound.flow must be xtls-rprx-vision for vless cold start".to_string());
        }
        if !matches!(self.network.as_deref(), None | Some("tcp")) {
            return Err("outbound.network must be tcp for vless cold start".to_string());
        }
        if self.tls != Some(true) {
            return Err("outbound.tls must be true for vless reality cold start".to_string());
        }
        if !matches!(self.client_fingerprint.as_deref(), None | Some("chrome")) {
            return Err("outbound.client-fingerprint must be chrome for vless cold start".into());
        }
        let server = self
            .server
            .ok_or_else(|| "outbound.server is required for vless".to_string())?;
        let port = self
            .port
            .ok_or_else(|| "outbound.port is required for vless".to_string())?;
        let uuid = self
            .uuid
            .ok_or_else(|| "outbound.uuid is required for vless".to_string())?;
        let server_name = match (self.sni, self.servername) {
            (Some(sni), None) | (None, Some(sni)) => sni,
            (Some(sni), Some(servername)) if sni == servername => sni,
            (Some(_), Some(_)) => {
                return Err("outbound.sni and outbound.servername disagree".to_string());
            }
            (None, None) => {
                return Err("outbound.servername is required for vless reality".to_string());
            }
        };
        let reality_opts = self
            .reality_opts
            .ok_or_else(|| "outbound.reality-opts is required for vless reality".to_string())?;
        let public_key = reality_opts
            .public_key
            .ok_or_else(|| "outbound.reality-opts.public-key is required".to_string())?;
        let short_id = reality_opts
            .short_id
            .ok_or_else(|| "outbound.reality-opts.short-id is required".to_string())?;
        Ok(OutboundConfig::Vless(VlessConfig {
            server,
            port,
            uuid,
            server_name,
            public_key,
            short_id,
        }))
    }
}

fn parse_socket(name: &str, value: &str) -> Result<SocketAddr, String> {
    value
        .parse()
        .map_err(|error| format!("{name} must be a socket address: {error}"))
}

fn positive_usize(name: &str, value: usize) -> Result<usize, String> {
    if value == 0 {
        return Err(format!("{name} must be a positive integer"));
    }
    Ok(value)
}
