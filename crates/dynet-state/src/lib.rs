use std::{env, net::SocketAddr, time::Duration};

use dynet_ingress::{DnsRelayConfig, IngressConfig, TcpRelayConfig, UdpRelayConfig};

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct AppState {
    pub config: Config,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Config {
    pub control: ControlConfig,
    pub ingress: IngressConfig,
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
            ingress: IngressConfig {
                dns: DnsRelayConfig::default(),
                tcp: TcpRelayConfig::default(),
                udp: UdpRelayConfig::default(),
            },
        }
    }
}

impl AppState {
    pub fn from_env() -> Result<Self, String> {
        Ok(Self {
            config: Config::from_env()?,
        })
    }
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let mut config = Self::default();
        config.control.bind = env_socket("DYNET_CONTROL_BIND", config.control.bind)?;
        config.ingress.dns.bind = env_socket("DYNET_DNS_BIND", config.ingress.dns.bind)?;
        config.ingress.dns.upstream =
            env_socket("DYNET_DNS_UPSTREAM", config.ingress.dns.upstream)?;
        config.ingress.dns.timeout =
            env_duration_ms("DYNET_DNS_TIMEOUT_MS", config.ingress.dns.timeout)?;
        config.ingress.tcp.bind = env_socket("DYNET_TCP_BIND", config.ingress.tcp.bind)?;
        config.ingress.tcp.upstream =
            env_socket("DYNET_TCP_UPSTREAM", config.ingress.tcp.upstream)?;
        config.ingress.udp.bind = env_socket("DYNET_UDP_BIND", config.ingress.udp.bind)?;
        config.ingress.udp.upstream =
            env_socket("DYNET_UDP_UPSTREAM", config.ingress.udp.upstream)?;
        config.ingress.udp.idle_timeout =
            env_duration_ms("DYNET_UDP_IDLE_TIMEOUT_MS", config.ingress.udp.idle_timeout)?;
        Ok(config)
    }
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
