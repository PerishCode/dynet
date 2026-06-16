use std::{env, net::SocketAddr, time::Duration};

use dynet_ingress::Socks5IngressConfig;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FileSocks5IngressConfig {
    bind: Option<String>,
    udp_idle_timeout_ms: Option<u64>,
    max_sessions: Option<usize>,
}

impl FileSocks5IngressConfig {
    pub(crate) fn apply(self, config: &mut Socks5IngressConfig) -> Result<(), String> {
        if let Some(bind) = self.bind {
            config.bind = parse_socket("ingress.socks5.bind", &bind)?;
        }
        if let Some(timeout_ms) = self.udp_idle_timeout_ms {
            config.idle_timeout = Duration::from_millis(timeout_ms);
        }
        if let Some(max_sessions) = self.max_sessions {
            config.max_sessions = positive_usize("ingress.socks5.max_sessions", max_sessions)?;
        }
        Ok(())
    }
}

pub(crate) fn apply_env(config: &mut Socks5IngressConfig) -> Result<(), String> {
    config.bind = env_socket("DYNET_SOCKS5_BIND", config.bind)?;
    config.idle_timeout = env_duration_ms("DYNET_SOCKS5_UDP_IDLE_TIMEOUT_MS", config.idle_timeout)?;
    config.max_sessions = env_positive_usize("DYNET_SOCKS5_MAX_SESSIONS", config.max_sessions)?;
    Ok(())
}

fn env_socket(name: &str, fallback: SocketAddr) -> Result<SocketAddr, String> {
    match env::var(name) {
        Ok(value) => parse_socket(name, &value),
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
            positive_usize(name, parsed)
        }
        Err(env::VarError::NotPresent) => Ok(fallback),
        Err(error) => Err(format!("failed to read {name}: {error}")),
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
