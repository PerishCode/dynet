use std::{env, net::SocketAddr, time::Duration};

use super::{
    dns_mapping_config, non_empty_string, persistence_config, service_config, socks_config, Config,
};

pub(super) fn apply_env(config: &mut Config) -> Result<(), String> {
    config.control.bind = env_socket("DYNET_CONTROL_BIND", config.control.bind)?;
    config.ingress.dns.bind = env_socket("DYNET_DNS_BIND", config.ingress.dns.bind)?;
    config.ingress.dns.max_sessions =
        env_positive_usize("DYNET_DNS_MAX_SESSIONS", config.ingress.dns.max_sessions)?;
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
    config.ipv6.enabled = env_bool("DYNET_IPV6_ENABLED", config.ipv6.enabled)?;
    dns_mapping_config::apply_env(&mut config.dns_mapping)?;
    persistence_config::apply_env(&mut config.persistence)?;
    service_config::apply_env(&mut config.service)?;
    Ok(())
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
