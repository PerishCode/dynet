use std::{env, net::SocketAddr, sync::Mutex, time::Duration};

use dynet_state::Config;

static ENV_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn env_overrides_config() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    let _guard = EnvGuard::set(&[
        ("DYNET_CONTROL_BIND", "127.0.0.1:9001"),
        ("DYNET_DNS_BIND", "127.0.0.1:9002"),
        ("DYNET_DNS_UPSTREAM", "127.0.0.1:9003"),
        ("DYNET_DNS_TIMEOUT_MS", "123"),
        ("DYNET_TCP_BIND", "127.0.0.1:9004"),
        ("DYNET_TCP_UPSTREAM", "127.0.0.1:9005"),
        ("DYNET_UDP_BIND", "127.0.0.1:9006"),
        ("DYNET_UDP_UPSTREAM", "127.0.0.1:9007"),
        ("DYNET_UDP_IDLE_TIMEOUT_MS", "456"),
    ]);

    let config = Config::from_env().expect("config loads from env");

    assert_eq!(config.control.bind, socket("127.0.0.1:9001"));
    assert_eq!(config.ingress.dns.bind, socket("127.0.0.1:9002"));
    assert_eq!(config.ingress.dns.upstream, socket("127.0.0.1:9003"));
    assert_eq!(config.ingress.dns.timeout, Duration::from_millis(123));
    assert_eq!(config.ingress.tcp.bind, socket("127.0.0.1:9004"));
    assert_eq!(config.ingress.tcp.upstream, socket("127.0.0.1:9005"));
    assert_eq!(config.ingress.udp.bind, socket("127.0.0.1:9006"));
    assert_eq!(config.ingress.udp.upstream, socket("127.0.0.1:9007"));
    assert_eq!(config.ingress.udp.idle_timeout, Duration::from_millis(456));
}

#[test]
fn env_rejects_invalid_socket() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    let _guard = EnvGuard::set(&[("DYNET_TCP_UPSTREAM", "not-a-socket")]);

    let error = Config::from_env().expect_err("invalid socket is rejected");

    assert!(error.contains("DYNET_TCP_UPSTREAM"));
}

fn socket(value: &str) -> SocketAddr {
    value.parse().expect("socket parses")
}

struct EnvGuard {
    previous: Vec<(&'static str, Option<String>)>,
}

impl EnvGuard {
    fn set(values: &[(&'static str, &'static str)]) -> Self {
        let previous = values
            .iter()
            .map(|(key, _)| (*key, env::var(key).ok()))
            .collect();
        for (key, value) in values {
            env::set_var(key, value);
        }
        Self { previous }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (key, value) in self.previous.drain(..) {
            match value {
                Some(value) => env::set_var(key, value),
                None => env::remove_var(key),
            }
        }
    }
}
