use std::{
    env, fs,
    net::SocketAddr,
    path::PathBuf,
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use dynet_state::Config;

static ENV_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn env_overrides_config() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    let _guard = EnvGuard::set(&[
        ("DYNET_CONTROL_BIND", "127.0.0.1:9001"),
        ("DYNET_DNS_BIND", "127.0.0.1:9002"),
        ("DYNET_TCP_BIND", "127.0.0.1:9004"),
        ("DYNET_TCP_UPSTREAM", "127.0.0.1:9005"),
        ("DYNET_TCP_MAX_SESSIONS", "64"),
        ("DYNET_UDP_BIND", "127.0.0.1:9006"),
        ("DYNET_UDP_UPSTREAM", "127.0.0.1:9007"),
        ("DYNET_UDP_IDLE_TIMEOUT_MS", "456"),
        ("DYNET_UDP_MAX_SESSIONS", "65"),
        ("DYNET_SOCKS5_BIND", "127.0.0.1:9008"),
        ("DYNET_SOCKS5_UDP_ADVERTISE_IP", "127.0.0.9"),
        ("DYNET_SOCKS5_UDP_IDLE_TIMEOUT_MS", "789"),
        ("DYNET_SOCKS5_MAX_SESSIONS", "66"),
    ]);

    let config = Config::from_env().expect("config loads from env");

    assert_eq!(config.control.bind, socket("127.0.0.1:9001"));
    assert_eq!(config.ingress.dns.bind, socket("127.0.0.1:9002"));
    assert_eq!(config.ingress.tcp.bind, socket("127.0.0.1:9004"));
    assert_eq!(config.ingress.tcp.upstream, socket("127.0.0.1:9005"));
    assert_eq!(config.ingress.tcp.max_sessions, 64);
    assert_eq!(config.ingress.udp.bind, socket("127.0.0.1:9006"));
    assert_eq!(config.ingress.udp.upstream, socket("127.0.0.1:9007"));
    assert_eq!(config.ingress.udp.idle_timeout, Duration::from_millis(456));
    assert_eq!(config.ingress.udp.max_sessions, 65);
    assert_eq!(config.ingress.socks5.bind, socket("127.0.0.1:9008"));
    assert_eq!(
        config.ingress.socks5.udp_advertise_ip,
        Some("127.0.0.9".parse().expect("ip"))
    );
    assert_eq!(
        config.ingress.socks5.idle_timeout,
        Duration::from_millis(789)
    );
    assert_eq!(config.ingress.socks5.max_sessions, 66);
}

#[test]
fn file_config_overrides_defaults() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    let _guard = EnvGuard::set(&[]);
    let config_path = temp_config_path("file_config_overrides_defaults");
    fs::write(
        &config_path,
        r#"
[control]
bind = "127.0.0.1:9101"

[ingress.dns]
bind = "127.0.0.1:9102"

[ingress.tcp]
bind = "127.0.0.1:9104"
upstream = "127.0.0.1:9105"
max_sessions = 32

[ingress.udp]
bind = "127.0.0.1:9106"
upstream = "127.0.0.1:9107"
idle_timeout_ms = 654
max_sessions = 33

[ingress.socks5]
bind = "127.0.0.1:9108"
udp_advertise_ip = "127.0.0.8"
udp_idle_timeout_ms = 987
max_sessions = 34
"#,
    )
    .expect("write config");

    let config = Config::from_config_path(Some(&config_path)).expect("config loads from file");

    assert_eq!(config.control.bind, socket("127.0.0.1:9101"));
    assert_eq!(config.ingress.dns.bind, socket("127.0.0.1:9102"));
    assert_eq!(config.ingress.tcp.bind, socket("127.0.0.1:9104"));
    assert_eq!(config.ingress.tcp.upstream, socket("127.0.0.1:9105"));
    assert_eq!(config.ingress.tcp.max_sessions, 32);
    assert_eq!(config.ingress.udp.bind, socket("127.0.0.1:9106"));
    assert_eq!(config.ingress.udp.upstream, socket("127.0.0.1:9107"));
    assert_eq!(config.ingress.udp.idle_timeout, Duration::from_millis(654));
    assert_eq!(config.ingress.udp.max_sessions, 33);
    assert_eq!(config.ingress.socks5.bind, socket("127.0.0.1:9108"));
    assert_eq!(
        config.ingress.socks5.udp_advertise_ip,
        Some("127.0.0.8".parse().expect("ip"))
    );
    assert_eq!(
        config.ingress.socks5.idle_timeout,
        Duration::from_millis(987)
    );
    assert_eq!(config.ingress.socks5.max_sessions, 34);

    fs::remove_file(config_path).expect("remove config");
}

#[test]
fn env_overrides_file_config() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    let _guard = EnvGuard::set(&[("DYNET_TCP_UPSTREAM", "127.0.0.1:9205")]);
    let config_path = temp_config_path("env_overrides_file_config");
    fs::write(
        &config_path,
        r#"
[ingress.tcp]
upstream = "127.0.0.1:9105"
"#,
    )
    .expect("write config");

    let config = Config::from_config_path(Some(&config_path)).expect("config loads");

    assert_eq!(config.ingress.tcp.upstream, socket("127.0.0.1:9205"));

    fs::remove_file(config_path).expect("remove config");
}

#[test]
fn missing_default_uses_defaults() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    let _guard = EnvGuard::set(&[]);
    let directory = temp_config_path("missing_default_uses_defaults");
    fs::create_dir(&directory).expect("create temp dir");
    let old_directory = env::current_dir().expect("current dir");
    env::set_current_dir(&directory).expect("enter temp dir");

    let config = Config::from_config_path(None).expect("missing default config is ignored");

    assert_eq!(config, Config::default());

    env::set_current_dir(old_directory).expect("restore current dir");
    fs::remove_dir(directory).expect("remove temp dir");
}

#[test]
fn missing_explicit_is_rejected() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    let _guard = EnvGuard::set(&[]);
    let config_path = temp_config_path("missing_explicit_is_rejected");

    let error = Config::from_config_path(Some(&config_path)).expect_err("missing file rejected");

    assert!(error.contains("failed to read config"));
}

#[test]
fn env_rejects_invalid_socket() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    let _guard = EnvGuard::set(&[("DYNET_TCP_UPSTREAM", "not-a-socket")]);

    let error = Config::from_env().expect_err("invalid socket is rejected");

    assert!(error.contains("DYNET_TCP_UPSTREAM"));
}

#[test]
fn env_rejects_zero_limit() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    let _guard = EnvGuard::set(&[("DYNET_TCP_MAX_SESSIONS", "0")]);

    let error = Config::from_env().expect_err("zero session limit is rejected");

    assert!(error.contains("DYNET_TCP_MAX_SESSIONS"));
}

fn socket(value: &str) -> SocketAddr {
    value.parse().expect("socket parses")
}

struct EnvGuard {
    previous: Vec<(&'static str, Option<String>)>,
}

impl EnvGuard {
    fn set(values: &[(&'static str, &'static str)]) -> Self {
        let previous = ENV_KEYS
            .iter()
            .map(|key| (*key, env::var(key).ok()))
            .collect();
        for key in ENV_KEYS {
            env::remove_var(key);
        }
        for (key, value) in values {
            env::set_var(key, value);
        }
        Self { previous }
    }
}

const ENV_KEYS: &[&str] = &[
    "DYNET_CONTROL_BIND",
    "DYNET_DNS_BIND",
    "DYNET_TCP_BIND",
    "DYNET_TCP_UPSTREAM",
    "DYNET_TCP_MAX_SESSIONS",
    "DYNET_UDP_BIND",
    "DYNET_UDP_UPSTREAM",
    "DYNET_UDP_IDLE_TIMEOUT_MS",
    "DYNET_UDP_MAX_SESSIONS",
    "DYNET_SOCKS5_BIND",
    "DYNET_SOCKS5_UDP_ADVERTISE_IP",
    "DYNET_SOCKS5_UDP_IDLE_TIMEOUT_MS",
    "DYNET_SOCKS5_MAX_SESSIONS",
];

fn temp_config_path(name: &str) -> PathBuf {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    env::temp_dir().join(format!("dynet-{name}-{}-{now}", std::process::id()))
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
