use std::{
    env, fs,
    net::SocketAddr,
    path::PathBuf,
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use dynet_state::{Config, ServiceManager};

static ENV_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn env_overrides_config() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    let _guard = EnvGuard::set(&[
        ("DYNET_CONTROL_BIND", "127.0.0.1:9001"),
        ("DYNET_DNS_BIND", "127.0.0.1:9002"),
        ("DYNET_DNS_MAX_SESSIONS", "63"),
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
        ("DYNET_CAPTURE_TUN_ENABLED", "true"),
        ("DYNET_CAPTURE_TUN_INTERFACE", "dynet-test0"),
        ("DYNET_CAPTURE_TUN_TCP_IDLE_TIMEOUT_MS", "2345"),
        ("DYNET_CAPTURE_TUN_UDP_IDLE_TIMEOUT_MS", "3456"),
        ("DYNET_CAPTURE_TUN_UDP_RESPONSE_TIMEOUT_MS", "4567"),
        ("DYNET_IPV6_ENABLED", "true"),
        ("DYNET_DNS_MAPPING_INTERFACE", "br-test"),
        ("DYNET_DNS_MAPPING_SOURCE_PORT", "5353"),
        ("DYNET_PERSISTENCE_RETENTION_HOURS", "12"),
        ("DYNET_PERSISTENCE_MAX_BYTES", "16777216"),
        ("DYNET_SERVICE_MANAGER", "systemd"),
        ("DYNET_SERVICE_USER", "service"),
        ("DYNET_RUNTIME_DB", "/var/lib/dynet/runtime.sqlite"),
        ("DYNET_SERVICE_ENVIRONMENT_FILE", "/etc/dynet/service.env"),
    ]);

    let config = Config::from_env().expect("config loads from env");

    assert_eq!(config.control.bind, socket("127.0.0.1:9001"));
    assert_eq!(config.ingress.dns.bind, socket("127.0.0.1:9002"));
    assert_eq!(config.ingress.dns.max_sessions, 63);
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
    assert!(config.capture.tun.enabled);
    assert_eq!(config.capture.tun.interface, "dynet-test0");
    assert_eq!(
        config.capture.tun.tcp_idle_timeout,
        Duration::from_millis(2345)
    );
    assert_eq!(
        config.capture.tun.udp_idle_timeout,
        Duration::from_millis(3456)
    );
    assert_eq!(
        config.capture.tun.udp_response_timeout,
        Duration::from_millis(4567)
    );
    assert!(config.ipv6.enabled);
    assert!(config.forwarding.seed.ipv6_enabled);
    assert_eq!(config.dns_mapping.interface.as_deref(), Some("br-test"));
    assert_eq!(config.dns_mapping.source_port, 5353);
    assert_eq!(config.persistence.retention, Duration::from_secs(12 * 3600));
    assert_eq!(config.persistence.max_bytes, 16 * 1024 * 1024);
    assert_eq!(config.service.manager, ServiceManager::Systemd);
    assert_eq!(config.service.user, "service");
    assert_eq!(
        config.service.runtime_database,
        PathBuf::from("/var/lib/dynet/runtime.sqlite")
    );
    assert_eq!(
        config.service.environment_file,
        Some(PathBuf::from("/etc/dynet/service.env"))
    );
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
max_sessions = 31

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

[capture.tun]
enabled = true
interface = "dynet-file0"
tcp_idle_timeout_ms = 1357
udp_idle_timeout_ms = 2468
udp_response_timeout_ms = 3579

[capture.router_ingress]
interface = "br-lan"
ipv4_sources = ["192.168.20.12/32"]
ipv6_sources = ["fd00:20::12/128"]

[ipv6]
enabled = true

[dns_mapping]
interface = "br-lan"
source_port = 53

[persistence]
retention_hours = 6
max_bytes = 8388608

[service]
manager = "procd"
user = "dynet-service"
runtime_database = "/var/lib/dynet/service.sqlite"
environment_file = "/etc/dynet/service.env"
"#,
    )
    .expect("write config");

    let config = Config::from_config_path(Some(&config_path)).expect("config loads from file");

    assert_eq!(config.control.bind, socket("127.0.0.1:9101"));
    assert_eq!(config.ingress.dns.bind, socket("127.0.0.1:9102"));
    assert_eq!(config.ingress.dns.max_sessions, 31);
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
    assert!(config.capture.tun.enabled);
    assert_eq!(config.capture.tun.interface, "dynet-file0");
    assert_eq!(
        config.capture.tun.tcp_idle_timeout,
        Duration::from_millis(1357)
    );
    assert_eq!(
        config.capture.tun.udp_idle_timeout,
        Duration::from_millis(2468)
    );
    assert_eq!(
        config.capture.tun.udp_response_timeout,
        Duration::from_millis(3579)
    );
    assert_eq!(
        config.capture.router_ingress.interface.as_deref(),
        Some("br-lan")
    );
    assert_eq!(
        config.capture.router_ingress.ipv4_sources,
        vec!["192.168.20.12/32"]
    );
    assert_eq!(
        config.capture.router_ingress.ipv6_sources,
        vec!["fd00:20::12/128"]
    );
    assert!(config.ipv6.enabled);
    assert!(config.forwarding.seed.ipv6_enabled);
    assert_eq!(config.dns_mapping.interface.as_deref(), Some("br-lan"));
    assert_eq!(config.dns_mapping.source_port, 53);
    assert_eq!(config.persistence.retention, Duration::from_secs(6 * 3600));
    assert_eq!(config.persistence.max_bytes, 8 * 1024 * 1024);
    assert_eq!(config.service.manager, ServiceManager::Procd);
    assert_eq!(config.service.user, "dynet-service");
    assert_eq!(
        config.service.runtime_database,
        PathBuf::from("/var/lib/dynet/service.sqlite")
    );

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

#[test]
fn rejects_empty_tun_interface() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    let _guard = EnvGuard::set(&[("DYNET_CAPTURE_TUN_INTERFACE", "")]);

    let error = Config::from_env().expect_err("empty TUN interface is rejected");

    assert!(error.contains("DYNET_CAPTURE_TUN_INTERFACE"));
}

#[test]
fn rejects_invalid_persistence_limits() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    let _guard = EnvGuard::set(&[("DYNET_PERSISTENCE_RETENTION_HOURS", "0")]);

    let error = Config::from_env().expect_err("zero retention is rejected");
    assert!(error.contains("DYNET_PERSISTENCE_RETENTION_HOURS"));

    drop(_guard);
    let _guard = EnvGuard::set(&[("DYNET_PERSISTENCE_MAX_BYTES", "1024")]);
    let error = Config::from_env().expect_err("undersized budget is rejected");
    assert!(error.contains("max_bytes must be at least"));
}

#[test]
fn rejects_unsafe_mapping_interface() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    let _guard = EnvGuard::set(&[("DYNET_DNS_MAPPING_INTERFACE", "br-lan;flush")]);

    let error = Config::from_env().expect_err("unsafe interface is rejected");

    assert!(error.contains("DYNET_DNS_MAPPING_INTERFACE"));
}

#[test]
fn rejects_bad_router_scope() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    let _guard = EnvGuard::set(&[]);
    for (label, body) in [
        (
            "interface",
            "[capture.router_ingress]\ninterface = \"br-lan;flush\"\nipv4_sources = [\"192.168.20.12/32\"]\n",
        ),
        (
            "family",
            "[capture.router_ingress]\ninterface = \"br-lan\"\nipv4_sources = [\"fd00:20::12/128\"]\n",
        ),
        (
            "host-bits",
            "[capture.router_ingress]\ninterface = \"br-lan\"\nipv4_sources = [\"192.168.20.12/24\"]\n",
        ),
        (
            "duplicate",
            "[capture.router_ingress]\ninterface = \"br-lan\"\nipv4_sources = [\"192.168.20.12/32\", \"192.168.20.12/32\"]\n",
        ),
    ] {
        let config_path = temp_config_path(label);
        fs::write(&config_path, body).expect("write config");
        let error = Config::from_config_path(Some(&config_path)).expect_err("scope rejected");
        assert!(error.contains("capture.router_ingress"));
        fs::remove_file(config_path).expect("remove config");
    }
}

#[test]
fn rejects_invalid_ipv6_policy() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    let _guard = EnvGuard::set(&[]);
    let config_path = temp_config_path("rejects_invalid_ipv6_policy");
    fs::write(
        &config_path,
        r#"
[forwarding]
default_group = "default"

[[forwarding.nodes]]
id = "default-node"
type = "direct"

[[forwarding.groups]]
id = "default"
mode = "smart"
members = ["default-node"]

[[forwarding.rules]]
id = "bad-ipv6"
priority = 100
match = "domain-suffix"
value = "example.org"
group = "default"
ipv6 = "drop"
"#,
    )
    .expect("write config");

    let error = Config::from_config_path(Some(&config_path)).expect_err("invalid policy rejected");

    assert!(error.contains("ipv6 must be allow, deny, or inherit"));
    fs::remove_file(config_path).expect("remove config");
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
    "DYNET_DNS_MAX_SESSIONS",
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
    "DYNET_CAPTURE_TUN_ENABLED",
    "DYNET_CAPTURE_TUN_INTERFACE",
    "DYNET_CAPTURE_TUN_TCP_IDLE_TIMEOUT_MS",
    "DYNET_CAPTURE_TUN_UDP_IDLE_TIMEOUT_MS",
    "DYNET_CAPTURE_TUN_UDP_RESPONSE_TIMEOUT_MS",
    "DYNET_IPV6_ENABLED",
    "DYNET_DNS_MAPPING_INTERFACE",
    "DYNET_DNS_MAPPING_SOURCE_PORT",
    "DYNET_PERSISTENCE_RETENTION_HOURS",
    "DYNET_PERSISTENCE_MAX_BYTES",
    "DYNET_SERVICE_MANAGER",
    "DYNET_SERVICE_USER",
    "DYNET_RUNTIME_DB",
    "DYNET_SERVICE_ENVIRONMENT_FILE",
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
