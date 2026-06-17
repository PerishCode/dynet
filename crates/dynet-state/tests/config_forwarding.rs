use std::{
    env, fs,
    path::PathBuf,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use dynet_ingress::{EgressNodeConfig, ShadowsocksMethod};
use dynet_state::Config;

static ENV_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn loads_shadowsocks_forwarding_node() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    let _guard = EnvGuard::set(&[]);
    let config_path = temp_config_path("loads_shadowsocks_forwarding_node");
    fs::write(
        &config_path,
        graph_config(
            r#"
type = "shadowsocks"
server = "demo.example"
port = 8388
method = "aes-256-gcm"
password = "fake-password"
udp = true
"#,
        ),
    )
    .expect("write config");

    let config = Config::from_config_path(Some(&config_path)).expect("config loads");

    let EgressNodeConfig::Shadowsocks(node_config) = node_execution_config(&config, "default-node")
    else {
        panic!("expected shadowsocks node config");
    };
    assert_eq!(node_config.server, "demo.example");
    assert_eq!(node_config.port, 8388);
    assert_eq!(node_config.method, ShadowsocksMethod::Aes256Gcm);
    assert_eq!(node_config.password, "fake-password");

    fs::remove_file(config_path).expect("remove config");
}

#[test]
fn loads_ss2022_forwarding_node() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    let _guard = EnvGuard::set(&[]);
    let config_path = temp_config_path("loads_ss2022_forwarding_node");
    fs::write(
        &config_path,
        graph_config(
            r#"
type = "ss"
server = "demo.example"
port = 8388
method = "2022-blake3-aes-128-gcm"
password = "AQIDBAUGBwgJCgsMDQ4PEA=="
udp = true
"#,
        ),
    )
    .expect("write config");

    let config = Config::from_config_path(Some(&config_path)).expect("config loads");

    let EgressNodeConfig::Shadowsocks(node_config) = node_execution_config(&config, "default-node")
    else {
        panic!("expected shadowsocks node config");
    };
    assert_eq!(node_config.method, ShadowsocksMethod::Blake3Aes128Gcm2022);
    assert_eq!(node_config.password, "AQIDBAUGBwgJCgsMDQ4PEA==");

    fs::remove_file(config_path).expect("remove config");
}

#[test]
fn loads_trojan_forwarding_node() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    let _guard = EnvGuard::set(&[]);
    let config_path = temp_config_path("loads_trojan_forwarding_node");
    fs::write(
        &config_path,
        graph_config(
            r#"
type = "trojan"
server = "demo.example"
port = 443
password = "fake-password"
sni = "sni.example"
skip-cert-verify = true
udp = true
"#,
        ),
    )
    .expect("write config");

    let config = Config::from_config_path(Some(&config_path)).expect("config loads");

    let EgressNodeConfig::Trojan(node_config) = node_execution_config(&config, "default-node")
    else {
        panic!("expected trojan node config");
    };
    assert_eq!(node_config.server, "demo.example");
    assert_eq!(node_config.port, 443);
    assert_eq!(node_config.password, "fake-password");
    assert_eq!(node_config.sni.as_deref(), Some("sni.example"));
    assert!(node_config.skip_cert_verify);

    fs::remove_file(config_path).expect("remove config");
}

#[test]
fn loads_trojan_servername_alias() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    let _guard = EnvGuard::set(&[]);
    let config_path = temp_config_path("loads_trojan_servername_alias");
    fs::write(
        &config_path,
        graph_config(
            r#"
type = "trojan"
server = "demo.example"
port = 443
password = "fake-password"
servername = "sni.example"
udp = true
"#,
        ),
    )
    .expect("write config");

    let config = Config::from_config_path(Some(&config_path)).expect("config loads");

    let EgressNodeConfig::Trojan(node_config) = node_execution_config(&config, "default-node")
    else {
        panic!("expected trojan node config");
    };
    assert_eq!(node_config.sni.as_deref(), Some("sni.example"));
    assert!(!node_config.skip_cert_verify);

    fs::remove_file(config_path).expect("remove config");
}

#[test]
fn loads_vmess_forwarding_node() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    let _guard = EnvGuard::set(&[]);
    let config_path = temp_config_path("loads_vmess_forwarding_node");
    fs::write(
        &config_path,
        graph_config(
            r#"
type = "vmess"
server = "demo.example"
port = 10086
uuid = "11111111-2222-3333-4444-555555555555"
alterId = 0
cipher = "auto"
udp = true
"#,
        ),
    )
    .expect("write config");

    let config = Config::from_config_path(Some(&config_path)).expect("config loads");

    let EgressNodeConfig::Vmess(node_config) = node_execution_config(&config, "default-node")
    else {
        panic!("expected vmess node config");
    };
    assert_eq!(node_config.server, "demo.example");
    assert_eq!(node_config.port, 10086);
    assert_eq!(node_config.uuid, "11111111-2222-3333-4444-555555555555");

    fs::remove_file(config_path).expect("remove config");
}

#[test]
fn loads_vless_forwarding_node() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    let _guard = EnvGuard::set(&[]);
    let config_path = temp_config_path("loads_vless_forwarding_node");
    fs::write(
        &config_path,
        graph_config(
            r#"
type = "vless"
server = "demo.example"
port = 443
uuid = "11111111-2222-3333-4444-555555555555"
servername = "www.example.com"
flow = "xtls-rprx-vision"
network = "tcp"
tls = true
udp = true

[forwarding.nodes.reality-opts]
public-key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
short-id = "0123456789abcdef"
"#,
        ),
    )
    .expect("write config");

    let config = Config::from_config_path(Some(&config_path)).expect("config loads");

    let EgressNodeConfig::Vless(node_config) = node_execution_config(&config, "default-node")
    else {
        panic!("expected vless node config");
    };
    assert_eq!(node_config.server, "demo.example");
    assert_eq!(node_config.port, 443);
    assert_eq!(node_config.uuid, "11111111-2222-3333-4444-555555555555");
    assert_eq!(node_config.server_name, "www.example.com");
    assert_eq!(
        node_config.public_key,
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    );
    assert_eq!(node_config.short_id, "0123456789abcdef");

    fs::remove_file(config_path).expect("remove config");
}

#[test]
fn loads_group_next_graph() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    let _guard = EnvGuard::set(&[]);
    let config_path = temp_config_path("loads_group_next_graph");
    fs::write(
        &config_path,
        r#"
[forwarding]
default_group = "Tunnel"

[[forwarding.nodes]]
id = "airport-us-01"
type = "direct"

[[forwarding.nodes]]
id = "private-fixed-ip"
type = "direct"

[[forwarding.groups]]
id = "Tunnel"
mode = "smart"
next = "Private"
members = ["airport-us-01"]

[[forwarding.groups]]
id = "Private"
mode = "smart"
members = ["private-fixed-ip"]

[[forwarding.rules]]
id = "tunnel-example"
priority = 100
match = "domain-suffix"
value = "example.org"
group = "Tunnel"
"#,
    )
    .expect("write config");

    let config = Config::from_config_path(Some(&config_path)).expect("config loads");

    assert_eq!(config.forwarding.seed.default_group_id.as_str(), "Tunnel");
    let tunnel = config
        .forwarding
        .seed
        .groups
        .iter()
        .find(|group| group.id.as_str() == "Tunnel")
        .expect("Tunnel group");
    assert_eq!(tunnel.next.label(), "Private");
    assert_eq!(config.forwarding.seed.route_rules.len(), 1);

    fs::remove_file(config_path).expect("remove config");
}

#[test]
fn rejects_vmess_alter_id() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    let _guard = EnvGuard::set(&[]);
    let config_path = temp_config_path("rejects_vmess_nonzero_alter_id");
    fs::write(
        &config_path,
        graph_config(
            r#"
type = "vmess"
server = "demo.example"
port = 10086
uuid = "11111111-2222-3333-4444-555555555555"
alterId = 1
cipher = "auto"
udp = true
"#,
        ),
    )
    .expect("write config");

    let error = Config::from_config_path(Some(&config_path)).expect_err("alterId rejected");

    assert!(error.contains("alterId"));

    fs::remove_file(config_path).expect("remove config");
}

#[test]
fn rejects_udp_missing_node() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    let _guard = EnvGuard::set(&[]);
    let config_path = temp_config_path("rejects_udp_missing_node");
    fs::write(
        &config_path,
        graph_config(
            r#"
type = "ss"
server = "demo.example"
port = 8388
method = "aes-256-gcm"
password = "fake-password"
"#,
        ),
    )
    .expect("write config");

    let error = Config::from_config_path(Some(&config_path)).expect_err("udp missing rejected");

    assert!(error.contains("forwarding.nodes[].udp"));

    fs::remove_file(config_path).expect("remove config");
}

fn graph_config(node_body: &str) -> String {
    format!(
        r#"
[forwarding]
default_group = "default"

[[forwarding.nodes]]
id = "default-node"
{node_body}

[[forwarding.groups]]
id = "default"
mode = "smart"
members = ["default-node"]
"#
    )
}

fn node_execution_config<'a>(config: &'a Config, id: &str) -> &'a EgressNodeConfig {
    config
        .forwarding
        .execution_nodes
        .get(id)
        .unwrap_or_else(|| panic!("missing forwarding node {id}"))
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
