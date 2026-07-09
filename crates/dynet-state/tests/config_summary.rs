use std::{
    env, fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use dynet_state::{redacted_summary_lines, Config};

#[test]
fn summary_redacts_secrets() {
    let config_path = temp_config_path("summary_redacts_secrets");
    fs::write(
        &config_path,
        r#"
[control]
bind = "127.0.0.1:9977"

[capture.tun]
enabled = true
interface = "dynet0"
tcp_idle_timeout_ms = 2000
udp_idle_timeout_ms = 2000
udp_response_timeout_ms = 1500

[forwarding]
default_group = "Tunnel"

[[forwarding.nodes]]
id = "airport-us-01"
type = "vmess"
server = "vmess-secret.example"
port = 10086
uuid = "11111111-2222-3333-4444-555555555555"
alterId = 0
cipher = "auto"
udp = true

[[forwarding.nodes]]
id = "private-fixed-ip"
type = "vless"
server = "vless-secret.example"
port = 443
uuid = "22222222-3333-4444-5555-666666666666"
servername = "front-secret.example"
flow = "xtls-rprx-vision"
network = "tcp"
tls = true
udp = true

[forwarding.nodes.reality-opts]
public-key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
short-id = "0123456789abcdef"

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
    let rendered = redacted_summary_lines(&config).join("\n");

    assert!(rendered.contains("nodes.total=2"));
    assert!(rendered.contains("vmess=1"));
    assert!(rendered.contains("vless=1"));
    assert!(rendered.contains("group id=Tunnel enabled=true members=1 next=Private"));
    assert!(rendered.contains("rules.total=1 Tunnel=1"));
    for secret in [
        "vmess-secret.example",
        "vless-secret.example",
        "11111111-2222-3333-4444-555555555555",
        "22222222-3333-4444-5555-666666666666",
        "front-secret.example",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "0123456789abcdef",
    ] {
        assert!(!rendered.contains(secret), "summary leaked {secret}");
    }

    fs::remove_file(config_path).expect("remove config");
}

fn temp_config_path(name: &str) -> PathBuf {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    env::temp_dir().join(format!("dynet-{name}-{}-{now}", std::process::id()))
}
