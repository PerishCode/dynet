use std::{
    env, fs,
    path::PathBuf,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use dynet_state::Config;

static ENV_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn loads_group_thresholds() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    let _guard = EnvGuard::set(&[]);
    let config_path = temp_config_path("loads_group_thresholds");
    fs::write(
        &config_path,
        r#"
[forwarding]
default_group = "GitHub"

[forwarding.thresholds]
min_success_rate = 0.950
max_active_sessions = 2

[[forwarding.nodes]]
id = "airport-us-01"
type = "direct"

[[forwarding.groups]]
id = "GitHub"
mode = "smart"
members = ["airport-us-01"]

[forwarding.groups.thresholds]
min_success_rate = 0.975
min_samples = 3
"#,
    )
    .expect("write config");

    let config = Config::from_config_path(Some(&config_path)).expect("config loads");
    let github = config
        .forwarding
        .seed
        .groups
        .iter()
        .find(|group| group.id.as_str() == "GitHub")
        .expect("GitHub group");

    assert_eq!(github.thresholds.min_success_rate_ppm, 975_000);
    assert_eq!(github.thresholds.min_samples, 3);
    assert_eq!(github.thresholds.max_active_sessions, Some(2));

    fs::remove_file(config_path).expect("remove config");
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
