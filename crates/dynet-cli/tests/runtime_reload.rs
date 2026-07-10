use dynet_cli::{ReloadResult, RuntimeReload};
use dynet_runtime::{ConfigReloadOutcome, ConfigReloadTrigger, RuntimeState, RuntimeStore};
use dynet_state::Config;
use std::{
    env, fs,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[tokio::test]
async fn applies_then_noops() {
    let directory = tempfile::TempDir::new().expect("tempdir");
    let path = temp_config_path("apply");
    fs::write(
        &path,
        r#"[capture.tun]
tcp_idle_timeout_ms = 9000

[forwarding]
default_group = "default"

[[forwarding.nodes]]
id = "default-node"
type = "direct"

[[forwarding.groups]]
id = "default"
mode = "smart"
members = ["default-node"]
"#,
    )
    .expect("write candidate");
    let config = Config::default();
    let store = RuntimeStore::open(directory.path().join("runtime.sqlite"))
        .await
        .expect("runtime store");
    let runtime = RuntimeState::from_store_seed(store.clone(), config.forwarding.seed.clone())
        .await
        .expect("runtime state");
    let inspector = store.clone();
    let reload = RuntimeReload::new(config, Some(path.clone()), runtime.clone(), store)
        .expect("reload controller");

    let applied = reload.reload(ConfigReloadTrigger::Manual).await;
    let noop = reload.reload(ConfigReloadTrigger::Manual).await;

    assert_eq!(
        applied,
        ReloadResult::Applied {
            generation: 2,
            changed_fields: vec![
                "capture.tun.tcp_idle_timeout".to_string(),
                "forwarding".to_string(),
            ],
        }
    );
    assert_eq!(noop, ReloadResult::Noop { generation: 2 });
    assert_eq!(runtime.generation(), 2);
    assert_eq!(
        reload
            .tun_config()
            .read()
            .expect("TUN config")
            .tcp_idle_timeout,
        Duration::from_secs(9)
    );
    assert_eq!(reload.audit().snapshot().len(), 2);
    let expected = Config::from_config_path(Some(&path))
        .expect("candidate config")
        .forwarding
        .seed
        .nodes[0]
        .fingerprint
        .clone();
    assert_eq!(
        inspector.load_nodes().await.expect("stored nodes")[0].fingerprint,
        expected
    );
    fs::remove_file(path).expect("remove candidate");
}

#[tokio::test]
async fn rejects_bad_candidates() {
    let directory = tempfile::TempDir::new().expect("tempdir");
    let path = temp_config_path("reject");
    fs::write(&path, "not valid toml").expect("write invalid candidate");
    let config = Config::default();
    let store = RuntimeStore::open(directory.path().join("runtime.sqlite"))
        .await
        .expect("runtime store");
    let runtime = RuntimeState::from_store_seed(store.clone(), config.forwarding.seed.clone())
        .await
        .expect("runtime state");
    let reload = RuntimeReload::new(config, Some(path.clone()), runtime.clone(), store)
        .expect("reload controller");

    let invalid = reload.reload(ConfigReloadTrigger::Manual).await;
    fs::write(&path, "[control]\nbind = \"127.0.0.1:19977\"\n").expect("write restart candidate");
    let restart = reload.reload(ConfigReloadTrigger::Manual).await;

    assert_eq!(invalid, ReloadResult::Invalid { generation: 1 });
    assert_eq!(
        restart,
        ReloadResult::RestartRequired {
            generation: 1,
            fields: vec!["control.bind".to_string()],
        }
    );
    assert_eq!(runtime.generation(), 1);
    assert_eq!(
        reload.audit().status().fingerprint,
        Config::default().fingerprint()
    );
    assert_eq!(
        reload.audit().status().last_reload_outcome,
        Some(ConfigReloadOutcome::RestartRequired)
    );
    fs::remove_file(path).expect("remove candidate");
}

fn temp_config_path(name: &str) -> PathBuf {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    env::temp_dir().join(format!(
        "dynet-reload-{name}-{}-{now}.toml",
        std::process::id()
    ))
}
