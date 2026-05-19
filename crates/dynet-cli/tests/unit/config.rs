use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::config::{resolve, ConfigSource, DEFAULT_CONFIG_FILENAME};

const SAMPLE_CONFIG: &str = r#"{ "inbounds": [], "outbounds": [], "routes": [] }"#;

#[test]
fn resolves_explicit_config_path() {
    let root = test_root("explicit");
    fs::create_dir_all(&root).unwrap();
    let explicit = root.join("custom.json");
    fs::write(&explicit, SAMPLE_CONFIG).unwrap();

    let resolved = resolve(root.clone(), Some(explicit.clone())).unwrap();

    assert_eq!(resolved.source, ConfigSource::Explicit(explicit));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn discovers_dynet_json_root() {
    let root = test_root("discovery");
    fs::create_dir_all(&root).unwrap();
    let discovered = root.join(DEFAULT_CONFIG_FILENAME);
    fs::write(&discovered, SAMPLE_CONFIG).unwrap();

    let resolved = resolve(root.clone(), None).unwrap();

    assert_eq!(
        resolved.source,
        ConfigSource::Discovered(canonical(&discovered))
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn walk_up_finds_nearest() {
    let root = test_root("walk-up");
    let nested = root.join("a/b/c");
    fs::create_dir_all(&nested).unwrap();
    fs::write(root.join(DEFAULT_CONFIG_FILENAME), SAMPLE_CONFIG).unwrap();
    let nearer_root = root.join("a");
    let nearer = nearer_root.join(DEFAULT_CONFIG_FILENAME);
    fs::write(&nearer, SAMPLE_CONFIG).unwrap();

    let resolved = resolve(nested, None).unwrap();

    assert_eq!(
        resolved.source,
        ConfigSource::Discovered(canonical(&nearer))
    );
    assert_eq!(resolved.root, canonical(&nearer_root));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn builtin_check_fallback() {
    let root = test_root("builtin");
    fs::create_dir_all(&root).unwrap();

    let resolved = resolve(root.clone(), None).unwrap();

    assert_eq!(resolved.source, ConfigSource::BuiltIn);
    assert_eq!(resolved.config.summary().inbounds, 0);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn propagates_parse_errors() {
    let root = test_root("parse-error");
    fs::create_dir_all(&root).unwrap();
    let explicit = root.join("broken.json");
    fs::write(&explicit, "{").unwrap();

    let error = resolve(root.clone(), Some(explicit)).unwrap_err();

    assert!(error.contains("failed to parse config"));

    let _ = fs::remove_dir_all(root);
}

fn test_root(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "dynet-config-{name}-{}-{}",
        std::process::id(),
        next_seq()
    ));
    let _ = fs::remove_dir_all(&root);
    root
}

fn next_seq() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    SEQ.fetch_add(1, Ordering::Relaxed)
}

fn canonical(path: &Path) -> PathBuf {
    path.canonicalize().expect("test path canonicalizes")
}
