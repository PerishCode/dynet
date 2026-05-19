use std::{fs, path::PathBuf};

#[test]
fn cli_avoids_protocol_names() {
    let source_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    for path in rust_sources(&source_root) {
        let source = fs::read_to_string(&path).unwrap();
        for forbidden in ["shadowsocks", "wireguard", "netstack"] {
            assert!(
                !source.contains(forbidden),
                "{} imports future protocol/backend detail `{forbidden}`",
                path.display()
            );
        }
    }
}

#[test]
fn harness_stays_outside_cli() {
    let cli_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    assert!(!cli_root.join("harness").exists());
    assert!(cli_root
        .join("../dynet-core/harness/configs/minimal.json")
        .exists());
}

fn rust_sources(root: &std::path::Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    collect_rust_sources(root, &mut paths);
    paths
}

fn collect_rust_sources(path: &std::path::Path, paths: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(path).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect_rust_sources(&path, paths);
            continue;
        }
        if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
            paths.push(path);
        }
    }
}
