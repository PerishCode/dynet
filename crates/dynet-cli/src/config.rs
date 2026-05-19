use std::{
    fs,
    path::{Path, PathBuf},
};

use dynet_core::DynetConfig;

pub(crate) const DEFAULT_CONFIG_FILENAME: &str = "dynet.json";

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum ConfigSource {
    Explicit(PathBuf),
    Discovered(PathBuf),
    BuiltIn,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct ResolvedConfig {
    pub(crate) root: PathBuf,
    pub(crate) config: DynetConfig,
    pub(crate) source: ConfigSource,
}

pub(crate) fn resolve(start: PathBuf, explicit: Option<PathBuf>) -> Result<ResolvedConfig, String> {
    if let Some(path) = explicit {
        let root = config_parent(&path);
        let config = from_file(&path)?;
        return Ok(ResolvedConfig {
            root,
            config,
            source: ConfigSource::Explicit(path),
        });
    }

    let start = canonicalize_start(&start)?;
    if let Some(candidate) = walk_up_for_config(&start) {
        let root = config_parent(&candidate);
        let config = from_file(&candidate)?;
        return Ok(ResolvedConfig {
            root,
            config,
            source: ConfigSource::Discovered(candidate),
        });
    }

    Ok(ResolvedConfig {
        root: start,
        config: DynetConfig::default(),
        source: ConfigSource::BuiltIn,
    })
}

fn from_file(path: &Path) -> Result<DynetConfig, String> {
    let source = fs::read_to_string(path)
        .map_err(|error| format!("failed to read config {}: {error}", path.display()))?;
    serde_json::from_str(&source)
        .map_err(|error| format!("failed to parse config {}: {error}", path.display()))
}

fn canonicalize_start(start: &Path) -> Result<PathBuf, String> {
    start
        .canonicalize()
        .map_err(|error| format!("failed to resolve {}: {error}", start.display()))
}

fn walk_up_for_config(start: &Path) -> Option<PathBuf> {
    for ancestor in start.ancestors() {
        let candidate = ancestor.join(DEFAULT_CONFIG_FILENAME);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn config_parent(config_path: &Path) -> PathBuf {
    match config_path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    }
}
