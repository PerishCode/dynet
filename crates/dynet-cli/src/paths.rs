use std::{
    env,
    path::{Path, PathBuf},
};

pub(crate) fn resolve_runtime_path(
    path: &Path,
    config_path: Option<&Path>,
) -> Result<PathBuf, String> {
    resolve_config_relative(path, config_path)
}

pub(crate) fn resolve_config_relative(
    path: &Path,
    config_path: Option<&Path>,
) -> Result<PathBuf, String> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    if let Some(parent) = config_path.and_then(Path::parent) {
        return Ok(parent.join(path));
    }
    env::current_dir()
        .map(|directory| directory.join(path))
        .map_err(|error| format!("failed to resolve path {}: {error}", path.display()))
}
