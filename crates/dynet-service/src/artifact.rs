use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

use sha2::{Digest, Sha256};

use crate::ResourceState;

const OWNER_MARKER: &str = "# dynet-owned: service-control";
const HASH_PREFIX: &str = "# dynet-content-sha256:";

pub(crate) fn managed_content(payload: &str) -> String {
    let hash = digest(payload.as_bytes());
    if let Some((shebang, body)) = payload
        .split_once('\n')
        .filter(|(line, _)| line.starts_with("#!"))
    {
        return format!("{shebang}\n{OWNER_MARKER}\n{HASH_PREFIX}{hash}\n{body}");
    }
    format!("{OWNER_MARKER}\n{HASH_PREFIX}{hash}\n{payload}")
}

pub(crate) fn classify(
    path: &Path,
    desired: &str,
    desired_mode: u32,
) -> Result<ResourceState, String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ResourceState::Missing)
        }
        Err(error) => {
            return Err(format!(
                "failed reading metadata for {}: {error}",
                path.display()
            ))
        }
    };
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Ok(ResourceState::Invalid);
    }
    let actual = match fs::read_to_string(path) {
        Ok(actual) => actual,
        Err(error) => return Err(format!("failed reading {}: {error}", path.display())),
    };
    if actual == desired {
        return Ok(if mode_matches(&metadata, desired_mode) {
            ResourceState::Ready
        } else {
            ResourceState::ManagedUpdate
        });
    }
    let mut lines = actual.lines();
    let first = lines.next();
    let shebang = first.filter(|line| line.starts_with("#!"));
    let owner = if shebang.is_some() {
        lines.next()
    } else {
        first
    };
    if owner != Some(OWNER_MARKER) {
        return Ok(ResourceState::Foreign);
    }
    let Some(recorded_hash) = lines.next().and_then(|line| line.strip_prefix(HASH_PREFIX)) else {
        return Ok(ResourceState::Drifted);
    };
    let body = lines.collect::<Vec<_>>().join("\n") + "\n";
    let payload = shebang.map_or(body.clone(), |line| format!("{line}\n{body}"));
    if digest(payload.as_bytes()) != recorded_hash {
        return Ok(ResourceState::Drifted);
    }
    Ok(ResourceState::ManagedUpdate)
}

pub(crate) fn atomic_write(path: &Path, content: &str, mode: u32) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", path.display()))?;
    if !parent.is_dir() {
        return Err(format!("service carrier {} is missing", parent.display()));
    }
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("{} has an invalid file name", path.display()))?;
    let temporary = parent.join(format!(".{file_name}.dynet-{}", std::process::id()));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .map_err(|error| format!("failed creating {}: {error}", temporary.display()))?;
    let result = (|| {
        file.write_all(content.as_bytes())
            .map_err(|error| format!("failed writing {}: {error}", temporary.display()))?;
        file.sync_all()
            .map_err(|error| format!("failed syncing {}: {error}", temporary.display()))?;
        set_mode(&temporary, mode)?;
        fs::rename(&temporary, path).map_err(|error| {
            format!(
                "failed replacing {} with {}: {error}",
                path.display(),
                temporary.display()
            )
        })?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub(crate) fn remove_owned(path: &Path, desired: &str, desired_mode: u32) -> Result<bool, String> {
    match classify(path, desired, desired_mode)? {
        ResourceState::Missing => Ok(false),
        ResourceState::Ready | ResourceState::ManagedUpdate => {
            fs::remove_file(path)
                .map_err(|error| format!("failed removing {}: {error}", path.display()))?;
            Ok(true)
        }
        state => Err(format!(
            "{} is {}; refusing to remove",
            path.display(),
            state.label()
        )),
    }
}

#[cfg(unix)]
fn mode_matches(metadata: &fs::Metadata, desired_mode: u32) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o777 == desired_mode
}

#[cfg(not(unix))]
fn mode_matches(_metadata: &fs::Metadata, _desired_mode: u32) -> bool {
    true
}

fn digest(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content);
    format!("{:x}", hasher.finalize())
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|error| format!("failed setting mode on {}: {error}", path.display()))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<(), String> {
    Ok(())
}
