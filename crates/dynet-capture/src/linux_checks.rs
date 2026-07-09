use std::path::{Path, PathBuf};

use crate::{CheckState, CommandOutput, TakeoverCheck};

pub(crate) fn directory_check(id: &'static str, label: &'static str, path: &Path) -> TakeoverCheck {
    let state = if path.is_dir() {
        CheckState::Ready
    } else if path.exists() {
        CheckState::InvalidHardFail
    } else {
        CheckState::MissingHardFail
    };
    TakeoverCheck {
        id,
        label,
        path: Some(path.to_path_buf()),
        state,
        auto_action: None,
    }
}

pub(crate) fn directory_auto_check(
    id: &'static str,
    label: &'static str,
    path: &Path,
    auto_action: &'static str,
) -> TakeoverCheck {
    let state = if path.is_dir() {
        CheckState::Ready
    } else if path.exists() {
        CheckState::InvalidHardFail
    } else {
        CheckState::MissingAutoCreatable
    };
    TakeoverCheck {
        id,
        label,
        path: Some(path.to_path_buf()),
        state,
        auto_action: Some(auto_action),
    }
}

pub(crate) fn device_check(id: &'static str, label: &'static str, path: &Path) -> TakeoverCheck {
    let state = if path.exists() {
        CheckState::Ready
    } else {
        CheckState::MissingHardFail
    };
    TakeoverCheck {
        id,
        label,
        path: Some(path.to_path_buf()),
        state,
        auto_action: None,
    }
}

pub(crate) fn fragment_check(
    id: &'static str,
    label: &'static str,
    path: &Path,
    auto_action: &'static str,
) -> TakeoverCheck {
    let state = if path.is_file() {
        CheckState::Ready
    } else if path.exists() {
        CheckState::InvalidHardFail
    } else {
        CheckState::MissingAutoCreatable
    };
    TakeoverCheck {
        id,
        label,
        path: Some(path.to_path_buf()),
        state,
        auto_action: Some(auto_action),
    }
}

pub(crate) fn command_check(
    id: &'static str,
    label: &'static str,
    command: &str,
    command_dirs: &[PathBuf],
) -> TakeoverCheck {
    let state = if command_in_dirs(command, command_dirs) {
        CheckState::Ready
    } else {
        CheckState::MissingHardFail
    };
    TakeoverCheck {
        id,
        label,
        path: None,
        state,
        auto_action: None,
    }
}

pub(crate) fn runtime_command_check(
    id: &'static str,
    label: &'static str,
    result: Result<CommandOutput, String>,
    auto_action: &'static str,
) -> TakeoverCheck {
    let state = match result {
        Ok(output) if output.success => CheckState::Ready,
        Ok(_) => CheckState::MissingAutoCreatable,
        Err(_) => CheckState::MissingHardFail,
    };
    TakeoverCheck {
        id,
        label,
        path: None,
        state,
        auto_action: Some(auto_action),
    }
}

fn command_in_dirs(command: &str, command_dirs: &[PathBuf]) -> bool {
    command_dirs
        .iter()
        .any(|directory| directory.join(command).is_file())
}
