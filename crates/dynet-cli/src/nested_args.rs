use std::{ffi::OsString, path::PathBuf};

use super::{
    parse_usize_arg, set_config, split_config_arg, Args, Command, ConfigAction, DnsMappingAction,
    HooksAction, RouterHooksAction, ServiceAction,
};

pub(super) fn parse_config_args(
    parsed: &mut Args,
    args: impl IntoIterator<Item = OsString>,
) -> Result<Command, String> {
    let mut args = args.into_iter();
    let Some(action) = args.next() else {
        return Err("config requires an action: summary, validate".to_string());
    };
    let action = match action.to_string_lossy().as_ref() {
        "summary" => ConfigAction::Summary,
        "validate" => ConfigAction::Validate,
        other => return Err(format!("unknown config action {other}")),
    };
    parse_only_config(parsed, "config", args)?;
    Ok(Command::Config { action })
}

pub(super) fn parse_dns_mapping_args(
    parsed: &mut Args,
    args: impl IntoIterator<Item = OsString>,
) -> Result<Command, String> {
    let mut args = args.into_iter();
    let Some(action) = args.next() else {
        return Err(
            "dns-mapping requires an action: plan, doctor, status, apply, cleanup".to_string(),
        );
    };
    let action = match action.to_string_lossy().as_ref() {
        "plan" => DnsMappingAction::Plan,
        "doctor" => DnsMappingAction::Doctor,
        "status" => DnsMappingAction::Status,
        "apply" => DnsMappingAction::Apply,
        "cleanup" => DnsMappingAction::Cleanup,
        other => return Err(format!("unknown dns-mapping action {other}")),
    };
    parse_only_config(parsed, "dns-mapping", args)?;
    Ok(Command::DnsMapping { action })
}

pub(super) fn parse_hooks_args(
    parsed: &mut Args,
    args: impl IntoIterator<Item = OsString>,
) -> Result<Command, String> {
    let mut args = args.into_iter();
    let Some(action) = args.next() else {
        return Err("hooks requires an action: status, apply, cleanup".to_string());
    };
    let action = match action.to_string_lossy().as_ref() {
        "status" => HooksAction::Status,
        "apply" => HooksAction::Apply,
        "cleanup" => HooksAction::Cleanup,
        other => return Err(format!("unknown hooks action {other}")),
    };
    parse_only_config(parsed, "hooks", args)?;
    Ok(Command::Hooks { action })
}

pub(super) fn parse_router_hooks_args(
    parsed: &mut Args,
    args: impl IntoIterator<Item = OsString>,
) -> Result<Command, String> {
    let mut args = args.into_iter();
    let Some(action) = args.next() else {
        return Err(
            "router-hooks requires an action: plan, doctor, status, apply, cleanup".to_string(),
        );
    };
    let action = match action.to_string_lossy().as_ref() {
        "plan" => RouterHooksAction::Plan,
        "doctor" => RouterHooksAction::Doctor,
        "status" => RouterHooksAction::Status,
        "apply" => RouterHooksAction::Apply,
        "cleanup" => RouterHooksAction::Cleanup,
        other => return Err(format!("unknown router-hooks action {other}")),
    };
    parse_only_config(parsed, "router-hooks", args)?;
    Ok(Command::RouterHooks { action })
}

pub(super) fn parse_service_args(
    parsed: &mut Args,
    args: impl IntoIterator<Item = OsString>,
) -> Result<Command, String> {
    let mut args = args.into_iter();
    let Some(action) = args.next() else {
        return Err(
            "service requires an action: plan, doctor, status, apply, cleanup, start, stop, restart, reload, logs"
                .to_string(),
        );
    };
    let action = action.to_string_lossy();
    let mut cleanup_hooks = false;
    let mut lines = 120_usize;
    let mut follow = false;
    let mut lines_set = false;
    while let Some(arg) = args.next() {
        if arg == "--config" {
            let Some(path) = args.next() else {
                return Err("--config requires a path".to_string());
            };
            set_config(parsed, PathBuf::from(path))?;
        } else if let Some(path) = split_config_arg(&arg) {
            set_config(parsed, path)?;
        } else if matches!(action.as_ref(), "stop" | "restart") && arg == "--cleanup-hooks" {
            if cleanup_hooks {
                return Err("--cleanup-hooks can only be provided once".to_string());
            }
            cleanup_hooks = true;
        } else if action == "logs" && (arg == "-f" || arg == "--follow") {
            if follow {
                return Err("service logs follow option can only be provided once".to_string());
            }
            follow = true;
        } else if action == "logs" && !lines_set {
            lines = parse_usize_arg("service logs", arg)?;
            if lines == 0 {
                return Err("service logs requires a positive line count".to_string());
            }
            lines_set = true;
        } else {
            return Err(format!(
                "unknown service {action} argument {}",
                arg.to_string_lossy()
            ));
        }
    }
    let action = match action.as_ref() {
        "plan" => ServiceAction::Plan,
        "doctor" => ServiceAction::Doctor,
        "status" => ServiceAction::Status,
        "apply" => ServiceAction::Apply,
        "cleanup" => ServiceAction::Cleanup,
        "start" => ServiceAction::Start,
        "stop" => ServiceAction::Stop { cleanup_hooks },
        "restart" => ServiceAction::Restart { cleanup_hooks },
        "reload" => ServiceAction::Reload,
        "logs" => ServiceAction::Logs { lines, follow },
        "supervise" => ServiceAction::Supervise,
        other => return Err(format!("unknown service action {other}")),
    };
    Ok(Command::Service { action })
}

fn parse_only_config(
    parsed: &mut Args,
    command: &str,
    args: impl IntoIterator<Item = OsString>,
) -> Result<(), String> {
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if arg == "--config" {
            let Some(path) = args.next() else {
                return Err("--config requires a path".to_string());
            };
            set_config(parsed, PathBuf::from(path))?;
        } else if let Some(path) = split_config_arg(&arg) {
            set_config(parsed, path)?;
        } else {
            return Err(format!(
                "{command} does not accept argument {}",
                arg.to_string_lossy()
            ));
        }
    }
    Ok(())
}
