use std::{
    ffi::OsString,
    path::{Path, PathBuf},
};

mod runtime_reload;
pub use runtime_reload::{ReloadResult, RuntimeReload};

#[derive(Debug, Default, Eq, PartialEq)]
pub struct Args {
    pub command: Command,
    pub config: Option<PathBuf>,
    pub process_stamp: Option<String>,
}

#[derive(Debug, Default, Eq, PartialEq)]
pub enum Command {
    #[default]
    Run,
    Plan,
    Doctor,
    Status,
    Apply {
        auto: bool,
    },
    Reconcile,
    Cleanup,
    Config {
        action: ConfigAction,
    },
    Hooks {
        action: HooksAction,
    },
    IpStackPoc {
        interface: String,
        max_tcp: usize,
        max_udp: usize,
        idle_ms: u64,
        udp_response_ms: u64,
    },
    IpStackRuntimePoc {
        interface: String,
        max_tcp: usize,
        max_udp: usize,
        idle_ms: u64,
        udp_response_ms: u64,
        tcp_idle_ms: u64,
    },
    TunProbe {
        interface: Option<String>,
        wait_ms: u64,
    },
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum HooksAction {
    Status,
    Apply,
    Cleanup,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ConfigAction {
    Summary,
    Validate,
}

impl Args {
    pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Self, String> {
        let mut parsed = Self::default();
        let mut args = args.into_iter();
        if let Some(first) = args.next() {
            match first.to_string_lossy().as_ref() {
                "run" => {}
                "plan" => {
                    parsed.command = Command::Plan;
                    reject_trailing("plan", args)?;
                    return Ok(parsed);
                }
                "doctor" => {
                    parsed.command = Command::Doctor;
                    reject_trailing("doctor", args)?;
                    return Ok(parsed);
                }
                "status" => {
                    parsed.command = Command::Status;
                    reject_trailing("status", args)?;
                    return Ok(parsed);
                }
                "apply" => {
                    parsed.command = Command::Apply {
                        auto: parse_apply_args(args)?,
                    };
                    return Ok(parsed);
                }
                "reconcile" => {
                    parsed.command = Command::Reconcile;
                    reject_trailing("reconcile", args)?;
                    return Ok(parsed);
                }
                "cleanup" => {
                    parsed.command = Command::Cleanup;
                    reject_trailing("cleanup", args)?;
                    return Ok(parsed);
                }
                "config" => {
                    parsed.command = parse_config_args(&mut parsed, args)?;
                    return Ok(parsed);
                }
                "hooks" => {
                    parsed.command = parse_hooks_args(args)?;
                    return Ok(parsed);
                }
                "ipstack-poc" => {
                    parsed.command = parse_ipstack_poc_args(args)?;
                    return Ok(parsed);
                }
                "ipstack-runtime-poc" => {
                    let (command, config) = parse_runtime_poc_args(args)?;
                    parsed.command = command;
                    if let Some(config) = config {
                        set_config(&mut parsed, config)?;
                    }
                    return Ok(parsed);
                }
                "tun-probe" => {
                    parsed.command = parse_tun_probe_args(args)?;
                    return Ok(parsed);
                }
                _ => parse_run_arg(&mut parsed, first, &mut args)?,
            }
        }
        while let Some(arg) = args.next() {
            parse_run_arg(&mut parsed, arg, &mut args)?;
        }
        Ok(parsed)
    }
}

fn parse_config_args(
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
    while let Some(arg) = args.next() {
        if arg == "--config" {
            let Some(path) = args.next() else {
                return Err("--config requires a path".to_string());
            };
            set_config(parsed, PathBuf::from(path))?;
        } else if let Some(path) = split_config_arg(&arg) {
            set_config(parsed, path)?;
        } else {
            return Err(format!("unknown config argument {}", arg.to_string_lossy()));
        }
    }
    Ok(Command::Config { action })
}

fn parse_hooks_args(args: impl IntoIterator<Item = OsString>) -> Result<Command, String> {
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
    reject_trailing("hooks", args)?;
    Ok(Command::Hooks { action })
}

fn parse_run_arg<I>(parsed: &mut Args, arg: OsString, args: &mut I) -> Result<(), String>
where
    I: Iterator<Item = OsString>,
{
    if arg == "--config" {
        let Some(path) = args.next() else {
            return Err("--config requires a path".to_string());
        };
        set_config(parsed, PathBuf::from(path))?;
    } else if arg == "--process-stamp" {
        let Some(stamp) = args.next() else {
            return Err("--process-stamp requires a value".to_string());
        };
        set_process_stamp(parsed, stamp.to_string_lossy().to_string())?;
    } else if let Some(path) = split_config_arg(&arg) {
        set_config(parsed, path)?;
    } else if let Some(stamp) = split_process_stamp_arg(&arg) {
        set_process_stamp(parsed, stamp)?;
    } else {
        return Err(format!("unknown argument {}", arg.to_string_lossy()));
    }
    Ok(())
}

fn split_config_arg(arg: &OsString) -> Option<PathBuf> {
    let value = arg.to_str()?;
    value
        .strip_prefix("--config=")
        .map(|path| Path::new(path).to_path_buf())
}

fn split_process_stamp_arg(arg: &OsString) -> Option<String> {
    let value = arg.to_str()?;
    value
        .strip_prefix("--process-stamp=")
        .map(|stamp| stamp.to_string())
}

fn set_config(args: &mut Args, path: PathBuf) -> Result<(), String> {
    if args.config.is_some() {
        return Err("--config can only be provided once".to_string());
    }
    if path.as_os_str().is_empty() {
        return Err("--config requires a non-empty path".to_string());
    }
    args.config = Some(path);
    Ok(())
}

fn set_process_stamp(args: &mut Args, stamp: String) -> Result<(), String> {
    if args.process_stamp.is_some() {
        return Err("--process-stamp can only be provided once".to_string());
    }
    if stamp.is_empty() {
        return Err("--process-stamp requires a non-empty value".to_string());
    }
    args.process_stamp = Some(stamp);
    Ok(())
}

fn parse_apply_args(args: impl IntoIterator<Item = OsString>) -> Result<bool, String> {
    let mut auto = false;
    for arg in args {
        if arg == "--auto" {
            if auto {
                return Err("--auto can only be provided once".to_string());
            }
            auto = true;
        } else {
            return Err(format!("unknown apply argument {}", arg.to_string_lossy()));
        }
    }
    Ok(auto)
}

fn parse_tun_probe_args(args: impl IntoIterator<Item = OsString>) -> Result<Command, String> {
    let mut interface = None;
    let mut wait_ms = 0;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if arg == "--wait-ms" {
            let Some(value) = args.next() else {
                return Err("--wait-ms requires a value".to_string());
            };
            wait_ms = parse_wait_ms(value)?;
        } else if let Some(value) = split_wait_ms_arg(&arg) {
            wait_ms = parse_wait_ms(OsString::from(value))?;
        } else if interface.is_none() {
            let value = arg.to_string_lossy().to_string();
            if value.is_empty() {
                return Err("tun-probe argument cannot be empty".to_string());
            }
            interface = Some(value);
        } else {
            return Err(format!(
                "tun-probe accepts at most one interface, got {}",
                arg.to_string_lossy()
            ));
        }
    }
    Ok(Command::TunProbe { interface, wait_ms })
}

fn parse_ipstack_poc_args(args: impl IntoIterator<Item = OsString>) -> Result<Command, String> {
    let mut interface = "dynet0".to_string();
    let mut max_tcp = 1;
    let mut max_udp = 0;
    let mut idle_ms = 15_000;
    let mut udp_response_ms = 1_500;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if arg == "--interface" {
            let Some(value) = args.next() else {
                return Err("--interface requires a value".to_string());
            };
            interface = parse_non_empty_value("--interface", value)?;
        } else if let Some(value) = split_value_arg(&arg, "--interface=") {
            interface = parse_non_empty_value("--interface", OsString::from(value))?;
        } else if arg == "--max-tcp" {
            let Some(value) = args.next() else {
                return Err("--max-tcp requires a value".to_string());
            };
            max_tcp = parse_usize_arg("--max-tcp", value)?;
        } else if let Some(value) = split_value_arg(&arg, "--max-tcp=") {
            max_tcp = parse_usize_arg("--max-tcp", OsString::from(value))?;
        } else if arg == "--max-udp" {
            let Some(value) = args.next() else {
                return Err("--max-udp requires a value".to_string());
            };
            max_udp = parse_usize_arg("--max-udp", value)?;
        } else if let Some(value) = split_value_arg(&arg, "--max-udp=") {
            max_udp = parse_usize_arg("--max-udp", OsString::from(value))?;
        } else if arg == "--idle-ms" {
            let Some(value) = args.next() else {
                return Err("--idle-ms requires a value".to_string());
            };
            idle_ms = parse_u64_arg("--idle-ms", value)?;
        } else if let Some(value) = split_value_arg(&arg, "--idle-ms=") {
            idle_ms = parse_u64_arg("--idle-ms", OsString::from(value))?;
        } else if arg == "--udp-response-ms" {
            let Some(value) = args.next() else {
                return Err("--udp-response-ms requires a value".to_string());
            };
            udp_response_ms = parse_u64_arg("--udp-response-ms", value)?;
        } else if let Some(value) = split_value_arg(&arg, "--udp-response-ms=") {
            udp_response_ms = parse_u64_arg("--udp-response-ms", OsString::from(value))?;
        } else {
            return Err(format!(
                "unknown ipstack-poc argument {}",
                arg.to_string_lossy()
            ));
        }
    }
    Ok(Command::IpStackPoc {
        interface,
        max_tcp,
        max_udp,
        idle_ms,
        udp_response_ms,
    })
}

fn parse_runtime_poc_args(
    args: impl IntoIterator<Item = OsString>,
) -> Result<(Command, Option<PathBuf>), String> {
    let mut interface = "dynet0".to_string();
    let mut max_tcp = 1;
    let mut max_udp = 0;
    let mut idle_ms = 15_000;
    let mut udp_response_ms = 1_500;
    let mut tcp_idle_ms = 2_000;
    let mut config = None;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if arg == "--config" {
            let Some(value) = args.next() else {
                return Err("--config requires a path".to_string());
            };
            set_optional_config(&mut config, PathBuf::from(value))?;
        } else if let Some(path) = split_config_arg(&arg) {
            set_optional_config(&mut config, path)?;
        } else if arg == "--interface" {
            let Some(value) = args.next() else {
                return Err("--interface requires a value".to_string());
            };
            interface = parse_non_empty_value("--interface", value)?;
        } else if let Some(value) = split_value_arg(&arg, "--interface=") {
            interface = parse_non_empty_value("--interface", OsString::from(value))?;
        } else if arg == "--max-tcp" {
            let Some(value) = args.next() else {
                return Err("--max-tcp requires a value".to_string());
            };
            max_tcp = parse_usize_arg("--max-tcp", value)?;
        } else if let Some(value) = split_value_arg(&arg, "--max-tcp=") {
            max_tcp = parse_usize_arg("--max-tcp", OsString::from(value))?;
        } else if arg == "--max-udp" {
            let Some(value) = args.next() else {
                return Err("--max-udp requires a value".to_string());
            };
            max_udp = parse_usize_arg("--max-udp", value)?;
        } else if let Some(value) = split_value_arg(&arg, "--max-udp=") {
            max_udp = parse_usize_arg("--max-udp", OsString::from(value))?;
        } else if arg == "--idle-ms" {
            let Some(value) = args.next() else {
                return Err("--idle-ms requires a value".to_string());
            };
            idle_ms = parse_u64_arg("--idle-ms", value)?;
        } else if let Some(value) = split_value_arg(&arg, "--idle-ms=") {
            idle_ms = parse_u64_arg("--idle-ms", OsString::from(value))?;
        } else if arg == "--udp-response-ms" {
            let Some(value) = args.next() else {
                return Err("--udp-response-ms requires a value".to_string());
            };
            udp_response_ms = parse_u64_arg("--udp-response-ms", value)?;
        } else if let Some(value) = split_value_arg(&arg, "--udp-response-ms=") {
            udp_response_ms = parse_u64_arg("--udp-response-ms", OsString::from(value))?;
        } else if arg == "--tcp-idle-ms" {
            let Some(value) = args.next() else {
                return Err("--tcp-idle-ms requires a value".to_string());
            };
            tcp_idle_ms = parse_u64_arg("--tcp-idle-ms", value)?;
        } else if let Some(value) = split_value_arg(&arg, "--tcp-idle-ms=") {
            tcp_idle_ms = parse_u64_arg("--tcp-idle-ms", OsString::from(value))?;
        } else {
            return Err(format!(
                "unknown ipstack-runtime-poc argument {}",
                arg.to_string_lossy()
            ));
        }
    }
    Ok((
        Command::IpStackRuntimePoc {
            interface,
            max_tcp,
            max_udp,
            idle_ms,
            udp_response_ms,
            tcp_idle_ms,
        },
        config,
    ))
}

fn split_wait_ms_arg(arg: &OsString) -> Option<String> {
    split_value_arg(arg, "--wait-ms=")
}

fn parse_wait_ms(value: OsString) -> Result<u64, String> {
    parse_u64_arg("--wait-ms", value)
}

fn split_value_arg(arg: &OsString, prefix: &str) -> Option<String> {
    let value = arg.to_str()?;
    value.strip_prefix(prefix).map(str::to_string)
}

fn parse_non_empty_value(label: &str, value: OsString) -> Result<String, String> {
    let value = value.to_string_lossy().to_string();
    if value.is_empty() {
        return Err(format!("{label} requires a non-empty value"));
    }
    Ok(value)
}

fn set_optional_config(config: &mut Option<PathBuf>, path: PathBuf) -> Result<(), String> {
    if config.is_some() {
        return Err("--config can only be provided once".to_string());
    }
    if path.as_os_str().is_empty() {
        return Err("--config requires a non-empty path".to_string());
    }
    *config = Some(path);
    Ok(())
}

fn parse_usize_arg(label: &str, value: OsString) -> Result<usize, String> {
    let value = value.to_string_lossy();
    value
        .parse::<usize>()
        .map_err(|_| format!("{label} requires a non-negative integer, got {value}"))
}

fn parse_u64_arg(label: &str, value: OsString) -> Result<u64, String> {
    let value = value.to_string_lossy();
    value
        .parse::<u64>()
        .map_err(|_| format!("{label} requires a non-negative integer, got {value}"))
}

fn reject_trailing(command: &str, args: impl IntoIterator<Item = OsString>) -> Result<(), String> {
    let trailing = args.into_iter().next();
    if let Some(arg) = trailing {
        return Err(format!(
            "{command} does not accept argument {}",
            arg.to_string_lossy()
        ));
    }
    Ok(())
}
