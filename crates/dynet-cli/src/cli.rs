use std::path::PathBuf;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum LogLevel {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct CommandOptions {
    pub(crate) root: PathBuf,
    pub(crate) config: Option<PathBuf>,
    pub(crate) format: OutputFormat,
    pub(crate) log_level: LogLevel,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum CliCommand {
    Check(CommandOptions),
    Doctor(CommandOptions),
    Install(InstallOptions),
    Plan(CommandOptions),
    Repair(LifecycleOptions),
    Run(CommandOptions),
    Status(LifecycleOptions),
    Uninstall(LifecycleOptions),
    Verify(LifecycleOptions),
    Api(ApiCommand),
    Help,
    Version,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct InstallOptions {
    pub(crate) lifecycle: LifecycleOptions,
    pub(crate) check: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct LifecycleOptions {
    pub(crate) root: PathBuf,
    pub(crate) config: Option<PathBuf>,
    pub(crate) format: OutputFormat,
    pub(crate) log_level: LogLevel,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum ApiCommand {
    Capabilities(ApiOptions),
    Serve(ApiServeOptions),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct ApiOptions {
    pub(crate) format: OutputFormat,
    pub(crate) log_level: LogLevel,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct ApiServeOptions {
    pub(crate) bind: String,
    pub(crate) once: bool,
    pub(crate) allow_non_loopback: bool,
    pub(crate) log_level: LogLevel,
}

impl CliCommand {
    pub(crate) fn log_level(&self) -> LogLevel {
        match self {
            CliCommand::Check(options)
            | CliCommand::Doctor(options)
            | CliCommand::Plan(options)
            | CliCommand::Run(options) => options.log_level,
            CliCommand::Install(options) => options.lifecycle.log_level,
            CliCommand::Repair(options)
            | CliCommand::Status(options)
            | CliCommand::Uninstall(options)
            | CliCommand::Verify(options) => options.log_level,
            CliCommand::Api(ApiCommand::Capabilities(options)) => options.log_level,
            CliCommand::Api(ApiCommand::Serve(options)) => options.log_level,
            CliCommand::Help | CliCommand::Version => LogLevel::Off,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum CommandMode {
    Check,
    Doctor,
    Install,
    Plan,
    Repair,
    Run,
    Status,
    Uninstall,
    Verify,
    Api,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ApiMode {
    Capabilities,
    Serve,
}

pub(crate) fn parse_args(args: Vec<String>) -> Result<CliCommand, String> {
    if args.is_empty() {
        return Ok(CliCommand::Help);
    }

    let mut root = PathBuf::from(".");
    let mut config = None;
    let mut format = OutputFormat::Text;
    let mut log_level = LogLevel::Off;
    let mut command_seen = false;
    let mut mode = CommandMode::Check;
    let mut api_mode = ApiMode::Capabilities;
    let mut api_subcommand_seen = false;
    let mut api_bind = "127.0.0.1:9977".to_string();
    let mut api_once = false;
    let mut api_allow_non_loopback = false;
    let mut install_check = false;
    let mut args = args.into_iter();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "api" if !command_seen => {
                command_seen = true;
                mode = CommandMode::Api;
            }
            "check" if !command_seen => {
                command_seen = true;
                mode = CommandMode::Check;
            }
            "doctor" if !command_seen => {
                command_seen = true;
                mode = CommandMode::Doctor;
            }
            "install" if !command_seen => {
                command_seen = true;
                mode = CommandMode::Install;
            }
            "plan" if !command_seen => {
                command_seen = true;
                mode = CommandMode::Plan;
            }
            "repair" if !command_seen => {
                command_seen = true;
                mode = CommandMode::Repair;
            }
            "run" if !command_seen => {
                command_seen = true;
                mode = CommandMode::Run;
            }
            "status" if !command_seen => {
                command_seen = true;
                mode = CommandMode::Status;
            }
            "uninstall" if !command_seen => {
                command_seen = true;
                mode = CommandMode::Uninstall;
            }
            "verify" if !command_seen => {
                command_seen = true;
                mode = CommandMode::Verify;
            }
            "capabilities" if mode == CommandMode::Api && !api_subcommand_seen => {
                api_subcommand_seen = true;
                api_mode = ApiMode::Capabilities;
            }
            "serve" if mode == CommandMode::Api && !api_subcommand_seen => {
                api_subcommand_seen = true;
                api_mode = ApiMode::Serve;
            }
            "help" | "--help" | "-h" => return Ok(CliCommand::Help),
            "version" | "--version" | "-V" => return Ok(CliCommand::Version),
            "--root" => {
                root = PathBuf::from(
                    args.next()
                        .ok_or_else(|| "--root requires a value".to_string())?,
                );
            }
            "--config" | "-c" => {
                config = Some(PathBuf::from(
                    args.next()
                        .ok_or_else(|| "--config requires a value".to_string())?,
                ));
            }
            "--format" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--format requires text or json".to_string())?;
                format = parse_format(&value)?;
            }
            "--log-level" => {
                let value = args.next().ok_or_else(|| {
                    "--log-level requires off, error, warn, info, debug, or trace".to_string()
                })?;
                log_level = parse_log_level(&value)?;
            }
            "--bind" if mode == CommandMode::Api => {
                api_bind = args
                    .next()
                    .ok_or_else(|| "--bind requires an address".to_string())?;
            }
            "--once" if mode == CommandMode::Api => {
                api_once = true;
            }
            "--allow-non-loopback" if mode == CommandMode::Api => {
                api_allow_non_loopback = true;
            }
            "--check" if mode == CommandMode::Install => {
                install_check = true;
            }
            other if other.starts_with("--root=") => {
                root = PathBuf::from(&other["--root=".len()..]);
            }
            other if other.starts_with("--config=") => {
                config = Some(PathBuf::from(&other["--config=".len()..]));
            }
            other if other.starts_with("-c=") => {
                config = Some(PathBuf::from(&other["-c=".len()..]));
            }
            other if other.starts_with("--format=") => {
                format = parse_format(&other["--format=".len()..])?;
            }
            other if other.starts_with("--log-level=") => {
                log_level = parse_log_level(&other["--log-level=".len()..])?;
            }
            other if mode == CommandMode::Api && other.starts_with("--bind=") => {
                api_bind = other["--bind=".len()..].to_string();
            }
            other => {
                return Err(format!(
                    "unsupported dynet argument: {other}\n\n{}",
                    help_text()
                ))
            }
        }
    }

    let options = CommandOptions {
        root,
        config,
        format,
        log_level,
    };
    let lifecycle = LifecycleOptions {
        root: options.root.clone(),
        config: options.config.clone(),
        format,
        log_level,
    };
    Ok(match mode {
        CommandMode::Check => CliCommand::Check(options),
        CommandMode::Doctor => CliCommand::Doctor(options),
        CommandMode::Install => CliCommand::Install(InstallOptions {
            lifecycle,
            check: install_check,
        }),
        CommandMode::Plan => CliCommand::Plan(options),
        CommandMode::Repair => CliCommand::Repair(lifecycle),
        CommandMode::Run => CliCommand::Run(options),
        CommandMode::Status => CliCommand::Status(lifecycle),
        CommandMode::Uninstall => CliCommand::Uninstall(lifecycle),
        CommandMode::Verify => CliCommand::Verify(lifecycle),
        CommandMode::Api => match api_mode {
            ApiMode::Capabilities => {
                CliCommand::Api(ApiCommand::Capabilities(ApiOptions { format, log_level }))
            }
            ApiMode::Serve => CliCommand::Api(ApiCommand::Serve(ApiServeOptions {
                bind: api_bind,
                once: api_once,
                allow_non_loopback: api_allow_non_loopback,
                log_level,
            })),
        },
    })
}

pub(crate) fn help_text() -> &'static str {
    r#"dynet

Sing-box-like proxy CLI skeleton.

Commands:
  api capabilities [--format text|json]
  api serve [--bind 127.0.0.1:9977] [--once] [--allow-non-loopback]
  check [--root <path>] [--config <path>] [--format text|json]
        [--log-level off|error|warn|info|debug|trace]
  doctor [--root <path>] [--config <path>] [--format text|json]
         [--log-level off|error|warn|info|debug|trace]
  install --check [--root <path>] [--config <path>] [--format text|json]
        [--log-level off|error|warn|info|debug|trace]
  plan  [--root <path>] [--config <path>] [--format text|json]
        [--log-level off|error|warn|info|debug|trace]
  repair [--format text|json]
  run   [--root <path>] [--config <path>] [--format text|json]
        [--log-level off|error|warn|info|debug|trace]
  status [--format text|json]
  uninstall [--format text|json]
  verify [--format text|json]
  help
  version

Config:
  --config, -c <path>  Load this JSON config. The file's directory becomes the
                       project root for relative runtime state.
  (no --config)        Walk ancestors of --root (default: cwd) looking for a
                       dynet.json. The nearest match wins. `check` falls back
                       to an empty built-in config if none is found.

Reports:
  check reports config summary and validation diagnostics in text or JSON.
  doctor reports config, platform, tun, resolver, and API bind readiness.
  install --check reports network ownership preflight, owned-resource scope,
  and render-only desired state artifacts.
  plan derives the current explicit route plan and explains rule ordering.
  status, verify, repair, and uninstall report dynet-owned resource state.

API:
  capabilities prints the local API surface. serve starts a loopback-only HTTP
  skeleton with GET /health and GET /v1/capabilities.

Runtime:
  run validates config but does not start a proxy yet. Runtime execution will
  land behind a separate boundary.

Exit codes:
  0  report completed without deny-level issues.
  1  config read/parse/validation failure, lifecycle deny issue, or runtime
     skeleton reached.

Project:
  Source:  https://github.com/PerishCode/dynet
"#
}

fn parse_format(value: &str) -> Result<OutputFormat, String> {
    match value {
        "text" => Ok(OutputFormat::Text),
        "json" => Ok(OutputFormat::Json),
        other => Err(format!("unsupported output format: {other}")),
    }
}

fn parse_log_level(value: &str) -> Result<LogLevel, String> {
    match value {
        "off" => Ok(LogLevel::Off),
        "error" => Ok(LogLevel::Error),
        "warn" | "warning" => Ok(LogLevel::Warn),
        "info" => Ok(LogLevel::Info),
        "debug" => Ok(LogLevel::Debug),
        "trace" => Ok(LogLevel::Trace),
        other => Err(format!("unsupported log level: {other}")),
    }
}
