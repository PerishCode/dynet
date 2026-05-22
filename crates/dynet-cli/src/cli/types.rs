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
    Plan(PlanOptions),
    Probe(ProbeOptions),
    Repair(LifecycleOptions),
    Run(RunOptions),
    Status(LifecycleOptions),
    Uninstall(LifecycleOptions),
    Verify(LifecycleOptions),
    Api(ApiCommand),
    Help,
    Version,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct PlanOptions {
    pub(crate) command: CommandOptions,
    pub(crate) context: Option<String>,
    pub(crate) dns_answers: Vec<String>,
    pub(crate) dns_now_secs: Option<u64>,
    pub(crate) dns_ttl_secs: u32,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct RunOptions {
    pub(crate) command: CommandOptions,
    pub(crate) max_dns_queries: Option<usize>,
    pub(crate) max_tun_packets: Option<usize>,
    pub(crate) max_tcp_sessions: Option<usize>,
    pub(crate) max_udp_sessions: Option<usize>,
    pub(crate) timeout_secs: Option<u64>,
    pub(crate) upstream_dns: Option<String>,
    pub(crate) quality_state: Option<PathBuf>,
    pub(crate) experimental_tcp_forward: bool,
    pub(crate) experimental_udp_forward: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct ProbeOptions {
    pub(crate) command: CommandOptions,
    pub(crate) protocol: ProbeProtocol,
    pub(crate) url: Option<String>,
    pub(crate) host: Option<String>,
    pub(crate) port: Option<u16>,
    pub(crate) path: Option<String>,
    pub(crate) inbound: Option<String>,
    pub(crate) quality_state: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum ProbeProtocol {
    HttpsHead,
    TlsHandshake,
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
            CliCommand::Check(options) | CliCommand::Doctor(options) => options.log_level,
            CliCommand::Run(options) => options.command.log_level,
            CliCommand::Plan(options) => options.command.log_level,
            CliCommand::Probe(options) => options.command.log_level,
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
