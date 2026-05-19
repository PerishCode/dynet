use std::{env, process::exit};

mod cli;
mod config;
mod model;
mod output;

use cli::{help_text, parse_args, CliCommand, LogLevel};
use config::ConfigSource;
use model::{Report, ReportMode};
use output::print_report;
use tracing::debug;
use tracing_subscriber::filter::LevelFilter;

fn main() {
    match run() {
        Ok(exit_code) => exit(exit_code),
        Err(error) => {
            eprintln!("dynet: {error}");
            exit(1);
        }
    }
}

fn run() -> Result<i32, String> {
    let command = parse_args(env::args().skip(1).collect())?;
    init_tracing(command.log_level())?;
    match command {
        CliCommand::Check(options) => {
            let resolved = config::resolve(options.root, options.config)?;
            debug!(root = %resolved.root.display(), source = ?resolved.source, "resolved config");
            if let ConfigSource::Discovered(path) = &resolved.source {
                eprintln!("dynet: using config {}", path.display());
            }
            let report = Report::from_config(
                ReportMode::Check,
                resolved.root,
                &resolved.source,
                &resolved.config,
            );
            print_report(&report, options.format)?;
            Ok(report.exit_code())
        }
        CliCommand::Run(options) => {
            let resolved = config::resolve(options.root, options.config)?;
            if matches!(resolved.source, ConfigSource::BuiltIn) {
                return Err("run requires a config; pass --config or create dynet.json".to_string());
            }
            let report = Report::from_config(
                ReportMode::Run,
                resolved.root,
                &resolved.source,
                &resolved.config,
            );
            print_report(&report, options.format)?;
            if report.exit_code() != 0 {
                return Ok(report.exit_code());
            }
            eprintln!("dynet: runtime execution is not implemented in this skeleton");
            Ok(1)
        }
        CliCommand::Help => {
            println!("{}", help_text());
            Ok(0)
        }
        CliCommand::Version => {
            println!("dynet {}", build_version());
            Ok(0)
        }
    }
}

fn build_version() -> &'static str {
    option_env!("DYNET_BUILD_VERSION").unwrap_or(concat!("v", env!("CARGO_PKG_VERSION")))
}

fn init_tracing(level: LogLevel) -> Result<(), String> {
    let filter = match level {
        LogLevel::Off => LevelFilter::OFF,
        LogLevel::Error => LevelFilter::ERROR,
        LogLevel::Warn => LevelFilter::WARN,
        LogLevel::Info => LevelFilter::INFO,
        LogLevel::Debug => LevelFilter::DEBUG,
        LogLevel::Trace => LevelFilter::TRACE,
    };
    if filter == LevelFilter::OFF {
        return Ok(());
    }
    tracing_subscriber::fmt()
        .with_max_level(filter)
        .with_target(false)
        .without_time()
        .with_writer(std::io::stderr)
        .try_init()
        .map_err(|error| format!("failed to initialize logging: {error}"))
}
