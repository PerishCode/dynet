use std::{env, net::IpAddr, process::exit};

mod api;
mod cli;
mod config;
mod model;
mod output;
mod platform;

use cli::{help_text, parse_args, ApiCommand, CliCommand, LogLevel};
use config::ConfigSource;
use dynet_core::{DnsReverseIndex, InboundContext};
use model::{
    ApiCapabilityReport, DoctorReport, PlanEvaluationInput, PlanReport, Report, ReportMode,
};
use output::{
    print_api_capabilities, print_doctor_report, print_lifecycle_report, print_plan_report,
    print_report,
};
use platform::LifecycleAction;
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
        CliCommand::Doctor(options) => {
            let resolved = config::resolve(options.root, options.config)?;
            debug!(root = %resolved.root.display(), source = ?resolved.source, "resolved config");
            let report =
                DoctorReport::from_config(&resolved.root, &resolved.source, &resolved.config);
            print_doctor_report(&report, options.format)?;
            Ok(report.exit_code())
        }
        CliCommand::Install(options) => {
            let resolved = config::resolve(options.lifecycle.root, options.lifecycle.config)?;
            if matches!(resolved.source, ConfigSource::BuiltIn) {
                return Err(
                    "install requires a config; pass --config or create dynet.json".to_string(),
                );
            }
            let report = platform::install_report(
                &resolved.root,
                &resolved.source,
                &resolved.config,
                options.check,
            );
            print_lifecycle_report(&report, options.lifecycle.format)?;
            Ok(report.exit_code())
        }
        CliCommand::Plan(options) => run_plan_command(options),
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
        CliCommand::Status(options) => {
            let report = platform::status_report(LifecycleAction::Status);
            print_lifecycle_report(&report, options.format)?;
            Ok(report.exit_code())
        }
        CliCommand::Verify(options) => {
            let report = platform::status_report(LifecycleAction::Verify);
            print_lifecycle_report(&report, options.format)?;
            Ok(report.exit_code())
        }
        CliCommand::Repair(options) => {
            let report = platform::status_report(LifecycleAction::Repair);
            print_lifecycle_report(&report, options.format)?;
            Ok(report.exit_code())
        }
        CliCommand::Uninstall(options) => {
            let report = platform::status_report(LifecycleAction::Uninstall);
            print_lifecycle_report(&report, options.format)?;
            Ok(report.exit_code())
        }
        CliCommand::Api(ApiCommand::Capabilities(options)) => {
            let report = ApiCapabilityReport::current();
            print_api_capabilities(&report, options.format)?;
            Ok(0)
        }
        CliCommand::Api(ApiCommand::Serve(options)) => api::serve(options),
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

fn run_plan_command(options: cli::PlanOptions) -> Result<i32, String> {
    let resolved = config::resolve(options.command.root.clone(), options.command.config.clone())?;
    debug!(root = %resolved.root.display(), source = ?resolved.source, "resolved config");
    if matches!(resolved.source, ConfigSource::BuiltIn) {
        return Err("plan requires a config; pass --config or create dynet.json".to_string());
    }
    let evaluation = plan_evaluation_input(&options)?;
    let report = PlanReport::from_config(
        &resolved.root,
        &resolved.source,
        &resolved.config,
        evaluation,
    );
    debug!(
        schema = %report.plan.schema,
        state_schema = %report.plan.state_schema,
        rules = report.plan_summary.rules,
        explicit_rules = report.plan_summary.explicit_rules,
        dynamic_rules = report.plan_summary.dynamic_rules,
        "built plan"
    );
    print_plan_report(&report, options.command.format)?;
    Ok(report.exit_code())
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

fn plan_evaluation_input(
    options: &cli::PlanOptions,
) -> Result<Option<PlanEvaluationInput>, String> {
    let Some(context) = &options.context else {
        return Ok(None);
    };
    let context = serde_json::from_str::<InboundContext>(context)
        .map_err(|error| format!("failed to parse --context JSON: {error}"))?;
    let mut dns_reverse = DnsReverseIndex::default();
    let observed_at_secs = 0;
    dns_reverse.now_secs = Some(options.dns_now_secs.unwrap_or(observed_at_secs));
    for answer in &options.dns_answers {
        add_dns_answer(
            &mut dns_reverse,
            answer,
            observed_at_secs,
            options.dns_ttl_secs,
        )?;
    }
    Ok(Some(PlanEvaluationInput {
        context,
        dns_reverse,
    }))
}

fn add_dns_answer(
    dns_reverse: &mut DnsReverseIndex,
    answer: &str,
    observed_at_secs: u64,
    ttl_secs: u32,
) -> Result<(), String> {
    let Some((domain, addresses)) = answer.split_once('=') else {
        return Err(format!(
            "--dns-answer must look like domain=ip[,ip...], got `{answer}`"
        ));
    };
    for address in addresses.split(',') {
        let address = address
            .parse::<IpAddr>()
            .map_err(|error| format!("invalid --dns-answer IP `{address}`: {error}"))?;
        dns_reverse.insert_real_answer(domain, None::<&str>, address, observed_at_secs, ttl_secs);
    }
    Ok(())
}
