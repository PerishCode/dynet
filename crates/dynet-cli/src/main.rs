use std::{
    env, fs,
    net::{IpAddr, SocketAddr},
    path::Path,
    process::exit,
    time::Duration,
};

mod api;
mod cli;
mod config;
mod model;
mod output;
mod platform;

use cli::{help_text, parse_args, ApiCommand, CliCommand, LogLevel};
use config::ConfigSource;
use dynet_core::{DnsChain, DnsReverseIndex, DynetConfig, InboundContext, OutboundQualityState};
use model::{
    ApiCapabilityReport, DoctorReport, PlanEvaluationInput, PlanReport, Report, ReportMode,
};
use output::{
    print_api_capabilities, print_doctor_report, print_lifecycle_report, print_plan_report,
    print_probe_report, print_report, print_runtime_report,
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
        CliCommand::Probe(options) => run_probe_command(options),
        CliCommand::Run(options) => run_runtime_command(options),
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
            let report = platform::uninstall_report();
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

fn run_runtime_command(options: cli::RunOptions) -> Result<i32, String> {
    let resolved = config::resolve(options.command.root.clone(), options.command.config.clone())?;
    if matches!(resolved.source, ConfigSource::BuiltIn) {
        return Err("run requires a config; pass --config or create dynet.json".to_string());
    }
    let config_report = Report::from_config(
        ReportMode::Run,
        resolved.root,
        &resolved.source,
        &resolved.config,
    );
    if config_report.exit_code() != 0 {
        print_report(&config_report, options.command.format)?;
        return Ok(config_report.exit_code());
    }
    let dns_chain = runtime_dns_chain(&resolved.config, options.upstream_dns.as_deref())?;
    let takeover = platform::runtime_takeover_settings()?;
    let limits = dynet_runtime::RunLimits {
        max_dns_queries: options.max_dns_queries,
        max_tun_packets: options.max_tun_packets,
        max_tcp_sessions: options.max_tcp_sessions,
        max_udp_sessions: options.max_udp_sessions,
        timeout: options.timeout_secs.map(Duration::from_secs),
    };
    let policy = if let Some(path) = &options.quality_state {
        dynet_runtime::RuntimePolicy::from_config_with_quality(
            resolved.config.clone(),
            load_quality_state(path)?,
        )
    } else {
        dynet_runtime::RuntimePolicy::from_config(resolved.config.clone())
    };
    let runtime_settings = takeover
        .runtime_settings(dns_chain)
        .with_policy(policy)
        .with_tcp_forwarding(dynet_runtime::TcpForwardingSettings {
            enabled: options.experimental_tcp_forward,
        })
        .with_udp_forwarding(dynet_runtime::UdpForwardingSettings {
            enabled: options.experimental_udp_forward,
        });
    let report = dynet_runtime::run(runtime_settings, limits)?;
    print_runtime_report(&report, options.command.format)?;
    Ok(if report.status == dynet_runtime::RuntimeStatus::Pass {
        0
    } else {
        1
    })
}

fn run_probe_command(options: cli::ProbeOptions) -> Result<i32, String> {
    let resolved = config::resolve(options.command.root.clone(), options.command.config.clone())?;
    if matches!(resolved.source, ConfigSource::BuiltIn) {
        return Err("probe requires a config; pass --config or create dynet.json".to_string());
    }
    let config_report = Report::from_config(
        ReportMode::Run,
        resolved.root,
        &resolved.source,
        &resolved.config,
    );
    if config_report.exit_code() != 0 {
        print_report(&config_report, options.command.format)?;
        return Ok(config_report.exit_code());
    }
    let target = probe_target(&options)?;
    let bypass_mark = 0;
    let policy = if let Some(path) = &options.quality_state {
        dynet_runtime::RuntimePolicy::from_config_with_quality(
            resolved.config,
            load_quality_state(path)?,
        )
    } else {
        dynet_runtime::RuntimePolicy::from_config(resolved.config)
    };
    let report = dynet_runtime::probe_https_head(dynet_runtime::ProbeSettings {
        target,
        inbound: options.inbound,
        bypass_mark,
        policy,
    })?;
    print_probe_report(&report, options.command.format)?;
    Ok(if report.status == dynet_runtime::RuntimeStatus::Pass {
        0
    } else {
        1
    })
}

fn load_quality_state(path: &Path) -> Result<OutboundQualityState, String> {
    let text = fs::read_to_string(path)
        .map_err(|error| format!("failed to read quality state {}: {error}", path.display()))?;
    serde_json::from_str(&text)
        .map_err(|error| format!("failed to parse quality state {}: {error}", path.display()))
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

fn runtime_dns_chain(
    config: &DynetConfig,
    upstream_dns: Option<&str>,
) -> Result<dynet_runtime::DnsRuntimeChain, String> {
    if let Some(value) = upstream_dns
        .map(str::to_string)
        .or_else(|| env::var("DYNET_DNS_UPSTREAM").ok())
    {
        let upstream_dns = value
            .parse::<SocketAddr>()
            .map_err(|error| format!("invalid upstream DNS `{value}`: {error}"))?;
        return Ok(dynet_runtime::DnsRuntimeChain::Udp { upstream_dns });
    }
    if let Some(chain) = env_dns_chain()? {
        return Ok(chain);
    }
    if let Some(chain) = configured_dns_chain(config) {
        return dns_chain_from_config(chain);
    }
    Err("run requires dns.chains[0] or an explicit DNS diagnostic override".to_string())
}

fn env_dns_chain() -> Result<Option<dynet_runtime::DnsRuntimeChain>, String> {
    let Some(endpoint) = env::var("DYNET_DOH_ENDPOINT").ok() else {
        return Ok(None);
    };
    let bootstrap =
        env::var("DYNET_DOH_BOOTSTRAP_IPS").unwrap_or_else(|_| "1.1.1.1,1.0.0.1".to_string());
    let bootstrap_ips = parse_ip_list("DYNET_DOH_BOOTSTRAP_IPS", &bootstrap)?;
    Ok(Some(dynet_runtime::DnsRuntimeChain::Doh {
        endpoint,
        bootstrap_ips,
    }))
}

fn configured_dns_chain(config: &DynetConfig) -> Option<&DnsChain> {
    config.dns.chains.first()
}

fn dns_chain_from_config(chain: &DnsChain) -> Result<dynet_runtime::DnsRuntimeChain, String> {
    match chain.kind.as_str() {
        "doh" => Ok(dynet_runtime::DnsRuntimeChain::Doh {
            endpoint: chain
                .endpoint
                .clone()
                .ok_or_else(|| format!("DNS chain `{}` has no endpoint", chain.tag))?,
            bootstrap_ips: chain.bootstrap_ips.clone(),
        }),
        "udp" => {
            let server = chain
                .server
                .as_deref()
                .ok_or_else(|| format!("DNS chain `{}` has no UDP server", chain.tag))?;
            let server = server
                .parse::<IpAddr>()
                .map_err(|error| format!("invalid DNS chain server `{server}`: {error}"))?;
            let port = chain
                .server_port
                .ok_or_else(|| format!("DNS chain `{}` has no UDP serverPort", chain.tag))?;
            Ok(dynet_runtime::DnsRuntimeChain::Udp {
                upstream_dns: SocketAddr::new(server, port),
            })
        }
        kind => Err(format!(
            "DNS chain `{}` has unsupported runtime type `{kind}`",
            chain.tag
        )),
    }
}

fn parse_ip_list(label: &str, value: &str) -> Result<Vec<IpAddr>, String> {
    let mut addresses = Vec::new();
    for item in value.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        addresses.push(
            item.parse::<IpAddr>()
                .map_err(|error| format!("invalid {label} IP `{item}`: {error}"))?,
        );
    }
    if addresses.is_empty() {
        return Err(format!("{label} must contain at least one IP address"));
    }
    Ok(addresses)
}

fn probe_target(options: &cli::ProbeOptions) -> Result<dynet_runtime::ProbeTarget, String> {
    let from_url = match &options.url {
        Some(url) => Some(parse_https_url(url)?),
        None => None,
    };
    let host = options
        .host
        .clone()
        .or_else(|| from_url.as_ref().map(|target| target.host.clone()))
        .ok_or_else(|| "probe requires --url or --host".to_string())?;
    let port = options
        .port
        .or_else(|| from_url.as_ref().map(|target| target.port))
        .unwrap_or(443);
    let path = options
        .path
        .clone()
        .or_else(|| from_url.map(|target| target.path))
        .unwrap_or_else(|| "/".to_string());
    Ok(dynet_runtime::ProbeTarget { host, port, path })
}

fn parse_https_url(url: &str) -> Result<dynet_runtime::ProbeTarget, String> {
    let Some(rest) = url.strip_prefix("https://") else {
        return Err("probe --url currently supports https:// URLs only".to_string());
    };
    let (host_port, path) = match rest.split_once('/') {
        Some((host_port, path)) => (host_port, format!("/{path}")),
        None => (rest, "/".to_string()),
    };
    if host_port.is_empty() {
        return Err("probe --url host must not be empty".to_string());
    }
    let (host, port) = match host_port.rsplit_once(':') {
        Some((host, port)) if !host.contains(']') => {
            let port = port
                .parse::<u16>()
                .map_err(|error| format!("invalid probe URL port `{port}`: {error}"))?;
            (host.to_string(), port)
        }
        _ => (host_port.to_string(), 443),
    };
    Ok(dynet_runtime::ProbeTarget { host, port, path })
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
