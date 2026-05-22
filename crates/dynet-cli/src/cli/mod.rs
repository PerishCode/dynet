use std::path::PathBuf;

mod help;
mod types;
mod values;

pub(crate) use help::help_text;
pub(crate) use types::*;
use values::{
    parse_format, parse_log_level, parse_probe_protocol, parse_u16, parse_u32, parse_u64,
    parse_usize,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum CommandMode {
    Check,
    Doctor,
    Install,
    Plan,
    Probe,
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
    let mut plan_context = None;
    let mut plan_dns_answers = Vec::new();
    let mut plan_dns_now_secs = None;
    let mut plan_dns_ttl_secs = 300;
    let mut probe_url = None;
    let mut probe_host = None;
    let mut probe_port = None;
    let mut probe_path = None;
    let mut probe_inbound = None;
    let mut probe_quality_state = None;
    let mut probe_protocol = ProbeProtocol::HttpsHead;
    let mut run_max_dns_queries = None;
    let mut run_max_tun_packets = None;
    let mut run_max_tcp_sessions = None;
    let mut run_max_udp_sessions = None;
    let mut run_timeout_secs = None;
    let mut run_upstream_dns = None;
    let mut run_quality_state = None;
    let mut run_experimental_tcp_forward = false;
    let mut run_experimental_udp_forward = false;
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
            "probe" if !command_seen => {
                command_seen = true;
                mode = CommandMode::Probe;
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
            "--context" if mode == CommandMode::Plan => {
                plan_context = Some(
                    args.next()
                        .ok_or_else(|| "--context requires a JSON object".to_string())?,
                );
            }
            "--dns-answer" if mode == CommandMode::Plan => {
                plan_dns_answers.push(
                    args.next()
                        .ok_or_else(|| "--dns-answer requires domain=ip[,ip...]".to_string())?,
                );
            }
            "--dns-now" if mode == CommandMode::Plan => {
                let value = args
                    .next()
                    .ok_or_else(|| "--dns-now requires an integer timestamp".to_string())?;
                plan_dns_now_secs = Some(parse_u64("--dns-now", &value)?);
            }
            "--dns-ttl" if mode == CommandMode::Plan => {
                let value = args
                    .next()
                    .ok_or_else(|| "--dns-ttl requires an integer seconds value".to_string())?;
                plan_dns_ttl_secs = parse_u32("--dns-ttl", &value)?;
            }
            "--url" if mode == CommandMode::Probe => {
                probe_url = Some(
                    args.next()
                        .ok_or_else(|| "--url requires an https URL".to_string())?,
                );
            }
            "--host" if mode == CommandMode::Probe => {
                probe_host = Some(
                    args.next()
                        .ok_or_else(|| "--host requires a domain or address".to_string())?,
                );
            }
            "--port" if mode == CommandMode::Probe => {
                let value = args
                    .next()
                    .ok_or_else(|| "--port requires a positive integer".to_string())?;
                probe_port = Some(parse_u16("--port", &value)?);
            }
            "--path" if mode == CommandMode::Probe => {
                probe_path = Some(
                    args.next()
                        .ok_or_else(|| "--path requires an absolute path".to_string())?,
                );
            }
            "--inbound" if mode == CommandMode::Probe => {
                probe_inbound = Some(
                    args.next()
                        .ok_or_else(|| "--inbound requires an inbound tag".to_string())?,
                );
            }
            "--quality-state" if mode == CommandMode::Probe => {
                probe_quality_state =
                    Some(PathBuf::from(args.next().ok_or_else(|| {
                        "--quality-state requires a JSON path".to_string()
                    })?));
            }
            "--protocol" if mode == CommandMode::Probe => {
                let value = args
                    .next()
                    .ok_or_else(|| "--protocol requires https-head or tls-handshake".to_string())?;
                probe_protocol = parse_probe_protocol(&value)?;
            }
            "--max-dns-queries" if mode == CommandMode::Run => {
                let value = args
                    .next()
                    .ok_or_else(|| "--max-dns-queries requires a positive integer".to_string())?;
                run_max_dns_queries = Some(parse_usize("--max-dns-queries", &value)?);
            }
            "--max-tun-packets" if mode == CommandMode::Run => {
                let value = args
                    .next()
                    .ok_or_else(|| "--max-tun-packets requires a positive integer".to_string())?;
                run_max_tun_packets = Some(parse_usize("--max-tun-packets", &value)?);
            }
            "--max-tcp-sessions" if mode == CommandMode::Run => {
                let value = args
                    .next()
                    .ok_or_else(|| "--max-tcp-sessions requires a positive integer".to_string())?;
                run_max_tcp_sessions = Some(parse_usize("--max-tcp-sessions", &value)?);
            }
            "--max-udp-sessions" if mode == CommandMode::Run => {
                let value = args
                    .next()
                    .ok_or_else(|| "--max-udp-sessions requires a positive integer".to_string())?;
                run_max_udp_sessions = Some(parse_usize("--max-udp-sessions", &value)?);
            }
            "--timeout" if mode == CommandMode::Run => {
                let value = args
                    .next()
                    .ok_or_else(|| "--timeout requires integer seconds".to_string())?;
                run_timeout_secs = Some(parse_u64("--timeout", &value)?);
            }
            "--upstream-dns" if mode == CommandMode::Run => {
                run_upstream_dns = Some(
                    args.next()
                        .ok_or_else(|| "--upstream-dns requires ip:port".to_string())?,
                );
            }
            "--quality-state" if mode == CommandMode::Run => {
                run_quality_state =
                    Some(PathBuf::from(args.next().ok_or_else(|| {
                        "--quality-state requires a JSON path".to_string()
                    })?));
            }
            "--experimental-tcp-forward" if mode == CommandMode::Run => {
                run_experimental_tcp_forward = true;
            }
            "--experimental-udp-forward" if mode == CommandMode::Run => {
                run_experimental_udp_forward = true;
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
            other if mode == CommandMode::Plan && other.starts_with("--context=") => {
                plan_context = Some(other["--context=".len()..].to_string());
            }
            other if mode == CommandMode::Plan && other.starts_with("--dns-answer=") => {
                plan_dns_answers.push(other["--dns-answer=".len()..].to_string());
            }
            other if mode == CommandMode::Plan && other.starts_with("--dns-now=") => {
                plan_dns_now_secs = Some(parse_u64("--dns-now", &other["--dns-now=".len()..])?);
            }
            other if mode == CommandMode::Plan && other.starts_with("--dns-ttl=") => {
                plan_dns_ttl_secs = parse_u32("--dns-ttl", &other["--dns-ttl=".len()..])?;
            }
            other if mode == CommandMode::Probe && other.starts_with("--url=") => {
                probe_url = Some(other["--url=".len()..].to_string());
            }
            other if mode == CommandMode::Probe && other.starts_with("--host=") => {
                probe_host = Some(other["--host=".len()..].to_string());
            }
            other if mode == CommandMode::Probe && other.starts_with("--port=") => {
                probe_port = Some(parse_u16("--port", &other["--port=".len()..])?);
            }
            other if mode == CommandMode::Probe && other.starts_with("--path=") => {
                probe_path = Some(other["--path=".len()..].to_string());
            }
            other if mode == CommandMode::Probe && other.starts_with("--inbound=") => {
                probe_inbound = Some(other["--inbound=".len()..].to_string());
            }
            other if mode == CommandMode::Probe && other.starts_with("--quality-state=") => {
                probe_quality_state = Some(PathBuf::from(&other["--quality-state=".len()..]));
            }
            other if mode == CommandMode::Probe && other.starts_with("--protocol=") => {
                probe_protocol = parse_probe_protocol(&other["--protocol=".len()..])?;
            }
            other if mode == CommandMode::Run && other.starts_with("--max-dns-queries=") => {
                run_max_dns_queries = Some(parse_usize(
                    "--max-dns-queries",
                    &other["--max-dns-queries=".len()..],
                )?);
            }
            other if mode == CommandMode::Run && other.starts_with("--max-tun-packets=") => {
                run_max_tun_packets = Some(parse_usize(
                    "--max-tun-packets",
                    &other["--max-tun-packets=".len()..],
                )?);
            }
            other if mode == CommandMode::Run && other.starts_with("--max-tcp-sessions=") => {
                run_max_tcp_sessions = Some(parse_usize(
                    "--max-tcp-sessions",
                    &other["--max-tcp-sessions=".len()..],
                )?);
            }
            other if mode == CommandMode::Run && other.starts_with("--max-udp-sessions=") => {
                run_max_udp_sessions = Some(parse_usize(
                    "--max-udp-sessions",
                    &other["--max-udp-sessions=".len()..],
                )?);
            }
            other if mode == CommandMode::Run && other.starts_with("--timeout=") => {
                run_timeout_secs = Some(parse_u64("--timeout", &other["--timeout=".len()..])?);
            }
            other if mode == CommandMode::Run && other.starts_with("--upstream-dns=") => {
                run_upstream_dns = Some(other["--upstream-dns=".len()..].to_string());
            }
            other if mode == CommandMode::Run && other.starts_with("--quality-state=") => {
                run_quality_state = Some(PathBuf::from(&other["--quality-state=".len()..]));
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
        CommandMode::Plan => CliCommand::Plan(PlanOptions {
            command: options,
            context: plan_context,
            dns_answers: plan_dns_answers,
            dns_now_secs: plan_dns_now_secs,
            dns_ttl_secs: plan_dns_ttl_secs,
        }),
        CommandMode::Probe => CliCommand::Probe(ProbeOptions {
            command: options,
            protocol: probe_protocol,
            url: probe_url,
            host: probe_host,
            port: probe_port,
            path: probe_path,
            inbound: probe_inbound,
            quality_state: probe_quality_state,
        }),
        CommandMode::Repair => CliCommand::Repair(lifecycle),
        CommandMode::Run => CliCommand::Run(RunOptions {
            command: options,
            max_dns_queries: run_max_dns_queries,
            max_tun_packets: run_max_tun_packets,
            max_tcp_sessions: run_max_tcp_sessions,
            max_udp_sessions: run_max_udp_sessions,
            timeout_secs: run_timeout_secs,
            upstream_dns: run_upstream_dns,
            quality_state: run_quality_state,
            experimental_tcp_forward: run_experimental_tcp_forward,
            experimental_udp_forward: run_experimental_udp_forward,
        }),
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
