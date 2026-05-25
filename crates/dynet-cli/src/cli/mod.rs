use std::path::PathBuf;

mod help;
mod probe_read;
mod probe_retry;
mod run_limits;
mod run_tcp;
mod types;
mod values;

pub(crate) use help::help_text;
pub(crate) use types::*;
use values::{
    parse_format, parse_log_level, parse_probe_protocol, parse_u16, parse_u32, parse_u64,
    parse_usize,
};

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
    let mut plan_quality_state = None;
    let mut probe_url = None;
    let mut probe_host = None;
    let mut probe_port = None;
    let mut probe_path = None;
    let mut probe_inbound = None;
    let mut probe_quality_state = None;
    let mut probe_protocol = ProbeProtocol::HttpsHead;
    let default_probe_read_policy = dynet_runtime::ProbeReadPolicy::default();
    let mut read_poll_ms = default_probe_read_policy.poll_timeout_ms;
    let mut read_budget_ms = default_probe_read_policy.pending_budget_ms;
    let mut read_sleep_ms = default_probe_read_policy.pending_sleep_ms;
    let mut probe_retry_attempts = 1;
    let mut probe_retry_sleep_ms = 250;
    let mut run_limits = run_limits::RunLimitArgs::default();
    let mut run_timeout_secs = None;
    let default_outbound_tcp = dynet_runtime::OutboundTcpSettings::default();
    let mut tcp_connect_ms = default_outbound_tcp.connect_timeout_ms;
    let mut tcp_rw_ms = default_outbound_tcp.read_write_timeout_ms;
    let mut run_upstream_dns = None;
    let mut run_quality_state = None;
    let mut run_experimental_tcp_forward = false;
    let mut tcp_slot_capacity = dynet_runtime::TcpForwardingSettings::DEFAULT_LISTEN_SLOTS_PER_PORT;
    let mut run_experimental_udp_forward = false;
    let mut args = args.into_iter();

    while let Some(arg) = args.next() {
        if mode == CommandMode::Probe
            && probe_retry::parse_arg(
                arg.as_str(),
                &mut args,
                &mut probe_retry_attempts,
                &mut probe_retry_sleep_ms,
            )?
        {
            continue;
        }
        if mode == CommandMode::Probe
            && probe_read::parse_arg(
                arg.as_str(),
                &mut args,
                &mut read_poll_ms,
                &mut read_budget_ms,
                &mut read_sleep_ms,
            )?
        {
            continue;
        }
        if mode == CommandMode::Run
            && run_limits::parse_arg(arg.as_str(), &mut args, &mut run_limits)?
        {
            continue;
        }
        if matches!(mode, CommandMode::Run | CommandMode::Probe)
            && run_tcp::parse_arg(arg.as_str(), &mut args, &mut tcp_connect_ms, &mut tcp_rw_ms)?
        {
            continue;
        }
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
            "--quality-state" if mode == CommandMode::Plan => {
                plan_quality_state =
                    Some(PathBuf::from(args.next().ok_or_else(|| {
                        "--quality-state requires a JSON path".to_string()
                    })?));
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
                let value = args.next().ok_or_else(|| {
                    "--protocol requires tcp-connect, https-head, or tls-handshake".to_string()
                })?;
                probe_protocol = parse_probe_protocol(&value)?;
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
            "--experimental-tcp-listen-slots-per-port" if mode == CommandMode::Run => {
                let value = args.next().ok_or_else(|| {
                    "--experimental-tcp-listen-slots-per-port requires a positive integer"
                        .to_string()
                })?;
                tcp_slot_capacity =
                    parse_usize("--experimental-tcp-listen-slots-per-port", &value)?;
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
            other if mode == CommandMode::Plan && other.starts_with("--quality-state=") => {
                plan_quality_state = Some(PathBuf::from(&other["--quality-state=".len()..]));
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
            other
                if mode == CommandMode::Run
                    && other.starts_with("--experimental-tcp-listen-slots-per-port=") =>
            {
                tcp_slot_capacity = parse_usize(
                    "--experimental-tcp-listen-slots-per-port",
                    &other["--experimental-tcp-listen-slots-per-port=".len()..],
                )?;
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
            quality_state: plan_quality_state,
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
            retry_direct_tls_eof_attempts: probe_retry_attempts,
            retry_direct_tls_eof_sleep_ms: probe_retry_sleep_ms,
            read_poll_timeout_ms: read_poll_ms,
            read_pending_budget_ms: read_budget_ms,
            read_pending_sleep_ms: read_sleep_ms,
            outbound_tcp_connect_timeout_ms: tcp_connect_ms,
            outbound_tcp_read_write_timeout_ms: tcp_rw_ms,
        }),
        CommandMode::Repair => CliCommand::Repair(lifecycle),
        CommandMode::Run => CliCommand::Run(RunOptions {
            command: options,
            max_dns_queries: run_limits.max_dns_queries,
            max_tun_packets: run_limits.max_tun_packets,
            max_tcp_sessions: run_limits.max_tcp_sessions,
            max_tcp_closed_sessions: run_limits.max_tcp_closed_sessions,
            max_tcp_terminal_sessions: run_limits.max_tcp_terminal_sessions,
            max_udp_sessions: run_limits.max_udp_sessions,
            max_udp_downstream_bytes: run_limits.max_udp_downstream_bytes,
            timeout_secs: run_timeout_secs,
            outbound_tcp_connect_timeout_ms: tcp_connect_ms,
            outbound_tcp_read_write_timeout_ms: tcp_rw_ms,
            upstream_dns: run_upstream_dns,
            quality_state: run_quality_state,
            experimental_tcp_forward: run_experimental_tcp_forward,
            experimental_tcp_listen_slots_per_port: tcp_slot_capacity,
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
