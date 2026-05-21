use std::path::PathBuf;

use crate::cli::{
    help_text, parse_args, ApiCommand, ApiOptions, ApiServeOptions, CliCommand, InstallOptions,
    LifecycleOptions, LogLevel, OutputFormat,
};

#[test]
fn no_args_shows_help() {
    assert_eq!(parse_args(Vec::new()).unwrap(), CliCommand::Help);
}

#[test]
fn parses_check_options() {
    let CliCommand::Check(options) = parse_args(vec![
        "check".into(),
        "--root".into(),
        "workspace".into(),
        "--config=dynet.json".into(),
        "--format=json".into(),
        "--log-level=debug".into(),
    ])
    .unwrap() else {
        panic!("expected check command");
    };

    assert_eq!(options.root, PathBuf::from("workspace"));
    assert_eq!(options.config, Some(PathBuf::from("dynet.json")));
    assert_eq!(options.format, OutputFormat::Json);
    assert_eq!(options.log_level, LogLevel::Debug);
}

#[test]
fn parses_run_options() {
    let CliCommand::Run(options) = parse_args(vec![
        "run".into(),
        "-c".into(),
        "proxy.json".into(),
        "--max-dns-queries=1".into(),
        "--max-tun-packets".into(),
        "1".into(),
        "--max-tcp-sessions=2".into(),
        "--max-udp-sessions".into(),
        "3".into(),
        "--timeout".into(),
        "10".into(),
        "--upstream-dns".into(),
        "8.8.8.8:53".into(),
        "--quality-state".into(),
        ".task/resources/quality.json".into(),
        "--experimental-tcp-forward".into(),
        "--experimental-udp-forward".into(),
    ])
    .unwrap() else {
        panic!("expected run command");
    };

    assert_eq!(options.command.root, PathBuf::from("."));
    assert_eq!(options.command.config, Some(PathBuf::from("proxy.json")));
    assert_eq!(options.command.format, OutputFormat::Text);
    assert_eq!(options.command.log_level, LogLevel::Off);
    assert_eq!(options.max_dns_queries, Some(1));
    assert_eq!(options.max_tun_packets, Some(1));
    assert_eq!(options.max_tcp_sessions, Some(2));
    assert_eq!(options.max_udp_sessions, Some(3));
    assert_eq!(options.timeout_secs, Some(10));
    assert_eq!(options.upstream_dns.as_deref(), Some("8.8.8.8:53"));
    assert_eq!(
        options.quality_state,
        Some(PathBuf::from(".task/resources/quality.json"))
    );
    assert!(options.experimental_tcp_forward);
    assert!(options.experimental_udp_forward);
}

#[test]
fn parses_doctor_options() {
    let CliCommand::Doctor(options) = parse_args(vec![
        "doctor".into(),
        "--config".into(),
        "dynet.json".into(),
        "--format".into(),
        "json".into(),
    ])
    .unwrap() else {
        panic!("expected doctor command");
    };

    assert_eq!(options.config, Some(PathBuf::from("dynet.json")));
    assert_eq!(options.format, OutputFormat::Json);
}

#[test]
fn parses_plan_options() {
    let CliCommand::Plan(options) = parse_args(vec![
        "plan".into(),
        "-c=plan.json".into(),
        "--context".into(),
        r#"{"destinationIp":"93.184.216.34"}"#.into(),
        "--dns-answer=example.com=93.184.216.34".into(),
        "--dns-now=100".into(),
        "--dns-ttl".into(),
        "60".into(),
    ])
    .unwrap() else {
        panic!("expected plan command");
    };

    assert_eq!(options.command.config, Some(PathBuf::from("plan.json")));
    assert_eq!(
        options.context.as_deref(),
        Some(r#"{"destinationIp":"93.184.216.34"}"#)
    );
    assert_eq!(options.dns_answers, ["example.com=93.184.216.34"]);
    assert_eq!(options.dns_now_secs, Some(100));
    assert_eq!(options.dns_ttl_secs, 60);
}

#[test]
fn parses_probe_options() {
    let CliCommand::Probe(options) = parse_args(vec![
        "probe".into(),
        "-c=proxy.json".into(),
        "--url".into(),
        "https://chatgpt.com/".into(),
        "--inbound=tun-in".into(),
        "--quality-state".into(),
        ".task/resources/quality.json".into(),
        "--format=json".into(),
    ])
    .unwrap() else {
        panic!("expected probe command");
    };

    assert_eq!(options.command.config, Some(PathBuf::from("proxy.json")));
    assert_eq!(options.command.format, OutputFormat::Json);
    assert_eq!(options.url.as_deref(), Some("https://chatgpt.com/"));
    assert_eq!(options.inbound.as_deref(), Some("tun-in"));
    assert_eq!(
        options.quality_state,
        Some(PathBuf::from(".task/resources/quality.json"))
    );
}

#[test]
fn parses_install_check_options() {
    assert_eq!(
        parse_args(vec![
            "install".into(),
            "--check".into(),
            "--config".into(),
            "dynet.json".into(),
            "--format=json".into(),
        ])
        .unwrap(),
        CliCommand::Install(InstallOptions {
            lifecycle: LifecycleOptions {
                root: PathBuf::from("."),
                config: Some(PathBuf::from("dynet.json")),
                format: OutputFormat::Json,
                log_level: LogLevel::Off,
            },
            check: true,
        })
    );
}

#[test]
fn parses_lifecycle_status_options() {
    assert_eq!(
        parse_args(vec!["verify".into(), "--format=json".into()]).unwrap(),
        CliCommand::Verify(LifecycleOptions {
            root: PathBuf::from("."),
            config: None,
            format: OutputFormat::Json,
            log_level: LogLevel::Off,
        })
    );
}

#[test]
fn parses_api_capabilities() {
    assert_eq!(
        parse_args(vec![
            "api".into(),
            "capabilities".into(),
            "--format=json".into()
        ])
        .unwrap(),
        CliCommand::Api(ApiCommand::Capabilities(ApiOptions {
            format: OutputFormat::Json,
            log_level: LogLevel::Off,
        }))
    );
}

#[test]
fn parses_api_serve() {
    assert_eq!(
        parse_args(vec![
            "api".into(),
            "serve".into(),
            "--bind".into(),
            "127.0.0.1:0".into(),
            "--once".into(),
        ])
        .unwrap(),
        CliCommand::Api(ApiCommand::Serve(ApiServeOptions {
            bind: "127.0.0.1:0".to_string(),
            once: true,
            allow_non_loopback: false,
            log_level: LogLevel::Off,
        }))
    );
}

#[test]
fn command_reports_log_level() {
    let command = parse_args(vec!["run".into(), "--log-level".into(), "trace".into()]).unwrap();

    assert_eq!(command.log_level(), LogLevel::Trace);
}

#[test]
fn flags_default_to_check() {
    let CliCommand::Check(options) =
        parse_args(vec!["--config".into(), "dynet.json".into()]).unwrap()
    else {
        panic!("expected check command");
    };

    assert_eq!(options.config, Some(PathBuf::from("dynet.json")));
}

#[test]
fn version_command_is_parsed() {
    assert_eq!(
        parse_args(vec!["--version".into()]).unwrap(),
        CliCommand::Version
    );
}

#[test]
fn help_text_describes_boundaries() {
    let help = help_text();

    assert!(help.contains("Sing-box-like proxy CLI skeleton"));
    assert!(help.contains("check [--root <path>]"));
    assert!(help.contains("doctor [--root <path>]"));
    assert!(help.contains("install --check"));
    assert!(help.contains("plan  [--root <path>]"));
    assert!(help.contains("probe [--root <path>]"));
    assert!(help.contains("api capabilities"));
    assert!(help.contains("status [--format text|json]"));
    assert!(help.contains("run   [--root <path>]"));
    assert!(help.contains("runtime"));
    assert!(help.contains("TUN packet observation"));
}
