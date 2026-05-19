use std::path::PathBuf;

use crate::cli::{
    help_text, parse_args, ApiCommand, ApiOptions, ApiServeOptions, CliCommand, CommandOptions,
    LogLevel, OutputFormat,
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
    assert_eq!(
        parse_args(vec!["run".into(), "-c".into(), "proxy.json".into()]).unwrap(),
        CliCommand::Run(CommandOptions {
            root: PathBuf::from("."),
            config: Some(PathBuf::from("proxy.json")),
            format: OutputFormat::Text,
            log_level: LogLevel::Off,
        })
    );
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
    let CliCommand::Plan(options) = parse_args(vec!["plan".into(), "-c=plan.json".into()]).unwrap()
    else {
        panic!("expected plan command");
    };

    assert_eq!(options.config, Some(PathBuf::from("plan.json")));
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
fn flags_without_command_default_to_check() {
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
    assert!(help.contains("plan  [--root <path>]"));
    assert!(help.contains("api capabilities"));
    assert!(help.contains("run   [--root <path>]"));
    assert!(help.contains("runtime"));
    assert!(help.contains("does not start a proxy yet"));
}
