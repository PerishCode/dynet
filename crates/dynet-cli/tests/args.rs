use std::{ffi::OsString, path::PathBuf};

use dynet_cli::{Args, Command};

#[test]
fn parses_config_flag() {
    let args = Args::parse([OsString::from("--config"), OsString::from("dynet.toml")])
        .expect("args parse");

    assert_eq!(args.config, Some(PathBuf::from("dynet.toml")));
    assert_eq!(args.command, Command::Run);
}

#[test]
fn parses_config_equals() {
    let args = Args::parse([OsString::from("--config=custom.toml")]).expect("args parse");

    assert_eq!(args.config, Some(PathBuf::from("custom.toml")));
}

#[test]
fn parses_process_stamp() {
    let args = Args::parse([OsString::from("--process-stamp=dynetctl:local")]).expect("args parse");

    assert_eq!(args.process_stamp.as_deref(), Some("dynetctl:local"));
}

#[test]
fn parses_lifecycle_commands() {
    let args = Args::parse([OsString::from("plan")]).expect("args parse");
    assert_eq!(args.command, Command::Plan);

    let args = Args::parse([OsString::from("doctor")]).expect("args parse");
    assert_eq!(args.command, Command::Doctor);

    let args = Args::parse([OsString::from("status")]).expect("args parse");
    assert_eq!(args.command, Command::Status);

    let args =
        Args::parse([OsString::from("apply"), OsString::from("--auto")]).expect("args parse");
    assert_eq!(args.command, Command::Apply { auto: true });

    let args = Args::parse([OsString::from("cleanup")]).expect("args parse");
    assert_eq!(args.command, Command::Cleanup);

    let args = Args::parse([OsString::from("tun-probe")]).expect("args parse");
    assert_eq!(
        args.command,
        Command::TunProbe {
            interface: None,
            wait_ms: 0
        }
    );

    let args =
        Args::parse([OsString::from("tun-probe"), OsString::from("dynet0")]).expect("args parse");
    assert_eq!(
        args.command,
        Command::TunProbe {
            interface: Some("dynet0".to_string()),
            wait_ms: 0
        }
    );

    let args = Args::parse([
        OsString::from("tun-probe"),
        OsString::from("dynet0"),
        OsString::from("--wait-ms=500"),
    ])
    .expect("args parse");
    assert_eq!(
        args.command,
        Command::TunProbe {
            interface: Some("dynet0".to_string()),
            wait_ms: 500
        }
    );

    let args = Args::parse([OsString::from("hooks-status")]).expect("args parse");
    assert_eq!(args.command, Command::HooksStatus);

    let args = Args::parse([OsString::from("hooks-apply")]).expect("args parse");
    assert_eq!(args.command, Command::HooksApply);

    let args = Args::parse([OsString::from("hooks-cleanup")]).expect("args parse");
    assert_eq!(args.command, Command::HooksCleanup);
}

#[test]
fn parses_ipstack_poc_defaults() {
    let args = Args::parse([OsString::from("ipstack-poc")]).expect("args parse");
    assert_eq!(
        args.command,
        Command::IpStackPoc {
            interface: "dynet0".to_string(),
            max_tcp: 1,
            max_udp: 0,
            idle_ms: 15_000,
            udp_response_ms: 1_500,
        }
    );
}

#[test]
fn parses_ipstack_poc_options() {
    let args = Args::parse([
        OsString::from("ipstack-poc"),
        OsString::from("--interface"),
        OsString::from("lab0"),
        OsString::from("--max-tcp=2"),
        OsString::from("--max-udp"),
        OsString::from("1"),
        OsString::from("--idle-ms=3000"),
        OsString::from("--udp-response-ms"),
        OsString::from("250"),
    ])
    .expect("args parse");
    assert_eq!(
        args.command,
        Command::IpStackPoc {
            interface: "lab0".to_string(),
            max_tcp: 2,
            max_udp: 1,
            idle_ms: 3000,
            udp_response_ms: 250,
        }
    );
}

#[test]
fn parses_runtime_poc_defaults() {
    let args = Args::parse([OsString::from("ipstack-runtime-poc")]).expect("args parse");
    assert_eq!(args.config, None);
    assert_eq!(
        args.command,
        Command::IpStackRuntimePoc {
            interface: "dynet0".to_string(),
            max_tcp: 1,
            max_udp: 0,
            idle_ms: 15_000,
            udp_response_ms: 1_500,
            tcp_idle_ms: 2_000,
        }
    );
}

#[test]
fn parses_runtime_poc_options() {
    let args = Args::parse([
        OsString::from("ipstack-runtime-poc"),
        OsString::from("--config=/etc/dynet/dynet.toml"),
        OsString::from("--interface"),
        OsString::from("lab0"),
        OsString::from("--max-tcp=2"),
        OsString::from("--max-udp"),
        OsString::from("1"),
        OsString::from("--idle-ms=3000"),
        OsString::from("--udp-response-ms"),
        OsString::from("250"),
        OsString::from("--tcp-idle-ms=700"),
    ])
    .expect("args parse");
    assert_eq!(args.config, Some(PathBuf::from("/etc/dynet/dynet.toml")));
    assert_eq!(
        args.command,
        Command::IpStackRuntimePoc {
            interface: "lab0".to_string(),
            max_tcp: 2,
            max_udp: 1,
            idle_ms: 3000,
            udp_response_ms: 250,
            tcp_idle_ms: 700,
        }
    );
}

#[test]
fn rejects_unknown_poc_arg() {
    let error = Args::parse([OsString::from("ipstack-poc"), OsString::from("--wat")])
        .expect_err("args error");
    assert!(error.contains("unknown ipstack-poc argument --wat"));
}

#[test]
fn rejects_unknown_runtime_arg() {
    let error = Args::parse([
        OsString::from("ipstack-runtime-poc"),
        OsString::from("--wat"),
    ])
    .expect_err("args error");
    assert!(error.contains("unknown ipstack-runtime-poc argument --wat"));
}

#[test]
fn parses_explicit_run_command() {
    let args = Args::parse([
        OsString::from("run"),
        OsString::from("--config"),
        OsString::from("dynet.toml"),
    ])
    .expect("args parse");

    assert_eq!(args.command, Command::Run);
    assert_eq!(args.config, Some(PathBuf::from("dynet.toml")));
}

#[test]
fn rejects_unknown_arg() {
    let error = Args::parse([OsString::from("--listen")]).expect_err("unknown arg rejected");

    assert!(error.contains("unknown argument"));
}

#[test]
fn rejects_lifecycle_trailing_args() {
    let error = Args::parse([
        OsString::from("doctor"),
        OsString::from("--config=dynet.toml"),
    ])
    .expect_err("trailing arg rejected");

    assert!(error.contains("doctor does not accept"));
}

#[test]
fn rejects_tun_probe_extra() {
    let error = Args::parse([
        OsString::from("tun-probe"),
        OsString::from("dynet0"),
        OsString::from("extra"),
    ])
    .expect_err("extra arg rejected");

    assert!(error.contains("tun-probe accepts at most one interface"));
}
