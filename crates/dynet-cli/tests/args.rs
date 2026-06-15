use std::{ffi::OsString, path::PathBuf};

use dynet_cli::Args;

#[test]
fn parses_config_flag() {
    let args = Args::parse([OsString::from("--config"), OsString::from("dynet.toml")])
        .expect("args parse");

    assert_eq!(args.config, Some(PathBuf::from("dynet.toml")));
}

#[test]
fn parses_config_equals() {
    let args = Args::parse([OsString::from("--config=custom.toml")]).expect("args parse");

    assert_eq!(args.config, Some(PathBuf::from("custom.toml")));
}

#[test]
fn rejects_unknown_arg() {
    let error = Args::parse([OsString::from("--listen")]).expect_err("unknown arg rejected");

    assert!(error.contains("unknown argument"));
}
