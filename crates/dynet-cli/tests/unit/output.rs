use std::path::PathBuf;

use dynet_core::DynetConfig;

use crate::{
    cli::OutputFormat,
    config::ConfigSource,
    model::{Report, ReportMode},
    output::{print_report, text_report},
};

#[test]
fn text_report_summarizes_valid_config() {
    let config = DynetConfig::default();
    let report = Report::from_config(
        ReportMode::Check,
        PathBuf::from("."),
        &ConfigSource::BuiltIn,
        &config,
    );

    let text = text_report(&report);

    assert!(text.contains("dynet check passed"));
    assert!(text.contains("summary: inbounds 0, outbounds 0, routes 0"));
}

#[test]
fn text_report_lists_diagnostics() {
    let config: DynetConfig = serde_json::from_str(
        r#"{
            "inbounds": [{ "tag": "mixed-in", "type": "mixed" }],
            "outbounds": [],
            "routes": [{ "inbound": "mixed-in", "outbound": "direct" }]
        }"#,
    )
    .unwrap();
    let report = Report::from_config(
        ReportMode::Check,
        PathBuf::from("."),
        &ConfigSource::BuiltIn,
        &config,
    );

    let text = text_report(&report);

    assert!(text.contains("deny routes[0].outbound"));
    assert_eq!(report.exit_code(), 1);
}

#[test]
fn print_report_accepts_json_format() {
    let config = DynetConfig::default();
    let report = Report::from_config(
        ReportMode::Run,
        PathBuf::from("."),
        &ConfigSource::BuiltIn,
        &config,
    );

    print_report(&report, OutputFormat::Json).unwrap();
}
