use std::path::PathBuf;

use dynet_core::DynetConfig;

use crate::{
    cli::OutputFormat,
    config::ConfigSource,
    model::{ApiCapabilityReport, DoctorReport, PlanReport, Report, ReportMode},
    output::{
        print_api_capabilities, print_doctor_report, print_plan_report, print_report,
        text_api_capabilities, text_doctor_report, text_plan_report, text_report,
    },
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

#[test]
fn text_plan_report_lists_explicit_rules() {
    let config: DynetConfig = serde_json::from_str(
        r#"{
            "inbounds": [{ "tag": "mixed-in", "type": "mixed" }],
            "outbounds": [{ "tag": "direct", "type": "direct" }],
            "routes": [{ "inbound": "mixed-in", "outbound": "direct" }]
        }"#,
    )
    .unwrap();
    let report = PlanReport::from_config(PathBuf::from("."), &ConfigSource::BuiltIn, &config);

    let text = text_plan_report(&report);

    assert!(text.contains("dynet plan passed"));
    assert!(text.contains("inbound mixed-in -> outbound direct"));
    assert_eq!(report.exit_code(), 0);
    print_plan_report(&report, OutputFormat::Json).unwrap();
}

#[test]
fn text_doctor_report_lists_checks() {
    let config = DynetConfig::default();
    let report = DoctorReport::from_config(PathBuf::from("."), &ConfigSource::BuiltIn, &config);

    let text = text_doctor_report(&report);

    assert!(text.contains("dynet doctor"));
    assert!(text.contains("checks:"));
    assert!(text.contains("config-source"));
    assert_eq!(report.exit_code(), 0);
    print_doctor_report(&report, OutputFormat::Json).unwrap();
}

#[test]
fn api_capability_output_lists_endpoints() {
    let report = ApiCapabilityReport::current();
    let text = text_api_capabilities(&report);

    assert!(text.contains("/health"));
    assert!(text.contains("/v1/capabilities"));
    print_api_capabilities(&report, OutputFormat::Json).unwrap();
}
