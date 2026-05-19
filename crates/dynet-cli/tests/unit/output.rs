use std::path::PathBuf;

use dynet_core::DynetConfig;

use crate::{
    cli::OutputFormat,
    config::ConfigSource,
    model::{ApiCapabilityReport, DoctorReport, PlanReport, Report, ReportMode},
    output::{
        print_api_capabilities, print_doctor_report, print_lifecycle_report, print_plan_report,
        print_report, text_api_capabilities, text_doctor_report, text_lifecycle_report,
        text_plan_report, text_report,
    },
    platform::{install_report, status_report, LifecycleAction, LifecycleStatus},
};

#[test]
fn text_report_summarizes_config() {
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
    assert!(text.contains("network model: dynet-network/v1alpha1"));
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
fn print_report_accepts_json() {
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
fn text_plan_lists_rules() {
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
    assert!(text.contains("plan model: dynet-plan/v1alpha1 over dynet-state/v1alpha1"));
    assert!(text.contains("match inbound mixed-in -> use outbound direct"));
    assert_eq!(report.exit_code(), 0);
    print_plan_report(&report, OutputFormat::Json).unwrap();
}

#[test]
fn text_report_lists_models() {
    let config: DynetConfig = serde_json::from_str(include_str!(
        "../../../dynet-core/harness/configs/tcp-udp.json"
    ))
    .unwrap();
    let report = Report::from_config(
        ReportMode::Check,
        PathBuf::from("."),
        &ConfigSource::BuiltIn,
        &config,
    );

    let text = text_report(&report);

    assert!(text.contains("inbounds:"));
    assert!(text.contains("- tcp-in tcp"));
    assert!(text.contains("- udp-out udp"));
    assert_eq!(report.exit_code(), 0);
}

#[test]
fn doctor_report_lists_checks() {
    let config = DynetConfig::default();
    let report = DoctorReport::from_config(PathBuf::from("."), &ConfigSource::BuiltIn, &config);

    let text = text_doctor_report(&report);

    assert!(text.contains("dynet doctor"));
    assert!(text.contains("checks:"));
    assert!(text.contains("config-source"));
    assert!(text.contains("network-model"));
    assert_eq!(report.exit_code(), 0);
    print_doctor_report(&report, OutputFormat::Json).unwrap();
}

#[test]
fn api_output_lists_endpoints() {
    let report = ApiCapabilityReport::current();
    let text = text_api_capabilities(&report);

    assert!(text.contains("/health"));
    assert!(text.contains("/v1/capabilities"));
    print_api_capabilities(&report, OutputFormat::Json).unwrap();
}

#[test]
fn lifecycle_lists_resources() {
    let report = status_report(LifecycleAction::Status);
    let text = text_lifecycle_report(&report);

    assert!(text.contains("dynet status"));
    assert!(text.contains("owned resources:"));
    assert!(text.contains("nft-table inet dynet"));
    print_lifecycle_report(&report, OutputFormat::Json).unwrap();
}

#[test]
fn install_lists_preflight() {
    let config = DynetConfig::default();
    let report = install_report(
        PathBuf::from(".").as_path(),
        &ConfigSource::BuiltIn,
        &config,
        true,
    );
    let text = text_lifecycle_report(&report);

    assert!(text.contains("dynet install"));
    assert!(text.contains("apply-engine"));
    assert!(text.contains("desired state: dynet-platform/v1alpha1 (render-only)"));
    assert!(text.contains("nftables dynet.nft -> nft -f -"));
    assert!(text.contains("desired validations:"));
    assert!(text.contains("artifact:nft-structure"));
    assert_eq!(report.exit_code(), 0);
}

#[test]
fn install_renders_templates() {
    let config = DynetConfig::default();
    let report = install_report(
        PathBuf::from(".").as_path(),
        &ConfigSource::BuiltIn,
        &config,
        true,
    );
    let desired_state = report.desired_state.as_ref().unwrap();

    assert_eq!(desired_state.mutation_mode, "render-only");
    assert!(desired_state
        .validations
        .iter()
        .all(|validation| validation.status != LifecycleStatus::Deny));
    assert!(desired_state
        .resources
        .iter()
        .any(|resource| resource.kind == "dns-listener" && resource.name == "127.0.0.1:1053"));
    assert!(desired_state
        .artifacts
        .iter()
        .any(|artifact| artifact.name == "dynet.nft"
            && artifact.content.contains("table inet dynet")
            && artifact.content.contains("redirect to :1053")));
    assert!(desired_state
        .artifacts
        .iter()
        .any(|artifact| artifact.name == "dynet-link-route.sh"
            && artifact
                .content
                .contains("ip tuntap add dev dynet0 mode tun")));
    assert!(desired_state
        .validations
        .iter()
        .any(|validation| validation.name == "nft-native-check"));
    assert!(desired_state
        .validations
        .iter()
        .any(|validation| validation.name == "link-route-safety"
            && validation.status == LifecycleStatus::Pass));
}

#[test]
fn install_apply_is_gated() {
    let config = DynetConfig::default();
    let report = install_report(
        PathBuf::from(".").as_path(),
        &ConfigSource::BuiltIn,
        &config,
        false,
    );
    let text = text_lifecycle_report(&report);

    assert!(text.contains("network apply is intentionally gated"));
    assert_eq!(report.exit_code(), 1);
}

#[test]
fn lifecycle_covers_cleanup() {
    for action in [
        LifecycleAction::Verify,
        LifecycleAction::Repair,
        LifecycleAction::Uninstall,
    ] {
        let report = status_report(action);
        let text = text_lifecycle_report(&report);
        assert!(text.contains("owned resources:"));
    }
}
