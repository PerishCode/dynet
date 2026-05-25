use std::{collections::BTreeMap, path::PathBuf};

use dynet_core::DynetConfig;

use crate::{
    cli::OutputFormat,
    config::ConfigSource,
    model::{ApiCapabilityReport, DoctorReport, PlanReport, Report, ReportMode},
    output::{
        print_api_capabilities, print_doctor_report, print_lifecycle_report, print_plan_report,
        print_probe_report, print_report, print_runtime_report, text_api_capabilities,
        text_doctor_report, text_lifecycle_report, text_plan_report, text_probe_report,
        text_report, text_runtime_report,
    },
    platform::{
        install_report, runtime_takeover_settings, status_report, uninstall_report,
        LifecycleAction, LifecycleStatus,
    },
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
    assert!(text.contains("summary: inbounds 0, outbounds 0, rules 0, routes 0, dns chains 0"));
    assert!(text.contains("network model: dynet-network/v1alpha1"));
    assert!(text.contains("dns model: dynet-dns/v1alpha1"));
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
    let report = PlanReport::from_config(
        PathBuf::from("."),
        &ConfigSource::BuiltIn,
        &config,
        None,
        None,
    );

    let text = text_plan_report(&report);

    assert!(text.contains("dynet plan passed"));
    assert!(text.contains("plan model: dynet-plan/v1alpha1 over dynet-state/v1alpha1"));
    assert!(text.contains("match inbound mixed-in -> use outbound direct"));
    assert_eq!(report.exit_code(), 0);
    print_plan_report(&report, OutputFormat::Json).unwrap();
}

#[test]
fn text_plan_route_matchers() {
    let config: DynetConfig = serde_json::from_str(include_str!(
        "../../../dynet-core/harness/configs/personal-static.json"
    ))
    .unwrap();
    let report = PlanReport::from_config(
        PathBuf::from("."),
        &ConfigSource::BuiltIn,
        &config,
        None,
        None,
    );

    let text = text_plan_report(&report);

    assert!(text.contains("domain suffix github.com -> use outbound proxy [dns-sensitive]"));
    assert!(text.contains("domain keyword openai -> use outbound proxy [dns-sensitive]"));
    assert!(
        text.contains("transport dns, ip cidr 8.8.8.8/32 -> use outbound proxy [dns-sensitive]")
    );
    assert!(text.contains("domain suffix ad.com -> reject"));
    print_plan_report(&report, OutputFormat::Json).unwrap();
}

#[test]
fn text_plan_outbound() {
    let config: DynetConfig = serde_json::from_str(include_str!(
        "../../../dynet-core/harness/configs/outbound-plan.json"
    ))
    .unwrap();
    let report = PlanReport::from_config(
        PathBuf::from("."),
        &ConfigSource::BuiltIn,
        &config,
        None,
        None,
    );

    let text = text_plan_report(&report);

    assert!(text.contains("match inbound *, domain suffix github.com -> use outbound auto-proxy"));
    assert_eq!(report.plan_summary.rules, 2);
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
    assert!(text.contains("dns-model"));
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
    assert!(text.contains("takeover: dynet-takeover/v1alpha1"));
    assert!(text.contains("effective config: nft inet dynet"));
    assert!(text.contains("nftables dynet.nft -> /etc/nftables.d/dynet.nft"));
    assert!(text.contains("desired validations:"));
    assert!(text.contains("artifact:nft-structure"));
    assert!(report
        .checks
        .iter()
        .filter(|check| check.status == LifecycleStatus::Deny)
        .all(|check| matches!(check.name.as_str(), "nft-dropin-dir" | "nft-dropin-include")));
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
    assert_eq!(
        desired_state.takeover.manifest.path,
        "/var/lib/dynet/takeover/manifest.json"
    );
    assert_eq!(desired_state.takeover.config.tun_name, "dynet0");
    assert_eq!(
        desired_state.takeover.config.nft_main_config,
        "/etc/nftables.conf"
    );
    assert_eq!(
        desired_state.takeover.config.nft_dropin_path,
        "/etc/nftables.d/dynet.nft"
    );
    assert!(desired_state
        .takeover
        .manifest
        .authority
        .contains("env only builds new takeover plans"));
    assert!(desired_state
        .validations
        .iter()
        .all(|validation| validation.status != LifecycleStatus::Deny));
    assert!(desired_state
        .resources
        .iter()
        .any(|resource| resource.kind == "nft-dropin"
            && resource.name == "/etc/nftables.d/dynet.nft"));
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

    assert!(text.contains("takeover apply skipped because preflight has deny issue(s)"));
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

#[test]
fn uninstall_report_is_rendered() {
    let report = uninstall_report();
    let text = text_lifecycle_report(&report);

    assert!(text.contains("dynet uninstall"));
    assert!(text.contains("uninstall-engine"));
}

#[test]
fn runtime_report_is_rendered() {
    let report = dynet_runtime::RuntimeReport {
        schema: "dynet-runtime/v1alpha1".to_string(),
        status: dynet_runtime::RuntimeStatus::Pass,
        reason: "runtime limits reached".to_string(),
        tun_packets: 1,
        dns_queries: 1,
        route_decisions: 1,
        proxied_dns_queries: 1,
        dns_records: 0,
        ipv6_packets_denied: 0,
        tcp_sessions: 1,
        tcp_session_failures: 0,
        tcp_closed_sessions: 1,
        tcp_upstream_bytes: 32,
        tcp_downstream_bytes: 64,
        tcp_listen_ports: vec![443, 80],
        tcp_listen_slots_per_port: 8,
        tcp_listen_capacity: 16,
        tcp_active_slots_max: 1,
        tcp_slot_pressure_events: 0,
        udp_sessions: 1,
        udp_session_failures: 0,
        udp_upstream_bytes: 16,
        udp_downstream_bytes: 24,
        udp_dropped_packets: 0,
        dns_reverse: dynet_core::DnsReverseIndex::default(),
        events: Vec::new(),
    };
    let text = text_runtime_report(&report);

    assert!(text.contains("dynet runtime passed"));
    assert!(text.contains("1 tun packet"));
    assert!(text.contains("1 route decision"));
    assert!(text.contains("1 proxied dns query"));
    assert!(text.contains("1 session"));
    assert!(text.contains("tcp listen capacity"));
    print_runtime_report(&report, OutputFormat::Json).unwrap();
}

#[test]
fn probe_report_is_rendered() {
    let report = dynet_runtime::ProbeReport {
        schema: "dynet-probe/v1alpha1".to_string(),
        status: dynet_runtime::RuntimeStatus::Pass,
        reason: "HTTPS HEAD completed with HTTP 200".to_string(),
        protocol: dynet_runtime::ProbeProtocol::HttpsHead,
        target: dynet_runtime::ProbeTarget {
            host: "example.com".to_string(),
            port: 443,
            path: "/".to_string(),
        },
        inbound: Some("tun-in".to_string()),
        failure_scope: None,
        route_decisions: 1,
        outbound_attempts: 1,
        read_policy: dynet_runtime::ProbeReadPolicy::default(),
        retry: dynet_runtime::ProbeRetryReport::default(),
        events: vec![dynet_runtime::RuntimeEvent {
            schema: "dynet-runtime-event/v1alpha1".to_string(),
            sequence: Some(1),
            emitted_at_unix_ms: None,
            kind: dynet_runtime::RuntimeEventKind::ProbeStarted,
            fields: BTreeMap::from([("target".to_string(), "example.com:443".to_string())]),
        }],
    };

    let text = text_probe_report(&report);

    assert!(text.contains("dynet probe passed"));
    assert!(text.contains("probe model: dynet-probe/v1alpha1"));
    assert!(text.contains("protocol: https-head"));
    assert!(text.contains("target: https://example.com:443/"));
    assert!(text.contains("runtime events:"));
    print_probe_report(&report, OutputFormat::Json).unwrap();
}

#[test]
fn runtime_takeover_preflight() {
    let result = runtime_takeover_settings();

    if let Err(error) = result {
        assert!(error.contains("runtime takeover preflight failed"));
    }
}
