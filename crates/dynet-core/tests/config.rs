use dynet_core::{build_plan, validate_config, DynetConfig, Severity};

#[test]
fn parses_harness_config() {
    let config: DynetConfig =
        serde_json::from_str(include_str!("../harness/configs/minimal.json")).unwrap();

    assert_eq!(config.summary().inbounds, 1);
    assert_eq!(config.summary().outbounds, 1);
    assert_eq!(config.summary().routes, 1);
    assert!(validate_config(&config).is_empty());
}

#[test]
fn parses_tcp_udp_harness_config() {
    let config: DynetConfig =
        serde_json::from_str(include_str!("../harness/configs/tcp-udp.json")).unwrap();

    assert_eq!(config.summary().inbounds, 2);
    assert_eq!(config.summary().outbounds, 2);
    assert!(validate_config(&config).is_empty());

    let network = config.network_model();
    assert_eq!(network.schema, "dynet-network/v1alpha1");
    assert!(network.inbounds[0]
        .capabilities
        .contains(&"tcp".to_string()));
    assert!(network.inbounds[1]
        .capabilities
        .contains(&"udp".to_string()));
    assert!(network.outbounds[0]
        .protocol_fields
        .contains(&"serverPort".to_string()));
    assert!(network.outbounds[0]
        .fingerprint
        .starts_with("dynet:outbound:"));
}

#[test]
fn reports_unknown_route_target() {
    let config: DynetConfig = serde_json::from_str(
        r#"{
            "inbounds": [{ "tag": "mixed-in", "type": "mixed" }],
            "outbounds": [{ "tag": "direct", "type": "direct" }],
            "routes": [{ "inbound": "missing", "outbound": "also-missing" }]
        }"#,
    )
    .unwrap();

    let diagnostics = validate_config(&config);

    assert!(diagnostics
        .iter()
        .any(|diagnostic| diagnostic.path == "routes[0].inbound"));
    assert!(diagnostics
        .iter()
        .any(|diagnostic| diagnostic.path == "routes[0].outbound"));
}

#[test]
fn validates_builtin_tcp_udp_payloads() {
    let config: DynetConfig = serde_json::from_str(
        r#"{
            "inbounds": [{ "tag": "tcp-in", "type": "tcp", "listen": "", "listenPort": 70000 }],
            "outbounds": [{ "tag": "udp-out", "type": "udp", "serverPort": "53" }],
            "routes": [{ "inbound": "tcp-in", "outbound": "udp-out" }]
        }"#,
    )
    .unwrap();

    let diagnostics = validate_config(&config);

    assert!(diagnostics
        .iter()
        .any(|diagnostic| diagnostic.path == "inbounds[0].listen"));
    assert!(diagnostics
        .iter()
        .any(|diagnostic| diagnostic.path == "inbounds[0].listenPort"));
    assert!(diagnostics
        .iter()
        .any(|diagnostic| diagnostic.path == "outbounds[0].server"));
    assert!(diagnostics
        .iter()
        .any(|diagnostic| diagnostic.path == "outbounds[0].serverPort"));
}

#[test]
fn denies_routes_without_shared_transport_capability() {
    let config: DynetConfig = serde_json::from_str(
        r#"{
            "inbounds": [{ "tag": "tcp-in", "type": "tcp", "listen": "127.0.0.1", "listenPort": 1080 }],
            "outbounds": [{ "tag": "udp-out", "type": "udp", "server": "1.1.1.1", "serverPort": 53 }],
            "routes": [{ "inbound": "tcp-in", "outbound": "udp-out" }]
        }"#,
    )
    .unwrap();

    let diagnostics = validate_config(&config);

    assert!(diagnostics.iter().any(|diagnostic| {
        diagnostic.severity == Severity::Deny && diagnostic.path == "routes[0]"
    }));
}

#[test]
fn builds_explicit_plan_from_routes() {
    let config: DynetConfig = serde_json::from_str(
        r#"{
            "inbounds": [{ "tag": "mixed-in", "type": "mixed" }],
            "outbounds": [{ "tag": "direct", "type": "direct" }],
            "routes": [{ "inbound": "mixed-in", "outbound": "direct" }]
        }"#,
    )
    .unwrap();

    let plan = build_plan(&config);

    assert_eq!(plan.summary().rules, 1);
    assert_eq!(plan.rules[0].order, 1);
    assert_eq!(plan.rules[0].inbound.as_deref(), Some("mixed-in"));
    assert_eq!(plan.rules[0].outbound, "direct");
}
