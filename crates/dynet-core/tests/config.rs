use dynet_core::{build_plan, validate_config, DynetConfig};

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
