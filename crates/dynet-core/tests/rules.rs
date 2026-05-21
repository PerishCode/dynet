use dynet_core::{
    build_plan, evaluate_rules, validate_config, AppState, DynetConfig, InboundContext, Severity,
    VerdictStatus,
};

#[test]
fn user_rule_dialer_harness() {
    let config: DynetConfig =
        serde_json::from_str(include_str!("../harness/configs/user-rules-dialer.json")).unwrap();

    assert_eq!(config.summary().rules, 2);
    assert!(validate_config(&config).is_empty());

    let state = AppState::from_config(config);
    let context = InboundContext::any().with_destination_domain("api.chatgpt.com");
    let decision = evaluate_rules(&state, &context).unwrap();

    assert_eq!(decision.tag, "identity-private");
    assert_eq!(decision.outbound, "private-via-airport");
    assert!(decision.bypasses_plan);
    assert_eq!(
        decision.matcher.domain_suffix.as_deref(),
        Some("chatgpt.com")
    );

    let plan = build_plan(&state);
    let verdict = plan.evaluate(&context, &state);
    assert_eq!(verdict.status, VerdictStatus::Accept);
    assert_eq!(
        verdict
            .outbound
            .as_ref()
            .map(|outbound| outbound.tag.as_str()),
        Some("direct")
    );
}

#[test]
fn user_rule_priority() {
    let config: DynetConfig = serde_json::from_str(
        r#"{
            "outbounds": [
                { "tag": "direct", "type": "direct" },
                { "tag": "dialer", "type": "dialer", "payload": { "bound": "direct", "target": "direct" } }
            ],
            "rules": [
                { "tag": "", "domainSuffix": " ", "outbound": "dialer" },
                { "tag": "missing-match", "outbound": "dialer" },
                { "tag": "bad-ip", "ip": "not-ip", "ipCidr": "8.8.8.8/99", "outbound": "dialer" },
                { "tag": "not-dialer", "domain": "example.com", "outbound": "direct" },
                { "tag": "missing-outbound", "domainKeyword": "ai", "outbound": "missing" }
            ]
        }"#,
    )
    .unwrap();

    let diagnostics = validate_config(&config);

    assert!(diagnostics
        .iter()
        .any(|diagnostic| diagnostic.path == "rules[0].tag"));
    assert!(diagnostics
        .iter()
        .any(|diagnostic| diagnostic.path == "rules[0].domainSuffix"));
    assert!(diagnostics
        .iter()
        .any(|diagnostic| diagnostic.path == "rules[1]"));
    assert!(diagnostics
        .iter()
        .any(|diagnostic| diagnostic.path == "rules[2].ip"));
    assert!(diagnostics
        .iter()
        .any(|diagnostic| diagnostic.path == "rules[2].ipCidr"));
    assert!(diagnostics.iter().any(|diagnostic| {
        diagnostic.severity == Severity::Deny && diagnostic.path == "rules[3].outbound"
    }));
    assert!(diagnostics
        .iter()
        .any(|diagnostic| diagnostic.path == "rules[4].outbound"));
}
