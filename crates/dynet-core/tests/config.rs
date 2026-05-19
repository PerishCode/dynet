use dynet_core::{
    build_plan, validate_config, AppState, DnsReverseIndex, DynetConfig, InboundContext,
    PlanAction, Severity, VerdictStatus,
};

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
fn parses_tcp_udp_harness() {
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
fn parses_dns_reverse_harness() {
    let config: DynetConfig =
        serde_json::from_str(include_str!("../harness/configs/dns-reverse.json")).unwrap();

    assert_eq!(config.summary().routes, 2);
    assert!(validate_config(&config).is_empty());

    let state = AppState::from_config(config);
    let plan = build_plan(&state);

    assert_eq!(plan.rules[0].matcher.domain.as_deref(), Some("alpha.test"));
    assert_eq!(plan.rules[1].matcher.domain, None);
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
fn validates_tcp_udp_payloads() {
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
fn denies_mismatched_transport() {
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
fn builds_explicit_plan() {
    let config: DynetConfig = serde_json::from_str(
        r#"{
            "inbounds": [{ "tag": "mixed-in", "type": "mixed" }],
            "outbounds": [{ "tag": "direct", "type": "direct" }],
            "routes": [{ "inbound": "mixed-in", "outbound": "direct" }]
        }"#,
    )
    .unwrap();

    let state = AppState::from_config(config);
    let plan = build_plan(&state);

    assert_eq!(plan.schema, "dynet-plan/v1alpha1");
    assert_eq!(plan.state_schema, "dynet-state/v1alpha1");
    assert_eq!(plan.summary().rules, 1);
    assert_eq!(plan.summary().explicit_rules, 1);
    assert_eq!(plan.rules[0].order, 1);
    assert_eq!(plan.rules[0].matcher.inbound.as_deref(), Some("mixed-in"));
    assert_eq!(
        plan.rules[0].action,
        PlanAction::UseOutbound {
            tag: "direct".to_string()
        }
    );
    let verdict = plan.evaluate(&InboundContext::from_inbound("mixed-in"), &state);
    assert_eq!(verdict.status, VerdictStatus::Accept);
    assert_eq!(verdict.matched_rule, Some(1));
    assert_eq!(
        verdict
            .outbound
            .as_ref()
            .map(|outbound| outbound.tag.as_str()),
        Some("direct")
    );
}

#[test]
fn builds_default_plan() {
    let config: DynetConfig = serde_json::from_str(
        r#"{
            "outbounds": [{ "tag": "direct", "type": "direct" }],
            "routes": [{ "outbound": "direct" }]
        }"#,
    )
    .unwrap();

    let state = AppState::from_config(config);
    let plan = build_plan(&state);

    assert!(plan.summary().has_default);
    assert!(plan.rules[0].matcher.inbound.is_none());
    let verdict = plan.evaluate(&InboundContext::any(), &state);
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
fn routes_domain_outbound() {
    let config: DynetConfig =
        serde_json::from_str(include_str!("../harness/configs/dns-reverse.json")).unwrap();
    let destination = "93.184.216.34".parse().unwrap();
    let state = AppState::from_config(config).with_dns_reverse(dns_index(
        "alpha.test",
        None::<&str>,
        destination,
        120,
    ));
    let plan = build_plan(&state);

    let verdict = plan.evaluate(
        &InboundContext::from_inbound("tun-in").with_destination_ip(destination),
        &state,
    );

    assert_eq!(verdict.status, VerdictStatus::Accept);
    assert_eq!(verdict.matched_rule, Some(1));
    assert_eq!(
        verdict
            .outbound
            .as_ref()
            .map(|outbound| outbound.tag.as_str()),
        Some("domain-out")
    );
}

#[test]
fn falls_back_without_dns() {
    let config: DynetConfig =
        serde_json::from_str(include_str!("../harness/configs/dns-reverse.json")).unwrap();
    let destination = "93.184.216.34".parse().unwrap();
    let state = AppState::from_config(config);
    let plan = build_plan(&state);

    let verdict = plan.evaluate(
        &InboundContext::from_inbound("tun-in").with_destination_ip(destination),
        &state,
    );

    assert_eq!(verdict.status, VerdictStatus::Accept);
    assert_eq!(verdict.matched_rule, Some(2));
    assert_eq!(
        verdict
            .outbound
            .as_ref()
            .map(|outbound| outbound.tag.as_str()),
        Some("fallback")
    );
}

#[test]
fn expires_by_ttl() {
    let config: DynetConfig =
        serde_json::from_str(include_str!("../harness/configs/dns-reverse.json")).unwrap();
    let destination = "93.184.216.34".parse().unwrap();
    let state = AppState::from_config(config).with_dns_reverse(dns_index(
        "alpha.test",
        None::<&str>,
        destination,
        161,
    ));
    let plan = build_plan(&state);

    let verdict = plan.evaluate(
        &InboundContext::from_inbound("tun-in").with_destination_ip(destination),
        &state,
    );

    assert_eq!(verdict.matched_rule, Some(2));
    assert_eq!(
        verdict
            .outbound
            .as_ref()
            .map(|outbound| outbound.tag.as_str()),
        Some("fallback")
    );
}

#[test]
fn matches_cname() {
    let config: DynetConfig = serde_json::from_str(
        r#"{
            "inbounds": [{ "tag": "tun-in", "type": "tun" }],
            "outbounds": [
                { "tag": "canonical", "type": "direct" },
                { "tag": "fallback", "type": "direct" }
            ],
            "routes": [
                { "domain": "edge.alpha.test", "outbound": "canonical" },
                { "outbound": "fallback" }
            ]
        }"#,
    )
    .unwrap();
    let destination = "93.184.216.34".parse().unwrap();
    let state = AppState::from_config(config).with_dns_reverse(dns_index(
        "www.alpha.test",
        Some("edge.alpha.test"),
        destination,
        120,
    ));
    let plan = build_plan(&state);

    let verdict = plan.evaluate(
        &InboundContext::any().with_destination_ip(destination),
        &state,
    );

    assert_eq!(verdict.matched_rule, Some(1));
    assert_eq!(
        verdict
            .outbound
            .as_ref()
            .map(|outbound| outbound.tag.as_str()),
        Some("canonical")
    );
}

#[test]
fn orders_shared_ip() {
    let config: DynetConfig = serde_json::from_str(
        r#"{
            "outbounds": [
                { "tag": "alpha", "type": "direct" },
                { "tag": "beta", "type": "direct" },
                { "tag": "fallback", "type": "direct" }
            ],
            "routes": [
                { "domain": "alpha.test", "outbound": "alpha" },
                { "domain": "beta.test", "outbound": "beta" },
                { "outbound": "fallback" }
            ]
        }"#,
    )
    .unwrap();
    let destination = "93.184.216.34".parse().unwrap();
    let mut dns = DnsReverseIndex::default().with_now_secs(120);
    dns.insert_real_answer("beta.test", None::<&str>, destination, 100, 60);
    dns.insert_real_answer("alpha.test", None::<&str>, destination, 100, 60);
    let state = AppState::from_config(config).with_dns_reverse(dns);
    let plan = build_plan(&state);

    let verdict = plan.evaluate(
        &InboundContext::any().with_destination_ip(destination),
        &state,
    );

    assert_eq!(
        state.dns_reverse.domains_for_ip(destination),
        ["alpha.test".to_string(), "beta.test".to_string()]
    );
    assert_eq!(verdict.matched_rule, Some(1));
    assert_eq!(
        verdict
            .outbound
            .as_ref()
            .map(|outbound| outbound.tag.as_str()),
        Some("alpha")
    );
}

#[test]
fn denies_missing_outbound() {
    let config: DynetConfig = serde_json::from_str(
        r#"{
            "routes": [{ "inbound": "missing-in", "outbound": "missing-out" }]
        }"#,
    )
    .unwrap();

    let state = AppState::from_config(config);
    let plan = build_plan(&state);
    let verdict = plan.evaluate(&InboundContext::from_inbound("missing-in"), &state);

    assert_eq!(verdict.status, VerdictStatus::Deny);
    assert_eq!(verdict.matched_rule, Some(1));
    assert!(verdict.outbound.is_none());
}

fn dns_index(
    query: &str,
    canonical: Option<&str>,
    address: std::net::IpAddr,
    now_secs: u64,
) -> DnsReverseIndex {
    let mut dns = DnsReverseIndex::default().with_now_secs(now_secs);
    dns.insert_real_answer(query, canonical, address, 100, 60);
    dns
}
