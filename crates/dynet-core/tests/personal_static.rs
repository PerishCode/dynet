use dynet_core::{
    build_plan, validate_config, AppState, DynetConfig, InboundContext, PlanAction, Transport,
    VerdictStatus,
};

#[test]
fn parses_personal_static_harness() {
    let config = personal_config();

    assert_eq!(config.summary().routes, 8);
    assert!(validate_config(&config).is_empty());

    let state = AppState::from_config(config);
    let plan = build_plan(&state);

    assert_eq!(plan.summary().rules, 8);
    assert_eq!(plan.summary().reject_rules, 1);
    assert_eq!(plan.summary().dns_sensitive_rules, 5);
    assert_eq!(
        plan.rules[1].matcher.domain_suffix.as_deref(),
        Some("github.com")
    );
    assert_eq!(
        plan.rules[3].matcher.domain_keyword.as_deref(),
        Some("openai")
    );
    assert_eq!(plan.rules[5].matcher.ip_cidr.as_deref(), Some("8.8.8.8/32"));
    assert_eq!(plan.rules[6].action, PlanAction::Reject);
}

#[test]
fn evaluates_static_profile() {
    let state = AppState::from_config(personal_config());
    let plan = build_plan(&state);

    let lan = plan.evaluate(
        &InboundContext::from_inbound("tun-in").with_destination_ip("192.168.1.1".parse().unwrap()),
        &state,
    );
    assert_eq!(lan.status, VerdictStatus::Accept);
    assert_eq!(lan.matched_rule, Some(1));
    assert_eq!(
        lan.outbound.as_ref().map(|outbound| outbound.tag.as_str()),
        Some("direct")
    );

    let github = plan.evaluate(
        &InboundContext::any().with_destination_domain("api.github.com"),
        &state,
    );
    assert_eq!(github.status, VerdictStatus::Accept);
    assert_eq!(github.matched_rule, Some(2));
    assert!(github.dns_sensitive);
    assert_eq!(
        github
            .outbound
            .as_ref()
            .map(|outbound| outbound.tag.as_str()),
        Some("proxy")
    );

    let dns = plan.evaluate(
        &InboundContext::any()
            .with_transport(Transport::Dns)
            .with_destination_ip("8.8.8.8".parse().unwrap())
            .with_destination_port(53),
        &state,
    );
    assert_eq!(dns.matched_rule, Some(6));
    assert!(dns.dns_sensitive);

    let rejected = plan.evaluate(
        &InboundContext::any().with_destination_domain("track.ad.com"),
        &state,
    );
    assert_eq!(rejected.status, VerdictStatus::Deny);
    assert_eq!(rejected.action, PlanAction::Reject);
    assert_eq!(rejected.matched_rule, Some(7));

    let fallback = plan.evaluate(
        &InboundContext::any().with_destination_domain("example.cn"),
        &state,
    );
    assert_eq!(fallback.matched_rule, Some(8));
    assert_eq!(
        fallback
            .outbound
            .as_ref()
            .map(|outbound| outbound.tag.as_str()),
        Some("direct")
    );
}

fn personal_config() -> DynetConfig {
    serde_json::from_str(include_str!("../harness/configs/personal-static.json")).unwrap()
}
