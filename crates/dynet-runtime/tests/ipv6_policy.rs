use dynet_runtime::{
    GroupId, InboundKind, IpFamily, Ipv6PolicySource, Ipv6RulePolicy, RouteMatcher, RouteRule,
    RuleId, RuntimeSeed, RuntimeState, SelectionContext, TargetContext,
};

#[test]
fn ipv6_defaults_allow() {
    let runtime = runtime(true, Vec::new());

    let decision = runtime
        .select(context("[2001:db8::10]:443", None))
        .expect("enabled IPv6 selection succeeds");

    assert_eq!(decision.ip_family, IpFamily::Ipv6);
    assert_eq!(decision.ipv6_policy_source, Some(Ipv6PolicySource::Global));
    assert_eq!(decision.group_id.as_str(), "default");
}

#[test]
fn disabled_ipv6_refuses_participation() {
    let runtime = runtime(false, Vec::new());

    let error = runtime
        .select(context("[2001:db8::10]:443", None))
        .expect_err("disabled IPv6 is rejected inside dynet");

    assert!(error.to_string().contains("participation is disabled"));
}

#[test]
fn rule_can_deny_ipv6() {
    let runtime = runtime(true, vec![rule(Ipv6RulePolicy::Deny)]);

    let error = runtime
        .select(context("[2001:db8::10]:443", Some("blocked.example")))
        .expect_err("rule denies IPv6");

    assert!(error.to_string().contains("blocked-v6"));
}

#[test]
fn rule_can_allow_ipv6() {
    let runtime = runtime(true, vec![rule(Ipv6RulePolicy::Allow)]);

    let decision = runtime
        .select(context("[2001:db8::10]:443", Some("blocked.example")))
        .expect("rule allows IPv6");

    assert_eq!(decision.ip_family, IpFamily::Ipv6);
    assert_eq!(decision.ipv6_policy_source, Some(Ipv6PolicySource::Rule));
}

#[test]
fn ipv6_no_node_fallback() {
    let mut seed = RuntimeSeed::single_node("direct");
    seed.ipv6_enabled = true;
    seed.nodes[0].supports_ipv6 = false;
    let runtime = RuntimeState::from_seed(seed);

    let error = runtime
        .select(context("[2001:db8::10]:443", None))
        .expect_err("incapable group is rejected");

    assert!(error.to_string().contains("no ipv6-capable enabled node"));
}

#[test]
fn ipv6_policy_preserves_ipv4() {
    let runtime = runtime(true, vec![rule(Ipv6RulePolicy::Deny)]);

    let decision = runtime
        .select(context("192.0.2.10:443", Some("blocked.example")))
        .expect("IPv4 ignores IPv6 policy");

    assert_eq!(decision.ip_family, IpFamily::Ipv4);
    assert_eq!(decision.ipv6_policy_source, None);
}

fn runtime(ipv6_enabled: bool, route_rules: Vec<RouteRule>) -> RuntimeState {
    let mut seed = RuntimeSeed::single_node("direct");
    seed.ipv6_enabled = ipv6_enabled;
    seed.route_rules = route_rules;
    RuntimeState::from_seed(seed)
}

fn rule(ipv6: Ipv6RulePolicy) -> RouteRule {
    RouteRule {
        id: RuleId::new("blocked-v6"),
        priority: 100,
        enabled: true,
        matcher: RouteMatcher::DomainExact("blocked.example".to_string()),
        group_id: GroupId::new("default"),
        ipv6,
    }
}

fn context(address: &str, domain: Option<&str>) -> SelectionContext {
    SelectionContext {
        session_id: 1,
        inbound: InboundKind::Tcp,
        target: TargetContext::external_context(
            address.parse().expect("socket address"),
            domain.map(str::to_string),
        ),
    }
}
