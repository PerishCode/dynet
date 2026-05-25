use dynet_core::{
    build_plan, resolve_outbound_path, validate_config, AppState, DynetConfig, InboundContext,
    OutboundQualityEntry, OutboundQualityState, OutboundStrategyRegistry, PlanAction, PlanMode,
    QualityConfidence, QualityScope, QualityVerdict, Severity, Transport, VerdictStatus,
};

#[test]
fn lists_strategies() {
    let registry = OutboundStrategyRegistry::default();
    let model = registry.model();

    assert_eq!(model.schema, "dynet-outbound-strategy-registry/v1alpha1");
    assert!(model
        .strategies
        .iter()
        .any(|strategy| strategy.source == "internal" && strategy.key == "static"));
    assert!(model
        .strategies
        .iter()
        .any(|strategy| strategy.source == "internal" && strategy.key == "sticky"));
    assert!(model
        .strategies
        .iter()
        .any(|strategy| strategy.source == "internal" && strategy.key == "cascade-quality"));
}

#[test]
fn parses_plan_outbound_harness() {
    let config = outbound_plan_config();

    assert!(validate_config(&config).is_empty());

    let state = AppState::from_config(config);
    let route_plan = build_plan(&state);

    assert_eq!(route_plan.mode, PlanMode::ExplicitOnly);
    assert_eq!(route_plan.summary().rules, 2);
    assert_eq!(
        route_plan.rules[0].action,
        PlanAction::UseOutbound {
            tag: "auto-proxy".to_string()
        }
    );
}

#[test]
fn sticky_plan_selects_site() {
    let state = AppState::from_config(outbound_plan_config());
    let route_plan = build_plan(&state);
    let context = InboundContext::any().with_destination_domain("api.github.com");
    let verdict = route_plan.evaluate(&context, &state);

    assert_eq!(verdict.status, VerdictStatus::Accept);
    assert_eq!(verdict.matched_rule, Some(1));
    assert_eq!(
        verdict
            .outbound
            .as_ref()
            .map(|outbound| outbound.tag.as_str()),
        Some("auto-proxy")
    );

    let first = resolve_outbound_path(&state, &context, "auto-proxy").unwrap();
    let second = resolve_outbound_path(&state, &context, "auto-proxy").unwrap();

    assert_eq!(first.selected, second.selected);
    assert!(matches!(first.selected.as_str(), "hk" | "jp"));
    assert_eq!(first.hops[0].tag, "auto-proxy");
    assert_eq!(first.hops[1].tag, first.selected);
    assert_eq!(first.decisions.len(), 1);
    assert_eq!(first.decisions[0].plan, "auto-proxy");
    assert_eq!(first.decisions[0].candidates.len(), 2);
    assert_eq!(first.decisions[0].selected, first.selected);
}

#[test]
fn default_strategy_skeleton() {
    let config: DynetConfig = serde_json::from_str(
        r#"{
            "outbounds": [
                { "tag": "direct", "type": "direct" },
                {
                    "tag": "auto",
                    "type": "plan",
                    "capabilities": ["dns"],
                    "payload": {
                        "strategy": {
                            "source": "internal",
                            "key": "",
                            "version": "",
                            "options": {}
                        },
                        "selection": {
                            "edges": [{ "type": "candidate", "to": "direct" }]
                        }
                    }
                }
            ],
            "routes": [{ "outbound": "auto" }]
        }"#,
    )
    .unwrap();

    assert!(validate_config(&config).is_empty());

    let state = AppState::from_config(config);
    let path = resolve_outbound_path(&state, &InboundContext::any(), "auto").unwrap();

    assert_eq!(path.selected, "direct");
    assert_eq!(path.decisions.len(), 1);
    assert_eq!(path.decisions[0].strategy.key, "static");
    assert_eq!(path.decisions[0].candidates[0].to, "direct");
}

#[test]
fn cascade_quality_selects() {
    let config = cascade_quality_config();
    assert!(validate_config(&config).is_empty());
    let quality = quality_state(vec![
        quality_entry("a", Some("chatgpt.com"), QualityVerdict::Unhealthy, 3, 0),
        quality_entry("b", Some("chatgpt.com"), QualityVerdict::Healthy, 3, 3),
    ]);
    let state = AppState::from_config(config).with_quality(quality);

    let path = resolve_outbound_path(
        &state,
        &InboundContext::any()
            .with_destination_domain("api.chatgpt.com")
            .with_quality_scope(QualityScope::DialerBound),
        "tunnel",
    )
    .unwrap();

    assert_eq!(path.selected, "b");
    assert_eq!(path.decisions[0].strategy.key, "cascade-quality");
    assert_eq!(
        path.decisions[0].strategy.selector,
        dynet_core::OutboundSelector::CascadeQuality
    );

    let candidates = &path.decisions[0].candidates;
    let a_quality = candidates
        .iter()
        .find(|candidate| candidate.to == "a")
        .and_then(|candidate| candidate.quality.as_ref())
        .unwrap();
    let b_quality = candidates
        .iter()
        .find(|candidate| candidate.to == "b")
        .and_then(|candidate| candidate.quality.as_ref())
        .unwrap();
    assert_eq!(a_quality.target_family.as_deref(), Some("chatgpt.com"));
    assert_eq!(b_quality.target_family.as_deref(), Some("chatgpt.com"));
    assert_eq!(a_quality.reason, "exact-quality");
    assert_eq!(b_quality.reason, "exact-quality");
    assert_eq!(a_quality.matches[0].scope, "dialer-bound");
    assert_eq!(b_quality.matches[0].scope, "dialer-bound");
    assert_eq!(a_quality.matches[0].verdict, QualityVerdict::Unhealthy);
    assert_eq!(b_quality.matches[0].verdict, QualityVerdict::Healthy);
    assert_eq!(a_quality.matches[0].weight, 4);
    assert_eq!(b_quality.matches[0].weight, 4);
    assert!(b_quality.score > a_quality.score);
}

#[test]
fn plan_scope_ignores_dialer() {
    let config = cascade_quality_config();
    let context = InboundContext::any().with_destination_domain("api.chatgpt.com");
    let expected =
        resolve_outbound_path(&AppState::from_config(config.clone()), &context, "tunnel")
            .unwrap()
            .selected;
    let quality = quality_state(vec![
        quality_entry("a", Some("chatgpt.com"), QualityVerdict::Unhealthy, 3, 0),
        quality_entry("b", Some("chatgpt.com"), QualityVerdict::Healthy, 3, 3),
    ]);
    let state = AppState::from_config(config).with_quality(quality);

    let path = resolve_outbound_path(&state, &context, "tunnel").unwrap();

    assert_eq!(path.selected, expected);
    assert!(path.decisions[0].candidates.iter().all(|candidate| {
        candidate
            .quality
            .as_ref()
            .is_some_and(|quality| quality.reason == "no-quality-evidence")
    }));
}

#[test]
fn plan_candidate_quality_selects() {
    let config = cascade_quality_config();
    let quality = quality_state(vec![
        plan_quality_entry("a", Some("github.com"), QualityVerdict::Unhealthy, 3, 0),
        plan_quality_entry("b", Some("github.com"), QualityVerdict::Healthy, 3, 3),
    ]);
    let state = AppState::from_config(config).with_quality(quality);

    let path = resolve_outbound_path(
        &state,
        &InboundContext::any().with_destination_domain("api.github.com"),
        "tunnel",
    )
    .unwrap();

    assert_eq!(path.selected, "b");
    let b_quality = path.decisions[0]
        .candidates
        .iter()
        .find(|candidate| candidate.to == "b")
        .and_then(|candidate| candidate.quality.as_ref())
        .unwrap();
    assert_eq!(b_quality.matches[0].scope, "plan-candidate");
}

#[test]
fn ignores_unscoped_quality() {
    let config = cascade_quality_config();
    let context = InboundContext::any().with_destination_domain("api.chatgpt.com");
    let expected =
        resolve_outbound_path(&AppState::from_config(config.clone()), &context, "tunnel")
            .unwrap()
            .selected;
    let quality = quality_state(vec![
        unscoped_quality_entry("a", Some("chatgpt.com"), QualityVerdict::Unhealthy, 3, 0),
        unscoped_quality_entry("b", Some("chatgpt.com"), QualityVerdict::Healthy, 3, 3),
    ]);
    let state = AppState::from_config(config).with_quality(quality);

    let path = resolve_outbound_path(&state, &context, "tunnel").unwrap();

    assert_eq!(path.selected, expected);
    assert!(path.decisions[0].candidates.iter().all(|candidate| {
        candidate
            .quality
            .as_ref()
            .is_some_and(|quality| quality.reason == "no-quality-evidence")
    }));
}

#[test]
fn stale_quality_falls_back() {
    let config = cascade_quality_config();
    let context = InboundContext::any().with_destination_domain("api.chatgpt.com");
    let expected =
        resolve_outbound_path(&AppState::from_config(config.clone()), &context, "tunnel")
            .unwrap()
            .selected;
    let mut quality = quality_state(vec![
        quality_entry("a", Some("chatgpt.com"), QualityVerdict::Unhealthy, 3, 0),
        quality_entry("b", Some("chatgpt.com"), QualityVerdict::Healthy, 3, 3),
    ]);
    quality.expires_at_unix_ms = 1;
    let state = AppState::from_config(config).with_quality(quality);

    let path = resolve_outbound_path(&state, &context, "tunnel").unwrap();

    assert_eq!(path.selected, expected);
    assert!(path.decisions[0].candidates.iter().all(|candidate| {
        candidate.quality.as_ref().is_some_and(|quality| {
            quality.stale && quality.reason == "quality-state-stale" && quality.matches.is_empty()
        })
    }));
}

#[test]
fn validates_plan_graph() {
    let config: DynetConfig = serde_json::from_str(
        r#"{
            "outbounds": [
                {
                    "tag": "a",
                    "type": "plan",
                    "capabilities": ["dns"],
                    "payload": {
                        "strategy": {
                            "source": "internal",
                            "key": "static",
                            "version": "v1alpha1",
                            "options": {
                                "capabilities": ["sticky-selection"]
                            }
                        },
                        "selection": {
                            "edges": [{ "type": "candidate", "to": "b" }]
                        }
                    }
                },
                {
                    "tag": "b",
                    "type": "plan",
                    "capabilities": ["dns"],
                    "payload": {
                        "selection": {
                            "edges": [{ "type": "candidate", "to": "a" }]
                        }
                    }
                },
                {
                    "tag": "bad",
                    "type": "plan",
                    "capabilities": ["udp"],
                    "payload": {
                        "selection": {
                            "edges": [{ "type": "candidate", "to": "tcp-only" }]
                        }
                    }
                },
                {
                    "tag": "tcp-only",
                    "type": "manual",
                    "capabilities": ["tcp"]
                },
                {
                    "tag": "missing-ref",
                    "type": "plan",
                    "payload": {
                        "selection": {
                            "edges": [{ "type": "candidate", "to": "missing" }]
                        }
                    }
                }
            ],
            "routes": [{ "outbound": "a" }]
        }"#,
    )
    .unwrap();

    let diagnostics = validate_config(&config);

    assert!(diagnostics.iter().any(|diagnostic| {
        diagnostic.severity == Severity::Deny && diagnostic.path == "outbounds[0].payload.strategy"
    }));
    assert!(diagnostics
        .iter()
        .any(|diagnostic| diagnostic.message.contains("cycle")));
    assert!(diagnostics
        .iter()
        .any(|diagnostic| diagnostic.message.contains("lacks required capability")));
    assert!(diagnostics
        .iter()
        .any(|diagnostic| diagnostic.message.contains("unknown outbound")));
}

#[test]
fn validates_dialer_graph() {
    let config: DynetConfig =
        serde_json::from_str(include_str!("../harness/configs/user-rules-dialer.json")).unwrap();

    assert!(validate_config(&config).is_empty());

    let state = AppState::from_config(config);
    let path =
        resolve_outbound_path(&state, &InboundContext::any(), "private-via-airport").unwrap();

    assert_eq!(path.requested, "private-via-airport");
    assert_eq!(path.selected, "private-via-airport");
    assert_eq!(path.hops[0].kind, "dialer");
}

#[test]
fn detects_dialer_cycle() {
    let config: DynetConfig = serde_json::from_str(
        r#"{
            "outbounds": [
                {
                    "tag": "airport-plan",
                    "type": "plan",
                    "capabilities": ["tcp"],
                    "payload": {
                        "selection": {
                            "edges": [{ "type": "candidate", "to": "private-via-airport" }]
                        }
                    }
                },
                {
                    "tag": "private-via-airport",
                    "type": "dialer",
                    "payload": {
                        "bound": "airport-plan",
                        "target": "airport-plan"
                    }
                }
            ]
        }"#,
    )
    .unwrap();

    let diagnostics = validate_config(&config);

    assert!(diagnostics
        .iter()
        .any(|diagnostic| diagnostic.message.contains("cycle")));
    assert!(diagnostics
        .iter()
        .any(|diagnostic| diagnostic.message.contains("concrete private outbound")));
}

fn outbound_plan_config() -> DynetConfig {
    serde_json::from_str(include_str!("../harness/configs/outbound-plan.json")).unwrap()
}

fn cascade_quality_config() -> DynetConfig {
    serde_json::from_str(
        r#"{
            "outbounds": [
                { "tag": "a", "type": "direct" },
                { "tag": "b", "type": "direct" },
                {
                    "tag": "tunnel",
                    "type": "plan",
                    "capabilities": ["tcp"],
                    "payload": {
                        "strategy": { "source": "internal", "key": "cascade-quality", "version": "", "options": {} },
                        "selection": {
                            "edges": [
                                { "type": "candidate", "to": "a" },
                                { "type": "candidate", "to": "b" }
                            ]
                        }
                    }
                }
            ],
            "routes": [{ "outbound": "tunnel" }]
        }"#,
    )
    .unwrap()
}

fn quality_state(entries: Vec<OutboundQualityEntry>) -> OutboundQualityState {
    OutboundQualityState {
        schema: "dynet-outbound-quality-state/v1alpha1".to_string(),
        generated_at_unix_ms: 1,
        ttl_secs: 3600,
        window_secs: 3600,
        expires_at_unix_ms: u128::MAX,
        planner_feedback: None,
        signals: Vec::new(),
        outbounds: entries,
    }
}

fn quality_entry(
    outbound: &str,
    family: Option<&str>,
    verdict: QualityVerdict,
    attempts: u32,
    successes: u32,
) -> OutboundQualityEntry {
    let failures = attempts - successes;
    OutboundQualityEntry {
        outbound: outbound.to_string(),
        scope: Some("dialer-bound".to_string()),
        dialer: Some("private-via-tunnel".to_string()),
        private: Some("private".to_string()),
        target_family: family.map(str::to_string),
        transport: Some(Transport::Tcp),
        verdict,
        attempts,
        successes,
        failures,
        error_rate: f64::from(failures) / f64::from(attempts),
        confidence: QualityConfidence::Medium,
        stages: Vec::new(),
    }
}

fn unscoped_quality_entry(
    outbound: &str,
    family: Option<&str>,
    verdict: QualityVerdict,
    attempts: u32,
    successes: u32,
) -> OutboundQualityEntry {
    let mut entry = quality_entry(outbound, family, verdict, attempts, successes);
    entry.scope = None;
    entry.dialer = None;
    entry.private = None;
    entry
}

fn plan_quality_entry(
    outbound: &str,
    family: Option<&str>,
    verdict: QualityVerdict,
    attempts: u32,
    successes: u32,
) -> OutboundQualityEntry {
    let mut entry = quality_entry(outbound, family, verdict, attempts, successes);
    entry.scope = Some("plan-candidate".to_string());
    entry.dialer = None;
    entry.private = None;
    entry
}
