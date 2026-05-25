use dynet_core::{
    resolve_outbound_path, AppState, DynetConfig, InboundContext, OutboundQualityEntry,
    OutboundQualityState, QualityConfidence, QualityVerdict, StageQualityEntry, Transport,
};

#[test]
fn state_carries_quality_snapshot() {
    let config: DynetConfig = serde_json::from_str(
        r#"{
            "outbounds": [{ "tag": "direct", "type": "direct" }],
            "routes": [{ "outbound": "direct" }]
        }"#,
    )
    .unwrap();
    let quality = OutboundQualityState {
        schema: "dynet-outbound-quality-state/v1alpha1".to_string(),
        generated_at_unix_ms: 1000,
        ttl_secs: 60,
        window_secs: 300,
        expires_at_unix_ms: 61000,
        planner_feedback: None,
        signals: Vec::new(),
        outbounds: vec![OutboundQualityEntry {
            outbound: "direct".to_string(),
            scope: Some("candidate-direct".to_string()),
            dialer: None,
            private: None,
            target_family: Some("example.com".to_string()),
            transport: None,
            verdict: QualityVerdict::Healthy,
            attempts: 3,
            successes: 3,
            failures: 0,
            error_rate: 0.0,
            confidence: QualityConfidence::Medium,
            stages: Vec::new(),
        }],
    };

    let state = AppState::from_config(config).with_quality(quality);

    assert_eq!(
        state.quality.schema,
        "dynet-outbound-quality-state/v1alpha1"
    );
    assert_eq!(state.quality.outbounds[0].outbound, "direct");
}

#[test]
fn state_carries_feedback_signals() {
    let state: OutboundQualityState = serde_json::from_str(
        r#"{
            "schema": "dynet-outbound-quality-state/v1alpha1",
            "generatedAtUnixMs": 1,
            "ttlSecs": 300,
            "windowSecs": 1800,
            "expiresAtUnixMs": 301000,
            "plannerFeedback": {
                "mode": "observe",
                "fallbackSignals": 2,
                "recoveredFallbackSignals": 2,
                "nonRetrySafeFallbackSignals": 0,
                "penaltyObservations": 0
            },
            "signals": [
                {
                    "type": "cascade-fallback",
                    "action": "observe",
                    "failedBound": "tunnel-poison-001",
                    "recoveredBound": "tunnel-001",
                    "replaySafe": "pre-payload"
                }
            ]
        }"#,
    )
    .unwrap();

    let feedback = state.planner_feedback.unwrap();
    assert_eq!(feedback.fallback_signals, 2);
    assert_eq!(feedback.recovered_fallback_signals, 2);
    assert_eq!(state.signals[0].signal_type, "cascade-fallback");
    assert_eq!(
        state.signals[0].failed_bound.as_deref(),
        Some("tunnel-poison-001")
    );
}

#[test]
fn static_reports_quality() {
    let quality = OutboundQualityState {
        schema: "dynet-outbound-quality-state/v1alpha1".to_string(),
        generated_at_unix_ms: 1,
        ttl_secs: 3600,
        window_secs: 3600,
        expires_at_unix_ms: u128::MAX,
        planner_feedback: None,
        signals: Vec::new(),
        outbounds: vec![
            entry("a", QualityVerdict::Unhealthy, 3, 0),
            entry("b", QualityVerdict::Healthy, 3, 3),
        ],
    };
    let state = AppState::from_config(static_config()).with_quality(quality);

    let path = resolve_outbound_path(
        &state,
        &InboundContext::any().with_destination_domain("api.github.com"),
        "tunnel",
    )
    .unwrap();

    assert_eq!(path.selected, "a");
    assert_eq!(path.decisions[0].strategy.key, "static");
    let a = candidate_score(&path.decisions[0].candidates, "a");
    let b = candidate_score(&path.decisions[0].candidates, "b");
    assert!(b > a);
}

#[test]
fn latency_breaks_ties() {
    let quality = OutboundQualityState {
        schema: "dynet-outbound-quality-state/v1alpha1".to_string(),
        generated_at_unix_ms: 1,
        ttl_secs: 3600,
        window_secs: 3600,
        expires_at_unix_ms: u128::MAX,
        planner_feedback: None,
        signals: Vec::new(),
        outbounds: vec![
            with_stage_p95(entry("a", QualityVerdict::Healthy, 6, 6), 1_300),
            with_stage_p95(entry("b", QualityVerdict::Healthy, 6, 6), 1_100),
        ],
    };
    let state = AppState::from_config(cascade_quality_config()).with_quality(quality);

    let path = resolve_outbound_path(
        &state,
        &InboundContext::any().with_destination_domain("api.github.com"),
        "tunnel",
    )
    .unwrap();

    assert_eq!(path.selected, "b");
    let a = candidate_score(&path.decisions[0].candidates, "a");
    let b = candidate_score(&path.decisions[0].candidates, "b");
    assert!(b > a);
}

fn static_config() -> DynetConfig {
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
                        "strategy": { "source": "internal", "key": "static" },
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
                        "strategy": { "source": "internal", "key": "cascade-quality" },
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

fn entry(
    outbound: &str,
    verdict: QualityVerdict,
    attempts: u32,
    successes: u32,
) -> OutboundQualityEntry {
    let failures = attempts - successes;
    OutboundQualityEntry {
        outbound: outbound.to_string(),
        scope: Some("plan-candidate".to_string()),
        dialer: None,
        private: None,
        target_family: Some("github.com".to_string()),
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

fn with_stage_p95(mut entry: OutboundQualityEntry, p95_ms: u128) -> OutboundQualityEntry {
    entry.stages = vec![StageQualityEntry {
        stage: format!("{}:tls-handshake", entry.outbound),
        attempts: entry.attempts,
        failures: entry.failures,
        error_rate: entry.error_rate,
        p95_ms: Some(p95_ms),
    }];
    entry
}

fn candidate_score(candidates: &[dynet_core::OutboundCandidate], tag: &str) -> i64 {
    candidates
        .iter()
        .find(|candidate| candidate.to == tag)
        .and_then(|candidate| candidate.quality.as_ref())
        .map(|quality| quality.score)
        .unwrap()
}
