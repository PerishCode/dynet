use std::path::PathBuf;

use dynet_core::{
    DnsReverseIndex, DynetConfig, InboundContext, OutboundQualityEntry,
    OutboundQualityPlannerFeedback, OutboundQualitySignal, OutboundQualityState, QualityConfidence,
    QualityVerdict, Transport,
};

use crate::{
    config::ConfigSource,
    model::{PlanEvaluationInput, PlanReport},
    output::text_plan_report,
};

#[test]
fn quality_state_selects_path() {
    let config = cascade_quality_config();
    let report = PlanReport::from_config(
        PathBuf::from("."),
        &ConfigSource::BuiltIn,
        &config,
        Some(PlanEvaluationInput {
            context: InboundContext::any().with_destination_domain("api.github.com"),
            dns_reverse: DnsReverseIndex::default(),
        }),
        Some(quality_state(vec![
            plan_quality_entry("a", QualityVerdict::Unhealthy),
            plan_quality_entry("b", QualityVerdict::Healthy),
        ])),
    );

    let text = text_plan_report(&report);

    assert!(text.contains("outbound path: tunnel -> b"));
    assert_eq!(
        report
            .outbound_path
            .as_ref()
            .map(|path| path.selected.as_str()),
        Some("b")
    );
    assert_eq!(
        report
            .outbound_path
            .as_ref()
            .and_then(|path| path.decisions.first())
            .and_then(|decision| decision.candidates[0].quality.as_ref())
            .map(|quality| quality.reason.as_str()),
        Some("exact-quality")
    );
}

#[test]
fn dialer_bound_path_quality() {
    let config = dialer_quality_config();
    let mut unhealthy = quality_entry("a", QualityVerdict::Unhealthy);
    unhealthy.target_family = Some("chatgpt.com".to_string());
    let mut healthy = quality_entry("b", QualityVerdict::Healthy);
    healthy.target_family = Some("chatgpt.com".to_string());

    let report = PlanReport::from_config(
        PathBuf::from("."),
        &ConfigSource::BuiltIn,
        &config,
        Some(PlanEvaluationInput {
            context: InboundContext::any().with_destination_domain("chatgpt.com"),
            dns_reverse: DnsReverseIndex::default(),
        }),
        Some(quality_state(vec![unhealthy, healthy])),
    );

    let text = text_plan_report(&report);

    assert!(text.contains("outbound path: private-via-airport -> private-via-airport"));
    assert!(text.contains("dialer bound path: tunnel -> b"));
    assert_eq!(
        report
            .outbound_path
            .as_ref()
            .map(|path| path.selected.as_str()),
        Some("private-via-airport")
    );
    let bound_path = report.dialer_bound_path.as_ref().unwrap();
    assert_eq!(bound_path.selected, "b");
    assert_eq!(
        bound_path.decisions[0]
            .candidates
            .iter()
            .find(|candidate| candidate.to == "b")
            .and_then(|candidate| candidate.quality.as_ref())
            .and_then(|quality| quality.matches.first())
            .map(|entry| entry.scope.as_str()),
        Some("dialer-bound")
    );
}

#[test]
fn quality_signals_are_reported() {
    let config = dialer_quality_config();
    let report = PlanReport::from_config(
        PathBuf::from("."),
        &ConfigSource::BuiltIn,
        &config,
        Some(PlanEvaluationInput {
            context: InboundContext::any().with_destination_domain("chatgpt.com"),
            dns_reverse: DnsReverseIndex::default(),
        }),
        Some(fallback_quality_state()),
    );

    let text = text_plan_report(&report);

    assert!(text.contains("quality feedback: mode=observe penalties=0"));
    assert!(text.contains("fallback signals=2 recovered=2 non-retry-safe=0"));
    assert!(text.contains("cascade-fallback action=observe"));
    assert!(text.contains("failed=tunnel-poison-001 recovered=tunnel-001"));
    assert_eq!(
        report
            .quality_feedback
            .as_ref()
            .map(|feedback| feedback.fallback_signals),
        Some(2)
    );
    assert_eq!(report.quality_signals.len(), 1);
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

fn dialer_quality_config() -> DynetConfig {
    serde_json::from_str(
        r#"{
            "outbounds": [
                { "tag": "direct", "type": "direct" },
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
                },
                {
                    "tag": "private",
                    "type": "ss",
                    "payload": {
                        "server": "private.example.com",
                        "port": 443,
                        "cipher": "aes-128-gcm",
                        "password": "private-password"
                    }
                },
                {
                    "tag": "private-via-airport",
                    "type": "dialer",
                    "payload": { "bound": "tunnel", "target": "private" }
                }
            ],
            "routes": [
                {
                    "domainSuffix": "chatgpt.com",
                    "outbound": "private-via-airport"
                },
                {
                    "outbound": "direct"
                }
            ]
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

fn fallback_quality_state() -> OutboundQualityState {
    OutboundQualityState {
        schema: "dynet-outbound-quality-state/v1alpha1".to_string(),
        generated_at_unix_ms: 1,
        ttl_secs: 3600,
        window_secs: 3600,
        expires_at_unix_ms: u128::MAX,
        planner_feedback: Some(OutboundQualityPlannerFeedback {
            mode: Some("observe".to_string()),
            requested_mode: Some("observe".to_string()),
            penalty_observations: 0,
            fallback_signals: 2,
            recovered_fallback_signals: 2,
            non_retry_safe_fallback_signals: 0,
        }),
        signals: vec![OutboundQualitySignal {
            signal_type: "cascade-fallback".to_string(),
            action: Some("observe".to_string()),
            planner_action: Some("observe".to_string()),
            fallback_type: Some("pre-replay-bound-failure-recovered".to_string()),
            scope: Some("dialer-bound".to_string()),
            outbound: None,
            flow_id: Some("tcp-session-1".to_string()),
            failed_bound: Some("tunnel-poison-001".to_string()),
            recovered_bound: Some("tunnel-001".to_string()),
            replay_safe: Some("pre-payload".to_string()),
            reason: Some("bound candidate recovered before replay".to_string()),
        }],
        outbounds: Vec::new(),
    }
}

fn quality_entry(outbound: &str, verdict: QualityVerdict) -> OutboundQualityEntry {
    let successes = if verdict == QualityVerdict::Healthy {
        3
    } else {
        0
    };
    let failures = 3 - successes;
    OutboundQualityEntry {
        outbound: outbound.to_string(),
        scope: Some("dialer-bound".to_string()),
        dialer: None,
        private: None,
        target_family: Some("github.com".to_string()),
        transport: Some(Transport::Tcp),
        verdict,
        attempts: 3,
        successes,
        failures,
        error_rate: f64::from(failures) / 3.0,
        confidence: QualityConfidence::Medium,
        stages: Vec::new(),
    }
}

fn plan_quality_entry(outbound: &str, verdict: QualityVerdict) -> OutboundQualityEntry {
    let mut entry = quality_entry(outbound, verdict);
    entry.scope = Some("plan-candidate".to_string());
    entry.dialer = None;
    entry.private = None;
    entry
}
