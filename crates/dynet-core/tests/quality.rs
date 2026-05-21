use dynet_core::{
    AppState, DynetConfig, OutboundQualityEntry, OutboundQualityState, QualityConfidence,
    QualityVerdict,
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
