use serde::{Deserialize, Serialize};

use crate::Transport;

#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutboundQualityState {
    pub schema: String,
    pub generated_at_unix_ms: u128,
    pub ttl_secs: u64,
    pub window_secs: u64,
    pub expires_at_unix_ms: u128,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outbounds: Vec<OutboundQualityEntry>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutboundQualityEntry {
    pub outbound: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dialer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_family: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<Transport>,
    pub verdict: QualityVerdict,
    pub attempts: u32,
    pub successes: u32,
    pub failures: u32,
    pub error_rate: f64,
    pub confidence: QualityConfidence,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stages: Vec<StageQualityEntry>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StageQualityEntry {
    pub stage: String,
    pub attempts: u32,
    pub failures: u32,
    pub error_rate: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p95_ms: Option<u128>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum QualityVerdict {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
    Stale,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum QualityConfidence {
    Low,
    Medium,
    High,
}

impl OutboundQualityState {
    pub fn empty() -> Self {
        Self {
            schema: "dynet-outbound-quality-state/v1alpha1".to_string(),
            generated_at_unix_ms: 0,
            ttl_secs: 0,
            window_secs: 0,
            expires_at_unix_ms: 0,
            outbounds: Vec::new(),
        }
    }
}
