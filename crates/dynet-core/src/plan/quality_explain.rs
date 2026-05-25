use serde::Serialize;

use crate::{
    AppState, OutboundQualityEntry, QualityConfidence, QualityScope, QualityVerdict, Transport,
};

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutboundCandidateQuality {
    pub stale: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_family: Option<String>,
    pub score: i64,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matches: Vec<OutboundCandidateQualityMatch>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutboundCandidateQualityMatch {
    pub scope: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_family: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<Transport>,
    pub verdict: QualityVerdict,
    pub attempts: u32,
    pub successes: u32,
    pub failures: u32,
    pub confidence: QualityConfidence,
    pub score: i64,
    pub weight: i64,
    pub weighted_score: i64,
}

pub(super) fn cascade_score(
    state: &AppState,
    family: Option<&str>,
    scope: QualityScope,
    outbound: &str,
) -> i64 {
    cascade_quality_matches(state, family, scope, outbound)
        .iter()
        .map(|item| item.weighted_score)
        .sum()
}

pub(super) fn explain_candidate_quality(
    state: &AppState,
    family: Option<String>,
    scope: QualityScope,
    stale: bool,
    outbound: &str,
) -> OutboundCandidateQuality {
    if stale {
        return OutboundCandidateQuality {
            stale: true,
            target_family: family,
            score: 0,
            reason: "quality-state-stale".to_string(),
            matches: Vec::new(),
        };
    }

    let matches = cascade_quality_matches(state, family.as_deref(), scope, outbound);
    let score = matches.iter().map(|item| item.weighted_score).sum();
    let reason = quality_reason(&matches);
    OutboundCandidateQuality {
        stale: false,
        target_family: family,
        score,
        reason,
        matches,
    }
}

fn cascade_quality_matches(
    state: &AppState,
    family: Option<&str>,
    scope: QualityScope,
    outbound: &str,
) -> Vec<OutboundCandidateQualityMatch> {
    let mut matches = Vec::new();
    let scope = scope.as_str();
    if let Some(family) = family {
        if let Some(entry) =
            quality_entry(state, outbound, scope, Some(family), Some(Transport::Tcp))
        {
            matches.push(candidate_quality_match(entry, 4));
        }
    }
    if let Some(entry) = quality_entry(state, outbound, scope, None, Some(Transport::Tcp)) {
        matches.push(candidate_quality_match(entry, 1));
    }
    matches
}

fn candidate_quality_match(
    entry: &OutboundQualityEntry,
    weight: i64,
) -> OutboundCandidateQualityMatch {
    let score = quality_score(entry);
    OutboundCandidateQualityMatch {
        scope: entry.scope.clone().unwrap_or_default(),
        target_family: entry.target_family.clone(),
        transport: entry.transport,
        verdict: entry.verdict,
        attempts: entry.attempts,
        successes: entry.successes,
        failures: entry.failures,
        confidence: entry.confidence,
        score,
        weight,
        weighted_score: score * weight,
    }
}

fn quality_entry<'a>(
    state: &'a AppState,
    outbound: &str,
    scope: &str,
    family: Option<&str>,
    transport: Option<Transport>,
) -> Option<&'a OutboundQualityEntry> {
    state.quality.outbounds.iter().find(|entry| {
        entry.outbound == outbound
            && entry.scope.as_deref() == Some(scope)
            && entry.target_family.as_deref() == family
            && entry.transport == transport
    })
}

fn quality_score(entry: &OutboundQualityEntry) -> i64 {
    let base = match entry.verdict {
        QualityVerdict::Healthy => 1_000,
        QualityVerdict::Degraded => 100,
        QualityVerdict::Unknown => 0,
        QualityVerdict::Stale => -500,
        QualityVerdict::Unhealthy => -1_000,
    };
    base + i64::from(entry.successes) * 20
        - i64::from(entry.failures) * 80
        - stage_latency_penalty(entry)
}

fn stage_latency_penalty(entry: &OutboundQualityEntry) -> i64 {
    let Some(p95_ms) = entry.stages.iter().filter_map(|stage| stage.p95_ms).max() else {
        return 0;
    };
    i64::try_from(p95_ms / 100).unwrap_or(i64::MAX).min(300)
}

fn quality_reason(matches: &[OutboundCandidateQualityMatch]) -> String {
    let has_exact = matches.iter().any(|item| item.target_family.is_some());
    let has_overall = matches.iter().any(|item| item.target_family.is_none());
    if has_exact && has_overall {
        "exact-and-overall-quality".to_string()
    } else if has_exact {
        "exact-quality".to_string()
    } else if has_overall {
        "overall-quality".to_string()
    } else {
        "no-quality-evidence".to_string()
    }
}
