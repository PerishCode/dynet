use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    normalize_domain, AppState, InboundContext, OutboundQualityEntry, QualityVerdict, Transport,
};

use super::outbound::{PlanEdge, PlanEdgeKind};

const INTERNAL_SOURCE: &str = "internal";
const CURRENT_VERSION: &str = "v1alpha1";
const DEFAULT_KEY: &str = "static";
const STICKY_KEY: &str = "sticky";
const CASCADE_QUALITY_KEY: &str = "cascade-quality";
const CASCADE_QUALITY_SCOPE: &str = "dialer-bound";
const CAPABILITIES_OPTION: &str = "capabilities";

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct OutboundStrategyConfig {
    #[serde(default = "default_strategy_source")]
    pub source: String,
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub options: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OutboundStrategyCapability {
    CandidateFilter,
    StickySelection,
    HealthObservation,
    Failover,
    Explanation,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutboundStrategyRegistryModel {
    pub schema: String,
    pub strategies: Vec<OutboundStrategyRegistryEntry>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutboundStrategyRegistryEntry {
    pub source: String,
    pub key: String,
    pub version: String,
    pub selector: OutboundSelector,
    pub capabilities: Vec<OutboundStrategyCapability>,
    pub description: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutboundStrategySnapshot {
    pub source: String,
    pub key: String,
    pub version: String,
    pub selector: OutboundSelector,
    pub capabilities: Vec<OutboundStrategyCapability>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OutboundSelector {
    FirstAvailable,
    StickySite,
    CascadeQuality,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct OutboundStrategyRegistry {
    entries: Vec<OutboundStrategyRegistryEntry>,
}

impl Default for OutboundStrategyConfig {
    fn default() -> Self {
        Self {
            source: default_strategy_source(),
            key: String::new(),
            version: String::new(),
            options: BTreeMap::new(),
        }
    }
}

impl Default for OutboundStrategyRegistry {
    fn default() -> Self {
        Self::built_in()
    }
}

impl OutboundStrategyRegistry {
    pub fn built_in() -> Self {
        Self {
            entries: vec![static_entry(), sticky_entry(), cascade_quality_entry()],
        }
    }

    pub fn model(&self) -> OutboundStrategyRegistryModel {
        OutboundStrategyRegistryModel {
            schema: "dynet-outbound-strategy-registry/v1alpha1".to_string(),
            strategies: self.entries.clone(),
        }
    }

    pub fn resolve(
        &self,
        config: &OutboundStrategyConfig,
    ) -> Result<OutboundStrategySnapshot, String> {
        let source = config.effective_source();
        let key = config.effective_key();
        let entry = self
            .entry(source, key)
            .ok_or_else(|| format!("unknown outbound strategy `{source}/{key}`"))?;
        let version = config.effective_version(entry);
        if version != entry.version {
            return Err(format!(
                "outbound strategy `{source}/{key}` does not support version `{version}`"
            ));
        }
        let requested = config.option_capabilities()?;
        let capabilities = if requested.is_empty() {
            entry.capabilities.clone()
        } else {
            validate_requested_capabilities(entry, &requested)?;
            requested
        };
        let selector = selector_for(&capabilities, entry.selector);
        Ok(OutboundStrategySnapshot {
            source: entry.source.clone(),
            key: entry.key.clone(),
            version: entry.version.clone(),
            selector,
            capabilities,
        })
    }

    pub fn entry(&self, source: &str, key: &str) -> Option<&OutboundStrategyRegistryEntry> {
        self.entries
            .iter()
            .find(|entry| entry.source == source && entry.key == key)
    }
}

impl OutboundStrategyConfig {
    pub fn effective_source(&self) -> &str {
        let source = self.source.trim();
        if source.is_empty() {
            INTERNAL_SOURCE
        } else {
            source
        }
    }

    pub fn effective_key(&self) -> &str {
        let key = self.key.trim();
        if key.is_empty() {
            DEFAULT_KEY
        } else {
            key
        }
    }

    pub fn effective_version<'a>(&'a self, entry: &'a OutboundStrategyRegistryEntry) -> &'a str {
        let version = self.version.trim();
        if version.is_empty() {
            entry.version.as_str()
        } else {
            version
        }
    }

    pub fn option_capabilities(&self) -> Result<Vec<OutboundStrategyCapability>, String> {
        let Some(value) = self.options.get(CAPABILITIES_OPTION) else {
            return Ok(Vec::new());
        };
        serde_json::from_value(value.clone()).map_err(|error| {
            format!(
                "outbound strategy option `{CAPABILITIES_OPTION}` must be a capability array: {error}"
            )
        })
    }
}

impl OutboundSelector {
    pub fn select(
        self,
        edges: &[PlanEdge],
        context: &InboundContext,
        state: &AppState,
    ) -> Option<PlanEdge> {
        let candidates = preferred_edges(edges);
        match self {
            Self::FirstAvailable => candidates.first().cloned(),
            Self::StickySite => sticky_select(&candidates, context, state),
            Self::CascadeQuality => cascade_quality_select(&candidates, context, state),
        }
    }
}

pub fn default_strategy_source() -> String {
    INTERNAL_SOURCE.to_string()
}

fn static_entry() -> OutboundStrategyRegistryEntry {
    OutboundStrategyRegistryEntry {
        source: INTERNAL_SOURCE.to_string(),
        key: DEFAULT_KEY.to_string(),
        version: CURRENT_VERSION.to_string(),
        selector: OutboundSelector::FirstAvailable,
        capabilities: vec![
            OutboundStrategyCapability::CandidateFilter,
            OutboundStrategyCapability::Explanation,
        ],
        description: "choose the first candidate edge".to_string(),
    }
}

fn sticky_entry() -> OutboundStrategyRegistryEntry {
    OutboundStrategyRegistryEntry {
        source: INTERNAL_SOURCE.to_string(),
        key: STICKY_KEY.to_string(),
        version: CURRENT_VERSION.to_string(),
        selector: OutboundSelector::StickySite,
        capabilities: vec![
            OutboundStrategyCapability::CandidateFilter,
            OutboundStrategyCapability::StickySelection,
            OutboundStrategyCapability::Explanation,
        ],
        description: "map each site key to a stable candidate edge".to_string(),
    }
}

fn cascade_quality_entry() -> OutboundStrategyRegistryEntry {
    OutboundStrategyRegistryEntry {
        source: INTERNAL_SOURCE.to_string(),
        key: CASCADE_QUALITY_KEY.to_string(),
        version: CURRENT_VERSION.to_string(),
        selector: OutboundSelector::CascadeQuality,
        capabilities: vec![
            OutboundStrategyCapability::CandidateFilter,
            OutboundStrategyCapability::HealthObservation,
            OutboundStrategyCapability::Failover,
            OutboundStrategyCapability::Explanation,
        ],
        description: "prefer recently successful cascade-bound candidates".to_string(),
    }
}

fn validate_requested_capabilities(
    entry: &OutboundStrategyRegistryEntry,
    requested: &[OutboundStrategyCapability],
) -> Result<(), String> {
    let supported = entry
        .capabilities
        .iter()
        .copied()
        .collect::<BTreeSet<OutboundStrategyCapability>>();
    for capability in requested {
        if !supported.contains(capability) {
            return Err(format!(
                "outbound strategy `{}` does not support capability `{}`",
                entry.key,
                capability_name(*capability)
            ));
        }
    }
    Ok(())
}

fn selector_for(
    capabilities: &[OutboundStrategyCapability],
    default_selector: OutboundSelector,
) -> OutboundSelector {
    if capabilities.contains(&OutboundStrategyCapability::HealthObservation) {
        OutboundSelector::CascadeQuality
    } else if capabilities.contains(&OutboundStrategyCapability::StickySelection) {
        OutboundSelector::StickySite
    } else {
        default_selector
    }
}

fn preferred_edges(edges: &[PlanEdge]) -> Vec<PlanEdge> {
    let candidates = edges
        .iter()
        .filter(|edge| edge.kind == PlanEdgeKind::Candidate)
        .cloned()
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        edges
            .iter()
            .filter(|edge| edge.kind == PlanEdgeKind::Fallback)
            .cloned()
            .collect()
    } else {
        candidates
    }
}

fn sticky_select(
    edges: &[PlanEdge],
    context: &InboundContext,
    state: &AppState,
) -> Option<PlanEdge> {
    let key = sticky_key(context, state);
    edges
        .iter()
        .max_by(|left, right| compare_sticky_candidate(&key, left, right))
        .cloned()
}

fn cascade_quality_select(
    edges: &[PlanEdge],
    context: &InboundContext,
    state: &AppState,
) -> Option<PlanEdge> {
    if quality_is_stale(state) {
        return sticky_select(edges, context, state);
    }
    let key = sticky_key(context, state);
    let family = target_family(&key);
    edges
        .iter()
        .max_by(|left, right| {
            compare_cascade_candidate(state, family.as_deref(), &key, left, right)
        })
        .cloned()
}

fn compare_cascade_candidate(
    state: &AppState,
    family: Option<&str>,
    sticky: &str,
    left: &PlanEdge,
    right: &PlanEdge,
) -> Ordering {
    let left_score = cascade_score(state, family, left.to.as_str());
    let right_score = cascade_score(state, family, right.to.as_str());
    left_score
        .cmp(&right_score)
        .then_with(|| compare_sticky_candidate(sticky, left, right))
}

fn cascade_score(state: &AppState, family: Option<&str>, outbound: &str) -> i64 {
    let exact = family
        .and_then(|family| {
            quality_entry(
                state,
                outbound,
                CASCADE_QUALITY_SCOPE,
                Some(family),
                Some(Transport::Tcp),
            )
        })
        .map(|entry| quality_score(entry) * 4);
    let overall = quality_entry(
        state,
        outbound,
        CASCADE_QUALITY_SCOPE,
        None,
        Some(Transport::Tcp),
    )
    .map(quality_score);
    exact.unwrap_or(0) + overall.unwrap_or(0)
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
    base + i64::from(entry.successes) * 20 - i64::from(entry.failures) * 80
}

fn quality_is_stale(state: &AppState) -> bool {
    state.quality.expires_at_unix_ms != 0
        && now_unix_ms().is_some_and(|now| now > state.quality.expires_at_unix_ms)
}

fn compare_sticky_candidate(key: &str, left: &PlanEdge, right: &PlanEdge) -> Ordering {
    let left_score = stable_hash(key, &left.to);
    let right_score = stable_hash(key, &right.to);
    left_score
        .cmp(&right_score)
        .then_with(|| right.to.cmp(&left.to))
}

fn sticky_key(context: &InboundContext, state: &AppState) -> String {
    if let Some(domain) = context
        .destination_domain
        .as_deref()
        .and_then(normalize_domain)
    {
        return domain;
    }
    if let Some(address) = context.destination_ip {
        if let Some(domain) = first_reverse_domain(address, state) {
            return domain;
        }
        return address.to_string();
    }
    context.inbound.as_deref().unwrap_or("*").to_string()
}

fn first_reverse_domain(address: IpAddr, state: &AppState) -> Option<String> {
    state.dns_reverse.domains_for_ip(address).into_iter().next()
}

fn target_family(host: &str) -> Option<String> {
    let labels = host
        .trim_end_matches('.')
        .split('.')
        .filter(|item| !item.is_empty())
        .collect::<Vec<_>>();
    if labels.len() >= 2 {
        Some(labels[labels.len() - 2..].join("."))
    } else {
        labels.first().map(|value| (*value).to_string())
    }
}

fn stable_hash(key: &str, tag: &str) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in key.bytes().chain([0]).chain(tag.bytes()) {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn now_unix_ms() -> Option<u128> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_millis())
}

fn capability_name(capability: OutboundStrategyCapability) -> &'static str {
    match capability {
        OutboundStrategyCapability::CandidateFilter => "candidate-filter",
        OutboundStrategyCapability::StickySelection => "sticky-selection",
        OutboundStrategyCapability::HealthObservation => "health-observation",
        OutboundStrategyCapability::Failover => "failover",
        OutboundStrategyCapability::Explanation => "explanation",
    }
}
