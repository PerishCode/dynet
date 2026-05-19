use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DynetConfig {
    #[serde(default)]
    pub log: Option<LogConfig>,
    #[serde(default)]
    pub inbounds: Vec<Endpoint>,
    #[serde(default)]
    pub outbounds: Vec<Endpoint>,
    #[serde(default)]
    pub routes: Vec<RouteRule>,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogConfig {
    pub level: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Endpoint {
    pub tag: String,
    #[serde(rename = "type")]
    pub kind: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteRule {
    #[serde(default)]
    pub inbound: Option<String>,
    pub outbound: String,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    Deny,
    Warning,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigDiagnostic {
    pub severity: Severity,
    pub path: String,
    pub message: String,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigSummary {
    pub inbounds: usize,
    pub outbounds: usize,
    pub routes: usize,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Plan {
    pub mode: PlanMode,
    pub rules: Vec<PlanRule>,
    pub final_outbound: Option<String>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PlanMode {
    ExplicitOnly,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanRule {
    pub order: usize,
    pub inbound: Option<String>,
    pub outbound: String,
    pub source: PlanRuleSource,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PlanRuleSource {
    ExplicitRoute,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanSummary {
    pub rules: usize,
    pub has_final: bool,
}

impl DynetConfig {
    pub fn summary(&self) -> ConfigSummary {
        ConfigSummary {
            inbounds: self.inbounds.len(),
            outbounds: self.outbounds.len(),
            routes: self.routes.len(),
        }
    }
}

impl Plan {
    pub fn summary(&self) -> PlanSummary {
        PlanSummary {
            rules: self.rules.len(),
            has_final: self.final_outbound.is_some(),
        }
    }
}

pub fn build_plan(config: &DynetConfig) -> Plan {
    let rules = config
        .routes
        .iter()
        .enumerate()
        .map(|(index, route)| PlanRule {
            order: index + 1,
            inbound: route.inbound.clone(),
            outbound: route.outbound.clone(),
            source: PlanRuleSource::ExplicitRoute,
            reason: match route.inbound.as_deref() {
                Some(inbound) => {
                    format!(
                        "explicit route maps inbound `{inbound}` to `{}`",
                        route.outbound
                    )
                }
                None => format!("explicit default route maps to `{}`", route.outbound),
            },
        })
        .collect();
    let final_outbound = config
        .routes
        .iter()
        .find(|route| route.inbound.is_none())
        .map(|route| route.outbound.clone());

    Plan {
        mode: PlanMode::ExplicitOnly,
        rules,
        final_outbound,
    }
}

pub fn validate_config(config: &DynetConfig) -> Vec<ConfigDiagnostic> {
    let mut diagnostics = Vec::new();
    validate_endpoints("inbounds", &config.inbounds, &mut diagnostics);
    validate_endpoints("outbounds", &config.outbounds, &mut diagnostics);
    validate_routes(config, &mut diagnostics);
    diagnostics
}

fn validate_endpoints(
    section: &'static str,
    endpoints: &[Endpoint],
    diagnostics: &mut Vec<ConfigDiagnostic>,
) {
    let mut seen = BTreeMap::<&str, usize>::new();
    for (index, endpoint) in endpoints.iter().enumerate() {
        if endpoint.tag.trim().is_empty() {
            diagnostics.push(deny(
                format!("{section}[{index}].tag"),
                "endpoint tag must not be empty",
            ));
        }
        if endpoint.kind.trim().is_empty() {
            diagnostics.push(deny(
                format!("{section}[{index}].type"),
                "endpoint type must not be empty",
            ));
        }
        if let Some(previous) = seen.insert(endpoint.tag.as_str(), index) {
            diagnostics.push(deny(
                format!("{section}[{index}].tag"),
                format!("duplicate endpoint tag also used at {section}[{previous}]"),
            ));
        }
    }
}

fn validate_routes(config: &DynetConfig, diagnostics: &mut Vec<ConfigDiagnostic>) {
    let inbounds = config
        .inbounds
        .iter()
        .map(|endpoint| endpoint.tag.as_str())
        .collect::<BTreeSet<_>>();
    let outbounds = config
        .outbounds
        .iter()
        .map(|endpoint| endpoint.tag.as_str())
        .collect::<BTreeSet<_>>();

    for (index, route) in config.routes.iter().enumerate() {
        if route.outbound.trim().is_empty() {
            diagnostics.push(deny(
                format!("routes[{index}].outbound"),
                "route outbound must not be empty",
            ));
        } else if !outbounds.contains(route.outbound.as_str()) {
            diagnostics.push(deny(
                format!("routes[{index}].outbound"),
                format!("route references unknown outbound `{}`", route.outbound),
            ));
        }
        if let Some(inbound) = route.inbound.as_deref() {
            if inbound.trim().is_empty() {
                diagnostics.push(deny(
                    format!("routes[{index}].inbound"),
                    "route inbound must not be empty when set",
                ));
            } else if !inbounds.contains(inbound) {
                diagnostics.push(deny(
                    format!("routes[{index}].inbound"),
                    format!("route references unknown inbound `{inbound}`"),
                ));
            }
        }
    }
}

fn deny(path: impl Into<String>, message: impl Into<String>) -> ConfigDiagnostic {
    ConfigDiagnostic {
        severity: Severity::Deny,
        path: path.into(),
        message: message.into(),
    }
}
