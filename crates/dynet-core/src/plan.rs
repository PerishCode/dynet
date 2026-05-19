use serde::Serialize;

use crate::DynetConfig;

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
