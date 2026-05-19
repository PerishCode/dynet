use serde::Serialize;

use crate::{AppState, InboundContext, PlanAction, Transport, Verdict};

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Plan {
    pub schema: String,
    pub mode: PlanMode,
    pub state_schema: String,
    pub rules: Vec<PlanRule>,
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
    pub priority: usize,
    #[serde(rename = "match")]
    pub matcher: PlanMatch,
    pub action: PlanAction,
    pub source: PlanRuleSource,
    pub reason: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanMatch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inbound: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<Transport>,
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
    pub explicit_rules: usize,
    pub dynamic_rules: usize,
    pub has_default: bool,
}

impl Plan {
    pub fn summary(&self) -> PlanSummary {
        PlanSummary {
            rules: self.rules.len(),
            explicit_rules: self
                .rules
                .iter()
                .filter(|rule| rule.source == PlanRuleSource::ExplicitRoute)
                .count(),
            dynamic_rules: 0,
            has_default: self.rules.iter().any(|rule| rule.matcher.inbound.is_none()),
        }
    }

    pub fn evaluate(&self, context: &InboundContext, state: &AppState) -> Verdict {
        for rule in &self.rules {
            if rule.matcher.matches(context) {
                return Verdict::from_action(
                    Some(rule.order),
                    rule.action.clone(),
                    rule.reason.clone(),
                    state,
                );
            }
        }

        Verdict::from_action(
            None,
            PlanAction::NoRoute,
            "no plan rule matched inbound context",
            state,
        )
    }
}

impl PlanMatch {
    fn matches(&self, context: &InboundContext) -> bool {
        if self
            .inbound
            .as_ref()
            .is_some_and(|inbound| context.inbound.as_ref() != Some(inbound))
        {
            return false;
        }
        if self
            .transport
            .is_some_and(|transport| context.transport != Some(transport))
        {
            return false;
        }
        true
    }
}

pub fn build_plan(state: &AppState) -> Plan {
    let rules = state
        .config
        .routes
        .iter()
        .enumerate()
        .map(|(index, route)| PlanRule {
            order: index + 1,
            priority: 0,
            matcher: PlanMatch {
                inbound: route.inbound.clone(),
                transport: None,
            },
            action: PlanAction::UseOutbound {
                tag: route.outbound.clone(),
            },
            source: PlanRuleSource::ExplicitRoute,
            reason: match route.inbound.as_deref() {
                Some(inbound) => format!(
                    "explicit user rule matches inbound `{inbound}` and uses outbound `{}`",
                    route.outbound
                ),
                None => {
                    format!(
                        "explicit user default rule uses outbound `{}`",
                        route.outbound
                    )
                }
            },
        })
        .collect();

    Plan {
        schema: "dynet-plan/v1alpha1".to_string(),
        mode: PlanMode::ExplicitOnly,
        state_schema: state.schema.clone(),
        rules,
    }
}
