use serde::Serialize;

use crate::{AppState, ModeledNode};

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Verdict {
    pub status: VerdictStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_rule: Option<usize>,
    pub action: PlanAction,
    pub dns_sensitive: bool,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbound: Option<OutboundTarget>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum VerdictStatus {
    Accept,
    Deny,
    NoMatch,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum PlanAction {
    UseOutbound { tag: String },
    Reject,
    NoRoute,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutboundTarget {
    pub tag: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub id: String,
    pub fingerprint: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
}

impl Verdict {
    pub fn from_action(
        matched_rule: Option<usize>,
        action: PlanAction,
        dns_sensitive: bool,
        reason: impl Into<String>,
        state: &AppState,
    ) -> Self {
        match &action {
            PlanAction::UseOutbound { tag } => match state.outbound(tag) {
                Some(outbound) => Self {
                    status: VerdictStatus::Accept,
                    matched_rule,
                    action,
                    dns_sensitive,
                    reason: reason.into(),
                    outbound: Some(OutboundTarget::from_node(outbound)),
                },
                None => {
                    let reason = format!("plan action references missing outbound `{tag}`");
                    Self {
                        status: VerdictStatus::Deny,
                        matched_rule,
                        action,
                        dns_sensitive,
                        reason,
                        outbound: None,
                    }
                }
            },
            PlanAction::Reject => Self {
                status: VerdictStatus::Deny,
                matched_rule,
                action,
                dns_sensitive,
                reason: reason.into(),
                outbound: None,
            },
            PlanAction::NoRoute => Self {
                status: VerdictStatus::NoMatch,
                matched_rule,
                action,
                dns_sensitive,
                reason: reason.into(),
                outbound: None,
            },
        }
    }
}

impl OutboundTarget {
    fn from_node(node: &ModeledNode) -> Self {
        Self {
            tag: node.tag.clone(),
            kind: node.kind.clone(),
            id: node.id.clone(),
            fingerprint: node.fingerprint.clone(),
            capabilities: node.capabilities.clone(),
        }
    }
}
