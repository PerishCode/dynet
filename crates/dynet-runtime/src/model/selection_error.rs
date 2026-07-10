use std::fmt;

use super::RuleId;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SelectionError {
    message: String,
    code: &'static str,
    matched_rule_id: Option<RuleId>,
}

impl SelectionError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            code: "selection-error",
            matched_rule_id: None,
        }
    }

    pub(crate) fn ipv6_disabled() -> Self {
        Self {
            message: "IPv6 target rejected because dynet IPv6 participation is disabled"
                .to_string(),
            code: "ipv6-disabled",
            matched_rule_id: None,
        }
    }

    pub(crate) fn ipv6_denied(rule_id: Option<RuleId>) -> Self {
        let rule = rule_id
            .as_ref()
            .map_or_else(|| "<default>".to_string(), ToString::to_string);
        Self {
            message: format!("IPv6 target rejected by forwarding rule {rule}"),
            code: "ipv6-policy-deny",
            matched_rule_id: rule_id,
        }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn matched_rule_id(&self) -> Option<&RuleId> {
        self.matched_rule_id.as_ref()
    }
}

impl fmt::Display for SelectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for SelectionError {}
