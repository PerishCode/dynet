pub(crate) mod matchset;

use std::net::IpAddr;

use serde::Serialize;

use crate::{normalize_domain, AppState, InboundContext, UserRule};

use self::matchset::{candidate_domains, domain_matches_suffix, ip_in_cidr, normalize_cidr_text};

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserRuleDecision {
    pub order: usize,
    pub tag: String,
    #[serde(rename = "match")]
    pub matcher: UserRuleMatch,
    pub outbound: String,
    pub bypasses_plan: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserRuleMatch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_suffix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_keyword: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_cidr: Option<String>,
}

pub fn evaluate_rules(state: &AppState, context: &InboundContext) -> Option<UserRuleDecision> {
    state
        .config
        .rules
        .iter()
        .enumerate()
        .find_map(|(index, rule)| {
            let matcher = UserRuleMatch::from_rule(rule);
            matcher.matches(context, state).then(|| UserRuleDecision {
                order: index + 1,
                tag: rule.tag.clone(),
                outbound: rule.outbound.clone(),
                bypasses_plan: true,
                reason: rule_reason(rule, &matcher),
                matcher,
            })
        })
}

impl UserRuleMatch {
    pub fn from_rule(rule: &UserRule) -> Self {
        Self {
            domain: rule.domain.as_deref().and_then(normalize_domain),
            domain_suffix: rule.domain_suffix.as_deref().and_then(normalize_domain),
            domain_keyword: rule
                .domain_keyword
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_ascii_lowercase),
            ip: rule
                .ip
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string),
            ip_cidr: rule.ip_cidr.as_deref().map(normalize_cidr_text),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.domain.is_none()
            && self.domain_suffix.is_none()
            && self.domain_keyword.is_none()
            && self.ip.is_none()
            && self.ip_cidr.is_none()
    }

    fn matches(&self, context: &InboundContext, state: &AppState) -> bool {
        if let Some(ip) = &self.ip {
            let Some(destination_ip) = context.destination_ip else {
                return false;
            };
            let Ok(ip) = ip.parse::<IpAddr>() else {
                return false;
            };
            if destination_ip != ip {
                return false;
            }
        }
        if let Some(cidr) = &self.ip_cidr {
            let Some(destination_ip) = context.destination_ip else {
                return false;
            };
            if !ip_in_cidr(destination_ip, cidr) {
                return false;
            }
        }
        let needs_domain =
            self.domain.is_some() || self.domain_suffix.is_some() || self.domain_keyword.is_some();
        if needs_domain {
            let domains = candidate_domains(context, state);
            if domains.is_empty() {
                return false;
            }
            if let Some(domain) = &self.domain {
                if !domains.iter().any(|candidate| candidate == domain) {
                    return false;
                }
            }
            if let Some(suffix) = &self.domain_suffix {
                if !domains
                    .iter()
                    .any(|candidate| domain_matches_suffix(candidate, suffix))
                {
                    return false;
                }
            }
            if let Some(keyword) = &self.domain_keyword {
                if !domains.iter().any(|candidate| candidate.contains(keyword)) {
                    return false;
                }
            }
        }
        true
    }
}

fn rule_reason(rule: &UserRule, matcher: &UserRuleMatch) -> String {
    let mut parts = Vec::new();
    if let Some(domain) = &matcher.domain {
        parts.push(format!("domain `{domain}`"));
    }
    if let Some(domain_suffix) = &matcher.domain_suffix {
        parts.push(format!("domain suffix `{domain_suffix}`"));
    }
    if let Some(domain_keyword) = &matcher.domain_keyword {
        parts.push(format!("domain keyword `{domain_keyword}`"));
    }
    if let Some(ip) = &matcher.ip {
        parts.push(format!("IP `{ip}`"));
    }
    if let Some(ip_cidr) = &matcher.ip_cidr {
        parts.push(format!("IP CIDR `{ip_cidr}`"));
    }
    if parts.is_empty() {
        parts.push("empty matcher".to_string());
    }
    format!(
        "user hard rule `{}` matches {} and bypasses plan to dialer outbound `{}`",
        rule.tag,
        parts.join(" plus "),
        rule.outbound
    )
}
