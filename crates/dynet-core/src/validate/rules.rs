use std::{collections::BTreeMap, net::IpAddr};

use crate::{
    normalize_domain, ConfigDiagnostic, DynetConfig, NetworkNode, UserRule, UserRuleMatch,
};

use super::{deny, node_index, validate_ip_cidr};

pub(super) fn validate_rules(config: &DynetConfig, diagnostics: &mut Vec<ConfigDiagnostic>) {
    let outbounds = node_index(&config.outbounds);
    let mut seen = BTreeMap::<&str, usize>::new();
    for (index, rule) in config.rules.iter().enumerate() {
        validate_base(index, rule, diagnostics);
        if let Some(previous) = seen.insert(rule.tag.as_str(), index) {
            diagnostics.push(deny(
                format!("rules[{index}].tag"),
                format!("duplicate user rule tag also used at rules[{previous}]"),
            ));
        }
        validate_matchers(index, rule, diagnostics);
        validate_outbound(index, rule, &outbounds, diagnostics);
    }
}

fn validate_base(index: usize, rule: &UserRule, diagnostics: &mut Vec<ConfigDiagnostic>) {
    if rule.tag.trim().is_empty() {
        diagnostics.push(deny(
            format!("rules[{index}].tag"),
            "user rule tag must not be empty",
        ));
    }
}

fn validate_matchers(index: usize, rule: &UserRule, diagnostics: &mut Vec<ConfigDiagnostic>) {
    validate_domain_field(index, "domain", rule.domain.as_deref(), diagnostics);
    validate_domain_field(
        index,
        "domainSuffix",
        rule.domain_suffix.as_deref(),
        diagnostics,
    );
    if matches!(rule.domain_keyword.as_deref(), Some(value) if value.trim().is_empty()) {
        diagnostics.push(deny(
            format!("rules[{index}].domainKeyword"),
            "user rule domain keyword must not be empty",
        ));
    }
    if let Some(ip) = &rule.ip {
        if ip.trim().parse::<IpAddr>().is_err() {
            diagnostics.push(deny(
                format!("rules[{index}].ip"),
                "user rule ip must be an IP address",
            ));
        }
    }
    if let Some(ip_cidr) = &rule.ip_cidr {
        validate_ip_cidr(
            format!("rules[{index}].ipCidr"),
            "user rule ipCidr",
            ip_cidr,
            diagnostics,
        );
    }
    if UserRuleMatch::from_rule(rule).is_empty() {
        diagnostics.push(deny(
            format!("rules[{index}]"),
            "user rule must include at least one domain* or ip* matcher",
        ));
    }
}

fn validate_domain_field(
    index: usize,
    field: &'static str,
    value: Option<&str>,
    diagnostics: &mut Vec<ConfigDiagnostic>,
) {
    match value {
        Some(value) if normalize_domain(value).is_none() => diagnostics.push(deny(
            format!("rules[{index}].{field}"),
            format!("user rule {field} must not be empty"),
        )),
        _ => {}
    }
}

fn validate_outbound(
    index: usize,
    rule: &UserRule,
    outbounds: &BTreeMap<&str, &NetworkNode>,
    diagnostics: &mut Vec<ConfigDiagnostic>,
) {
    if rule.outbound.trim().is_empty() {
        diagnostics.push(deny(
            format!("rules[{index}].outbound"),
            "user rule outbound must not be empty",
        ));
        return;
    }
    let Some(outbound) = outbounds.get(rule.outbound.as_str()) else {
        diagnostics.push(deny(
            format!("rules[{index}].outbound"),
            format!("user rule references unknown outbound `{}`", rule.outbound),
        ));
        return;
    };
    if outbound.kind != "dialer" {
        diagnostics.push(deny(
            format!("rules[{index}].outbound"),
            format!(
                "user rule outbound `{}` must be a dialer outbound for the fail-closed priority channel",
                outbound.tag
            ),
        ));
    }
}
