use std::net::IpAddr;

use dynet_runtime::{GroupId, Ipv6RulePolicy, RouteMatcher, RouteRule, RuleId};
use serde::Deserialize;

use super::non_empty;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FileRouteRuleConfig {
    id: String,
    priority: i64,
    #[serde(rename = "match")]
    matcher: String,
    value: String,
    group: String,
    enabled: Option<bool>,
    ipv6: Option<String>,
}

impl FileRouteRuleConfig {
    pub(super) fn load(self) -> Result<RouteRule, String> {
        let id = non_empty("forwarding.rules[].id", self.id)?;
        let ipv6 = parse_ipv6_policy(&id, self.ipv6.as_deref())?;
        let matcher = match self.matcher.as_str() {
            "domain-exact" => RouteMatcher::DomainExact(self.value.to_ascii_lowercase()),
            "domain-suffix" => RouteMatcher::DomainSuffix(self.value.to_ascii_lowercase()),
            "ip-exact" => parse_ip_exact_rule(&id, &self.value)?,
            "ip-cidr" => RouteMatcher::IpCidr(self.value),
            _ => {
                return Err(format!(
                    "forwarding rule {id:?} match {:?} is unsupported",
                    self.matcher
                ));
            }
        };
        Ok(RouteRule {
            id: RuleId::new(id),
            priority: self.priority,
            enabled: self.enabled.unwrap_or(true),
            matcher,
            group_id: GroupId::new(non_empty("forwarding.rules[].group", self.group)?),
            ipv6,
        })
    }
}

fn parse_ipv6_policy(id: &str, value: Option<&str>) -> Result<Ipv6RulePolicy, String> {
    match value.unwrap_or("inherit") {
        "inherit" => Ok(Ipv6RulePolicy::Inherit),
        "allow" => Ok(Ipv6RulePolicy::Allow),
        "deny" => Ok(Ipv6RulePolicy::Deny),
        value => Err(format!(
            "forwarding rule {id:?} ipv6 must be allow, deny, or inherit, got {value:?}"
        )),
    }
}

fn parse_ip_exact_rule(id: &str, value: &str) -> Result<RouteMatcher, String> {
    Ok(RouteMatcher::IpExact(value.parse::<IpAddr>().map_err(
        |error| format!("forwarding rule {id:?} value must be an IP: {error}"),
    )?))
}
