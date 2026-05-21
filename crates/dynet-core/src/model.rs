use std::{collections::BTreeMap, net::IpAddr};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::Transport;

#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct DynetConfig {
    #[serde(default)]
    pub log: Option<LogConfig>,
    #[serde(default)]
    pub dns: DnsConfig,
    #[serde(default)]
    pub inbounds: Vec<Inbound>,
    #[serde(default)]
    pub outbounds: Vec<Outbound>,
    #[serde(default)]
    pub rules: Vec<UserRule>,
    #[serde(default)]
    pub routes: Vec<RouteRule>,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogConfig {
    pub level: String,
}

pub type Inbound = NetworkNode;
pub type Outbound = NetworkNode;
pub type Endpoint = NetworkNode;

#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct DnsConfig {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chains: Vec<DnsChain>,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsChain {
    pub tag: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bootstrap_ips: Vec<IpAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_port: Option<u16>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
    #[serde(flatten)]
    pub protocol: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct NetworkNode {
    pub tag: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub constraints: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub payload: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct RouteRule {
    #[serde(default)]
    pub inbound: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<Transport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_suffix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_keyword: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_cidr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_port: Option<u16>,
    #[serde(default)]
    pub dns_sensitive: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<RouteAction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbound: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct UserRule {
    pub tag: String,
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
    pub outbound: String,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RouteAction {
    Reject,
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
    pub rules: usize,
    pub routes: usize,
    pub dns_chains: usize,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkModel {
    pub schema: String,
    pub inbounds: Vec<ModeledNode>,
    pub outbounds: Vec<ModeledNode>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsModel {
    pub schema: String,
    pub chains: Vec<ModeledDnsChain>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModeledDnsChain {
    pub tag: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub endpoint: Option<String>,
    pub bootstrap_ips: Vec<String>,
    pub protocol_fields: Vec<String>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NodeRole {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModeledNode {
    pub role: NodeRole,
    pub tag: String,
    pub id: String,
    pub fingerprint: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub labels: Vec<String>,
    pub capabilities: Vec<String>,
    pub constraints: Vec<String>,
    pub payload_fields: Vec<String>,
}

impl DynetConfig {
    pub fn summary(&self) -> ConfigSummary {
        ConfigSummary {
            inbounds: self.inbounds.len(),
            outbounds: self.outbounds.len(),
            rules: self.rules.len(),
            routes: self.routes.len(),
            dns_chains: self.dns.chains.len(),
        }
    }

    pub fn network_model(&self) -> NetworkModel {
        crate::capability::network_model(self)
    }

    pub fn dns_model(&self) -> DnsModel {
        crate::capability::dns_model(self)
    }
}
