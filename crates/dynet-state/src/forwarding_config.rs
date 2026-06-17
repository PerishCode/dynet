use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

use dynet_ingress::{EgressNodeConfig, ShadowsocksConfig, TrojanConfig, VlessConfig, VmessConfig};
use dynet_runtime::{
    ForwardGroup, ForwardNode, GroupId, GroupMember, NextRef, NodeId, RouteMatcher, RouteRule,
    RuleId, RuntimeSeed, SchedulerPolicy,
};
use serde::Deserialize;

use crate::{method_config::parse_shadowsocks_method, ForwardingConfig};

mod validation;
use validation::{validate_execution_node, validate_thresholds};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FileForwardingConfig {
    default_group: Option<String>,
    nodes: Option<Vec<FileForwardNodeConfig>>,
    groups: Option<Vec<FileForwardGroupConfig>>,
    rules: Option<Vec<FileRouteRuleConfig>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileForwardGroupConfig {
    id: String,
    enabled: Option<bool>,
    mode: String,
    profile: Option<String>,
    next: Option<String>,
    members: Vec<String>,
    thresholds: Option<FileGroupThresholds>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileGroupThresholds {
    window_secs: Option<u64>,
    min_confidence: Option<f64>,
    max_explore_ratio: Option<f64>,
    failure_cooldown_secs: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileRouteRuleConfig {
    id: String,
    priority: i64,
    #[serde(rename = "match")]
    matcher: String,
    value: String,
    group: String,
    enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileForwardNodeConfig {
    id: String,
    enabled: Option<bool>,
    #[serde(rename = "type")]
    kind: String,
    server: Option<String>,
    port: Option<u16>,
    method: Option<String>,
    cipher: Option<String>,
    #[serde(rename = "alterId")]
    alter_id: Option<u16>,
    uuid: Option<String>,
    flow: Option<String>,
    network: Option<String>,
    tls: Option<bool>,
    password: Option<String>,
    sni: Option<String>,
    servername: Option<String>,
    #[serde(rename = "client-fingerprint")]
    client_fingerprint: Option<String>,
    #[serde(rename = "reality-opts")]
    reality_opts: Option<FileRealityOptions>,
    #[serde(rename = "skip-cert-verify")]
    skip_cert_verify: Option<bool>,
    udp: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileRealityOptions {
    #[serde(rename = "public-key")]
    public_key: Option<String>,
    #[serde(rename = "short-id")]
    short_id: Option<String>,
}

impl FileForwardingConfig {
    pub(crate) fn load(self) -> Result<ForwardingConfig, String> {
        let nodes = self
            .nodes
            .ok_or_else(|| "forwarding.nodes is required".to_string())?;
        let groups = self
            .groups
            .ok_or_else(|| "forwarding.groups is required".to_string())?;
        if nodes.is_empty() {
            return Err("forwarding.nodes must not be empty".to_string());
        }
        if groups.is_empty() {
            return Err("forwarding.groups must not be empty".to_string());
        }
        build_graph(self.default_group, nodes, groups, self.rules)
    }
}

fn build_graph(
    default_group: Option<String>,
    nodes: Vec<FileForwardNodeConfig>,
    groups: Vec<FileForwardGroupConfig>,
    rules: Option<Vec<FileRouteRuleConfig>>,
) -> Result<ForwardingConfig, String> {
    let default_group = default_group.unwrap_or_else(|| groups[0].id.clone());
    let (runtime_nodes, node_execution_configs) = load_nodes(nodes)?;
    let (runtime_groups, group_members) = load_groups(groups)?;
    let route_rules = rules
        .unwrap_or_default()
        .into_iter()
        .map(FileRouteRuleConfig::load)
        .collect::<Result<Vec<_>, _>>()?;
    validate_execution_node(
        &default_group,
        &runtime_groups,
        &group_members,
        &node_execution_configs,
    )?;
    let defaults = RuntimeSeed::single_node("direct");
    Ok(ForwardingConfig {
        seed: RuntimeSeed {
            nodes: runtime_nodes,
            default_group_id: GroupId::new(default_group),
            groups: runtime_groups,
            group_members,
            route_rules,
            dns_upstreams: defaults.dns_upstreams,
            dns_policy: defaults.dns_policy,
        },
        execution_nodes: node_execution_configs,
    })
}

fn load_nodes(
    nodes: Vec<FileForwardNodeConfig>,
) -> Result<(Vec<ForwardNode>, BTreeMap<String, EgressNodeConfig>), String> {
    let mut runtime_nodes = Vec::with_capacity(nodes.len());
    let mut node_execution_configs = BTreeMap::new();
    for node in nodes {
        let (runtime_node, node_config) = node.load_execution_node()?;
        let id = runtime_node.id.as_str().to_string();
        if node_execution_configs
            .insert(id.clone(), node_config)
            .is_some()
        {
            return Err(format!("forwarding node id {id:?} is duplicated"));
        }
        runtime_nodes.push(runtime_node);
    }
    Ok((runtime_nodes, node_execution_configs))
}

fn load_groups(
    groups: Vec<FileForwardGroupConfig>,
) -> Result<(Vec<ForwardGroup>, Vec<GroupMember>), String> {
    let mut runtime_groups = Vec::with_capacity(groups.len());
    let mut group_members = Vec::new();
    let mut group_ids = BTreeSet::new();
    for group in groups {
        let id = non_empty("forwarding.groups[].id", group.id.clone())?;
        validate_group_header(&id, &group, &mut group_ids)?;
        let next = group
            .next
            .map_or_else(NextRef::direct_audit_outlet, NextRef::named);
        push_group_members(&id, group.members, &mut group_members)?;
        runtime_groups.push(ForwardGroup {
            id: GroupId::new(id),
            enabled: group.enabled.unwrap_or(true),
            scheduler: SchedulerPolicy::SingleFirstEnabled,
            next,
        });
    }
    Ok((runtime_groups, group_members))
}

fn validate_group_header(
    id: &str,
    group: &FileForwardGroupConfig,
    group_ids: &mut BTreeSet<String>,
) -> Result<(), String> {
    if id == NextRef::DIRECT_AUDIT_OUTLET {
        return Err("forwarding group id 'direct' is reserved".to_string());
    }
    if !group_ids.insert(id.to_string()) {
        return Err(format!("forwarding group id {id:?} is duplicated"));
    }
    if group.mode != "smart" {
        return Err(format!(
            "forwarding group {id:?} mode must be smart, got {:?}",
            group.mode
        ));
    }
    validate_thresholds(id, group.thresholds.as_ref())?;
    let _ = &group.profile;
    Ok(())
}

fn push_group_members(
    group_id: &str,
    members: Vec<String>,
    group_members: &mut Vec<GroupMember>,
) -> Result<(), String> {
    for (priority, member) in members.into_iter().enumerate() {
        group_members.push(GroupMember {
            group_id: GroupId::new(group_id.to_string()),
            node_id: NodeId::new(non_empty("forwarding.groups[].members[]", member)?),
            enabled: true,
            priority: u32::try_from(priority)
                .map_err(|_| format!("forwarding group {group_id:?} has too many members"))?,
        });
    }
    Ok(())
}

impl FileRouteRuleConfig {
    fn load(self) -> Result<RouteRule, String> {
        let id = non_empty("forwarding.rules[].id", self.id)?;
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
        })
    }
}

fn parse_ip_exact_rule(id: &str, value: &str) -> Result<RouteMatcher, String> {
    Ok(RouteMatcher::IpExact(value.parse::<IpAddr>().map_err(
        |error| format!("forwarding rule {id:?} value must be an IP: {error}"),
    )?))
}

impl FileForwardNodeConfig {
    fn load_execution_node(self) -> Result<(ForwardNode, EgressNodeConfig), String> {
        let id = non_empty("forwarding.nodes[].id", self.id.clone())?;
        let enabled = self.enabled.unwrap_or(true);
        let tag = self.kind.clone();
        let node_config = self.load_execution_config()?;
        Ok((
            ForwardNode {
                id: NodeId::new(id),
                tag,
                enabled,
            },
            node_config,
        ))
    }

    fn load_execution_config(self) -> Result<EgressNodeConfig, String> {
        match self.kind.as_str() {
            "direct" => Ok(EgressNodeConfig::Direct),
            "shadowsocks" | "ss" => self.load_shadowsocks(),
            "trojan" => self.load_trojan(),
            "vless" => self.load_vless(),
            "vmess" => self.load_vmess(),
            _ => Err(format!(
                "forwarding.nodes[].type unsupported: {}",
                self.kind
            )),
        }
    }

    fn load_shadowsocks(self) -> Result<EgressNodeConfig, String> {
        if self.udp != Some(true) {
            return Err(
                "forwarding.nodes[].udp must be true for shadowsocks cold start".to_string(),
            );
        }
        let server = self
            .server
            .ok_or_else(|| "forwarding.nodes[].server is required for shadowsocks".to_string())?;
        let port = self
            .port
            .ok_or_else(|| "forwarding.nodes[].port is required for shadowsocks".to_string())?;
        let method = match (self.method, self.cipher) {
            (Some(method), None) | (None, Some(method)) => method,
            (Some(method), Some(cipher)) if method == cipher => method,
            (Some(_), Some(_)) => {
                return Err(
                    "forwarding.nodes[].method and forwarding.nodes[].cipher disagree".to_string(),
                );
            }
            (None, None) => {
                return Err("forwarding.nodes[].method is required for shadowsocks".to_string());
            }
        };
        let password = self
            .password
            .ok_or_else(|| "forwarding.nodes[].password is required for shadowsocks".to_string())?;
        Ok(EgressNodeConfig::Shadowsocks(ShadowsocksConfig {
            server,
            port,
            method: parse_shadowsocks_method(&method)?,
            password,
        }))
    }

    fn load_trojan(self) -> Result<EgressNodeConfig, String> {
        if self.udp != Some(true) {
            return Err("forwarding.nodes[].udp must be true for trojan cold start".to_string());
        }
        let server = self
            .server
            .ok_or_else(|| "forwarding.nodes[].server is required for trojan".to_string())?;
        let port = self
            .port
            .ok_or_else(|| "forwarding.nodes[].port is required for trojan".to_string())?;
        let password = self
            .password
            .ok_or_else(|| "forwarding.nodes[].password is required for trojan".to_string())?;
        let sni = match (self.sni, self.servername) {
            (Some(sni), None) | (None, Some(sni)) => Some(sni),
            (Some(sni), Some(servername)) if sni == servername => Some(sni),
            (Some(_), Some(_)) => {
                return Err(
                    "forwarding.nodes[].sni and forwarding.nodes[].servername disagree".to_string(),
                );
            }
            (None, None) => None,
        };
        Ok(EgressNodeConfig::Trojan(TrojanConfig {
            server,
            port,
            password,
            sni,
            skip_cert_verify: self.skip_cert_verify.unwrap_or(false),
        }))
    }

    fn load_vmess(self) -> Result<EgressNodeConfig, String> {
        if self.udp != Some(true) {
            return Err("forwarding.nodes[].udp must be true for vmess cold start".to_string());
        }
        if self.alter_id != Some(0) {
            return Err("forwarding.nodes[].alterId must be 0 for vmess cold start".to_string());
        }
        if self.cipher.as_deref() != Some("auto") {
            return Err("forwarding.nodes[].cipher must be auto for vmess cold start".to_string());
        }
        if !matches!(self.network.as_deref(), None | Some("tcp")) {
            return Err("forwarding.nodes[].network must be tcp for vmess cold start".to_string());
        }
        if self.tls == Some(true) {
            return Err("forwarding.nodes[].tls is not supported for vmess cold start".to_string());
        }
        let server = self
            .server
            .ok_or_else(|| "forwarding.nodes[].server is required for vmess".to_string())?;
        let port = self
            .port
            .ok_or_else(|| "forwarding.nodes[].port is required for vmess".to_string())?;
        let uuid = self
            .uuid
            .ok_or_else(|| "forwarding.nodes[].uuid is required for vmess".to_string())?;
        Ok(EgressNodeConfig::Vmess(VmessConfig { server, port, uuid }))
    }

    fn load_vless(self) -> Result<EgressNodeConfig, String> {
        if self.udp != Some(true) {
            return Err("forwarding.nodes[].udp must be true for vless cold start".to_string());
        }
        if self.flow.as_deref() != Some("xtls-rprx-vision") {
            return Err(
                "forwarding.nodes[].flow must be xtls-rprx-vision for vless cold start".to_string(),
            );
        }
        if !matches!(self.network.as_deref(), None | Some("tcp")) {
            return Err("forwarding.nodes[].network must be tcp for vless cold start".to_string());
        }
        if self.tls != Some(true) {
            return Err(
                "forwarding.nodes[].tls must be true for vless reality cold start".to_string(),
            );
        }
        if !matches!(self.client_fingerprint.as_deref(), None | Some("chrome")) {
            return Err(
                "forwarding.nodes[].client-fingerprint must be chrome for vless cold start".into(),
            );
        }
        let server = self
            .server
            .ok_or_else(|| "forwarding.nodes[].server is required for vless".to_string())?;
        let port = self
            .port
            .ok_or_else(|| "forwarding.nodes[].port is required for vless".to_string())?;
        let uuid = self
            .uuid
            .ok_or_else(|| "forwarding.nodes[].uuid is required for vless".to_string())?;
        let server_name = match (self.sni, self.servername) {
            (Some(sni), None) | (None, Some(sni)) => sni,
            (Some(sni), Some(servername)) if sni == servername => sni,
            (Some(_), Some(_)) => {
                return Err(
                    "forwarding.nodes[].sni and forwarding.nodes[].servername disagree".to_string(),
                );
            }
            (None, None) => {
                return Err(
                    "forwarding.nodes[].servername is required for vless reality".to_string(),
                );
            }
        };
        let reality_opts = self.reality_opts.ok_or_else(|| {
            "forwarding.nodes[].reality-opts is required for vless reality".to_string()
        })?;
        let public_key = reality_opts
            .public_key
            .ok_or_else(|| "forwarding.nodes[].reality-opts.public-key is required".to_string())?;
        let short_id = reality_opts
            .short_id
            .ok_or_else(|| "forwarding.nodes[].reality-opts.short-id is required".to_string())?;
        Ok(EgressNodeConfig::Vless(VlessConfig {
            server,
            port,
            uuid,
            server_name,
            public_key,
            short_id,
        }))
    }
}

fn non_empty(name: &str, value: String) -> Result<String, String> {
    if value.trim().is_empty() {
        Err(format!("{name} must not be empty"))
    } else {
        Ok(value)
    }
}
