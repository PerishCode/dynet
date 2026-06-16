use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

use dynet_ingress::{OutboundConfig, ShadowsocksConfig, TrojanConfig, VlessConfig, VmessConfig};
use dynet_runtime::{
    GroupId, GroupMember, NodeId, OutboundGroup, OutboundNode, OutboundRef, RouteMatcher,
    RouteRule, RuleId, RuntimeSeed, SchedulerPolicy,
};
use serde::Deserialize;

use crate::{method_config::parse_shadowsocks_method, OutboundGraphConfig};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FileOutboundConfig {
    default_group: Option<String>,
    nodes: Option<Vec<FileOutboundNodeConfig>>,
    groups: Option<Vec<FileOutboundGroupConfig>>,
    rules: Option<Vec<FileRouteRuleConfig>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileOutboundGroupConfig {
    id: String,
    enabled: Option<bool>,
    mode: String,
    profile: Option<String>,
    outbound: Option<String>,
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
struct FileOutboundNodeConfig {
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

impl FileOutboundConfig {
    pub(crate) fn load(self) -> Result<OutboundGraphConfig, String> {
        let nodes = self
            .nodes
            .ok_or_else(|| "outbound.nodes is required".to_string())?;
        let groups = self
            .groups
            .ok_or_else(|| "outbound.groups is required".to_string())?;
        if nodes.is_empty() {
            return Err("outbound.nodes must not be empty".to_string());
        }
        if groups.is_empty() {
            return Err("outbound.groups must not be empty".to_string());
        }
        build_graph(self.default_group, nodes, groups, self.rules)
    }
}

fn build_graph(
    default_group: Option<String>,
    nodes: Vec<FileOutboundNodeConfig>,
    groups: Vec<FileOutboundGroupConfig>,
    rules: Option<Vec<FileRouteRuleConfig>>,
) -> Result<OutboundGraphConfig, String> {
    let default_group = default_group.unwrap_or_else(|| groups[0].id.clone());
    let (runtime_nodes, node_outbounds) = load_nodes(nodes)?;
    let (runtime_groups, group_members) = load_groups(groups)?;
    let route_rules = rules
        .unwrap_or_default()
        .into_iter()
        .map(FileRouteRuleConfig::load)
        .collect::<Result<Vec<_>, _>>()?;
    let execution_outbound = select_execution_outbound(
        &default_group,
        &runtime_groups,
        &group_members,
        &node_outbounds,
    )?;
    let defaults = RuntimeSeed::single_node("direct");
    Ok(OutboundGraphConfig {
        seed: RuntimeSeed {
            nodes: runtime_nodes,
            default_group_id: GroupId::new(default_group),
            groups: runtime_groups,
            group_members,
            route_rules,
            dns_upstreams: defaults.dns_upstreams,
            dns_policy: defaults.dns_policy,
        },
        execution_outbound,
    })
}

fn load_nodes(
    nodes: Vec<FileOutboundNodeConfig>,
) -> Result<(Vec<OutboundNode>, BTreeMap<String, OutboundConfig>), String> {
    let mut runtime_nodes = Vec::with_capacity(nodes.len());
    let mut node_outbounds = BTreeMap::new();
    for node in nodes {
        let (runtime_node, outbound) = node.load_node_outbound()?;
        let id = runtime_node.id.as_str().to_string();
        if node_outbounds.insert(id.clone(), outbound).is_some() {
            return Err(format!("outbound node id {id:?} is duplicated"));
        }
        runtime_nodes.push(runtime_node);
    }
    Ok((runtime_nodes, node_outbounds))
}

fn load_groups(
    groups: Vec<FileOutboundGroupConfig>,
) -> Result<(Vec<OutboundGroup>, Vec<GroupMember>), String> {
    let mut runtime_groups = Vec::with_capacity(groups.len());
    let mut group_members = Vec::new();
    let mut group_ids = BTreeSet::new();
    for group in groups {
        let id = non_empty("outbound.groups[].id", group.id.clone())?;
        validate_group_header(&id, &group, &mut group_ids)?;
        let outbound = group
            .outbound
            .map_or_else(OutboundRef::direct_audit_outlet, OutboundRef::named);
        push_group_members(&id, group.members, &mut group_members)?;
        runtime_groups.push(OutboundGroup {
            id: GroupId::new(id),
            enabled: group.enabled.unwrap_or(true),
            scheduler: SchedulerPolicy::SingleFirstEnabled,
            outbound,
        });
    }
    Ok((runtime_groups, group_members))
}

fn validate_group_header(
    id: &str,
    group: &FileOutboundGroupConfig,
    group_ids: &mut BTreeSet<String>,
) -> Result<(), String> {
    if id == OutboundRef::DIRECT_AUDIT_OUTLET {
        return Err("outbound group id 'direct' is reserved".to_string());
    }
    if !group_ids.insert(id.to_string()) {
        return Err(format!("outbound group id {id:?} is duplicated"));
    }
    if group.mode != "smart" {
        return Err(format!(
            "outbound group {id:?} mode must be smart, got {:?}",
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
            node_id: NodeId::new(non_empty("outbound.groups[].members[]", member)?),
            enabled: true,
            priority: u32::try_from(priority)
                .map_err(|_| format!("outbound group {group_id:?} has too many members"))?,
        });
    }
    Ok(())
}

impl FileRouteRuleConfig {
    fn load(self) -> Result<RouteRule, String> {
        let id = non_empty("outbound.rules[].id", self.id)?;
        let matcher = match self.matcher.as_str() {
            "domain-exact" => RouteMatcher::DomainExact(self.value.to_ascii_lowercase()),
            "domain-suffix" => RouteMatcher::DomainSuffix(self.value.to_ascii_lowercase()),
            "ip-exact" => parse_ip_exact_rule(&id, &self.value)?,
            "ip-cidr" => RouteMatcher::IpCidr(self.value),
            _ => {
                return Err(format!(
                    "outbound rule {id:?} match {:?} is unsupported",
                    self.matcher
                ));
            }
        };
        Ok(RouteRule {
            id: RuleId::new(id),
            priority: self.priority,
            enabled: self.enabled.unwrap_or(true),
            matcher,
            group_id: GroupId::new(non_empty("outbound.rules[].group", self.group)?),
        })
    }
}

fn parse_ip_exact_rule(id: &str, value: &str) -> Result<RouteMatcher, String> {
    Ok(RouteMatcher::IpExact(value.parse::<IpAddr>().map_err(
        |error| format!("outbound rule {id:?} value must be an IP: {error}"),
    )?))
}

impl FileOutboundNodeConfig {
    fn load_node_outbound(self) -> Result<(OutboundNode, OutboundConfig), String> {
        let id = non_empty("outbound.nodes[].id", self.id.clone())?;
        let enabled = self.enabled.unwrap_or(true);
        let tag = self.kind.clone();
        let outbound = self.load_outbound()?;
        Ok((
            OutboundNode {
                id: NodeId::new(id),
                tag,
                enabled,
            },
            outbound,
        ))
    }

    fn load_outbound(self) -> Result<OutboundConfig, String> {
        match self.kind.as_str() {
            "direct" => Ok(OutboundConfig::Direct),
            "shadowsocks" | "ss" => self.load_shadowsocks(),
            "trojan" => self.load_trojan(),
            "vless" => self.load_vless(),
            "vmess" => self.load_vmess(),
            _ => Err(format!("outbound.type unsupported: {}", self.kind)),
        }
    }

    fn load_shadowsocks(self) -> Result<OutboundConfig, String> {
        if self.udp != Some(true) {
            return Err("outbound.udp must be true for shadowsocks cold start".to_string());
        }
        let server = self
            .server
            .ok_or_else(|| "outbound.server is required for shadowsocks".to_string())?;
        let port = self
            .port
            .ok_or_else(|| "outbound.port is required for shadowsocks".to_string())?;
        let method = match (self.method, self.cipher) {
            (Some(method), None) | (None, Some(method)) => method,
            (Some(method), Some(cipher)) if method == cipher => method,
            (Some(_), Some(_)) => {
                return Err("outbound.method and outbound.cipher disagree".to_string());
            }
            (None, None) => {
                return Err("outbound.method is required for shadowsocks".to_string());
            }
        };
        let password = self
            .password
            .ok_or_else(|| "outbound.password is required for shadowsocks".to_string())?;
        Ok(OutboundConfig::Shadowsocks(ShadowsocksConfig {
            server,
            port,
            method: parse_shadowsocks_method(&method)?,
            password,
        }))
    }

    fn load_trojan(self) -> Result<OutboundConfig, String> {
        if self.udp != Some(true) {
            return Err("outbound.udp must be true for trojan cold start".to_string());
        }
        let server = self
            .server
            .ok_or_else(|| "outbound.server is required for trojan".to_string())?;
        let port = self
            .port
            .ok_or_else(|| "outbound.port is required for trojan".to_string())?;
        let password = self
            .password
            .ok_or_else(|| "outbound.password is required for trojan".to_string())?;
        let sni = match (self.sni, self.servername) {
            (Some(sni), None) | (None, Some(sni)) => Some(sni),
            (Some(sni), Some(servername)) if sni == servername => Some(sni),
            (Some(_), Some(_)) => {
                return Err("outbound.sni and outbound.servername disagree".to_string());
            }
            (None, None) => None,
        };
        Ok(OutboundConfig::Trojan(TrojanConfig {
            server,
            port,
            password,
            sni,
            skip_cert_verify: self.skip_cert_verify.unwrap_or(false),
        }))
    }

    fn load_vmess(self) -> Result<OutboundConfig, String> {
        if self.udp != Some(true) {
            return Err("outbound.udp must be true for vmess cold start".to_string());
        }
        if self.alter_id != Some(0) {
            return Err("outbound.alterId must be 0 for vmess cold start".to_string());
        }
        if self.cipher.as_deref() != Some("auto") {
            return Err("outbound.cipher must be auto for vmess cold start".to_string());
        }
        if !matches!(self.network.as_deref(), None | Some("tcp")) {
            return Err("outbound.network must be tcp for vmess cold start".to_string());
        }
        if self.tls == Some(true) {
            return Err("outbound.tls is not supported for vmess cold start".to_string());
        }
        let server = self
            .server
            .ok_or_else(|| "outbound.server is required for vmess".to_string())?;
        let port = self
            .port
            .ok_or_else(|| "outbound.port is required for vmess".to_string())?;
        let uuid = self
            .uuid
            .ok_or_else(|| "outbound.uuid is required for vmess".to_string())?;
        Ok(OutboundConfig::Vmess(VmessConfig { server, port, uuid }))
    }

    fn load_vless(self) -> Result<OutboundConfig, String> {
        if self.udp != Some(true) {
            return Err("outbound.udp must be true for vless cold start".to_string());
        }
        if self.flow.as_deref() != Some("xtls-rprx-vision") {
            return Err("outbound.flow must be xtls-rprx-vision for vless cold start".to_string());
        }
        if !matches!(self.network.as_deref(), None | Some("tcp")) {
            return Err("outbound.network must be tcp for vless cold start".to_string());
        }
        if self.tls != Some(true) {
            return Err("outbound.tls must be true for vless reality cold start".to_string());
        }
        if !matches!(self.client_fingerprint.as_deref(), None | Some("chrome")) {
            return Err("outbound.client-fingerprint must be chrome for vless cold start".into());
        }
        let server = self
            .server
            .ok_or_else(|| "outbound.server is required for vless".to_string())?;
        let port = self
            .port
            .ok_or_else(|| "outbound.port is required for vless".to_string())?;
        let uuid = self
            .uuid
            .ok_or_else(|| "outbound.uuid is required for vless".to_string())?;
        let server_name = match (self.sni, self.servername) {
            (Some(sni), None) | (None, Some(sni)) => sni,
            (Some(sni), Some(servername)) if sni == servername => sni,
            (Some(_), Some(_)) => {
                return Err("outbound.sni and outbound.servername disagree".to_string());
            }
            (None, None) => {
                return Err("outbound.servername is required for vless reality".to_string());
            }
        };
        let reality_opts = self
            .reality_opts
            .ok_or_else(|| "outbound.reality-opts is required for vless reality".to_string())?;
        let public_key = reality_opts
            .public_key
            .ok_or_else(|| "outbound.reality-opts.public-key is required".to_string())?;
        let short_id = reality_opts
            .short_id
            .ok_or_else(|| "outbound.reality-opts.short-id is required".to_string())?;
        Ok(OutboundConfig::Vless(VlessConfig {
            server,
            port,
            uuid,
            server_name,
            public_key,
            short_id,
        }))
    }
}

fn select_execution_outbound(
    default_group: &str,
    groups: &[OutboundGroup],
    group_members: &[GroupMember],
    node_outbounds: &BTreeMap<String, OutboundConfig>,
) -> Result<OutboundConfig, String> {
    let group = groups
        .iter()
        .find(|group| group.id.as_str() == default_group)
        .ok_or_else(|| format!("outbound.default_group {default_group:?} is missing"))?;
    if !group.enabled {
        return Err(format!(
            "outbound.default_group {default_group:?} is disabled"
        ));
    }
    let member = group_members
        .iter()
        .filter(|member| member.group_id == group.id)
        .min_by(|left, right| {
            left.priority
                .cmp(&right.priority)
                .then_with(|| left.node_id.cmp(&right.node_id))
        })
        .ok_or_else(|| format!("outbound.default_group {default_group:?} has no members"))?;
    node_outbounds
        .get(member.node_id.as_str())
        .cloned()
        .ok_or_else(|| {
            format!(
                "outbound.default_group {default_group:?} member {:?} is missing",
                member.node_id.as_str()
            )
        })
}

fn validate_thresholds(id: &str, thresholds: Option<&FileGroupThresholds>) -> Result<(), String> {
    let Some(thresholds) = thresholds else {
        return Ok(());
    };
    if thresholds.window_secs == Some(0) {
        return Err(format!(
            "outbound group {id:?} thresholds.window_secs must be positive"
        ));
    }
    for (name, value) in [
        ("min_confidence", thresholds.min_confidence),
        ("max_explore_ratio", thresholds.max_explore_ratio),
    ] {
        if let Some(value) = value {
            if !(0.0..=1.0).contains(&value) {
                return Err(format!(
                    "outbound group {id:?} thresholds.{name} must be between 0 and 1"
                ));
            }
        }
    }
    let _ = thresholds.failure_cooldown_secs;
    Ok(())
}

fn non_empty(name: &str, value: String) -> Result<String, String> {
    if value.trim().is_empty() {
        Err(format!("{name} must not be empty"))
    } else {
        Ok(value)
    }
}
