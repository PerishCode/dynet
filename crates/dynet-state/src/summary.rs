use std::collections::BTreeMap;

use dynet_ingress::EgressNodeConfig;

use crate::Config;

pub fn redacted_summary_lines(config: &Config) -> Vec<String> {
    let seed = &config.forwarding.seed;
    let mut lines = vec![
        "dynet config summary:".to_string(),
        format!("control.bind={}", config.control.bind),
        format!(
            "ingress.bind dns={} tcp={} udp={} socks5={}",
            config.ingress.dns.bind,
            config.ingress.tcp.bind,
            config.ingress.udp.bind,
            config.ingress.socks5.bind
        ),
        format!(
            "capture.tun enabled={} interface={} tcp_idle_ms={} udp_idle_ms={} udp_response_ms={}",
            config.capture.tun.enabled,
            config.capture.tun.interface,
            config.capture.tun.tcp_idle_timeout.as_millis(),
            config.capture.tun.udp_idle_timeout.as_millis(),
            config.capture.tun.udp_response_timeout.as_millis()
        ),
        format!(
            "forwarding.default_group={}",
            seed.default_group_id.as_str()
        ),
    ];

    let mut node_counts = BTreeMap::new();
    for node in config.forwarding.execution_nodes.values() {
        *node_counts
            .entry(node_protocol_label(node))
            .or_insert(0_usize) += 1;
    }
    lines.push(format!(
        "nodes.total={} {}",
        config.forwarding.execution_nodes.len(),
        format_counts(&node_counts)
    ));

    lines.push(format!("groups.total={}", seed.groups.len()));
    let mut member_counts = BTreeMap::new();
    for member in &seed.group_members {
        *member_counts
            .entry(member.group_id.as_str().to_string())
            .or_insert(0_usize) += 1;
    }
    for group in &seed.groups {
        let members = member_counts
            .get(group.id.as_str())
            .copied()
            .unwrap_or_default();
        lines.push(format!(
            "group id={} enabled={} members={} next={}",
            group.id.as_str(),
            group.enabled,
            members,
            group.next.label()
        ));
    }

    let mut route_counts = BTreeMap::new();
    for rule in &seed.route_rules {
        *route_counts
            .entry(rule.group_id.as_str().to_string())
            .or_insert(0_usize) += 1;
    }
    lines.push(format!(
        "rules.total={} {}",
        seed.route_rules.len(),
        format_counts(&route_counts)
    ));
    lines.push(format!("dns_upstreams.total={}", seed.dns_upstreams.len()));
    lines
}

fn node_protocol_label(config: &EgressNodeConfig) -> String {
    match config {
        EgressNodeConfig::Direct => "direct".to_string(),
        EgressNodeConfig::Shadowsocks(config) => format!("ss:{}", config.method.as_str()),
        EgressNodeConfig::Trojan(_) => "trojan".to_string(),
        EgressNodeConfig::Vless(_) => "vless".to_string(),
        EgressNodeConfig::Vmess(_) => "vmess".to_string(),
    }
}

fn format_counts(counts: &BTreeMap<String, usize>) -> String {
    counts
        .iter()
        .map(|(label, count)| format!("{label}={count}"))
        .collect::<Vec<_>>()
        .join(" ")
}
