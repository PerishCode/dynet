use std::collections::BTreeSet;

use crate::{
    DnsRacePolicy, DnsUpstream, GroupId, GroupMember, OutboundGroup, OutboundNode, OutboundRef,
    RouteRule, RuntimeSeed,
};

use super::RuntimeStoreError;

pub(super) fn validate_seed(seed: &RuntimeSeed) -> Result<(), RuntimeStoreError> {
    validate_bootstrap(
        &seed.nodes,
        &seed.default_group_id,
        &seed.groups,
        &seed.group_members,
        &seed.route_rules,
        &seed.dns_upstreams,
        &seed.dns_policy,
    )
}

pub(super) fn validate_bootstrap(
    nodes: &[OutboundNode],
    default_group_id: &GroupId,
    groups: &[OutboundGroup],
    group_members: &[GroupMember],
    route_rules: &[RouteRule],
    dns_upstreams: &[DnsUpstream],
    dns_policy: &DnsRacePolicy,
) -> Result<(), RuntimeStoreError> {
    validate_unique_ids(nodes, groups, route_rules, dns_upstreams)?;
    if nodes.is_empty() {
        return Err(RuntimeStoreError::InvalidBootstrap(
            "at least one node is required".to_string(),
        ));
    }
    let group = groups
        .iter()
        .find(|group| &group.id == default_group_id)
        .ok_or_else(|| {
            RuntimeStoreError::InvalidBootstrap(format!(
                "default group {default_group_id} is missing"
            ))
        })?;
    if !group.enabled {
        return Err(RuntimeStoreError::InvalidBootstrap(format!(
            "default group {default_group_id} is disabled"
        )));
    }
    if !group_members
        .iter()
        .any(|member| member.group_id == *default_group_id && member.enabled)
    {
        return Err(RuntimeStoreError::InvalidBootstrap(format!(
            "default group {default_group_id} has no enabled member"
        )));
    }
    validate_references(nodes, groups, group_members, route_rules)?;
    if !dns_upstreams.iter().any(|upstream| upstream.enabled) {
        return Err(RuntimeStoreError::InvalidBootstrap(
            "at least one enabled DNS upstream is required".to_string(),
        ));
    }
    if dns_policy.timeout.is_zero() {
        return Err(RuntimeStoreError::InvalidBootstrap(
            "dns_race_timeout_ms must be positive".to_string(),
        ));
    }
    Ok(())
}

fn validate_references(
    nodes: &[OutboundNode],
    groups: &[OutboundGroup],
    group_members: &[GroupMember],
    route_rules: &[RouteRule],
) -> Result<(), RuntimeStoreError> {
    for member in group_members {
        if !groups.iter().any(|group| group.id == member.group_id) {
            return Err(RuntimeStoreError::InvalidBootstrap(format!(
                "group member references missing group {}",
                member.group_id
            )));
        }
        if !nodes.iter().any(|node| node.id == member.node_id) {
            return Err(RuntimeStoreError::InvalidBootstrap(format!(
                "group member references missing node {}",
                member.node_id
            )));
        }
    }
    for rule in route_rules {
        if !groups.iter().any(|group| group.id == rule.group_id) {
            return Err(RuntimeStoreError::InvalidBootstrap(format!(
                "route rule {} references missing group {}",
                rule.id, rule.group_id
            )));
        }
    }
    validate_group_outbounds(nodes, groups)
}

fn validate_unique_ids(
    nodes: &[OutboundNode],
    groups: &[OutboundGroup],
    route_rules: &[RouteRule],
    dns_upstreams: &[DnsUpstream],
) -> Result<(), RuntimeStoreError> {
    let mut outbound_names = BTreeSet::new();
    for node in nodes {
        let id = node.id.as_str();
        if id == OutboundRef::DIRECT_AUDIT_OUTLET {
            return Err(RuntimeStoreError::InvalidBootstrap(
                "node id 'direct' is reserved".to_string(),
            ));
        }
        if !outbound_names.insert(id.to_string()) {
            return Err(RuntimeStoreError::InvalidBootstrap(format!(
                "outbound name {id:?} is duplicated"
            )));
        }
    }
    for group in groups {
        let id = group.id.as_str();
        if id == OutboundRef::DIRECT_AUDIT_OUTLET {
            return Err(RuntimeStoreError::InvalidBootstrap(
                "group id 'direct' is reserved".to_string(),
            ));
        }
        if !outbound_names.insert(id.to_string()) {
            return Err(RuntimeStoreError::InvalidBootstrap(format!(
                "outbound name {id:?} is duplicated"
            )));
        }
    }
    validate_unique_rule_ids(route_rules)?;
    validate_unique_dns_ids(dns_upstreams)
}

fn validate_unique_rule_ids(route_rules: &[RouteRule]) -> Result<(), RuntimeStoreError> {
    let mut route_ids = BTreeSet::new();
    for rule in route_rules {
        if !route_ids.insert(rule.id.as_str().to_string()) {
            return Err(RuntimeStoreError::InvalidBootstrap(format!(
                "route rule id {:?} is duplicated",
                rule.id.as_str()
            )));
        }
    }
    Ok(())
}

fn validate_unique_dns_ids(dns_upstreams: &[DnsUpstream]) -> Result<(), RuntimeStoreError> {
    let mut dns_ids = BTreeSet::new();
    for upstream in dns_upstreams {
        if !dns_ids.insert(upstream.id.as_str().to_string()) {
            return Err(RuntimeStoreError::InvalidBootstrap(format!(
                "DNS upstream id {:?} is duplicated",
                upstream.id.as_str()
            )));
        }
    }
    Ok(())
}

fn validate_group_outbounds(
    nodes: &[OutboundNode],
    groups: &[OutboundGroup],
) -> Result<(), RuntimeStoreError> {
    for group in groups {
        validate_group_outbound_reference(nodes, groups, group)?;
    }
    for group in groups {
        validate_group_outbound_cycle(nodes, groups, group.id.as_str())?;
    }
    Ok(())
}

fn validate_group_outbound_reference(
    nodes: &[OutboundNode],
    groups: &[OutboundGroup],
    group: &OutboundGroup,
) -> Result<(), RuntimeStoreError> {
    let outbound = group.outbound.label();
    if outbound == OutboundRef::DIRECT_AUDIT_OUTLET {
        return Ok(());
    }
    let references_node = nodes.iter().any(|node| node.id.as_str() == outbound);
    let references_group = groups
        .iter()
        .any(|candidate| candidate.id.as_str() == outbound);
    if references_node || references_group {
        Ok(())
    } else {
        Err(RuntimeStoreError::InvalidBootstrap(format!(
            "group {} outbound {outbound:?} references no declared outbound",
            group.id
        )))
    }
}

fn validate_group_outbound_cycle(
    nodes: &[OutboundNode],
    groups: &[OutboundGroup],
    start: &str,
) -> Result<(), RuntimeStoreError> {
    let mut seen = BTreeSet::new();
    let mut current = start;
    loop {
        if !seen.insert(current.to_string()) {
            return Err(RuntimeStoreError::InvalidBootstrap(format!(
                "group outbound cycle includes {current:?}"
            )));
        }
        let Some(group) = groups
            .iter()
            .find(|candidate| candidate.id.as_str() == current)
        else {
            break;
        };
        let outbound = group.outbound.label();
        if outbound == OutboundRef::DIRECT_AUDIT_OUTLET {
            break;
        }
        if nodes.iter().any(|node| node.id.as_str() == outbound) {
            break;
        }
        current = outbound;
    }
    Ok(())
}
