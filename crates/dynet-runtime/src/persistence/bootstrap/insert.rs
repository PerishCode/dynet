use sqlx::{Sqlite, Transaction};

use crate::{
    DnsUpstream, DnsUpstreamTransport, ForwardGroup, ForwardNode, GroupMember, RouteMatcher,
    RouteRule,
};

use super::{row_value::u64_to_i64, RuntimeStoreError};

pub(super) async fn insert_node(
    transaction: &mut Transaction<'_, Sqlite>,
    node: &ForwardNode,
) -> Result<(), RuntimeStoreError> {
    let enabled = if node.enabled { 1_i64 } else { 0_i64 };
    let supports_ipv6 = if node.supports_ipv6 { 1_i64 } else { 0_i64 };
    sqlx::query(
        "insert into runtime_nodes (id, tag, enabled, fingerprint, supports_ipv6, updated_at_unix_ms)
         values (?1, ?2, ?3, ?4, ?5, ?6)",
    )
    .bind(node.id.as_str())
    .bind(&node.tag)
    .bind(enabled)
    .bind(&node.fingerprint)
    .bind(supports_ipv6)
    .bind(super::super::unix_ms_i64())
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

pub(super) async fn insert_group(
    transaction: &mut Transaction<'_, Sqlite>,
    group: &ForwardGroup,
) -> Result<(), RuntimeStoreError> {
    let enabled = if group.enabled { 1_i64 } else { 0_i64 };
    sqlx::query(
        "insert into runtime_forward_groups (
            id, enabled, scheduler, min_success_rate_ppm, min_samples, max_active_sessions, next, updated_at_unix_ms
         )
         values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
    )
    .bind(group.id.as_str())
    .bind(enabled)
    .bind(group.scheduler.as_str())
    .bind(i64::from(group.thresholds.min_success_rate_ppm))
    .bind(i64::try_from(group.thresholds.min_samples).unwrap_or(i64::MAX))
    .bind(group.thresholds.max_active_sessions.map(u64_to_i64))
    .bind(group.next.label())
    .bind(super::super::unix_ms_i64())
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

pub(super) async fn insert_route_rule(
    transaction: &mut Transaction<'_, Sqlite>,
    rule: &RouteRule,
) -> Result<(), RuntimeStoreError> {
    let enabled = if rule.enabled { 1_i64 } else { 0_i64 };
    let (matcher_kind, matcher_value) = match &rule.matcher {
        RouteMatcher::DomainExact(value) => ("domain-exact", value.clone()),
        RouteMatcher::DomainSuffix(value) => ("domain-suffix", value.clone()),
        RouteMatcher::IpExact(value) => ("ip-exact", value.to_string()),
        RouteMatcher::IpCidr(value) => ("ip-cidr", value.clone()),
    };
    sqlx::query(
        "insert into runtime_route_rules (
            id, priority, enabled, matcher_kind, matcher_value, group_id,
            ipv6_policy, updated_at_unix_ms
         )
         values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
    )
    .bind(rule.id.as_str())
    .bind(rule.priority)
    .bind(enabled)
    .bind(matcher_kind)
    .bind(matcher_value)
    .bind(rule.group_id.as_str())
    .bind(rule.ipv6.as_str())
    .bind(super::super::unix_ms_i64())
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

pub(super) async fn insert_group_member(
    transaction: &mut Transaction<'_, Sqlite>,
    member: &GroupMember,
) -> Result<(), RuntimeStoreError> {
    let enabled = if member.enabled { 1_i64 } else { 0_i64 };
    sqlx::query(
        "insert into runtime_group_members (
            group_id, node_id, enabled, priority, updated_at_unix_ms
         )
         values (?1, ?2, ?3, ?4, ?5)",
    )
    .bind(member.group_id.as_str())
    .bind(member.node_id.as_str())
    .bind(enabled)
    .bind(i64::from(member.priority))
    .bind(super::super::unix_ms_i64())
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

pub(super) async fn insert_dns_upstream(
    transaction: &mut Transaction<'_, Sqlite>,
    upstream: &DnsUpstream,
) -> Result<(), RuntimeStoreError> {
    let enabled = if upstream.enabled { 1_i64 } else { 0_i64 };
    let (transport, host, path) = match &upstream.transport {
        DnsUpstreamTransport::Udp => ("udp", None, None),
        DnsUpstreamTransport::Https(endpoint) => (
            "https",
            Some(endpoint.host.as_str()),
            Some(endpoint.path.as_str()),
        ),
    };
    sqlx::query(
        "insert into runtime_dns_upstreams (
            id, address, transport, host, path, enabled, priority, updated_at_unix_ms
         )
         values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
    )
    .bind(upstream.id.as_str())
    .bind(upstream.address.to_string())
    .bind(transport)
    .bind(host)
    .bind(path)
    .bind(enabled)
    .bind(i64::from(upstream.priority))
    .bind(super::super::unix_ms_i64())
    .execute(&mut **transaction)
    .await?;
    Ok(())
}
