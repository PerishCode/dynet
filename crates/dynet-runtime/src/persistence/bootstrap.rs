use std::net::SocketAddr;

use sqlx::{sqlite::SqliteRow, Row, Sqlite, Transaction};

use crate::{
    default_dns_upstreams, DnsRacePolicy, DnsUpstream, DnsUpstreamId, GroupId, GroupMember, NodeId,
    OutboundGroup, OutboundNode, RouteMatcher, RouteRule, RuleId, SchedulerPolicy,
};

use super::{
    dns_policy::insert_default_dns_policy, RuntimeStore, RuntimeStoreError, SCHEMA_VERSION,
};

const DEFAULT_GROUP_ID: &str = "default";

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct RuntimeBootstrap {
    pub(crate) nodes: Vec<OutboundNode>,
    pub(crate) default_group_id: GroupId,
    pub(crate) groups: Vec<OutboundGroup>,
    pub(crate) group_members: Vec<GroupMember>,
    pub(crate) route_rules: Vec<RouteRule>,
    pub(crate) dns_upstreams: Vec<DnsUpstream>,
    pub(crate) dns_policy: DnsRacePolicy,
}

impl RuntimeStore {
    pub async fn load_nodes(&self) -> Result<Vec<OutboundNode>, RuntimeStoreError> {
        let rows = sqlx::query(
            "select id, tag, enabled from runtime_nodes order by case when id = 'default' then 0 else 1 end, id",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_node).collect()
    }

    pub(crate) async fn load_or_seed_bootstrap(
        &self,
        node: OutboundNode,
    ) -> Result<RuntimeBootstrap, RuntimeStoreError> {
        if self.bootstrap_is_empty().await? {
            self.seed_bootstrap(node).await?;
        }
        self.load_bootstrap().await
    }

    async fn bootstrap_is_empty(&self) -> Result<bool, RuntimeStoreError> {
        let table_counts = [
            self.count_rows("runtime_nodes").await?,
            self.count_rows("runtime_outbound_groups").await?,
            self.count_rows("runtime_group_members").await?,
            self.count_rows("runtime_dns_upstreams").await?,
            self.count_rows("runtime_route_rules").await?,
        ];
        Ok(table_counts.into_iter().all(|count| count == 0))
    }

    async fn count_rows(&self, table: &str) -> Result<i64, RuntimeStoreError> {
        let query = format!("select count(*) as count from {table}");
        let row = sqlx::query(&query).fetch_one(&self.pool).await?;
        Ok(row.get::<i64, _>("count"))
    }

    async fn seed_bootstrap(&self, node: OutboundNode) -> Result<(), RuntimeStoreError> {
        let group = OutboundGroup {
            id: GroupId::new(DEFAULT_GROUP_ID),
            enabled: true,
            scheduler: SchedulerPolicy::SingleFirstEnabled,
        };
        let member = GroupMember {
            group_id: group.id.clone(),
            node_id: node.id.clone(),
            enabled: true,
            priority: 0,
        };
        let mut transaction = self.pool.begin().await?;
        insert_node(&mut transaction, &node).await?;
        insert_group(&mut transaction, &group).await?;
        insert_group_member(&mut transaction, &member).await?;
        for upstream in default_dns_upstreams() {
            insert_dns_upstream(&mut transaction, &upstream).await?;
        }
        sqlx::query(
            "insert into runtime_meta (key, value)
             values ('default_group_id', ?1)
             on conflict(key) do update set value = excluded.value",
        )
        .bind(group.id.as_str())
        .execute(&mut *transaction)
        .await?;
        insert_default_dns_policy(&mut transaction).await?;
        transaction.commit().await?;
        Ok(())
    }

    async fn load_bootstrap(&self) -> Result<RuntimeBootstrap, RuntimeStoreError> {
        let schema_version = self.meta_value("schema_version").await?;
        if schema_version.as_deref() != Some(SCHEMA_VERSION) {
            return Err(RuntimeStoreError::InvalidBootstrap(format!(
                "runtime store schema_version must be {SCHEMA_VERSION}, got {:?}",
                schema_version
            )));
        }
        let default_group_id = self
            .meta_value("default_group_id")
            .await?
            .ok_or_else(|| RuntimeStoreError::InvalidBootstrap("missing default_group_id".into()))
            .map(GroupId::new)?;
        let nodes = self.load_nodes().await?;
        let groups = self.load_groups().await?;
        let group_members = self.load_group_members().await?;
        let route_rules = self.load_route_rules().await?;
        let dns_upstreams = self.load_dns_upstreams().await?;
        let dns_policy = self.load_dns_policy().await?;
        validate_bootstrap(
            &nodes,
            &default_group_id,
            &groups,
            &group_members,
            &route_rules,
            &dns_upstreams,
            &dns_policy,
        )?;
        Ok(RuntimeBootstrap {
            nodes,
            default_group_id,
            groups,
            group_members,
            route_rules,
            dns_upstreams,
            dns_policy,
        })
    }

    pub(super) async fn meta_value(&self, key: &str) -> Result<Option<String>, RuntimeStoreError> {
        let value = sqlx::query("select value from runtime_meta where key = ?1")
            .bind(key)
            .fetch_optional(&self.pool)
            .await?
            .map(|row| row.get::<String, _>("value"));
        Ok(value)
    }

    async fn load_groups(&self) -> Result<Vec<OutboundGroup>, RuntimeStoreError> {
        let rows =
            sqlx::query("select id, enabled, scheduler from runtime_outbound_groups order by id")
                .fetch_all(&self.pool)
                .await?;
        rows.into_iter().map(row_to_group).collect()
    }

    async fn load_group_members(&self) -> Result<Vec<GroupMember>, RuntimeStoreError> {
        let rows = sqlx::query(
            "select group_id, node_id, enabled, priority from runtime_group_members order by group_id, priority, node_id",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_group_member).collect()
    }

    async fn load_route_rules(&self) -> Result<Vec<RouteRule>, RuntimeStoreError> {
        let rows = sqlx::query(
            "select id, priority, enabled, matcher_kind, matcher_value, group_id from runtime_route_rules order by priority desc, id",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_route_rule).collect()
    }

    async fn load_dns_upstreams(&self) -> Result<Vec<DnsUpstream>, RuntimeStoreError> {
        let rows = sqlx::query(
            "select id, address, enabled, priority from runtime_dns_upstreams order by priority, id",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_dns_upstream).collect()
    }
}

fn row_to_node(row: SqliteRow) -> Result<OutboundNode, RuntimeStoreError> {
    let id = row.get::<String, _>("id");
    let tag = row.get::<String, _>("tag");
    let enabled = row.get::<i64, _>("enabled");
    if enabled != 0 && enabled != 1 {
        return Err(RuntimeStoreError::InvalidNode {
            id,
            message: format!("enabled must be 0 or 1, got {enabled}"),
        });
    }
    Ok(OutboundNode {
        id: NodeId::new(id),
        tag,
        enabled: enabled == 1,
    })
}

fn row_to_group(row: SqliteRow) -> Result<OutboundGroup, RuntimeStoreError> {
    let id = row.get::<String, _>("id");
    let enabled = bool_from_i64(row.get::<i64, _>("enabled")).ok_or_else(|| {
        RuntimeStoreError::InvalidGroup {
            id: id.clone(),
            message: "enabled must be 0 or 1".to_string(),
        }
    })?;
    let scheduler = scheduler_from_str(&row.get::<String, _>("scheduler")).ok_or_else(|| {
        RuntimeStoreError::InvalidGroup {
            id: id.clone(),
            message: "scheduler is unsupported".to_string(),
        }
    })?;
    Ok(OutboundGroup {
        id: GroupId::new(id),
        enabled,
        scheduler,
    })
}

fn row_to_group_member(row: SqliteRow) -> Result<GroupMember, RuntimeStoreError> {
    let group_id = row.get::<String, _>("group_id");
    let node_id = row.get::<String, _>("node_id");
    let enabled = bool_from_i64(row.get::<i64, _>("enabled")).ok_or_else(|| {
        RuntimeStoreError::InvalidGroupMember {
            group_id: group_id.clone(),
            node_id: node_id.clone(),
            message: "enabled must be 0 or 1".to_string(),
        }
    })?;
    let priority = u32_from_i64(row.get::<i64, _>("priority")).ok_or_else(|| {
        RuntimeStoreError::InvalidGroupMember {
            group_id: group_id.clone(),
            node_id: node_id.clone(),
            message: "priority must fit u32".to_string(),
        }
    })?;
    Ok(GroupMember {
        group_id: GroupId::new(group_id),
        node_id: NodeId::new(node_id),
        enabled,
        priority,
    })
}

fn row_to_route_rule(row: SqliteRow) -> Result<RouteRule, RuntimeStoreError> {
    let id = row.get::<String, _>("id");
    let enabled = bool_from_i64(row.get::<i64, _>("enabled")).ok_or_else(|| {
        RuntimeStoreError::InvalidRouteRule {
            id: id.clone(),
            message: "enabled must be 0 or 1".to_string(),
        }
    })?;
    let matcher_kind = row.get::<String, _>("matcher_kind");
    let matcher_value = row.get::<String, _>("matcher_value");
    let matcher = match matcher_kind.as_str() {
        "domain-exact" => RouteMatcher::DomainExact(matcher_value.to_ascii_lowercase()),
        "domain-suffix" => RouteMatcher::DomainSuffix(matcher_value.to_ascii_lowercase()),
        "ip-exact" => RouteMatcher::IpExact(matcher_value.parse().map_err(|error| {
            RuntimeStoreError::InvalidRouteRule {
                id: id.clone(),
                message: format!("matcher_value must be an IP address: {error}"),
            }
        })?),
        "ip-cidr" => RouteMatcher::IpCidr(matcher_value),
        _ => {
            return Err(RuntimeStoreError::InvalidRouteRule {
                id,
                message: format!("matcher_kind {matcher_kind:?} is unsupported"),
            });
        }
    };
    Ok(RouteRule {
        id: RuleId::new(id),
        priority: row.get::<i64, _>("priority"),
        enabled,
        matcher,
        group_id: GroupId::new(row.get::<String, _>("group_id")),
    })
}

fn row_to_dns_upstream(row: SqliteRow) -> Result<DnsUpstream, RuntimeStoreError> {
    let id = row.get::<String, _>("id");
    let enabled = bool_from_i64(row.get::<i64, _>("enabled")).ok_or_else(|| {
        RuntimeStoreError::InvalidDnsUpstream {
            id: id.clone(),
            message: "enabled must be 0 or 1".to_string(),
        }
    })?;
    let address = row
        .get::<String, _>("address")
        .parse::<SocketAddr>()
        .map_err(|error| RuntimeStoreError::InvalidDnsUpstream {
            id: id.clone(),
            message: format!("address must be a socket address: {error}"),
        })?;
    let priority = u32_from_i64(row.get::<i64, _>("priority")).ok_or_else(|| {
        RuntimeStoreError::InvalidDnsUpstream {
            id: id.clone(),
            message: "priority must fit u32".to_string(),
        }
    })?;
    Ok(DnsUpstream {
        id: DnsUpstreamId::new(id),
        address,
        enabled,
        priority,
    })
}

async fn insert_node(
    transaction: &mut Transaction<'_, Sqlite>,
    node: &OutboundNode,
) -> Result<(), RuntimeStoreError> {
    let enabled = if node.enabled { 1_i64 } else { 0_i64 };
    sqlx::query(
        "insert into runtime_nodes (id, tag, enabled, updated_at_unix_ms)
         values (?1, ?2, ?3, ?4)",
    )
    .bind(node.id.as_str())
    .bind(&node.tag)
    .bind(enabled)
    .bind(super::unix_ms_i64())
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn insert_group(
    transaction: &mut Transaction<'_, Sqlite>,
    group: &OutboundGroup,
) -> Result<(), RuntimeStoreError> {
    let enabled = if group.enabled { 1_i64 } else { 0_i64 };
    sqlx::query(
        "insert into runtime_outbound_groups (id, enabled, scheduler, updated_at_unix_ms)
         values (?1, ?2, ?3, ?4)",
    )
    .bind(group.id.as_str())
    .bind(enabled)
    .bind(group.scheduler.as_str())
    .bind(super::unix_ms_i64())
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn insert_group_member(
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
    .bind(super::unix_ms_i64())
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn insert_dns_upstream(
    transaction: &mut Transaction<'_, Sqlite>,
    upstream: &DnsUpstream,
) -> Result<(), RuntimeStoreError> {
    let enabled = if upstream.enabled { 1_i64 } else { 0_i64 };
    sqlx::query(
        "insert into runtime_dns_upstreams (
            id, address, enabled, priority, updated_at_unix_ms
         )
         values (?1, ?2, ?3, ?4, ?5)",
    )
    .bind(upstream.id.as_str())
    .bind(upstream.address.to_string())
    .bind(enabled)
    .bind(i64::from(upstream.priority))
    .bind(super::unix_ms_i64())
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

fn validate_bootstrap(
    nodes: &[OutboundNode],
    default_group_id: &GroupId,
    groups: &[OutboundGroup],
    group_members: &[GroupMember],
    route_rules: &[RouteRule],
    dns_upstreams: &[DnsUpstream],
    dns_policy: &DnsRacePolicy,
) -> Result<(), RuntimeStoreError> {
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
    Ok(())
}

fn bool_from_i64(value: i64) -> Option<bool> {
    match value {
        0 => Some(false),
        1 => Some(true),
        _ => None,
    }
}

fn u32_from_i64(value: i64) -> Option<u32> {
    u32::try_from(value).ok()
}

fn scheduler_from_str(value: &str) -> Option<SchedulerPolicy> {
    match value {
        "single-first-enabled" => Some(SchedulerPolicy::SingleFirstEnabled),
        _ => None,
    }
}
