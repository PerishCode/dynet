use std::net::SocketAddr;

use sqlx::{sqlite::SqliteRow, Row, Sqlite, Transaction};

use crate::{
    DnsHttpsEndpoint, DnsRacePolicy, DnsUpstream, DnsUpstreamId, DnsUpstreamTransport,
    ForwardGroup, ForwardNode, GroupId, GroupMember, NextRef, NodeId, RouteMatcher, RouteRule,
    RuleId, RuntimeSeed, SchedulerPolicy,
};

use super::{
    dns_policy::insert_dns_policy,
    validation::{validate_bootstrap, validate_seed},
    RuntimeStore, RuntimeStoreError, SCHEMA_VERSION,
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct RuntimeBootstrap {
    pub(crate) nodes: Vec<ForwardNode>,
    pub(crate) default_group_id: GroupId,
    pub(crate) groups: Vec<ForwardGroup>,
    pub(crate) group_members: Vec<GroupMember>,
    pub(crate) route_rules: Vec<RouteRule>,
    pub(crate) dns_upstreams: Vec<DnsUpstream>,
    pub(crate) dns_policy: DnsRacePolicy,
}

impl RuntimeStore {
    pub async fn load_nodes(&self) -> Result<Vec<ForwardNode>, RuntimeStoreError> {
        let rows = sqlx::query(
            "select id, tag, enabled from runtime_nodes order by case when id = 'default-node' then 0 else 1 end, id",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_node).collect()
    }

    pub(crate) async fn load_or_seed_bootstrap(
        &self,
        seed: RuntimeSeed,
    ) -> Result<RuntimeBootstrap, RuntimeStoreError> {
        if self.bootstrap_is_empty().await? {
            validate_seed(&seed)?;
            self.seed_bootstrap(seed).await?;
        }
        self.load_bootstrap().await
    }

    async fn bootstrap_is_empty(&self) -> Result<bool, RuntimeStoreError> {
        let table_counts = [
            self.count_rows("runtime_nodes").await?,
            self.count_rows("runtime_forward_groups").await?,
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

    async fn seed_bootstrap(&self, seed: RuntimeSeed) -> Result<(), RuntimeStoreError> {
        let mut transaction = self.pool.begin().await?;
        for node in &seed.nodes {
            insert_node(&mut transaction, node).await?;
        }
        for group in &seed.groups {
            insert_group(&mut transaction, group).await?;
        }
        for member in &seed.group_members {
            insert_group_member(&mut transaction, member).await?;
        }
        for rule in &seed.route_rules {
            insert_route_rule(&mut transaction, rule).await?;
        }
        for upstream in &seed.dns_upstreams {
            insert_dns_upstream(&mut transaction, upstream).await?;
        }
        sqlx::query(
            "insert into runtime_meta (key, value)
             values ('default_group_id', ?1)
             on conflict(key) do update set value = excluded.value",
        )
        .bind(seed.default_group_id.as_str())
        .execute(&mut *transaction)
        .await?;
        insert_dns_policy(&mut transaction, seed.dns_policy).await?;
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

    async fn load_groups(&self) -> Result<Vec<ForwardGroup>, RuntimeStoreError> {
        let rows = sqlx::query(
            "select id, enabled, scheduler, next from runtime_forward_groups order by id",
        )
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
            "select id, address, transport, host, path, enabled, priority
             from runtime_dns_upstreams
             order by priority, id",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_dns_upstream).collect()
    }
}

fn row_to_node(row: SqliteRow) -> Result<ForwardNode, RuntimeStoreError> {
    let id = row.get::<String, _>("id");
    let tag = row.get::<String, _>("tag");
    let enabled = row.get::<i64, _>("enabled");
    if enabled != 0 && enabled != 1 {
        return Err(RuntimeStoreError::InvalidNode {
            id,
            message: format!("enabled must be 0 or 1, got {enabled}"),
        });
    }
    Ok(ForwardNode {
        id: NodeId::new(id),
        tag,
        enabled: enabled == 1,
    })
}

fn row_to_group(row: SqliteRow) -> Result<ForwardGroup, RuntimeStoreError> {
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
    Ok(ForwardGroup {
        id: GroupId::new(id),
        enabled,
        scheduler,
        next: NextRef::named(row.get::<String, _>("next")),
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
    let transport = dns_transport_from_row(&id, &row)?;
    Ok(DnsUpstream {
        id: DnsUpstreamId::new(id),
        address,
        transport,
        enabled,
        priority,
    })
}

fn dns_transport_from_row(
    id: &str,
    row: &SqliteRow,
) -> Result<DnsUpstreamTransport, RuntimeStoreError> {
    match row.get::<String, _>("transport").as_str() {
        "udp" => Ok(DnsUpstreamTransport::Udp),
        "https" => {
            let host = row.get::<Option<String>, _>("host").ok_or_else(|| {
                RuntimeStoreError::InvalidDnsUpstream {
                    id: id.to_string(),
                    message: "host is required for HTTPS DNS upstream".to_string(),
                }
            })?;
            let path = row
                .get::<Option<String>, _>("path")
                .unwrap_or_else(|| "/dns-query".to_string());
            Ok(DnsUpstreamTransport::Https(DnsHttpsEndpoint { host, path }))
        }
        other => Err(RuntimeStoreError::InvalidDnsUpstream {
            id: id.to_string(),
            message: format!("transport {other:?} is unsupported"),
        }),
    }
}

async fn insert_node(
    transaction: &mut Transaction<'_, Sqlite>,
    node: &ForwardNode,
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
    group: &ForwardGroup,
) -> Result<(), RuntimeStoreError> {
    let enabled = if group.enabled { 1_i64 } else { 0_i64 };
    sqlx::query(
        "insert into runtime_forward_groups (
            id, enabled, scheduler, next, updated_at_unix_ms
         )
         values (?1, ?2, ?3, ?4, ?5)",
    )
    .bind(group.id.as_str())
    .bind(enabled)
    .bind(group.scheduler.as_str())
    .bind(group.next.label())
    .bind(super::unix_ms_i64())
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn insert_route_rule(
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
            updated_at_unix_ms
         )
         values (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    )
    .bind(rule.id.as_str())
    .bind(rule.priority)
    .bind(enabled)
    .bind(matcher_kind)
    .bind(matcher_value)
    .bind(rule.group_id.as_str())
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
    .bind(super::unix_ms_i64())
    .execute(&mut **transaction)
    .await?;
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
