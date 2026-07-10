use std::net::SocketAddr;

use sqlx::{sqlite::SqliteRow, Row};

use crate::{
    DnsHttpsEndpoint, DnsRacePolicy, DnsUpstream, DnsUpstreamId, DnsUpstreamTransport,
    ForwardGroup, ForwardNode, GroupId, GroupMember, GroupThresholds, Ipv6RulePolicy, NextRef,
    NodeId, RouteMatcher, RouteRule, RuleId, RuntimeSeed,
};

use super::{
    dns_policy::insert_dns_policy,
    validation::{validate_bootstrap, validate_seed},
    RuntimeStore, RuntimeStoreError, SCHEMA_VERSION,
};

mod insert;
mod row_value;
use insert::*;
use row_value::{bool_from_i64, scheduler_from_str, u32_from_i64};

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct RuntimeBootstrap {
    pub(crate) ipv6_enabled: bool,
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
            "select id, tag, enabled, fingerprint, supports_ipv6 from runtime_nodes order by case when id = 'default-node' then 0 else 1 end, id",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_node).collect()
    }

    pub(crate) async fn replace_and_load_bootstrap(
        &self,
        seed: RuntimeSeed,
    ) -> Result<RuntimeBootstrap, RuntimeStoreError> {
        self.replace_bootstrap(seed).await?;
        self.load_bootstrap().await
    }

    pub async fn replace_bootstrap(&self, seed: RuntimeSeed) -> Result<(), RuntimeStoreError> {
        validate_seed(&seed)?;
        let mut transaction = self.pool.begin().await?;
        for table in [
            "runtime_group_members",
            "runtime_route_rules",
            "runtime_forward_groups",
            "runtime_nodes",
            "runtime_dns_upstreams",
        ] {
            sqlx::query(&format!("delete from {table}"))
                .execute(&mut *transaction)
                .await?;
        }
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
        sqlx::query(
            "insert into runtime_meta (key, value)
             values ('ipv6_enabled', ?1)
             on conflict(key) do update set value = excluded.value",
        )
        .bind(if seed.ipv6_enabled { "1" } else { "0" })
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
        let ipv6_enabled = match self.meta_value("ipv6_enabled").await?.as_deref() {
            Some("1") => true,
            Some("0") | None => false,
            Some(value) => {
                return Err(RuntimeStoreError::InvalidBootstrap(format!(
                    "ipv6_enabled must be 0 or 1, got {value:?}"
                )))
            }
        };
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
            ipv6_enabled,
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
            "select id, enabled, scheduler, min_success_rate_ppm, min_samples, max_active_sessions, next
             from runtime_forward_groups
             order by id",
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
            "select id, priority, enabled, matcher_kind, matcher_value, group_id, ipv6_policy from runtime_route_rules order by priority desc, id",
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
    let fingerprint = row.get::<String, _>("fingerprint");
    let supports_ipv6 = bool_from_i64(row.get::<i64, _>("supports_ipv6")).ok_or_else(|| {
        RuntimeStoreError::InvalidNode {
            id: id.clone(),
            message: "supports_ipv6 must be 0 or 1".to_string(),
        }
    })?;
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
        fingerprint,
        supports_ipv6,
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
        id: GroupId::new(id.clone()),
        enabled,
        scheduler,
        thresholds: GroupThresholds {
            min_success_rate_ppm: u32_from_i64(row.get::<i64, _>("min_success_rate_ppm"))
                .ok_or_else(|| RuntimeStoreError::InvalidGroup {
                    id: id.clone(),
                    message: "min_success_rate_ppm must fit u32".to_string(),
                })?,
            min_samples: u64::try_from(row.get::<i64, _>("min_samples")).map_err(|_| {
                RuntimeStoreError::InvalidGroup {
                    id: id.clone(),
                    message: "min_samples must fit u64".to_string(),
                }
            })?,
            max_active_sessions: row
                .get::<Option<i64>, _>("max_active_sessions")
                .map(u64::try_from)
                .transpose()
                .map_err(|_| RuntimeStoreError::InvalidGroup {
                    id: id.clone(),
                    message: "max_active_sessions must fit u64".to_string(),
                })?,
        },
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
    let ipv6 = match row.get::<String, _>("ipv6_policy").as_str() {
        "inherit" => Ipv6RulePolicy::Inherit,
        "allow" => Ipv6RulePolicy::Allow,
        "deny" => Ipv6RulePolicy::Deny,
        value => {
            return Err(RuntimeStoreError::InvalidRouteRule {
                id,
                message: format!("ipv6_policy {value:?} is unsupported"),
            })
        }
    };
    Ok(RouteRule {
        id: RuleId::new(id),
        priority: row.get::<i64, _>("priority"),
        enabled,
        matcher,
        group_id: GroupId::new(row.get::<String, _>("group_id")),
        ipv6,
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
