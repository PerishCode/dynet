use sqlx::SqlitePool;

use super::{RuntimeStoreError, SCHEMA_VERSION};

pub(super) async fn migrate(pool: &SqlitePool) -> Result<(), RuntimeStoreError> {
    sqlx::query(
        "create table if not exists runtime_meta (
            key text primary key,
            value text not null
        )",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "create table if not exists runtime_nodes (
            id text primary key,
            tag text not null,
            enabled integer not null,
            updated_at_unix_ms integer not null
        )",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "create table if not exists runtime_dns_upstreams (
            id text primary key,
            address text not null,
            enabled integer not null,
            priority integer not null,
            updated_at_unix_ms integer not null
        )",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "create table if not exists runtime_outbound_groups (
            id text primary key,
            enabled integer not null,
            scheduler text not null,
            outbound text not null,
            updated_at_unix_ms integer not null
        )",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "create table if not exists runtime_group_members (
            group_id text not null,
            node_id text not null,
            enabled integer not null,
            priority integer not null,
            updated_at_unix_ms integer not null,
            primary key (group_id, node_id)
        )",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "create table if not exists runtime_route_rules (
            id text primary key,
            priority integer not null,
            enabled integer not null,
            matcher_kind text not null,
            matcher_value text not null,
            group_id text not null,
            updated_at_unix_ms integer not null
        )",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "create table if not exists runtime_events (
            row_id integer primary key autoincrement,
            event_id integer not null,
            observed_at_unix_ms integer not null,
            kind text not null,
            fields_json text not null
        )",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "create table if not exists selection_decisions (
            row_id integer primary key autoincrement,
            decision_id integer not null,
            observed_at_unix_ms integer not null,
            session_id integer not null,
            inbound text not null,
            target_addr text not null,
            target_domain text,
            target_source text not null,
            group_id text not null,
            matched_rule_id text,
            node_id text not null,
            outbound text not null,
            reason text not null,
            scheduler text not null,
            candidate_count integer not null
        )",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "insert into runtime_meta (key, value)
         values ('schema_version', ?1)
         on conflict(key) do nothing",
    )
    .bind(SCHEMA_VERSION)
    .execute(pool)
    .await?;
    Ok(())
}
