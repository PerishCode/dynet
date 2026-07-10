use sqlx::{Row, SqlitePool};

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
            fingerprint text not null default '',
            updated_at_unix_ms integer not null
        )",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "create table if not exists runtime_dns_upstreams (
            id text primary key,
            address text not null,
            transport text not null default 'udp',
            host text,
            path text,
            enabled integer not null,
            priority integer not null,
            updated_at_unix_ms integer not null
        )",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "create table if not exists runtime_forward_groups (
            id text primary key,
            enabled integer not null,
            scheduler text not null,
            min_success_rate_ppm integer not null default 980000,
            min_samples integer not null default 1,
            max_active_sessions integer,
            next text not null,
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
            config_generation integer not null default 1,
            observed_at_unix_ms integer not null,
            session_id integer not null,
            inbound text not null,
            target_addr text not null,
            target_domain text,
            target_source text not null,
            group_id text not null,
            matched_rule_id text,
            node_id text not null,
            next text not null,
            reason text not null,
            scheduler text not null,
            candidate_count integer not null
        )",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "create table if not exists runtime_traffic_sessions (
            session_key text primary key,
            session_id integer not null,
            decision_id integer,
            config_generation integer,
            inbound text not null,
            node_protocol text,
            peer_addr text,
            target_addr text,
            target_ip text,
            target_port integer,
            target_domain text,
            target_source text,
            upstream_addr text,
            selection_groups text,
            selection_nodes text,
            selection_trace text,
            started_at_unix_ms integer not null,
            closed_at_unix_ms integer,
            duration_ms integer,
            close_reason text,
            error_stage text,
            error_code text,
            error_class text,
            error_side text,
            error_phase text,
            error_protocol_phase text,
            error_score_impact text,
            error text,
            client_to_upstream_bytes integer not null default 0,
            upstream_to_client_bytes integer not null default 0,
            client_to_upstream_datagrams integer not null default 0,
            upstream_to_client_datagrams integer not null default 0,
            first_upstream_at_unix_ms integer,
            first_downstream_at_unix_ms integer,
            first_response_latency_ms integer,
            last_observed_at_unix_ms integer not null
        )",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "create table if not exists matrix_shadow_decisions (
            row_id integer primary key autoincrement,
            decision_id integer not null,
            session_id integer not null,
            observed_at_unix_ms integer not null,
            inbound text not null,
            group_id text not null,
            actual_node_id text not null,
            shadow_node_id text,
            shadow_differs_from_actual integer not null,
            shadow_reason text not null,
            candidates_json text not null
        )",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "create index if not exists runtime_traffic_sessions_recent_completed_idx
         on runtime_traffic_sessions (last_observed_at_unix_ms desc, session_key desc)
         where closed_at_unix_ms is not null or error is not null",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "create index if not exists matrix_shadow_decisions_recent_idx
         on matrix_shadow_decisions (observed_at_unix_ms desc, row_id desc)",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "insert into runtime_meta (key, value)
         values ('schema_version', ?1)
         on conflict(key) do update set value = excluded.value",
    )
    .bind(SCHEMA_VERSION)
    .execute(pool)
    .await?;
    ensure_column(
        pool,
        "runtime_nodes",
        "fingerprint",
        "alter table runtime_nodes add column fingerprint text not null default ''",
    )
    .await?;
    ensure_column(
        pool,
        "selection_decisions",
        "config_generation",
        "alter table selection_decisions add column config_generation integer not null default 1",
    )
    .await?;
    ensure_column(
        pool,
        "runtime_traffic_sessions",
        "config_generation",
        "alter table runtime_traffic_sessions add column config_generation integer",
    )
    .await?;
    sqlx::query("update runtime_nodes set fingerprint = 'node-id:' || id where fingerprint = ''")
        .execute(pool)
        .await?;
    ensure_column(
        pool,
        "runtime_dns_upstreams",
        "transport",
        "alter table runtime_dns_upstreams add column transport text not null default 'udp'",
    )
    .await?;
    ensure_column(
        pool,
        "runtime_dns_upstreams",
        "host",
        "alter table runtime_dns_upstreams add column host text",
    )
    .await?;
    ensure_column(
        pool,
        "runtime_dns_upstreams",
        "path",
        "alter table runtime_dns_upstreams add column path text",
    )
    .await?;
    ensure_column(
        pool,
        "runtime_forward_groups",
        "min_success_rate_ppm",
        "alter table runtime_forward_groups add column min_success_rate_ppm integer not null default 980000",
    )
    .await?;
    ensure_column(
        pool,
        "runtime_forward_groups",
        "min_samples",
        "alter table runtime_forward_groups add column min_samples integer not null default 1",
    )
    .await?;
    ensure_column(
        pool,
        "runtime_forward_groups",
        "max_active_sessions",
        "alter table runtime_forward_groups add column max_active_sessions integer",
    )
    .await?;
    for (column, ddl) in [
        (
            "error_code",
            "alter table runtime_traffic_sessions add column error_code text",
        ),
        (
            "error_class",
            "alter table runtime_traffic_sessions add column error_class text",
        ),
        (
            "error_side",
            "alter table runtime_traffic_sessions add column error_side text",
        ),
        (
            "error_phase",
            "alter table runtime_traffic_sessions add column error_phase text",
        ),
        (
            "error_protocol_phase",
            "alter table runtime_traffic_sessions add column error_protocol_phase text",
        ),
        (
            "error_score_impact",
            "alter table runtime_traffic_sessions add column error_score_impact text",
        ),
    ] {
        ensure_column(pool, "runtime_traffic_sessions", column, ddl).await?;
    }
    Ok(())
}

async fn ensure_column(
    pool: &SqlitePool,
    table: &str,
    column: &str,
    alter_sql: &str,
) -> Result<(), RuntimeStoreError> {
    let rows = sqlx::query(&format!("pragma table_info({table})"))
        .fetch_all(pool)
        .await?;
    if rows
        .iter()
        .any(|row| row.get::<String, _>("name") == column)
    {
        return Ok(());
    }
    sqlx::query(alter_sql).execute(pool).await?;
    Ok(())
}
