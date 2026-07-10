use std::{
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use dynet_runtime::{PersistencePolicy, RuntimeStore};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    SqlitePool,
};
use tempfile::TempDir;

const FOUR_MIB: u64 = 4 * 1024 * 1024;

#[tokio::test]
async fn retention_preserves_active_sessions() {
    let directory = TempDir::new().expect("temp directory");
    let path = directory.path().join("runtime.sqlite");
    let store = RuntimeStore::open_with_policy(
        &path,
        PersistencePolicy {
            retention: Duration::from_secs(60 * 60),
            max_bytes: FOUR_MIB,
        },
    )
    .await
    .expect("runtime store");
    let inspector = open_inspector(&path).await;
    let now = unix_ms();
    let old = now - 2 * 60 * 60 * 1000;

    for (event_id, observed_at) in [(1_i64, old), (2, now)] {
        sqlx::query(
            "insert into runtime_events (event_id, observed_at_unix_ms, kind, fields_json)
             values (?1, ?2, 'tcp-accept', '{}')",
        )
        .bind(event_id)
        .bind(observed_at)
        .execute(&inspector)
        .await
        .expect("insert event");
    }
    for (decision_id, observed_at) in [(1_i64, old), (2, now)] {
        sqlx::query(
            "insert into selection_decisions (
                decision_id, observed_at_unix_ms, session_id, inbound, target_addr,
                target_source, group_id, node_id, next, reason, scheduler, candidate_count
             ) values (?1, ?2, ?1, 'tcp', '127.0.0.1:80', 'fixed-upstream',
                       'default', 'default-node', 'direct', 'single', 'single', 1)",
        )
        .bind(decision_id)
        .bind(observed_at)
        .execute(&inspector)
        .await
        .expect("insert selection");
        sqlx::query(
            "insert into matrix_shadow_decisions (
                decision_id, session_id, observed_at_unix_ms, inbound, group_id,
                actual_node_id, shadow_differs_from_actual, shadow_reason, candidates_json
             ) values (?1, ?1, ?2, 'tcp', 'default', 'default-node', 0, 'same', '[]')",
        )
        .bind(decision_id)
        .bind(observed_at)
        .execute(&inspector)
        .await
        .expect("insert shadow");
    }
    insert_session(&inspector, "closed-old", old, Some(old)).await;
    insert_session(&inspector, "active-old", old, None).await;
    insert_session(&inspector, "closed-fresh", now, Some(now)).await;

    store
        .maintain_persistence()
        .await
        .expect("persistence maintenance");

    assert_eq!(count(&inspector, "runtime_events").await, 1);
    assert_eq!(count(&inspector, "selection_decisions").await, 1);
    assert_eq!(count(&inspector, "matrix_shadow_decisions").await, 1);
    let sessions = sqlx::query_scalar::<_, String>(
        "select session_key from runtime_traffic_sessions order by session_key",
    )
    .fetch_all(&inspector)
    .await
    .expect("load sessions");
    assert_eq!(sessions, vec!["active-old", "closed-fresh"]);
}

#[tokio::test]
async fn size_budget_caps_database() {
    let directory = TempDir::new().expect("temp directory");
    let path = directory.path().join("runtime.sqlite");
    let store = RuntimeStore::open_with_policy(
        &path,
        PersistencePolicy {
            retention: Duration::from_secs(24 * 60 * 60),
            max_bytes: FOUR_MIB,
        },
    )
    .await
    .expect("runtime store");
    let inspector = open_inspector(&path).await;
    let payload = "x".repeat(8 * 1024);
    let mut event_id = 0_i64;
    while allocated_bytes(&inspector).await < 3 * 1024 * 1024 {
        for _ in 0..8 {
            event_id += 1;
            sqlx::query(
                "insert into runtime_events (event_id, observed_at_unix_ms, kind, fields_json)
                 values (?1, ?1, 'tcp-accept', ?2)",
            )
            .bind(event_id)
            .bind(&payload)
            .execute(&inspector)
            .await
            .expect("insert bounded event");
        }
    }
    let before = count(&inspector, "runtime_events").await;

    store
        .maintain_persistence()
        .await
        .expect("persistence maintenance");

    let after = count(&inspector, "runtime_events").await;
    assert!(after < before, "capacity maintenance did not prune rows");
    assert!(live_bytes(&inspector).await <= FOUR_MIB * 7 / 8 * 65 / 100);
    assert!(allocated_bytes(&inspector).await <= FOUR_MIB * 7 / 8);
}

#[tokio::test]
async fn rejects_tiny_persistence_budget() {
    let directory = TempDir::new().expect("temp directory");
    let error = RuntimeStore::open_with_policy(
        directory.path().join("runtime.sqlite"),
        PersistencePolicy {
            retention: Duration::from_secs(1),
            max_bytes: 1024,
        },
    )
    .await
    .expect_err("undersized budget rejected");

    assert!(error.to_string().contains("max_bytes must be at least"));
}

async fn insert_session(pool: &SqlitePool, key: &str, observed_at: i64, closed_at: Option<i64>) {
    sqlx::query(
        "insert into runtime_traffic_sessions (
            session_key, session_id, inbound, started_at_unix_ms,
            closed_at_unix_ms, last_observed_at_unix_ms
         ) values (?1, 1, 'tcp', ?2, ?3, ?2)",
    )
    .bind(key)
    .bind(observed_at)
    .bind(closed_at)
    .execute(pool)
    .await
    .expect("insert session");
}

async fn count(pool: &SqlitePool, table: &str) -> i64 {
    sqlx::query_scalar::<_, i64>(&format!("select count(*) from {table}"))
        .fetch_one(pool)
        .await
        .expect("count rows")
}

async fn allocated_bytes(pool: &SqlitePool) -> u64 {
    pragma(pool, "pragma page_size").await * pragma(pool, "pragma page_count").await
}

async fn live_bytes(pool: &SqlitePool) -> u64 {
    let page_size = pragma(pool, "pragma page_size").await;
    let page_count = pragma(pool, "pragma page_count").await;
    let freelist = pragma(pool, "pragma freelist_count").await;
    page_size * (page_count - freelist)
}

async fn pragma(pool: &SqlitePool, statement: &str) -> u64 {
    let value = sqlx::query_scalar::<_, i64>(statement)
        .fetch_one(pool)
        .await
        .expect("read pragma");
    u64::try_from(value).expect("non-negative pragma")
}

async fn open_inspector(path: &Path) -> SqlitePool {
    let options = SqliteConnectOptions::new().filename(path);
    SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .expect("inspector pool")
}

fn unix_ms() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_millis(),
    )
    .expect("timestamp fits i64")
}
