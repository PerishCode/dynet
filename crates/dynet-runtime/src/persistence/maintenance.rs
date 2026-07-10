use sqlx::{Executor, Sqlite};

use super::{RuntimeStore, RuntimeStoreError};

const DATABASE_BUDGET_NUMERATOR: u64 = 7;
const DATABASE_BUDGET_DENOMINATOR: u64 = 8;
const HIGH_WATER_PERCENT: u64 = 85;
const LOW_WATER_PERCENT: u64 = 65;
const DELETE_BATCH_SIZE: i64 = 512;

pub(super) async fn initialize(store: &RuntimeStore) -> Result<(), RuntimeStoreError> {
    prune_expired(store).await?;
    prune_for_size(store, false).await?;
    checkpoint(store, "truncate").await?;

    let budget = database_budget(store);
    let mut metrics = page_metrics(store).await?;
    if metrics.allocated_bytes() > budget {
        sqlx::query("vacuum").execute(&store.pool).await?;
        metrics = page_metrics(store).await?;
    }
    if metrics.allocated_bytes() > budget {
        return Err(RuntimeStoreError::InvalidPersistencePolicy(format!(
            "max_bytes={} leaves {} bytes for the database, but its schema and retained state require {} bytes",
            store.persistence_policy.max_bytes,
            budget,
            metrics.allocated_bytes()
        )));
    }

    let max_page_count = (budget / metrics.page_size).max(1);
    let applied =
        sqlx::query_scalar::<_, i64>(&format!("pragma max_page_count = {max_page_count}"))
            .fetch_one(&store.pool)
            .await?;
    if u64::try_from(applied).unwrap_or_default() > max_page_count {
        return Err(RuntimeStoreError::InvalidPersistencePolicy(format!(
            "unable to lower SQLite max_page_count to {max_page_count}"
        )));
    }
    record_policy(store).await?;
    Ok(())
}

pub(super) async fn maintain(
    store: &RuntimeStore,
    force_size_prune: bool,
) -> Result<(), RuntimeStoreError> {
    prune_expired(store).await?;
    prune_for_size(store, force_size_prune).await?;
    checkpoint(store, "passive").await
}

async fn prune_expired(store: &RuntimeStore) -> Result<(), RuntimeStoreError> {
    let retention_ms =
        i64::try_from(store.persistence_policy.retention.as_millis()).unwrap_or(i64::MAX);
    let cutoff = super::unix_ms_i64().saturating_sub(retention_ms);
    let mut transaction = store.pool.begin().await?;
    for statement in [
        "delete from runtime_events where observed_at_unix_ms < ?1",
        "delete from selection_decisions where observed_at_unix_ms < ?1",
        "delete from matrix_shadow_decisions where observed_at_unix_ms < ?1",
        "delete from runtime_traffic_sessions
         where last_observed_at_unix_ms < ?1
           and (closed_at_unix_ms is not null or error is not null)",
    ] {
        sqlx::query(statement)
            .bind(cutoff)
            .execute(&mut *transaction)
            .await?;
    }
    transaction.commit().await?;
    Ok(())
}

async fn prune_for_size(store: &RuntimeStore, force: bool) -> Result<(), RuntimeStoreError> {
    let budget = database_budget(store);
    let metrics = page_metrics(store).await?;
    let high_water = budget.saturating_mul(HIGH_WATER_PERCENT) / 100;
    if !force && metrics.allocated_bytes() < high_water {
        return Ok(());
    }

    let low_water = budget.saturating_mul(LOW_WATER_PERCENT) / 100;
    let mut first_batch = true;
    loop {
        let metrics = page_metrics(store).await?;
        if (!force || !first_batch) && metrics.live_bytes() <= low_water {
            break;
        }
        let deleted = delete_oldest_batch(store).await?;
        first_batch = false;
        if deleted == 0 {
            break;
        }
    }
    Ok(())
}

async fn delete_oldest_batch(store: &RuntimeStore) -> Result<u64, RuntimeStoreError> {
    let mut transaction = store.pool.begin().await?;
    let mut deleted = 0_u64;
    for statement in [
        "delete from runtime_events where row_id in (
            select row_id from runtime_events
            order by observed_at_unix_ms, row_id limit ?1
         )",
        "delete from selection_decisions where row_id in (
            select row_id from selection_decisions
            order by observed_at_unix_ms, row_id limit ?1
         )",
        "delete from matrix_shadow_decisions where row_id in (
            select row_id from matrix_shadow_decisions
            order by observed_at_unix_ms, row_id limit ?1
         )",
        "delete from runtime_traffic_sessions where session_key in (
            select session_key from runtime_traffic_sessions
            order by last_observed_at_unix_ms, session_key limit ?1
         )",
    ] {
        deleted = deleted.saturating_add(
            sqlx::query(statement)
                .bind(DELETE_BATCH_SIZE)
                .execute(&mut *transaction)
                .await?
                .rows_affected(),
        );
    }
    transaction.commit().await?;
    Ok(deleted)
}

async fn record_policy(store: &RuntimeStore) -> Result<(), RuntimeStoreError> {
    let values = [
        (
            "persistence_retention_ms",
            store.persistence_policy.retention.as_millis().to_string(),
        ),
        (
            "persistence_max_bytes",
            store.persistence_policy.max_bytes.to_string(),
        ),
    ];
    let mut transaction = store.pool.begin().await?;
    for (key, value) in values {
        sqlx::query(
            "insert into runtime_meta (key, value) values (?1, ?2)
             on conflict(key) do update set value = excluded.value",
        )
        .bind(key)
        .bind(value)
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await?;
    Ok(())
}

async fn checkpoint(store: &RuntimeStore, mode: &str) -> Result<(), RuntimeStoreError> {
    sqlx::query(&format!("pragma wal_checkpoint({mode})"))
        .execute(&store.pool)
        .await?;
    Ok(())
}

fn database_budget(store: &RuntimeStore) -> u64 {
    store
        .persistence_policy
        .max_bytes
        .saturating_mul(DATABASE_BUDGET_NUMERATOR)
        / DATABASE_BUDGET_DENOMINATOR
}

#[derive(Debug, Clone, Copy)]
struct PageMetrics {
    page_size: u64,
    page_count: u64,
    freelist_count: u64,
}

impl PageMetrics {
    fn allocated_bytes(self) -> u64 {
        self.page_count.saturating_mul(self.page_size)
    }

    fn live_bytes(self) -> u64 {
        self.page_count
            .saturating_sub(self.freelist_count)
            .saturating_mul(self.page_size)
    }
}

async fn page_metrics(store: &RuntimeStore) -> Result<PageMetrics, RuntimeStoreError> {
    let mut connection = store.pool.acquire().await?;
    let page_size = pragma_u64(&mut *connection, "pragma page_size").await?;
    let page_count = pragma_u64(&mut *connection, "pragma page_count").await?;
    let freelist_count = pragma_u64(&mut *connection, "pragma freelist_count").await?;
    Ok(PageMetrics {
        page_size,
        page_count,
        freelist_count,
    })
}

async fn pragma_u64<'e, E>(executor: E, statement: &str) -> Result<u64, RuntimeStoreError>
where
    E: Executor<'e, Database = Sqlite>,
{
    let value = sqlx::query_scalar::<_, i64>(statement)
        .fetch_one(executor)
        .await?;
    Ok(u64::try_from(value).unwrap_or_default())
}
