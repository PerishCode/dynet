use std::time::Duration;

use sqlx::{Sqlite, Transaction};

use crate::{DnsRacePolicy, DnsRaceStrategy};

use super::{RuntimeStore, RuntimeStoreError};

impl RuntimeStore {
    pub(super) async fn load_dns_policy(&self) -> Result<DnsRacePolicy, RuntimeStoreError> {
        let strategy = self
            .meta_value("dns_race_strategy")
            .await?
            .ok_or_else(|| RuntimeStoreError::InvalidBootstrap("missing dns_race_strategy".into()))
            .and_then(|value| {
                dns_strategy_from_str(&value).ok_or_else(|| {
                    RuntimeStoreError::InvalidBootstrap(format!(
                        "dns_race_strategy {value:?} is unsupported"
                    ))
                })
            })?;
        let timeout_ms = self
            .meta_value("dns_race_timeout_ms")
            .await?
            .ok_or_else(|| {
                RuntimeStoreError::InvalidBootstrap("missing dns_race_timeout_ms".into())
            })
            .and_then(|value| {
                value.parse::<u64>().map_err(|error| {
                    RuntimeStoreError::InvalidBootstrap(format!(
                        "dns_race_timeout_ms must be an integer: {error}"
                    ))
                })
            })?;
        Ok(DnsRacePolicy {
            timeout: Duration::from_millis(timeout_ms),
            strategy,
        })
    }
}

pub(super) async fn insert_default_dns_policy(
    transaction: &mut Transaction<'_, Sqlite>,
) -> Result<(), RuntimeStoreError> {
    sqlx::query(
        "insert into runtime_meta (key, value)
         values ('dns_race_strategy', ?1)
         on conflict(key) do update set value = excluded.value",
    )
    .bind(DnsRaceStrategy::Parallel.as_str())
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "insert into runtime_meta (key, value)
         values ('dns_race_timeout_ms', ?1)
         on conflict(key) do update set value = excluded.value",
    )
    .bind("2000")
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

fn dns_strategy_from_str(value: &str) -> Option<DnsRaceStrategy> {
    match value {
        "parallel" => Some(DnsRaceStrategy::Parallel),
        _ => None,
    }
}
