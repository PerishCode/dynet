use std::{env, time::Duration};

use dynet_runtime::PersistencePolicy;
use serde::Deserialize;

pub(crate) fn apply_env(policy: &mut PersistencePolicy) -> Result<(), String> {
    if let Some(hours) = env_positive_u64("DYNET_PERSISTENCE_RETENTION_HOURS")? {
        policy.retention = duration_from_hours("DYNET_PERSISTENCE_RETENTION_HOURS", hours)?;
    }
    if let Some(max_bytes) = env_positive_u64("DYNET_PERSISTENCE_MAX_BYTES")? {
        policy.max_bytes = max_bytes;
    }
    policy
        .validate()
        .map_err(|error| format!("invalid persistence configuration: {error}"))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FilePersistenceConfig {
    retention_hours: Option<u64>,
    max_bytes: Option<u64>,
}

impl FilePersistenceConfig {
    pub(crate) fn apply(self, policy: &mut PersistencePolicy) -> Result<(), String> {
        if let Some(hours) = self.retention_hours {
            policy.retention = duration_from_hours("persistence.retention_hours", hours)?;
        }
        if let Some(max_bytes) = self.max_bytes {
            if max_bytes == 0 {
                return Err("persistence.max_bytes must be a positive integer".to_string());
            }
            policy.max_bytes = max_bytes;
        }
        policy
            .validate()
            .map_err(|error| format!("invalid persistence configuration: {error}"))
    }
}

fn env_positive_u64(name: &str) -> Result<Option<u64>, String> {
    match env::var(name) {
        Ok(value) => {
            let value = value
                .parse::<u64>()
                .map_err(|error| format!("{name} must be a positive integer: {error}"))?;
            if value == 0 {
                return Err(format!("{name} must be a positive integer"));
            }
            Ok(Some(value))
        }
        Err(env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(format!("failed to read {name}: {error}")),
    }
}

fn duration_from_hours(name: &str, hours: u64) -> Result<Duration, String> {
    if hours == 0 {
        return Err(format!("{name} must be a positive integer"));
    }
    hours
        .checked_mul(60 * 60)
        .map(Duration::from_secs)
        .ok_or_else(|| format!("{name} is too large"))
}
