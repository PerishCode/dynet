use std::{env, path::PathBuf};

use serde::Deserialize;

use crate::non_empty_string;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ServiceConfig {
    pub manager: ServiceManager,
    pub user: String,
    pub runtime_database: PathBuf,
    pub environment_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub enum ServiceManager {
    #[default]
    Auto,
    Systemd,
    Procd,
}

impl ServiceManager {
    pub fn label(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Systemd => "systemd",
            Self::Procd => "procd",
        }
    }
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            manager: ServiceManager::Auto,
            user: "dynet".to_string(),
            runtime_database: PathBuf::from("dynet.sqlite"),
            environment_file: None,
        }
    }
}

pub(crate) fn apply_env(config: &mut ServiceConfig) -> Result<(), String> {
    config.manager = match env::var("DYNET_SERVICE_MANAGER") {
        Ok(value) => parse_manager("DYNET_SERVICE_MANAGER", &value)?,
        Err(env::VarError::NotPresent) => config.manager,
        Err(error) => return Err(format!("failed to read DYNET_SERVICE_MANAGER: {error}")),
    };
    config.user = match env::var("DYNET_SERVICE_USER") {
        Ok(value) => non_empty_string("DYNET_SERVICE_USER", value)?,
        Err(env::VarError::NotPresent) => config.user.clone(),
        Err(error) => return Err(format!("failed to read DYNET_SERVICE_USER: {error}")),
    };
    config.runtime_database = env_path("DYNET_RUNTIME_DB", config.runtime_database.clone())?;
    config.environment_file = env_optional_path(
        "DYNET_SERVICE_ENVIRONMENT_FILE",
        config.environment_file.clone(),
    )?;
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FileServiceConfig {
    manager: Option<String>,
    user: Option<String>,
    runtime_database: Option<PathBuf>,
    environment_file: Option<PathBuf>,
}

impl FileServiceConfig {
    pub(crate) fn apply(self, config: &mut ServiceConfig) -> Result<(), String> {
        if let Some(manager) = self.manager {
            config.manager = parse_manager("service.manager", &manager)?;
        }
        if let Some(user) = self.user {
            config.user = non_empty_string("service.user", user)?;
        }
        if let Some(path) = self.runtime_database {
            config.runtime_database = non_empty_path("service.runtime_database", path)?;
        }
        if let Some(path) = self.environment_file {
            config.environment_file = Some(non_empty_path("service.environment_file", path)?);
        }
        Ok(())
    }
}

fn parse_manager(name: &str, value: &str) -> Result<ServiceManager, String> {
    match value {
        "auto" => Ok(ServiceManager::Auto),
        "systemd" => Ok(ServiceManager::Systemd),
        "procd" => Ok(ServiceManager::Procd),
        _ => Err(format!("{name} must be auto, systemd, or procd")),
    }
}

fn env_path(name: &str, fallback: PathBuf) -> Result<PathBuf, String> {
    match env::var_os(name) {
        Some(value) if value.is_empty() => Err(format!("{name} requires a non-empty path")),
        Some(value) => Ok(PathBuf::from(value)),
        None => Ok(fallback),
    }
}

fn env_optional_path(name: &str, fallback: Option<PathBuf>) -> Result<Option<PathBuf>, String> {
    match env::var_os(name) {
        Some(value) if value.is_empty() => Err(format!("{name} requires a non-empty path")),
        Some(value) => Ok(Some(PathBuf::from(value))),
        None => Ok(fallback),
    }
}

fn non_empty_path(name: &str, value: PathBuf) -> Result<PathBuf, String> {
    if value.as_os_str().is_empty() {
        return Err(format!("{name} requires a non-empty path"));
    }
    Ok(value)
}
