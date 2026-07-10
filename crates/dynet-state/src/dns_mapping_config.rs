use std::env;

use serde::Deserialize;

use crate::non_empty_string;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DnsMappingConfig {
    pub interface: Option<String>,
    pub source_port: u16,
}

impl Default for DnsMappingConfig {
    fn default() -> Self {
        Self {
            interface: None,
            source_port: 53,
        }
    }
}

pub(crate) fn apply_env(config: &mut DnsMappingConfig) -> Result<(), String> {
    config.interface = match env::var("DYNET_DNS_MAPPING_INTERFACE") {
        Ok(value) => Some(validate_interface(
            "DYNET_DNS_MAPPING_INTERFACE",
            non_empty_string("DYNET_DNS_MAPPING_INTERFACE", value)?,
        )?),
        Err(env::VarError::NotPresent) => config.interface.clone(),
        Err(error) => {
            return Err(format!(
                "failed to read DYNET_DNS_MAPPING_INTERFACE: {error}"
            ))
        }
    };
    config.source_port = match env::var("DYNET_DNS_MAPPING_SOURCE_PORT") {
        Ok(value) => parse_port("DYNET_DNS_MAPPING_SOURCE_PORT", &value)?,
        Err(env::VarError::NotPresent) => config.source_port,
        Err(error) => {
            return Err(format!(
                "failed to read DYNET_DNS_MAPPING_SOURCE_PORT: {error}"
            ))
        }
    };
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FileDnsMappingConfig {
    interface: Option<String>,
    source_port: Option<u16>,
}

impl FileDnsMappingConfig {
    pub(crate) fn apply(self, config: &mut DnsMappingConfig) -> Result<(), String> {
        if let Some(interface) = self.interface {
            config.interface = Some(validate_interface(
                "dns_mapping.interface",
                non_empty_string("dns_mapping.interface", interface)?,
            )?);
        }
        if let Some(source_port) = self.source_port {
            if source_port == 0 {
                return Err("dns_mapping.source_port must be between 1 and 65535".to_string());
            }
            config.source_port = source_port;
        }
        Ok(())
    }
}

fn validate_interface(name: &str, value: String) -> Result<String, String> {
    if value.len() > 15
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "_.:-".contains(character))
    {
        return Err(format!(
            "{name} must be a 1-15 character Linux interface name using letters, digits, _, ., :, or -"
        ));
    }
    Ok(value)
}

fn parse_port(name: &str, value: &str) -> Result<u16, String> {
    let port = value
        .parse::<u16>()
        .map_err(|error| format!("{name} must be a port between 1 and 65535: {error}"))?;
    if port == 0 {
        return Err(format!("{name} must be a port between 1 and 65535"));
    }
    Ok(port)
}
