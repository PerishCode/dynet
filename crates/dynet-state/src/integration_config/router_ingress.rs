use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use serde::Deserialize;

use crate::non_empty_string;

const MAX_SOURCE_SELECTORS: usize = 64;

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct RouterIngressConfig {
    pub interface: Option<String>,
    pub ipv4_sources: Vec<String>,
    pub ipv6_sources: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FileRouterIngressConfig {
    interface: Option<String>,
    ipv4_sources: Option<Vec<String>>,
    ipv6_sources: Option<Vec<String>>,
}

impl FileRouterIngressConfig {
    pub(crate) fn apply(self, config: &mut RouterIngressConfig) -> Result<(), String> {
        if let Some(interface) = self.interface {
            config.interface = Some(validate_interface(
                "capture.router_ingress.interface",
                non_empty_string("capture.router_ingress.interface", interface)?,
            )?);
        }
        if let Some(sources) = self.ipv4_sources {
            config.ipv4_sources =
                validate_sources("capture.router_ingress.ipv4_sources", sources, IpFamily::V4)?;
        }
        if let Some(sources) = self.ipv6_sources {
            config.ipv6_sources =
                validate_sources("capture.router_ingress.ipv6_sources", sources, IpFamily::V6)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum IpFamily {
    V4,
    V6,
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

fn validate_sources(
    name: &str,
    sources: Vec<String>,
    family: IpFamily,
) -> Result<Vec<String>, String> {
    if sources.len() > MAX_SOURCE_SELECTORS {
        return Err(format!(
            "{name} accepts at most {MAX_SOURCE_SELECTORS} CIDR selectors"
        ));
    }
    let mut unique = BTreeSet::new();
    let mut validated = Vec::with_capacity(sources.len());
    for source in sources {
        let normalized = validate_source(name, &source, family)?;
        if !unique.insert(normalized.clone()) {
            return Err(format!("{name} contains duplicate selector {normalized}"));
        }
        validated.push(normalized);
    }
    Ok(validated)
}

fn validate_source(name: &str, source: &str, family: IpFamily) -> Result<String, String> {
    let (address, prefix) = source
        .split_once('/')
        .ok_or_else(|| format!("{name} entry {source:?} must be an explicit CIDR"))?;
    let address = address
        .parse::<IpAddr>()
        .map_err(|error| format!("{name} entry {source:?} has an invalid address: {error}"))?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|error| format!("{name} entry {source:?} has an invalid prefix: {error}"))?;
    match (family, address) {
        (IpFamily::V4, IpAddr::V4(address)) if prefix <= 32 => {
            require_canonical_v4(name, source, address, prefix)?;
            Ok(format!("{address}/{prefix}"))
        }
        (IpFamily::V6, IpAddr::V6(address)) if prefix <= 128 => {
            require_canonical_v6(name, source, address, prefix)?;
            Ok(format!("{address}/{prefix}"))
        }
        (IpFamily::V4, IpAddr::V6(_)) => {
            Err(format!("{name} entry {source:?} must be an IPv4 CIDR"))
        }
        (IpFamily::V6, IpAddr::V4(_)) => {
            Err(format!("{name} entry {source:?} must be an IPv6 CIDR"))
        }
        (IpFamily::V4, IpAddr::V4(_)) => Err(format!(
            "{name} entry {source:?} prefix must be between 0 and 32"
        )),
        (IpFamily::V6, IpAddr::V6(_)) => Err(format!(
            "{name} entry {source:?} prefix must be between 0 and 128"
        )),
    }
}

fn require_canonical_v4(
    name: &str,
    source: &str,
    address: Ipv4Addr,
    prefix: u8,
) -> Result<(), String> {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    let canonical = Ipv4Addr::from(u32::from(address) & mask);
    if canonical == address {
        Ok(())
    } else {
        Err(format!(
            "{name} entry {source:?} has host bits set; use {canonical}/{prefix}"
        ))
    }
}

fn require_canonical_v6(
    name: &str,
    source: &str,
    address: Ipv6Addr,
    prefix: u8,
) -> Result<(), String> {
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    let canonical = Ipv6Addr::from(u128::from(address) & mask);
    if canonical == address {
        Ok(())
    } else {
        Err(format!(
            "{name} entry {source:?} has host bits set; use {canonical}/{prefix}"
        ))
    }
}
