use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

const MAX_SOURCE_SELECTORS: usize = 64;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TrafficScope {
    pub interface: String,
    pub ipv4_sources: Vec<String>,
    pub ipv6_sources: Vec<String>,
}

impl TrafficScope {
    pub fn validate(&self, ipv6_enabled: bool) -> Result<(), String> {
        validate_interface(&self.interface)?;
        validate_sources("IPv4", &self.ipv4_sources, IpFamily::V4)?;
        validate_sources("IPv6", &self.ipv6_sources, IpFamily::V6)?;
        if self.ipv4_sources.is_empty() {
            return Err("traffic scope requires at least one IPv4 source CIDR".to_string());
        }
        if ipv6_enabled && self.ipv6_sources.is_empty() {
            return Err(
                "IPv6-enabled traffic scope requires at least one IPv6 source CIDR".to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum IpFamily {
    V4,
    V6,
}

fn validate_interface(interface: &str) -> Result<(), String> {
    if interface.is_empty()
        || interface.len() > 15
        || !interface
            .chars()
            .all(|value| value.is_ascii_alphanumeric() || "_.:-".contains(value))
    {
        return Err(
            "traffic scope interface must be a 1-15 character Linux interface name using letters, digits, _, ., :, or -"
                .to_string(),
        );
    }
    Ok(())
}

fn validate_sources(label: &str, sources: &[String], family: IpFamily) -> Result<(), String> {
    if sources.len() > MAX_SOURCE_SELECTORS {
        return Err(format!(
            "traffic scope accepts at most {MAX_SOURCE_SELECTORS} {label} source CIDRs"
        ));
    }
    let mut unique = BTreeSet::new();
    for source in sources {
        validate_source(label, source, family)?;
        if !unique.insert(source) {
            return Err(format!(
                "traffic scope contains duplicate {label} source CIDR {source}"
            ));
        }
    }
    Ok(())
}

fn validate_source(label: &str, source: &str, family: IpFamily) -> Result<(), String> {
    let (address, prefix) = source
        .split_once('/')
        .ok_or_else(|| format!("traffic scope {label} source {source:?} must be a CIDR"))?;
    let address = address.parse::<IpAddr>().map_err(|error| {
        format!("traffic scope {label} source {source:?} has an invalid address: {error}")
    })?;
    let prefix = prefix.parse::<u8>().map_err(|error| {
        format!("traffic scope {label} source {source:?} has an invalid prefix: {error}")
    })?;
    match (family, address) {
        (IpFamily::V4, IpAddr::V4(address)) if prefix <= 32 => {
            require_canonical_v4(label, source, address, prefix)
        }
        (IpFamily::V6, IpAddr::V6(address)) if prefix <= 128 => {
            require_canonical_v6(label, source, address, prefix)
        }
        (IpFamily::V4, IpAddr::V6(_)) => Err(format!(
            "traffic scope {label} source {source:?} must be IPv4"
        )),
        (IpFamily::V6, IpAddr::V4(_)) => Err(format!(
            "traffic scope {label} source {source:?} must be IPv6"
        )),
        _ => Err(format!(
            "traffic scope {label} source {source:?} has an out-of-range prefix"
        )),
    }
}

fn require_canonical_v4(
    label: &str,
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
            "traffic scope {label} source {source:?} has host bits set; use {canonical}/{prefix}"
        ))
    }
}

fn require_canonical_v6(
    label: &str,
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
            "traffic scope {label} source {source:?} has host bits set; use {canonical}/{prefix}"
        ))
    }
}
