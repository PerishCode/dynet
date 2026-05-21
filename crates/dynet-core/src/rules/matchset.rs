use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use crate::{normalize_domain, AppState, InboundContext};

pub(crate) fn candidate_domains(context: &InboundContext, state: &AppState) -> Vec<String> {
    let mut domains = BTreeSet::new();
    if let Some(domain) = context
        .destination_domain
        .as_deref()
        .and_then(normalize_domain)
    {
        domains.insert(domain);
    }
    if let Some(destination_ip) = context.destination_ip {
        domains.extend(state.dns_reverse.domains_for_ip(destination_ip));
    }
    domains.into_iter().collect()
}

pub(crate) fn domain_matches_suffix(domain: &str, suffix: &str) -> bool {
    domain == suffix || domain.ends_with(&format!(".{suffix}"))
}

pub(crate) fn ip_in_cidr(address: IpAddr, cidr: &str) -> bool {
    let Some((network, prefix)) = parse_cidr(cidr) else {
        return false;
    };
    match (address, network) {
        (IpAddr::V4(address), IpAddr::V4(network)) => {
            prefix <= 32 && masked_v4(address, prefix) == masked_v4(network, prefix)
        }
        (IpAddr::V6(address), IpAddr::V6(network)) => {
            prefix <= 128 && masked_v6(address, prefix) == masked_v6(network, prefix)
        }
        _ => false,
    }
}

pub(crate) fn normalize_cidr_text(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn parse_cidr(cidr: &str) -> Option<(IpAddr, u8)> {
    let (address, prefix) = cidr.trim().split_once('/')?;
    let address = address.parse().ok()?;
    let prefix = prefix.parse().ok()?;
    Some((address, prefix))
}

fn masked_v4(address: Ipv4Addr, prefix: u8) -> u32 {
    let value = u32::from(address);
    if prefix == 0 {
        0
    } else {
        value & (!0_u32 << (32 - prefix))
    }
}

fn masked_v6(address: Ipv6Addr, prefix: u8) -> u128 {
    let value = u128::from(address);
    if prefix == 0 {
        0
    } else {
        value & (!0_u128 << (128 - prefix))
    }
}
