use std::net::SocketAddr;

use super::{TargetContext, TargetSource};

impl TargetContext {
    pub fn fixed_upstream(address: SocketAddr) -> Self {
        Self {
            address,
            domain: None,
            source: TargetSource::FixedUpstream,
        }
    }

    pub fn external_context(address: SocketAddr, domain: Option<String>) -> Self {
        Self {
            address,
            domain,
            source: TargetSource::ExternalContext,
        }
    }

    pub fn dynet_dns(address: SocketAddr, domain: String) -> Self {
        Self {
            address,
            domain: Some(domain),
            source: TargetSource::ObservedDns,
        }
    }
}
