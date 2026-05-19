use std::{collections::BTreeSet, net::IpAddr};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsReverseIndex {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub now_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub records: Vec<DnsReverseRecord>,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsReverseRecord {
    pub query: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical: Option<String>,
    pub address: IpAddr,
    pub observed_at_secs: u64,
    pub ttl_secs: u32,
    pub expires_at_secs: u64,
}

impl DnsReverseIndex {
    pub fn with_now_secs(mut self, now_secs: u64) -> Self {
        self.now_secs = Some(now_secs);
        self
    }

    pub fn insert_real_answer(
        &mut self,
        query: impl AsRef<str>,
        canonical: Option<impl AsRef<str>>,
        address: IpAddr,
        observed_at_secs: u64,
        ttl_secs: u32,
    ) {
        self.records.push(DnsReverseRecord::real_answer(
            query,
            canonical,
            address,
            observed_at_secs,
            ttl_secs,
        ));
    }

    pub fn domains_for_ip(&self, address: IpAddr) -> Vec<String> {
        let mut domains = BTreeSet::new();
        for record in &self.records {
            if record.address != address || !record.is_active_at(self.now_secs) {
                continue;
            }
            if let Some(query) = normalize_domain(&record.query) {
                domains.insert(query);
            }
            if let Some(canonical) = record.canonical.as_deref().and_then(normalize_domain) {
                domains.insert(canonical);
            }
        }
        domains.into_iter().collect()
    }

    pub fn contains_domain(&self, address: IpAddr, domain: &str) -> bool {
        let Some(domain) = normalize_domain(domain) else {
            return false;
        };
        self.domains_for_ip(address)
            .iter()
            .any(|candidate| candidate == &domain)
    }
}

impl DnsReverseRecord {
    pub fn real_answer(
        query: impl AsRef<str>,
        canonical: Option<impl AsRef<str>>,
        address: IpAddr,
        observed_at_secs: u64,
        ttl_secs: u32,
    ) -> Self {
        let query = normalize_domain(query.as_ref()).unwrap_or_default();
        let canonical = canonical.and_then(|value| normalize_domain(value.as_ref()));
        Self {
            query,
            canonical,
            address,
            observed_at_secs,
            ttl_secs,
            expires_at_secs: observed_at_secs + u64::from(ttl_secs),
        }
    }

    fn is_active_at(&self, now_secs: Option<u64>) -> bool {
        now_secs.is_none_or(|now| self.observed_at_secs <= now && now < self.expires_at_secs)
    }
}

pub fn normalize_domain(value: &str) -> Option<String> {
    let domain = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty() {
        None
    } else {
        Some(domain)
    }
}
