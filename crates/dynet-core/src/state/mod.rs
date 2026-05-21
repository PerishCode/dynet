mod quality;

use serde::Serialize;

pub use quality::{
    OutboundQualityEntry, OutboundQualityState, QualityConfidence, QualityVerdict,
    StageQualityEntry,
};

use crate::{ConfigSummary, DnsModel, DnsReverseIndex, DynetConfig, ModeledNode, NetworkModel};

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppState {
    pub schema: String,
    pub config: DynetConfig,
    pub network: NetworkModel,
    pub dns: DnsModel,
    pub dns_reverse: DnsReverseIndex,
    pub quality: OutboundQualityState,
}

impl AppState {
    pub fn from_config(config: DynetConfig) -> Self {
        let network = config.network_model();
        let dns = config.dns_model();
        Self {
            schema: "dynet-state/v1alpha1".to_string(),
            config,
            network,
            dns,
            dns_reverse: DnsReverseIndex::default(),
            quality: OutboundQualityState::empty(),
        }
    }

    pub fn with_dns_reverse(mut self, dns_reverse: DnsReverseIndex) -> Self {
        self.dns_reverse = dns_reverse;
        self
    }

    pub fn with_quality(mut self, quality: OutboundQualityState) -> Self {
        self.quality = quality;
        self
    }

    pub fn summary(&self) -> ConfigSummary {
        self.config.summary()
    }

    pub fn inbound(&self, tag: &str) -> Option<&ModeledNode> {
        self.network.inbounds.iter().find(|node| node.tag == tag)
    }

    pub fn outbound(&self, tag: &str) -> Option<&ModeledNode> {
        self.network.outbounds.iter().find(|node| node.tag == tag)
    }
}

impl From<DynetConfig> for AppState {
    fn from(config: DynetConfig) -> Self {
        Self::from_config(config)
    }
}
