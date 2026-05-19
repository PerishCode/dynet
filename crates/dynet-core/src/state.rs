use serde::Serialize;

use crate::{ConfigSummary, DynetConfig, ModeledNode, NetworkModel};

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppState {
    pub schema: String,
    pub config: DynetConfig,
    pub network: NetworkModel,
}

impl AppState {
    pub fn from_config(config: DynetConfig) -> Self {
        let network = config.network_model();
        Self {
            schema: "dynet-state/v1alpha1".to_string(),
            config,
            network,
        }
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
