use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
};

use dynet_runtime::SelectionDecision;

use crate::EgressNodeConfig;

use super::{
    EgressError, EgressNode, GraphEgress, TcpRelayOutcome, TcpRelaySession, UdpRelayAssociation,
    UdpRelayOutcome,
};

const RETAINED_GENERATIONS: usize = 8;

#[derive(Debug, Clone)]
pub struct ReloadableEgress {
    inner: Arc<RwLock<BTreeMap<u64, Arc<GraphEgress>>>>,
}

impl ReloadableEgress {
    pub fn new(
        generation: u64,
        configs: BTreeMap<String, EgressNodeConfig>,
    ) -> Result<Self, String> {
        let graph = Arc::new(GraphEgress::try_from(configs)?);
        Ok(Self {
            inner: Arc::new(RwLock::new(BTreeMap::from([(generation, graph)]))),
        })
    }

    pub fn install(
        &self,
        generation: u64,
        configs: BTreeMap<String, EgressNodeConfig>,
    ) -> Result<(), String> {
        let graph = Arc::new(GraphEgress::try_from(configs)?);
        let mut generations = self.inner.write().expect("egress graph lock poisoned");
        generations.insert(generation, graph);
        while generations.len() > RETAINED_GENERATIONS {
            let oldest = *generations
                .keys()
                .next()
                .expect("installed egress generations are non-empty");
            generations.remove(&oldest);
        }
        Ok(())
    }

    pub fn remove(&self, generation: u64) {
        self.inner
            .write()
            .expect("egress graph lock poisoned")
            .remove(&generation);
    }

    pub fn generations(&self) -> Vec<u64> {
        self.inner
            .read()
            .expect("egress graph lock poisoned")
            .keys()
            .copied()
            .collect()
    }

    fn graph_for(&self, generation: u64) -> Result<Arc<GraphEgress>, EgressError> {
        self.inner
            .read()
            .expect("egress graph lock poisoned")
            .get(&generation)
            .cloned()
            .ok_or_else(|| {
                EgressError::new(
                    "egress-generation",
                    None,
                    format!("egress generation {generation} is no longer retained"),
                )
            })
    }
}

impl EgressNode for ReloadableEgress {
    fn tag(&self) -> &'static str {
        "reloadable-graph"
    }

    fn decision_tag(&self, decision: &SelectionDecision) -> &'static str {
        self.graph_for(decision.config_generation)
            .map_or(self.tag(), |graph| graph.decision_tag(decision))
    }

    async fn handle_tcp(&self, session: TcpRelaySession) -> Result<TcpRelayOutcome, EgressError> {
        self.graph_for(session.decision.config_generation)?
            .handle_tcp(session)
            .await
    }

    async fn handle_udp(
        &self,
        association: UdpRelayAssociation,
    ) -> Result<UdpRelayOutcome, EgressError> {
        self.graph_for(association.decision.config_generation)?
            .handle_udp(association)
            .await
    }
}
