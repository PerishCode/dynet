use std::collections::BTreeMap;

use dynet_runtime::SelectionDecision;

use crate::OutboundConfig;

use super::{
    Outbound, OutboundError, OutboundMedium, TcpOutboundOutcome, TcpOutboundSession,
    UdpOutboundAssociation, UdpOutboundOutcome,
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct GraphOutbound {
    nodes: BTreeMap<String, OutboundMedium>,
}

impl TryFrom<BTreeMap<String, OutboundConfig>> for GraphOutbound {
    type Error = String;

    fn try_from(configs: BTreeMap<String, OutboundConfig>) -> Result<Self, Self::Error> {
        let mut nodes = BTreeMap::new();
        for (id, config) in configs {
            nodes.insert(id, OutboundMedium::try_from(config)?);
        }
        Ok(Self { nodes })
    }
}

impl GraphOutbound {
    fn outbound_for_decision(
        &self,
        decision: &SelectionDecision,
    ) -> Result<&OutboundMedium, OutboundError> {
        self.nodes
            .get(decision.node_id.as_str())
            .ok_or_else(|| OutboundError {
                stage: "outbound-select",
                upstream: None,
                message: format!(
                    "selection node {} has no execution outbound",
                    decision.node_id
                ),
            })
    }
}

impl Outbound for GraphOutbound {
    fn tag(&self) -> &'static str {
        "graph"
    }

    fn decision_tag(&self, decision: &SelectionDecision) -> &'static str {
        self.nodes
            .get(decision.node_id.as_str())
            .map_or(self.tag(), OutboundMedium::tag)
    }

    async fn handle_tcp(
        &self,
        session: TcpOutboundSession,
    ) -> Result<TcpOutboundOutcome, OutboundError> {
        self.outbound_for_decision(&session.decision)?
            .handle_tcp(session)
            .await
    }

    async fn handle_udp(
        &self,
        association: UdpOutboundAssociation,
    ) -> Result<UdpOutboundOutcome, OutboundError> {
        self.outbound_for_decision(&association.decision)?
            .handle_udp(association)
            .await
    }
}
