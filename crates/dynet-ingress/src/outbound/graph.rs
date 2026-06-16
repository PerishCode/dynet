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
        let outbound = self.outbound_for_decision(&session.decision)?;
        if session.decision.trace.len() == 1 && session.decision.terminal.kind() == "direct" {
            return outbound.handle_tcp(session).await;
        }
        if session.decision.terminal.kind() == "direct" {
            return outbound.handle_tcp_direct(session).await;
        }
        Err(chained_error("TCP"))
    }

    async fn handle_udp(
        &self,
        association: UdpOutboundAssociation,
    ) -> Result<UdpOutboundOutcome, OutboundError> {
        reject_chained_udp(&association.decision)?;
        self.outbound_for_decision(&association.decision)?
            .handle_udp(association)
            .await
    }
}

fn reject_chained_udp(decision: &SelectionDecision) -> Result<(), OutboundError> {
    if decision.trace.len() == 1 && decision.terminal.kind() == "direct" {
        return Ok(());
    }
    Err(chained_error("UDP"))
}

fn chained_error(protocol: &str) -> OutboundError {
    OutboundError {
        stage: "outbound-select",
        upstream: None,
        message: format!("{protocol} chained graph execution is not implemented"),
    }
}
