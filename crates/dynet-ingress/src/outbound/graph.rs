use std::collections::BTreeMap;

use dynet_runtime::SelectionDecision;

use crate::OutboundConfig;

use super::{
    DirectOutbound, Outbound, OutboundError, OutboundMedium, TcpOutboundOutcome,
    TcpOutboundSession, UdpOutboundAssociation, UdpOutboundOutcome,
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

    fn outbound_for_node(&self, node_id: &str) -> Result<&OutboundMedium, OutboundError> {
        self.nodes.get(node_id).ok_or_else(|| OutboundError {
            stage: "outbound-select",
            upstream: None,
            message: format!("selection node {node_id} has no execution outbound"),
        })
    }

    fn tcp_dialer_for_tail(
        &self,
        decision: &SelectionDecision,
    ) -> Result<&DirectOutbound, OutboundError> {
        for hop in decision.trace.iter().skip(1) {
            let outbound = self.outbound_for_node(hop.node_id.as_str())?;
            if outbound.tcp_dialer().is_none() {
                return Err(OutboundError {
                    stage: "outbound-select",
                    upstream: None,
                    message: format!(
                        "TCP chained graph execution through node {} without TCP dialer is not implemented",
                        hop.node_id
                    ),
                });
            }
        }
        let tail = decision.trace.last().ok_or_else(|| chained_error("TCP"))?;
        self.outbound_for_node(tail.node_id.as_str())?
            .tcp_dialer()
            .ok_or_else(|| OutboundError {
                stage: "outbound-select",
                upstream: None,
                message: format!(
                    "TCP chained graph tail node {} has no TCP dialer",
                    tail.node_id
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
            let dialer = self.tcp_dialer_for_tail(&session.decision)?;
            return outbound.handle_tcp_with_dialer(session, dialer).await;
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
