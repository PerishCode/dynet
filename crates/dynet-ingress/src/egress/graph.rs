use std::collections::BTreeMap;

use dynet_runtime::SelectionDecision;

use crate::EgressNodeConfig;

use super::{
    DirectEgress, EgressError, EgressMedium, EgressNode, TcpRelayOutcome, TcpRelaySession,
    UdpRelayAssociation, UdpRelayOutcome,
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct GraphEgress {
    nodes: BTreeMap<String, EgressMedium>,
}

impl TryFrom<BTreeMap<String, EgressNodeConfig>> for GraphEgress {
    type Error = String;

    fn try_from(configs: BTreeMap<String, EgressNodeConfig>) -> Result<Self, Self::Error> {
        let mut nodes = BTreeMap::new();
        for (id, config) in configs {
            nodes.insert(id, EgressMedium::try_from(config)?);
        }
        Ok(Self { nodes })
    }
}

impl GraphEgress {
    fn egress_for_decision(
        &self,
        decision: &SelectionDecision,
    ) -> Result<&EgressMedium, EgressError> {
        self.nodes
            .get(decision.node_id.as_str())
            .ok_or_else(|| EgressError {
                stage: "egress-select",
                upstream: None,
                message: format!(
                    "selection node {} has no execution egress",
                    decision.node_id
                ),
            })
    }

    fn egress_for_node(&self, node_id: &str) -> Result<&EgressMedium, EgressError> {
        self.nodes.get(node_id).ok_or_else(|| EgressError {
            stage: "egress-select",
            upstream: None,
            message: format!("selection node {node_id} has no execution egress"),
        })
    }

    fn tcp_dialer_for_tail(
        &self,
        decision: &SelectionDecision,
    ) -> Result<&DirectEgress, EgressError> {
        for hop in decision.trace.iter().skip(1) {
            let egress = self.egress_for_node(hop.node_id.as_str())?;
            if egress.tcp_dialer().is_none() {
                return Err(EgressError {
                    stage: "egress-select",
                    upstream: None,
                    message: format!(
                        "TCP chained graph execution through node {} without TCP dialer is not implemented",
                        hop.node_id
                    ),
                });
            }
        }
        let tail = decision.trace.last().ok_or_else(|| chained_error("TCP"))?;
        self.egress_for_node(tail.node_id.as_str())?
            .tcp_dialer()
            .ok_or_else(|| EgressError {
                stage: "egress-select",
                upstream: None,
                message: format!(
                    "TCP chained graph tail node {} has no TCP dialer",
                    tail.node_id
                ),
            })
    }
}

impl EgressNode for GraphEgress {
    fn tag(&self) -> &'static str {
        "graph"
    }

    fn decision_tag(&self, decision: &SelectionDecision) -> &'static str {
        self.nodes
            .get(decision.node_id.as_str())
            .map_or(self.tag(), EgressMedium::tag)
    }

    async fn handle_tcp(&self, session: TcpRelaySession) -> Result<TcpRelayOutcome, EgressError> {
        let egress = self.egress_for_decision(&session.decision)?;
        if session.decision.trace.len() == 1 && session.decision.terminal.kind() == "direct" {
            return egress.handle_tcp(session).await;
        }
        if session.decision.terminal.kind() == "direct" {
            let dialer = self.tcp_dialer_for_tail(&session.decision)?;
            return egress.handle_tcp_with_dialer(session, dialer).await;
        }
        Err(chained_error("TCP"))
    }

    async fn handle_udp(
        &self,
        association: UdpRelayAssociation,
    ) -> Result<UdpRelayOutcome, EgressError> {
        reject_chained_udp(&association.decision)?;
        self.egress_for_decision(&association.decision)?
            .handle_udp(association)
            .await
    }
}

fn reject_chained_udp(decision: &SelectionDecision) -> Result<(), EgressError> {
    if decision.trace.len() == 1 && decision.terminal.kind() == "direct" {
        return Ok(());
    }
    Err(chained_error("UDP"))
}

fn chained_error(protocol: &str) -> EgressError {
    EgressError {
        stage: "egress-select",
        upstream: None,
        message: format!("{protocol} chained graph execution is not implemented"),
    }
}
