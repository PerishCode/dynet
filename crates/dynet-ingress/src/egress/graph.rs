use std::collections::BTreeMap;

use dynet_runtime::SelectionDecision;

use crate::EgressNodeConfig;

use super::{
    EgressError, EgressMedium, EgressNode, TcpDialerMedium, TcpRelayOutcome, TcpRelaySession,
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
    fn final_egress_for_decision(
        &self,
        decision: &SelectionDecision,
    ) -> Result<&EgressMedium, EgressError> {
        let hop = decision.trace.last().ok_or_else(|| chained_error("TCP"))?;
        self.nodes
            .get(hop.node_id.as_str())
            .ok_or_else(|| EgressError {
                stage: "egress-select",
                upstream: None,
                message: format!("selection node {} has no execution egress", hop.node_id),
            })
    }

    fn egress_for_node(&self, node_id: &str) -> Result<&EgressMedium, EgressError> {
        self.nodes.get(node_id).ok_or_else(|| EgressError {
            stage: "egress-select",
            upstream: None,
            message: format!("selection node {node_id} has no execution egress"),
        })
    }

    fn tcp_dialer_for_head(
        &self,
        decision: &SelectionDecision,
    ) -> Result<TcpDialerMedium<'_>, EgressError> {
        if decision.trace.len() != 2 {
            return Err(EgressError {
                stage: "egress-select",
                upstream: None,
                message: format!(
                    "TCP graph execution supports exactly one dialer hop, got {} hops",
                    decision.trace.len()
                ),
            });
        }
        let head = decision.trace.first().ok_or_else(|| chained_error("TCP"))?;
        self.egress_for_node(head.node_id.as_str())?
            .tcp_dialer()
            .ok_or_else(|| EgressError {
                stage: "egress-select",
                upstream: None,
                message: format!(
                    "TCP chained graph dialer node {} has no TCP dialer",
                    head.node_id
                ),
            })
    }
}

impl EgressNode for GraphEgress {
    fn tag(&self) -> &'static str {
        "graph"
    }

    fn decision_tag(&self, decision: &SelectionDecision) -> &'static str {
        self.final_egress_for_decision(decision)
            .map_or(self.tag(), EgressMedium::tag)
    }

    async fn handle_tcp(&self, session: TcpRelaySession) -> Result<TcpRelayOutcome, EgressError> {
        let egress = self.final_egress_for_decision(&session.decision)?;
        if session.decision.trace.len() == 1 && session.decision.terminal.kind() == "direct" {
            return egress.handle_tcp(session).await;
        }
        if session.decision.terminal.kind() == "direct" {
            let dialer = self.tcp_dialer_for_head(&session.decision)?;
            return egress.handle_tcp_with_dialer(session, &dialer).await;
        }
        Err(chained_error("TCP"))
    }

    async fn handle_udp(
        &self,
        association: UdpRelayAssociation,
    ) -> Result<UdpRelayOutcome, EgressError> {
        reject_chained_udp(&association.decision)?;
        self.final_egress_for_decision(&association.decision)?
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
