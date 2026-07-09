use std::{collections::BTreeMap, net::SocketAddr, sync::Arc};

use dynet_runtime::{
    InboundKind, RuntimeState, SelectionContext, SelectionDecision, TargetContext,
};
use tokio::{
    net::{TcpListener, UdpSocket},
    sync::{mpsc, Semaphore},
};

use crate::egress::{
    push_egress_error_fields, EgressError, EgressNode, TcpRelaySession, UdpDownstream,
    UdpRelayAssociation,
};
use crate::{
    push_decision_fields, push_target_context_fields, session_fields, IngressEventKind,
    TcpRelayConfig, UdpRelayConfig, DATAGRAM_LIMIT,
};

const TCP_INBOUND: &str = "tcp";
const UDP_INBOUND: &str = "udp";
const UDP_CHANNEL_DEPTH: usize = 64;

pub async fn run_tcp<O>(
    config: TcpRelayConfig,
    egress: O,
    runtime: RuntimeState,
) -> Result<(), String>
where
    O: EgressNode,
{
    let listener = TcpListener::bind(config.bind)
        .await
        .map_err(|error| format!("failed to bind TCP relay {}: {error}", config.bind))?;
    let capacity = Arc::new(Semaphore::new(config.max_sessions));
    loop {
        let (client, peer) = listener
            .accept()
            .await
            .map_err(|error| format!("failed accepting TCP connection: {error}"))?;
        let Ok(permit) = capacity.clone().try_acquire_owned() else {
            let session_id = runtime.events().next_session_id();
            let target = config.upstream;
            let mut fields =
                session_fields(session_id, TCP_INBOUND, egress.tag(), peer, target, target);
            fields.push(("errorStage", "inbound-capacity".to_string()));
            fields.push(("error", "TCP session limit reached".to_string()));
            fields.push(("maxSessions", config.max_sessions.to_string()));
            runtime.events().record(IngressEventKind::TcpError, fields);
            drop(client);
            continue;
        };
        let runtime = runtime.clone();
        let egress = egress.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let session_id = runtime.events().next_session_id();
            let target = config.upstream;
            let target_context = TargetContext::fixed_upstream(target);
            let decision = match runtime.select(SelectionContext {
                session_id,
                inbound: InboundKind::Tcp,
                target: target_context.clone(),
            }) {
                Ok(decision) => decision,
                Err(error) => {
                    let mut fields =
                        session_fields(session_id, TCP_INBOUND, egress.tag(), peer, target, target);
                    fields.push(("errorStage", "egress-select".to_string()));
                    fields.push(("error", error.to_string()));
                    runtime.events().record(IngressEventKind::TcpError, fields);
                    return;
                }
            };
            let node_protocol = egress.decision_tag(&decision);
            let mut fields =
                session_fields(session_id, TCP_INBOUND, node_protocol, peer, target, target);
            push_target_context_fields(&mut fields, &target_context);
            push_decision_fields(&mut fields, &decision);
            runtime.events().record(IngressEventKind::TcpAccept, fields);
            let session = TcpRelaySession {
                target,
                downstream: Box::new(client),
                decision: decision.clone(),
                idle_timeout: None,
            };
            match egress.handle_tcp(session).await {
                Ok(outcome) => {
                    let mut fields = session_fields(
                        session_id,
                        TCP_INBOUND,
                        node_protocol,
                        peer,
                        target,
                        outcome.upstream,
                    );
                    push_target_context_fields(&mut fields, &target_context);
                    push_decision_fields(&mut fields, &decision);
                    fields.push((
                        "clientToUpstreamBytes",
                        outcome.client_to_upstream_bytes.to_string(),
                    ));
                    fields.push((
                        "upstreamToClientBytes",
                        outcome.upstream_to_client_bytes.to_string(),
                    ));
                    fields.push(("closeReason", outcome.close_reason.to_string()));
                    runtime.events().record(IngressEventKind::TcpClose, fields);
                }
                Err(error) => {
                    runtime.events().record(
                        IngressEventKind::TcpError,
                        error_fields(
                            session_id,
                            TCP_INBOUND,
                            node_protocol,
                            peer,
                            target,
                            error,
                            Some(&decision),
                        ),
                    );
                }
            }
        });
    }
}

pub async fn run_udp<O>(
    config: UdpRelayConfig,
    egress: O,
    runtime: RuntimeState,
) -> Result<(), String>
where
    O: EgressNode,
{
    let socket = Arc::new(
        UdpSocket::bind(config.bind)
            .await
            .map_err(|error| format!("failed to bind UDP relay {}: {error}", config.bind))?,
    );
    let mut sessions = BTreeMap::<SocketAddr, UdpSessionSender>::new();
    let (complete_tx, mut complete_rx) = mpsc::channel::<SocketAddr>(UDP_CHANNEL_DEPTH);
    let mut buffer = vec![0_u8; DATAGRAM_LIMIT];
    loop {
        tokio::select! {
            completed = complete_rx.recv() => {
                if let Some(peer) = completed {
                    sessions.remove(&peer);
                }
            }
            received = socket.recv_from(&mut buffer) => {
                let (size, peer) = received
                    .map_err(|error| format!("failed receiving UDP datagram: {error}"))?;
                let payload = buffer[..size].to_vec();
                let sender = if let Some(sender) = sessions.get(&peer) {
                    sender.clone()
                } else {
                    if sessions.len() >= config.max_sessions {
                        let session_id = runtime.events().next_session_id();
                        let target = config.upstream;
                        let mut fields = session_fields(
                            session_id,
                            UDP_INBOUND,
                            egress.tag(),
                            peer,
                            target,
                            target,
                        );
                        fields.push(("errorStage", "inbound-capacity".to_string()));
                        fields.push(("error", "UDP session limit reached".to_string()));
                        fields.push(("maxSessions", config.max_sessions.to_string()));
                        runtime.events().record(IngressEventKind::UdpError, fields);
                        continue;
                    }
                    let (tx, rx) = mpsc::channel(UDP_CHANNEL_DEPTH);
                    let session_id = runtime.events().next_session_id();
                    let target = config.upstream;
                    let target_context = TargetContext::fixed_upstream(target);
                    let decision = match runtime.select(SelectionContext {
                        session_id,
                        inbound: InboundKind::Udp,
                        target: target_context.clone(),
                    }) {
                        Ok(decision) => decision,
                        Err(error) => {
                            let mut fields = session_fields(
                                session_id,
                                UDP_INBOUND,
                                egress.tag(),
                                peer,
                                target,
                                target,
                            );
                            fields.push(("errorStage", "egress-select".to_string()));
                            fields.push(("error", error.to_string()));
                            runtime.events().record(IngressEventKind::UdpError, fields);
                            continue;
                        }
                    };
                    let session = UdpSessionSender {
                        session_id,
                        decision: decision.clone(),
                        target_context: target_context.clone(),
                        node_protocol: egress.decision_tag(&decision),
                        tx,
                    };
                    sessions.insert(peer, session.clone());
                    spawn_udp_association(UdpAssociationTask {
                        peer,
                        config,
                    egress: egress.clone(),
                        downstream: socket.clone(),
                        downstream_rx: rx,
                        complete_tx: complete_tx.clone(),
                        session_id: session.session_id,
                        decision,
                        target_context,
                        runtime: runtime.clone(),
                    });
                    session
                };
                let target = config.upstream;
                let mut fields = session_fields(
                    sender.session_id,
                    UDP_INBOUND,
                    sender.node_protocol,
                    peer,
                    target,
                    target,
                );
                push_target_context_fields(&mut fields, &sender.target_context);
                push_decision_fields(&mut fields, &sender.decision);
                fields.push(("direction", "client-to-upstream".to_string()));
                fields.push(("bytes", size.to_string()));
                runtime.events().record(IngressEventKind::UdpDatagram, fields);
                if sender.tx.send(payload).await.is_err() {
                    sessions.remove(&peer);
                }
            }
        }
    }
}

struct UdpAssociationTask<O> {
    peer: SocketAddr,
    config: UdpRelayConfig,
    egress: O,
    downstream: Arc<UdpSocket>,
    downstream_rx: mpsc::Receiver<Vec<u8>>,
    complete_tx: mpsc::Sender<SocketAddr>,
    session_id: u64,
    decision: SelectionDecision,
    target_context: TargetContext,
    runtime: RuntimeState,
}

fn spawn_udp_association<O>(task: UdpAssociationTask<O>)
where
    O: EgressNode,
{
    tokio::spawn(async move {
        let UdpAssociationTask {
            peer,
            config,
            egress,
            downstream,
            downstream_rx,
            complete_tx,
            session_id,
            decision,
            target_context,
            runtime,
        } = task;
        let target = config.upstream;
        let node_protocol = egress.decision_tag(&decision);
        let mut fields =
            session_fields(session_id, UDP_INBOUND, node_protocol, peer, target, target);
        push_target_context_fields(&mut fields, &target_context);
        push_decision_fields(&mut fields, &decision);
        runtime
            .events()
            .record(IngressEventKind::UdpSessionStart, fields);
        let association = UdpRelayAssociation {
            session_id,
            inbound: UDP_INBOUND,
            peer,
            target,
            idle_timeout: config.idle_timeout,
            downstream: UdpDownstream::Raw(downstream),
            downstream_rx,
            decision: decision.clone(),
            runtime: runtime.clone(),
        };
        match egress.handle_udp(association).await {
            Ok(outcome) => {
                let mut fields = session_fields(
                    session_id,
                    UDP_INBOUND,
                    node_protocol,
                    peer,
                    target,
                    outcome.upstream,
                );
                push_target_context_fields(&mut fields, &target_context);
                push_decision_fields(&mut fields, &decision);
                fields.push(("closeReason", outcome.close_reason.to_string()));
                runtime
                    .events()
                    .record(IngressEventKind::UdpSessionClose, fields);
            }
            Err(error) => {
                runtime.events().record(
                    IngressEventKind::UdpError,
                    error_fields(
                        session_id,
                        UDP_INBOUND,
                        node_protocol,
                        peer,
                        target,
                        error,
                        Some(&decision),
                    ),
                );
                let mut fields =
                    session_fields(session_id, UDP_INBOUND, node_protocol, peer, target, target);
                push_target_context_fields(&mut fields, &target_context);
                push_decision_fields(&mut fields, &decision);
                fields.push(("closeReason", "error".to_string()));
                runtime
                    .events()
                    .record(IngressEventKind::UdpSessionClose, fields);
            }
        }
        let _ = complete_tx.send(peer).await;
    });
}

fn error_fields(
    session_id: u64,
    inbound: &'static str,
    egress: &'static str,
    peer: SocketAddr,
    target: SocketAddr,
    error: EgressError,
    decision: Option<&SelectionDecision>,
) -> Vec<(&'static str, String)> {
    let upstream = error.upstream.unwrap_or(target);
    let mut fields = session_fields(session_id, inbound, egress, peer, target, upstream);
    if let Some(decision) = decision {
        push_decision_fields(&mut fields, decision);
    }
    push_egress_error_fields(&mut fields, egress, &error);
    fields
}

#[derive(Clone)]
struct UdpSessionSender {
    session_id: u64,
    decision: SelectionDecision,
    target_context: TargetContext,
    node_protocol: &'static str,
    tx: mpsc::Sender<Vec<u8>>,
}
