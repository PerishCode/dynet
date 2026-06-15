use std::{collections::BTreeMap, net::SocketAddr, sync::Arc};

use tokio::{
    net::{TcpListener, UdpSocket},
    sync::{mpsc, Semaphore},
};

use crate::outbound::{Outbound, OutboundError, TcpOutboundSession, UdpOutboundAssociation};
use crate::{
    session_fields, EventStore, IngressEventKind, TcpRelayConfig, UdpRelayConfig, DATAGRAM_LIMIT,
};

const TCP_INBOUND: &str = "tcp";
const UDP_INBOUND: &str = "udp";
const UDP_CHANNEL_DEPTH: usize = 64;

pub async fn run_tcp<O>(
    config: TcpRelayConfig,
    outbound: O,
    events: EventStore,
) -> Result<(), String>
where
    O: Outbound,
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
            let session_id = events.next_session_id();
            let target = config.upstream;
            let mut fields = session_fields(
                session_id,
                TCP_INBOUND,
                outbound.tag(),
                peer,
                target,
                target,
            );
            fields.push(("errorStage", "inbound-capacity".to_string()));
            fields.push(("error", "TCP session limit reached".to_string()));
            fields.push(("maxSessions", config.max_sessions.to_string()));
            events.record(IngressEventKind::TcpError, fields);
            drop(client);
            continue;
        };
        let events = events.clone();
        let outbound = outbound.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let session_id = events.next_session_id();
            let target = config.upstream;
            events.record(
                IngressEventKind::TcpAccept,
                session_fields(
                    session_id,
                    TCP_INBOUND,
                    outbound.tag(),
                    peer,
                    target,
                    target,
                ),
            );
            let session = TcpOutboundSession {
                target,
                downstream: client,
            };
            match outbound.handle_tcp(session).await {
                Ok(outcome) => {
                    let mut fields = session_fields(
                        session_id,
                        TCP_INBOUND,
                        outbound.tag(),
                        peer,
                        target,
                        outcome.upstream,
                    );
                    fields.push((
                        "clientToUpstreamBytes",
                        outcome.client_to_upstream_bytes.to_string(),
                    ));
                    fields.push((
                        "upstreamToClientBytes",
                        outcome.upstream_to_client_bytes.to_string(),
                    ));
                    fields.push(("closeReason", outcome.close_reason.to_string()));
                    events.record(IngressEventKind::TcpClose, fields);
                }
                Err(error) => {
                    events.record(
                        IngressEventKind::TcpError,
                        error_fields(session_id, TCP_INBOUND, outbound.tag(), peer, target, error),
                    );
                }
            }
        });
    }
}

pub async fn run_udp<O>(
    config: UdpRelayConfig,
    outbound: O,
    events: EventStore,
) -> Result<(), String>
where
    O: Outbound,
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
                        let session_id = events.next_session_id();
                        let target = config.upstream;
                        let mut fields = session_fields(
                            session_id,
                            UDP_INBOUND,
                            outbound.tag(),
                            peer,
                            target,
                            target,
                        );
                        fields.push(("errorStage", "inbound-capacity".to_string()));
                        fields.push(("error", "UDP session limit reached".to_string()));
                        fields.push(("maxSessions", config.max_sessions.to_string()));
                        events.record(IngressEventKind::UdpError, fields);
                        continue;
                    }
                    let (tx, rx) = mpsc::channel(UDP_CHANNEL_DEPTH);
                    let session = UdpSessionSender {
                        session_id: events.next_session_id(),
                        tx,
                    };
                    sessions.insert(peer, session.clone());
                    spawn_udp_association(UdpAssociationTask {
                        peer,
                        config,
                        outbound: outbound.clone(),
                        downstream: socket.clone(),
                        downstream_rx: rx,
                        complete_tx: complete_tx.clone(),
                        session_id: session.session_id,
                        events: events.clone(),
                    });
                    session
                };
                let target = config.upstream;
                let mut fields = session_fields(
                    sender.session_id,
                    UDP_INBOUND,
                    outbound.tag(),
                    peer,
                    target,
                    target,
                );
                fields.push(("direction", "client-to-upstream".to_string()));
                fields.push(("bytes", size.to_string()));
                events.record(IngressEventKind::UdpDatagram, fields);
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
    outbound: O,
    downstream: Arc<UdpSocket>,
    downstream_rx: mpsc::Receiver<Vec<u8>>,
    complete_tx: mpsc::Sender<SocketAddr>,
    session_id: u64,
    events: EventStore,
}

fn spawn_udp_association<O>(task: UdpAssociationTask<O>)
where
    O: Outbound,
{
    tokio::spawn(async move {
        let UdpAssociationTask {
            peer,
            config,
            outbound,
            downstream,
            downstream_rx,
            complete_tx,
            session_id,
            events,
        } = task;
        let target = config.upstream;
        events.record(
            IngressEventKind::UdpSessionStart,
            session_fields(
                session_id,
                UDP_INBOUND,
                outbound.tag(),
                peer,
                target,
                target,
            ),
        );
        let association = UdpOutboundAssociation {
            session_id,
            inbound: UDP_INBOUND,
            peer,
            target,
            idle_timeout: config.idle_timeout,
            downstream,
            downstream_rx,
            events: events.clone(),
        };
        match outbound.handle_udp(association).await {
            Ok(outcome) => {
                let mut fields = session_fields(
                    session_id,
                    UDP_INBOUND,
                    outbound.tag(),
                    peer,
                    target,
                    outcome.upstream,
                );
                fields.push(("closeReason", outcome.close_reason.to_string()));
                events.record(IngressEventKind::UdpSessionClose, fields);
            }
            Err(error) => {
                events.record(
                    IngressEventKind::UdpError,
                    error_fields(session_id, UDP_INBOUND, outbound.tag(), peer, target, error),
                );
                let mut fields = session_fields(
                    session_id,
                    UDP_INBOUND,
                    outbound.tag(),
                    peer,
                    target,
                    target,
                );
                fields.push(("closeReason", "error".to_string()));
                events.record(IngressEventKind::UdpSessionClose, fields);
            }
        }
        let _ = complete_tx.send(peer).await;
    });
}

fn error_fields(
    session_id: u64,
    inbound: &'static str,
    outbound: &'static str,
    peer: SocketAddr,
    target: SocketAddr,
    error: OutboundError,
) -> Vec<(&'static str, String)> {
    let upstream = error.upstream.unwrap_or(target);
    let mut fields = session_fields(session_id, inbound, outbound, peer, target, upstream);
    fields.push(("errorStage", error.stage.to_string()));
    fields.push(("error", error.message));
    fields
}

#[derive(Clone)]
struct UdpSessionSender {
    session_id: u64,
    tx: mpsc::Sender<Vec<u8>>,
}
