use std::{collections::BTreeMap, net::SocketAddr, sync::Arc};

use dynet_runtime::{InboundKind, RuntimeState, SelectionContext, TargetContext};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{mpsc, Semaphore},
};

use crate::{
    egress::{EgressNode, TcpRelaySession, UdpDownstream, UdpRelayAssociation},
    push_decision_fields, push_endpoint_fields, push_target_context_fields, IngressEventKind,
    Socks5IngressConfig, DATAGRAM_LIMIT,
};
mod events;
mod protocol;
use events::{
    base_socks_fields, egress_error_fields, record_socks_error, socks_session_fields,
    SOCKS5_INBOUND,
};
use protocol::{
    negotiate_no_auth, parse_udp_packet, read_request, write_reply, SocksDestination, SocksError,
    SocksRequest, SOCKS_CMD_BIND, SOCKS_CMD_CONNECT, SOCKS_CMD_UDP_ASSOCIATE,
    SOCKS_REPLY_COMMAND_NOT_SUPPORTED, SOCKS_REPLY_SUCCEEDED,
};
const UDP_CHANNEL_DEPTH: usize = 64;

pub async fn run_socks5<O>(
    config: Socks5IngressConfig,
    egress: O,
    runtime: RuntimeState,
) -> Result<(), String>
where
    O: EgressNode,
{
    let listener = TcpListener::bind(config.bind)
        .await
        .map_err(|error| format!("failed to bind SOCKS5 ingress {}: {error}", config.bind))?;
    let capacity = Arc::new(Semaphore::new(config.max_sessions));
    loop {
        let (client, peer) = listener
            .accept()
            .await
            .map_err(|error| format!("failed accepting SOCKS5 connection: {error}"))?;
        let Ok(permit) = capacity.clone().try_acquire_owned() else {
            let session_id = runtime.events().next_session_id();
            record_socks_error(
                &runtime,
                session_id,
                peer,
                "inbound-capacity",
                "SOCKS5 session limit reached",
            );
            drop(client);
            continue;
        };
        let egress = egress.clone();
        let runtime = runtime.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let session_id = runtime.events().next_session_id();
            if let Err(error) =
                handle_client(client, peer, config, egress, runtime.clone(), session_id).await
            {
                record_socks_error(
                    &runtime,
                    session_id,
                    peer,
                    error.stage,
                    error.message.as_str(),
                );
            }
        });
    }
}

async fn handle_client<O>(
    mut client: TcpStream,
    peer: SocketAddr,
    config: Socks5IngressConfig,
    egress: O,
    runtime: RuntimeState,
    session_id: u64,
) -> Result<(), SocksError>
where
    O: EgressNode,
{
    negotiate_no_auth(&mut client).await?;
    let request = read_request(&mut client).await?;
    match request.command {
        SOCKS_CMD_CONNECT => {
            handle_connect(client, peer, egress, runtime, session_id, request).await
        }
        SOCKS_CMD_UDP_ASSOCIATE => {
            handle_udp_associate(client, peer, config, egress, runtime, session_id).await
        }
        SOCKS_CMD_BIND => {
            write_reply(
                &mut client,
                SOCKS_REPLY_COMMAND_NOT_SUPPORTED,
                SocketAddr::from(([0, 0, 0, 0], 0)),
            )
            .await?;
            Err(SocksError::new(
                "socks-request",
                "SOCKS5 BIND is not supported",
            ))
        }
        _ => {
            write_reply(
                &mut client,
                SOCKS_REPLY_COMMAND_NOT_SUPPORTED,
                SocketAddr::from(([0, 0, 0, 0], 0)),
            )
            .await?;
            Err(SocksError::new(
                "socks-request",
                "SOCKS5 command is not supported",
            ))
        }
    }
}

async fn handle_connect<O>(
    mut client: TcpStream,
    peer: SocketAddr,
    egress: O,
    runtime: RuntimeState,
    session_id: u64,
    request: SocksRequest,
) -> Result<(), SocksError>
where
    O: EgressNode,
{
    let target_context = resolve_destination(&runtime, &request.destination).await?;
    let target = target_context.address;
    let decision = select_target(
        &runtime,
        session_id,
        InboundKind::Tcp,
        target_context.clone(),
    )?;
    write_reply(
        &mut client,
        SOCKS_REPLY_SUCCEEDED,
        SocketAddr::from(([0, 0, 0, 0], 0)),
    )
    .await?;
    let node_protocol = egress.decision_tag(&decision);
    let mut fields = socks_session_fields(
        session_id,
        node_protocol,
        peer,
        target,
        &request.destination,
    );
    push_target_context_fields(&mut fields, &target_context);
    push_decision_fields(&mut fields, &decision);
    runtime.events().record(IngressEventKind::TcpAccept, fields);
    let session = TcpRelaySession {
        target,
        downstream: client,
        decision: decision.clone(),
    };
    match egress.handle_tcp(session).await {
        Ok(outcome) => {
            let mut fields = socks_session_fields(
                session_id,
                node_protocol,
                peer,
                target,
                &request.destination,
            );
            push_target_context_fields(&mut fields, &target_context);
            push_decision_fields(&mut fields, &decision);
            fields.push(("upstream", outcome.upstream.to_string()));
            push_endpoint_fields(&mut fields, "upstream", outcome.upstream);
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
            Ok(())
        }
        Err(error) => {
            runtime.events().record(
                IngressEventKind::TcpError,
                egress_error_fields(
                    session_id,
                    node_protocol,
                    peer,
                    target,
                    &request.destination,
                    error,
                    Some(&decision),
                ),
            );
            Ok(())
        }
    }
}

async fn handle_udp_associate<O>(
    mut control: TcpStream,
    peer: SocketAddr,
    config: Socks5IngressConfig,
    egress: O,
    runtime: RuntimeState,
    session_id: u64,
) -> Result<(), SocksError>
where
    O: EgressNode,
{
    let downstream = Arc::new(
        UdpSocket::bind(SocketAddr::new(config.bind.ip(), 0))
            .await
            .map_err(|error| {
                SocksError::with_source(
                    "socks-udp-bind",
                    "failed binding UDP associate socket",
                    error,
                )
            })?,
    );
    let bind = downstream.local_addr().map_err(|error| {
        SocksError::with_source("socks-udp-bind", "failed reading UDP associate bind", error)
    })?;
    let advertised_bind =
        SocketAddr::new(config.udp_advertise_ip.unwrap_or(bind.ip()), bind.port());
    write_reply(&mut control, SOCKS_REPLY_SUCCEEDED, advertised_bind).await?;
    let mut fields = base_socks_fields(session_id, egress.tag(), peer);
    fields.push(("udpBind", advertised_bind.to_string()));
    fields.push(("udpListen", bind.to_string()));
    push_endpoint_fields(&mut fields, "upstream", advertised_bind);
    runtime
        .events()
        .record(IngressEventKind::UdpSessionStart, fields);
    let completion = spawn_udp_control_watch(control);
    run_socks_udp_loop(SocksUdpLoop {
        downstream,
        egress,
        runtime,
        config,
        peer,
        session_id,
        completion,
    })
    .await
}

fn spawn_udp_control_watch(mut control: TcpStream) -> mpsc::Receiver<()> {
    let (tx, rx) = mpsc::channel(1);
    tokio::spawn(async move {
        let mut buffer = [0_u8; 1];
        let _ = control.read(&mut buffer).await;
        let _ = tx.send(()).await;
    });
    rx
}

struct SocksUdpLoop<O> {
    downstream: Arc<UdpSocket>,
    egress: O,
    runtime: RuntimeState,
    config: Socks5IngressConfig,
    peer: SocketAddr,
    session_id: u64,
    completion: mpsc::Receiver<()>,
}

async fn run_socks_udp_loop<O>(mut task: SocksUdpLoop<O>) -> Result<(), SocksError>
where
    O: EgressNode,
{
    let mut associations = BTreeMap::<(SocketAddr, SocketAddr), UdpAssociationSender>::new();
    let (complete_tx, mut complete_rx) =
        mpsc::channel::<(SocketAddr, SocketAddr)>(UDP_CHANNEL_DEPTH);
    let mut buffer = vec![0_u8; DATAGRAM_LIMIT];
    loop {
        tokio::select! {
            _ = task.completion.recv() => {
                return Ok(());
            }
            completed = complete_rx.recv() => {
                if let Some(key) = completed {
                    associations.remove(&key);
                }
            }
            received = task.downstream.recv_from(&mut buffer) => {
                let (size, udp_peer) = received
                    .map_err(|error| SocksError::with_source("socks-udp-read", "failed receiving SOCKS5 UDP datagram", error))?;
                let packet = parse_udp_packet(&buffer[..size])?;
                let target_context = resolve_destination(&task.runtime, &packet.destination).await?;
                let target = target_context.address;
                let response_target = response_target_for_destination(&packet.destination, target);
                let key = (udp_peer, target);
                let sender = if let Some(sender) = associations.get(&key) {
                    sender.clone()
                } else {
                    let decision =
                        select_target(&task.runtime, task.session_id, InboundKind::Udp, target_context.clone())?;
                    let (tx, rx) = mpsc::channel(UDP_CHANNEL_DEPTH);
                    let sender = UdpAssociationSender {
                        node_protocol: task.egress.decision_tag(&decision),
                        decision: decision.clone(),
                        target_context: target_context.clone(),
                        tx,
                    };
                    associations.insert(key, sender.clone());
                    spawn_socks_udp_association(SocksUdpAssociationTask {
                        udp_peer,
                        target,
                        target_context: target_context.clone(),
                        response_target,
                        destination: packet.destination.clone(),
                        downstream: task.downstream.clone(),
                        downstream_rx: rx,
                        complete_tx: complete_tx.clone(),
                        session_id: task.session_id,
                        decision,
                        runtime: task.runtime.clone(),
                        egress: task.egress.clone(),
                        idle_timeout: task.config.idle_timeout,
                    });
                    sender
                };
                let mut fields = socks_session_fields(
                    task.session_id,
                    sender.node_protocol,
                    task.peer,
                    target,
                    &packet.destination,
                );
                push_target_context_fields(&mut fields, &sender.target_context);
                push_decision_fields(&mut fields, &sender.decision);
                fields.push(("udpPeer", udp_peer.to_string()));
                fields.push(("direction", "client-to-upstream".to_string()));
                fields.push(("bytes", packet.payload.len().to_string()));
                task.runtime.events().record(IngressEventKind::UdpDatagram, fields);
                if sender.tx.send(packet.payload).await.is_err() {
                    associations.remove(&key);
                }
            }
        }
    }
}

struct SocksUdpAssociationTask<O> {
    udp_peer: SocketAddr,
    target: SocketAddr,
    target_context: TargetContext,
    response_target: SocketAddr,
    destination: SocksDestination,
    downstream: Arc<UdpSocket>,
    downstream_rx: mpsc::Receiver<Vec<u8>>,
    complete_tx: mpsc::Sender<(SocketAddr, SocketAddr)>,
    session_id: u64,
    decision: dynet_runtime::SelectionDecision,
    runtime: RuntimeState,
    egress: O,
    idle_timeout: std::time::Duration,
}

fn spawn_socks_udp_association<O>(task: SocksUdpAssociationTask<O>)
where
    O: EgressNode,
{
    tokio::spawn(async move {
        let SocksUdpAssociationTask {
            udp_peer,
            target,
            target_context,
            response_target,
            destination,
            downstream,
            downstream_rx,
            complete_tx,
            session_id,
            decision,
            runtime,
            egress,
            idle_timeout,
        } = task;
        let node_protocol = egress.decision_tag(&decision);
        let association = UdpRelayAssociation {
            session_id,
            inbound: SOCKS5_INBOUND,
            peer: udp_peer,
            target,
            idle_timeout,
            downstream: UdpDownstream::Socks5 {
                socket: downstream,
                response_target,
            },
            downstream_rx,
            decision: decision.clone(),
            runtime: runtime.clone(),
        };
        match egress.handle_udp(association).await {
            Ok(outcome) => {
                let mut fields =
                    socks_session_fields(session_id, node_protocol, udp_peer, target, &destination);
                push_target_context_fields(&mut fields, &target_context);
                push_decision_fields(&mut fields, &decision);
                fields.push(("upstream", outcome.upstream.to_string()));
                push_endpoint_fields(&mut fields, "upstream", outcome.upstream);
                fields.push(("closeReason", outcome.close_reason.to_string()));
                runtime
                    .events()
                    .record(IngressEventKind::UdpSessionClose, fields);
            }
            Err(error) => {
                runtime.events().record(
                    IngressEventKind::UdpError,
                    egress_error_fields(
                        session_id,
                        node_protocol,
                        udp_peer,
                        target,
                        &destination,
                        error,
                        Some(&decision),
                    ),
                );
            }
        }
        let _ = complete_tx.send((udp_peer, target)).await;
    });
}

fn select_target(
    runtime: &RuntimeState,
    session_id: u64,
    inbound: InboundKind,
    target: TargetContext,
) -> Result<dynet_runtime::SelectionDecision, SocksError> {
    runtime
        .select(SelectionContext {
            session_id,
            inbound,
            target,
        })
        .map_err(|error| SocksError::new("egress-select", error.to_string()))
}

async fn resolve_destination(
    runtime: &RuntimeState,
    destination: &SocksDestination,
) -> Result<TargetContext, SocksError> {
    match destination {
        SocksDestination::Socket(address) => {
            Ok(resolve_socket_destination(runtime, *address).await)
        }
        SocksDestination::Domain { domain, port } => {
            let address = runtime
                .resolve_domain_a(domain, *port)
                .await
                .map_err(|error| {
                    SocksError::new(
                        "socks-resolve",
                        format!("failed resolving {domain}:{port}: {error}"),
                    )
                })?;
            Ok(TargetContext::dynet_dns(address, domain.clone()))
        }
    }
}

async fn resolve_socket_destination(runtime: &RuntimeState, address: SocketAddr) -> TargetContext {
    let Some(domain) = runtime.dns_map().domain_for_ip(address.ip()) else {
        return TargetContext::external_context(address, None);
    };
    match runtime.resolve_domain_a(&domain, address.port()).await {
        Ok(restored) => TargetContext::dynet_dns(restored, domain),
        Err(_) => TargetContext::external_context(address, Some(domain)),
    }
}

fn response_target_for_destination(
    destination: &SocksDestination,
    target: SocketAddr,
) -> SocketAddr {
    match destination {
        SocksDestination::Socket(address) => *address,
        SocksDestination::Domain { .. } => target,
    }
}

#[derive(Debug, Clone)]
struct UdpAssociationSender {
    node_protocol: &'static str,
    decision: dynet_runtime::SelectionDecision,
    target_context: TargetContext,
    tx: mpsc::Sender<Vec<u8>>,
}
