use std::{collections::BTreeMap, net::SocketAddr, time::Duration};

use dynet_runtime::{
    InboundKind, RuntimeState, SelectionContext, SelectionDecision, TargetContext,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::mpsc,
    task::JoinHandle,
    time,
};

use crate::{
    egress::{
        push_egress_error_fields, EgressError, EgressNode, GraphEgress, TcpRelayOutcome,
        TcpRelaySession, UdpDownstream, UdpRelayAssociation, UdpRelayOutcome,
    },
    push_decision_fields, push_endpoint_fields, push_target_context_fields, session_fields,
    EgressNodeConfig, IngressEventKind, ReloadableEgress, DATAGRAM_LIMIT,
};

const TUN_INBOUND: &str = "tun";
const UDP_CHANNEL_DEPTH: usize = 4;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct CapturedTcpRelayOutcome {
    pub session_id: u64,
    pub target: SocketAddr,
    pub upstream: SocketAddr,
    pub client_to_upstream_bytes: u64,
    pub upstream_to_client_bytes: u64,
    pub close_reason: &'static str,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct CapturedUdpRelayOutcome {
    pub session_id: u64,
    pub target: SocketAddr,
    pub upstream: SocketAddr,
    pub request_bytes: usize,
    pub response_bytes: usize,
    pub close_reason: &'static str,
}

pub async fn relay_captured_tcp_graph<S>(
    stream: S,
    peer: SocketAddr,
    target: SocketAddr,
    egress_nodes: BTreeMap<String, EgressNodeConfig>,
    runtime: RuntimeState,
    idle_timeout: Duration,
) -> Result<CapturedTcpRelayOutcome, String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let egress = GraphEgress::try_from(egress_nodes)?;
    relay_captured_tcp(stream, peer, target, egress, runtime, idle_timeout).await
}

pub async fn relay_captured_tcp_reloadable<S>(
    stream: S,
    peer: SocketAddr,
    target: SocketAddr,
    egress: ReloadableEgress,
    runtime: RuntimeState,
    idle_timeout: Duration,
) -> Result<CapturedTcpRelayOutcome, String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    relay_captured_tcp(stream, peer, target, egress, runtime, idle_timeout).await
}

async fn relay_captured_tcp<S, O>(
    stream: S,
    peer: SocketAddr,
    target: SocketAddr,
    egress: O,
    runtime: RuntimeState,
    idle_timeout: Duration,
) -> Result<CapturedTcpRelayOutcome, String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    O: EgressNode,
{
    let session_id = runtime.events().next_session_id();
    let target_context = resolve_socket_destination(&runtime, target).await;
    let decision = match select_target(
        &runtime,
        session_id,
        InboundKind::Tcp,
        target_context.clone(),
    ) {
        Ok(decision) => decision,
        Err(error) => {
            runtime.events().record(
                IngressEventKind::TcpError,
                selection_error_fields(session_id, peer, target, &error),
            );
            return Err(error.to_string());
        }
    };
    let node_protocol = egress.decision_tag(&decision);
    let mut fields = session_fields(session_id, TUN_INBOUND, node_protocol, peer, target, target);
    push_target_context_fields(&mut fields, &target_context);
    push_decision_fields(&mut fields, &decision);
    runtime.events().record(IngressEventKind::TcpAccept, fields);

    let session = TcpRelaySession {
        target,
        downstream: Box::new(stream),
        decision: decision.clone(),
        idle_timeout: Some(idle_timeout),
    };
    match egress.handle_tcp(session).await {
        Ok(outcome) => Ok(tcp_close_outcome(
            TcpCaptureCtx {
                runtime: &runtime,
                target_context: &target_context,
                decision: &decision,
                session_id,
                node_protocol,
                peer,
                target,
            },
            outcome,
        )),
        Err(error) => {
            let message = error.message.clone();
            runtime.events().record(
                IngressEventKind::TcpError,
                captured_error_fields(
                    session_id,
                    node_protocol,
                    peer,
                    target,
                    &target_context,
                    error,
                    Some(&decision),
                ),
            );
            Err(message)
        }
    }
}

struct TcpCaptureCtx<'a> {
    runtime: &'a RuntimeState,
    target_context: &'a TargetContext,
    decision: &'a SelectionDecision,
    session_id: u64,
    node_protocol: &'static str,
    peer: SocketAddr,
    target: SocketAddr,
}

fn tcp_close_outcome(ctx: TcpCaptureCtx<'_>, outcome: TcpRelayOutcome) -> CapturedTcpRelayOutcome {
    let mut fields = session_fields(
        ctx.session_id,
        TUN_INBOUND,
        ctx.node_protocol,
        ctx.peer,
        ctx.target,
        outcome.upstream,
    );
    push_target_context_fields(&mut fields, ctx.target_context);
    push_decision_fields(&mut fields, ctx.decision);
    fields.push((
        "clientToUpstreamBytes",
        outcome.client_to_upstream_bytes.to_string(),
    ));
    fields.push((
        "upstreamToClientBytes",
        outcome.upstream_to_client_bytes.to_string(),
    ));
    fields.push(("closeReason", outcome.close_reason.to_string()));
    ctx.runtime
        .events()
        .record(IngressEventKind::TcpClose, fields);
    CapturedTcpRelayOutcome {
        session_id: ctx.session_id,
        target: ctx.target,
        upstream: outcome.upstream,
        client_to_upstream_bytes: outcome.client_to_upstream_bytes,
        upstream_to_client_bytes: outcome.upstream_to_client_bytes,
        close_reason: outcome.close_reason,
    }
}
pub async fn relay_captured_udp_graph<S>(
    stream: S,
    peer: SocketAddr,
    target: SocketAddr,
    egress_nodes: BTreeMap<String, EgressNodeConfig>,
    runtime: RuntimeState,
    idle_timeout: Duration,
    response_timeout: Duration,
) -> Result<CapturedUdpRelayOutcome, String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let egress = GraphEgress::try_from(egress_nodes)?;
    relay_captured_udp(
        stream,
        peer,
        target,
        egress,
        runtime,
        idle_timeout,
        response_timeout,
    )
    .await
}

pub async fn relay_captured_udp_reloadable<S>(
    stream: S,
    peer: SocketAddr,
    target: SocketAddr,
    egress: ReloadableEgress,
    runtime: RuntimeState,
    idle_timeout: Duration,
    response_timeout: Duration,
) -> Result<CapturedUdpRelayOutcome, String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    relay_captured_udp(
        stream,
        peer,
        target,
        egress,
        runtime,
        idle_timeout,
        response_timeout,
    )
    .await
}

async fn relay_captured_udp<S, O>(
    mut stream: S,
    peer: SocketAddr,
    target: SocketAddr,
    egress: O,
    runtime: RuntimeState,
    idle_timeout: Duration,
    response_timeout: Duration,
) -> Result<CapturedUdpRelayOutcome, String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    O: EgressNode,
{
    let mut payload = vec![0_u8; DATAGRAM_LIMIT];
    let request_bytes = stream
        .read(&mut payload)
        .await
        .map_err(|error| format!("failed reading captured UDP payload: {error}"))?;
    if request_bytes == 0 {
        return Err("captured UDP stream returned empty payload".to_string());
    }
    payload.truncate(request_bytes);

    let session_id = runtime.events().next_session_id();
    let target_context = resolve_socket_destination(&runtime, target).await;
    let decision = match select_target(
        &runtime,
        session_id,
        InboundKind::Udp,
        target_context.clone(),
    ) {
        Ok(decision) => decision,
        Err(error) => {
            runtime.events().record(
                IngressEventKind::UdpError,
                selection_error_fields(session_id, peer, target, &error),
            );
            return Err(error.to_string());
        }
    };
    let node_protocol = egress.decision_tag(&decision);
    let mut fields = session_fields(session_id, TUN_INBOUND, node_protocol, peer, target, target);
    push_target_context_fields(&mut fields, &target_context);
    push_decision_fields(&mut fields, &decision);
    fields.push(("direction", "client-to-upstream".to_string()));
    fields.push(("bytes", request_bytes.to_string()));
    runtime
        .events()
        .record(IngressEventKind::UdpDatagram, fields);

    let (downstream_tx, downstream_rx) = mpsc::channel(UDP_CHANNEL_DEPTH);
    let (response_tx, mut response_rx) = mpsc::channel(UDP_CHANNEL_DEPTH);
    downstream_tx
        .send(payload)
        .await
        .map_err(|_| "captured UDP downstream channel closed before relay".to_string())?;

    let association = UdpRelayAssociation {
        session_id,
        inbound: TUN_INBOUND,
        peer,
        target,
        idle_timeout,
        downstream: UdpDownstream::Channel(response_tx),
        downstream_rx,
        decision: decision.clone(),
        runtime: runtime.clone(),
    };
    let mut egress_task = tokio::spawn(async move { egress.handle_udp(association).await });
    let response = match time::timeout(response_timeout, response_rx.recv()).await {
        Ok(Some(response)) => response,
        Ok(None) => {
            drop(downstream_tx);
            let error = await_udp_error(&mut egress_task)
                .await
                .unwrap_or_else(|| "captured UDP relay produced no response".to_string());
            runtime.events().record(
                IngressEventKind::UdpError,
                captured_error_fields(
                    session_id,
                    node_protocol,
                    peer,
                    target,
                    &target_context,
                    EgressError::new("relay", Some(target), error.clone()),
                    Some(&decision),
                ),
            );
            return Err(error);
        }
        Err(_) => {
            drop(downstream_tx);
            egress_task.abort();
            let error = format!(
                "timed out after {}ms waiting for captured UDP response",
                response_timeout.as_millis()
            );
            runtime.events().record(
                IngressEventKind::UdpError,
                captured_error_fields(
                    session_id,
                    node_protocol,
                    peer,
                    target,
                    &target_context,
                    EgressError::new("relay", Some(target), error.clone()),
                    Some(&decision),
                ),
            );
            return Err(error);
        }
    };
    let response_bytes = response.len();
    stream
        .write_all(&response)
        .await
        .map_err(|error| format!("failed writing captured UDP response: {error}"))?;
    drop(downstream_tx);
    let outcome = await_udp_outcome(&mut egress_task, idle_timeout + response_timeout).await?;

    let mut fields = session_fields(
        session_id,
        TUN_INBOUND,
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

    Ok(CapturedUdpRelayOutcome {
        session_id,
        target,
        upstream: outcome.upstream,
        request_bytes,
        response_bytes,
        close_reason: outcome.close_reason,
    })
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

fn select_target(
    runtime: &RuntimeState,
    session_id: u64,
    inbound: InboundKind,
    target: TargetContext,
) -> Result<SelectionDecision, dynet_runtime::SelectionError> {
    runtime.select(SelectionContext {
        session_id,
        inbound,
        target,
    })
}

fn selection_error_fields(
    session_id: u64,
    peer: SocketAddr,
    target: SocketAddr,
    error: &dynet_runtime::SelectionError,
) -> Vec<(&'static str, String)> {
    let mut fields = session_fields(session_id, TUN_INBOUND, "selection", peer, target, target);
    fields.push(("errorStage", "egress-select".to_string()));
    fields.push(("errorCode", error.code().to_string()));
    fields.push((
        "ipFamily",
        if target.is_ipv6() { "ipv6" } else { "ipv4" }.to_string(),
    ));
    if let Some(rule_id) = error.matched_rule_id() {
        fields.push(("matchedRuleId", rule_id.to_string()));
        fields.push(("ipv6Policy", "deny".to_string()));
        fields.push(("ipv6PolicySource", "rule".to_string()));
    }
    fields.push(("error", error.to_string()));
    fields
}

fn captured_error_fields(
    session_id: u64,
    node_protocol: &'static str,
    peer: SocketAddr,
    target: SocketAddr,
    target_context: &TargetContext,
    error: EgressError,
    decision: Option<&SelectionDecision>,
) -> Vec<(&'static str, String)> {
    let upstream = error.upstream.unwrap_or(target);
    let mut fields = session_fields(
        session_id,
        TUN_INBOUND,
        node_protocol,
        peer,
        target,
        upstream,
    );
    push_target_context_fields(&mut fields, target_context);
    if let Some(decision) = decision {
        push_decision_fields(&mut fields, decision);
    }
    push_egress_error_fields(&mut fields, node_protocol, &error);
    push_endpoint_fields(&mut fields, "upstream", upstream);
    fields
}

async fn await_udp_error(
    task: &mut JoinHandle<Result<UdpRelayOutcome, EgressError>>,
) -> Option<String> {
    match task.await {
        Ok(Ok(outcome)) => Some(format!(
            "captured UDP relay closed before response: {}",
            outcome.close_reason
        )),
        Ok(Err(error)) => Some(error.message),
        Err(error) => Some(format!("captured UDP relay task failed: {error}")),
    }
}

async fn await_udp_outcome(
    task: &mut JoinHandle<Result<UdpRelayOutcome, EgressError>>,
    timeout: Duration,
) -> Result<UdpRelayOutcome, String> {
    match time::timeout(timeout, &mut *task).await {
        Ok(Ok(Ok(outcome))) => Ok(outcome),
        Ok(Ok(Err(error))) => Err(error.message),
        Ok(Err(error)) => Err(format!("captured UDP relay task failed: {error}")),
        Err(_) => {
            task.abort();
            Err(format!(
                "timed out after {}ms waiting for captured UDP relay to close",
                timeout.as_millis()
            ))
        }
    }
}
