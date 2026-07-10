use std::{io::ErrorKind, net::SocketAddr, sync::Arc};

use dynet_runtime::{sniff_dns_query, sniff_dns_response, IngressEventKind, RuntimeState};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::Semaphore,
};
use tokio_util::sync::CancellationToken;

use crate::{push_endpoint_fields, DnsRelayConfig, DATAGRAM_LIMIT};

pub async fn run(config: DnsRelayConfig, runtime: RuntimeState) -> Result<(), String> {
    run_until(config, runtime, CancellationToken::new()).await
}

pub async fn run_until(
    config: DnsRelayConfig,
    runtime: RuntimeState,
    shutdown: CancellationToken,
) -> Result<(), String> {
    let udp = UdpSocket::bind(config.bind)
        .await
        .map_err(|error| format!("failed to bind UDP DNS relay {}: {error}", config.bind))?;
    let tcp = TcpListener::bind(config.bind)
        .await
        .map_err(|error| format!("failed to bind TCP DNS relay {}: {error}", config.bind))?;
    tokio::try_join!(
        run_udp(udp, runtime.clone(), shutdown.clone()),
        run_tcp(tcp, config.max_sessions, runtime, shutdown),
    )?;
    Ok(())
}

async fn run_udp(
    socket: UdpSocket,
    runtime: RuntimeState,
    shutdown: CancellationToken,
) -> Result<(), String> {
    let mut buffer = vec![0_u8; DATAGRAM_LIMIT];
    loop {
        let (size, peer) = tokio::select! {
            _ = shutdown.cancelled() => return Ok(()),
            received = socket.recv_from(&mut buffer) => received
                .map_err(|error| format!("failed receiving DNS datagram: {error}"))?,
        };
        if let Some(response) = resolve_query(&runtime, peer, buffer[..size].to_vec(), "udp").await
        {
            socket
                .send_to(&response, peer)
                .await
                .map_err(|error| format!("failed sending DNS response: {error}"))?;
        }
    }
}

async fn run_tcp(
    listener: TcpListener,
    max_sessions: usize,
    runtime: RuntimeState,
    shutdown: CancellationToken,
) -> Result<(), String> {
    let capacity = Arc::new(Semaphore::new(max_sessions));
    loop {
        let accepted = tokio::select! {
            _ = shutdown.cancelled() => return Ok(()),
            accepted = listener.accept() => accepted
                .map_err(|error| format!("failed accepting TCP DNS session: {error}"))?,
        };
        let (stream, peer) = accepted;
        let Ok(permit) = capacity.clone().try_acquire_owned() else {
            runtime.events().record(
                IngressEventKind::DnsError,
                [
                    ("peer", peer.to_string()),
                    ("transport", "tcp".to_string()),
                    ("error", "DNS TCP session capacity exhausted".to_string()),
                    ("maxSessions", max_sessions.to_string()),
                ],
            );
            drop(stream);
            continue;
        };
        let session_runtime = runtime.clone();
        let session_shutdown = shutdown.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) =
                handle_tcp_session(stream, peer, session_runtime.clone(), session_shutdown).await
            {
                session_runtime.events().record(
                    IngressEventKind::DnsError,
                    [
                        ("peer", peer.to_string()),
                        ("transport", "tcp".to_string()),
                        ("error", error),
                    ],
                );
            }
        });
    }
}

async fn handle_tcp_session(
    mut stream: TcpStream,
    peer: SocketAddr,
    runtime: RuntimeState,
    shutdown: CancellationToken,
) -> Result<(), String> {
    loop {
        let mut length = [0_u8; 2];
        let read = tokio::select! {
            _ = shutdown.cancelled() => return Ok(()),
            read = stream.read_exact(&mut length) => read,
        };
        match read {
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(format!("failed reading DNS TCP length: {error}")),
        }
        let length = usize::from(u16::from_be_bytes(length));
        if length == 0 {
            return Err("DNS TCP query length must be non-zero".to_string());
        }
        let mut query = vec![0_u8; length];
        tokio::select! {
            _ = shutdown.cancelled() => return Ok(()),
            read = stream.read_exact(&mut query) => read
                .map_err(|error| format!("failed reading DNS TCP query: {error}"))?,
        };
        let Some(response) = resolve_query(&runtime, peer, query, "tcp").await else {
            continue;
        };
        let response_length = u16::try_from(response.len())
            .map_err(|_| "DNS TCP response exceeds 65535 bytes".to_string())?;
        tokio::select! {
            _ = shutdown.cancelled() => return Ok(()),
            written = async {
                stream.write_all(&response_length.to_be_bytes()).await?;
                stream.write_all(&response).await
            } => written.map_err(|error| format!("failed writing DNS TCP response: {error}"))?,
        }
    }
}

async fn resolve_query(
    runtime: &RuntimeState,
    peer: SocketAddr,
    query: Vec<u8>,
    transport: &'static str,
) -> Option<Vec<u8>> {
    let query_info = sniff_dns_query(&query);
    let mut fields = vec![
        ("peer", peer.to_string()),
        ("transport", transport.to_string()),
        ("bytes", query.len().to_string()),
    ];
    push_endpoint_fields(&mut fields, "peer", peer);
    if let Some(info) = &query_info {
        fields.push(("transactionId", info.transaction_id.to_string()));
        fields.push(("queryName", info.query_name.clone()));
        fields.push(("queryType", info.query_type.clone()));
    }
    runtime.events().record(IngressEventKind::DnsQuery, fields);
    match runtime.resolve_dns_wire(query).await {
        Ok(resolution) => {
            runtime.events().record(
                IngressEventKind::DnsResponse,
                response_fields(peer, transport, &resolution),
            );
            Some(resolution.response)
        }
        Err(error) => {
            let mut fields = vec![
                ("peer", peer.to_string()),
                ("transport", transport.to_string()),
                ("error", error.to_string()),
            ];
            push_endpoint_fields(&mut fields, "peer", peer);
            runtime.events().record(IngressEventKind::DnsError, fields);
            None
        }
    }
}

fn response_fields(
    peer: SocketAddr,
    transport: &'static str,
    resolution: &dynet_runtime::DnsResolution,
) -> Vec<(&'static str, String)> {
    let mut fields = vec![
        ("peer", peer.to_string()),
        ("transport", transport.to_string()),
        ("upstreamId", resolution.upstream.id.to_string()),
        ("upstream", resolution.upstream.address.to_string()),
        ("source", resolution.source.to_string()),
        ("bytes", resolution.response.len().to_string()),
    ];
    push_endpoint_fields(&mut fields, "peer", peer);
    push_endpoint_fields(&mut fields, "upstream", resolution.upstream.address);
    push_endpoint_fields(&mut fields, "source", resolution.source);
    if let Some(info) = resolution
        .response_info
        .clone()
        .or_else(|| sniff_dns_response(&resolution.response))
    {
        fields.push(("transactionId", info.transaction_id.to_string()));
        if let Some(query_name) = info.query_name {
            fields.push(("queryName", query_name));
        }
        if let Some(query_type) = info.query_type {
            fields.push(("queryType", query_type));
        }
        if !info.answer_ips.is_empty() {
            fields.push((
                "answerIps",
                info.answer_ips
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            ));
        }
    }
    if resolution.ipv6_filtered {
        fields.push(("ipv6Policy", "deny".to_string()));
        fields.push(("ipv6PolicySource", "rule".to_string()));
        if let Some(rule_id) = &resolution.matched_rule_id {
            fields.push(("matchedRuleId", rule_id.to_string()));
        }
    }
    fields
}
