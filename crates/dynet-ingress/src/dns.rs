use std::net::SocketAddr;

use dynet_runtime::{sniff_dns_query, sniff_dns_response, IngressEventKind, RuntimeState};
use tokio::net::UdpSocket;
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
    let socket = UdpSocket::bind(config.bind)
        .await
        .map_err(|error| format!("failed to bind DNS relay {}: {error}", config.bind))?;
    let mut buffer = vec![0_u8; DATAGRAM_LIMIT];
    loop {
        let (size, peer) = tokio::select! {
            _ = shutdown.cancelled() => return Ok(()),
            received = socket.recv_from(&mut buffer) => received
                .map_err(|error| format!("failed receiving DNS datagram: {error}"))?,
        };
        let query = buffer[..size].to_vec();
        let query_info = sniff_dns_query(&query);
        let mut fields = vec![("peer", peer.to_string()), ("bytes", size.to_string())];
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
                    response_fields(peer, &resolution),
                );
                socket
                    .send_to(&resolution.response, peer)
                    .await
                    .map_err(|error| format!("failed sending DNS response: {error}"))?;
            }
            Err(error) => {
                let mut fields = vec![("peer", peer.to_string()), ("error", error.to_string())];
                push_endpoint_fields(&mut fields, "peer", peer);
                runtime.events().record(IngressEventKind::DnsError, fields);
            }
        }
    }
}

fn response_fields(
    peer: SocketAddr,
    resolution: &dynet_runtime::DnsResolution,
) -> Vec<(&'static str, String)> {
    let mut fields = vec![
        ("peer", peer.to_string()),
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
    fields
}
