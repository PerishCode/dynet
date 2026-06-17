use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use serde_json::json;
use tokio::net::UdpSocket;
use tower::ServiceExt;
use utoipa::OpenApi;

use dynet_api::{router, ApiDoc};
use dynet_runtime::{
    DnsRacePolicy, DnsRaceStrategy, DnsUpstream, DnsUpstreamId, IngressEventKind, RuntimeState,
};
use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

#[tokio::test]
async fn health_payload() {
    let response = router(RuntimeState::default())
        .oneshot(
            Request::builder()
                .uri("/api/v1/health")
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("router handles request");

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024)
        .await
        .expect("body reads");
    let payload: serde_json::Value = serde_json::from_slice(&body).expect("body is json");
    assert_eq!(
        payload,
        json!({
            "status": "ok",
            "service": "dynet-api",
            "apiVersion": "v1"
        })
    );
}

#[tokio::test]
async fn events_snapshot() {
    let runtime = RuntimeState::default();
    runtime.events().record(
        IngressEventKind::TcpAccept,
        [
            ("peer", "127.0.0.1:50000".to_string()),
            ("upstream", "127.0.0.1:80".to_string()),
        ],
    );

    let response = router(runtime)
        .oneshot(
            Request::builder()
                .uri("/api/v1/events")
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("router handles request");

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024)
        .await
        .expect("body reads");
    let payload: serde_json::Value = serde_json::from_slice(&body).expect("body is json");
    assert_eq!(payload["events"][0]["kind"], "tcp-accept");
}

#[tokio::test]
async fn observed_dns_snapshot() {
    let dns = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind dns");
    let dns_addr = dns.local_addr().expect("dns addr");
    tokio::spawn(async move {
        let mut buffer = [0_u8; 1024];
        let (size, peer) = dns.recv_from(&mut buffer).await.expect("recv query");
        let response = dns_a_response(&buffer[..size], Ipv4Addr::new(203, 0, 113, 9));
        dns.send_to(&response, peer).await.expect("send response");
    });
    let runtime = RuntimeState::single_node_dns_policy(
        "direct",
        vec![DnsUpstream {
            id: DnsUpstreamId::new("test"),
            address: dns_addr,
            enabled: true,
            priority: 0,
        }],
        DnsRacePolicy {
            timeout: Duration::from_secs(2),
            strategy: DnsRaceStrategy::Parallel,
        },
    );
    runtime
        .resolve_domain_a("example.test", 80)
        .await
        .expect("domain resolves");

    let response = router(runtime)
        .oneshot(
            Request::builder()
                .uri("/api/v1/dns/observed")
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("router handles request");

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024)
        .await
        .expect("body reads");
    let payload: serde_json::Value = serde_json::from_slice(&body).expect("body is json");
    assert_eq!(
        payload,
        json!({
            "entries": [{
                "domain": "example.test",
                "answerIps": ["203.0.113.9"]
            }]
        })
    );
}

#[test]
fn openapi_health_path() {
    let document = ApiDoc::openapi();
    assert!(document.paths.paths.contains_key("/api/v1/dns/observed"));
    assert!(document.paths.paths.contains_key("/api/v1/events"));
    assert!(document.paths.paths.contains_key("/api/v1/health"));
}

fn dns_a_response(query: &[u8], address: Ipv4Addr) -> Vec<u8> {
    let question_end = query
        .iter()
        .enumerate()
        .skip(12)
        .find_map(|(index, byte)| (*byte == 0).then_some(index + 5))
        .expect("question end");
    let mut response = Vec::new();
    response.extend_from_slice(&query[..2]);
    response.extend_from_slice(&0x8180_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&query[12..question_end]);
    response.extend_from_slice(&[0xc0, 0x0c]);
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&60_u32.to_be_bytes());
    response.extend_from_slice(&4_u16.to_be_bytes());
    response.extend_from_slice(&address.octets());
    response
}
