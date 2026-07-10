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
    DnsRacePolicy, DnsRaceStrategy, DnsUpstream, DnsUpstreamId, DnsUpstreamTransport, InboundKind,
    IngressEventKind, RuntimeState, SelectionContext, TargetContext,
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
async fn traffic_sessions_snapshot() {
    let runtime = RuntimeState::default();
    runtime.events().record(
        IngressEventKind::TcpAccept,
        [
            ("sessionId", "7".to_string()),
            ("decisionId", "3".to_string()),
            ("configGeneration", "1".to_string()),
            ("inbound", "tcp".to_string()),
            ("nodeProtocol", "direct".to_string()),
            ("peer", "127.0.0.1:50000".to_string()),
            ("target", "127.0.0.1:80".to_string()),
            ("targetIp", "127.0.0.1".to_string()),
            ("targetPort", "80".to_string()),
            ("targetSource", "fixed-upstream".to_string()),
            ("selectionGroups", "default".to_string()),
            ("selectionNodes", "default-node".to_string()),
            ("selectionTrace", "default:default-node->direct".to_string()),
        ],
    );
    runtime.events().record(
        IngressEventKind::TcpClose,
        [
            ("sessionId", "7".to_string()),
            ("decisionId", "3".to_string()),
            ("inbound", "tcp".to_string()),
            ("clientToUpstreamBytes", "11".to_string()),
            ("upstreamToClientBytes", "17".to_string()),
            ("closeReason", "eof".to_string()),
        ],
    );

    let response = router(runtime)
        .oneshot(
            Request::builder()
                .uri("/api/v1/observability/sessions")
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("router handles request");

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 4096)
        .await
        .expect("body reads");
    let payload: serde_json::Value = serde_json::from_slice(&body).expect("body is json");
    assert_eq!(payload["sessions"][0]["sessionId"], 7);
    assert_eq!(payload["sessions"][0]["decisionId"], 3);
    assert_eq!(payload["sessions"][0]["configGeneration"], 1);
    assert_eq!(payload["sessions"][0]["targetSource"], "fixed-upstream");
    assert_eq!(payload["sessions"][0]["clientToUpstreamBytes"], 11);
    assert_eq!(payload["sessions"][0]["upstreamToClientBytes"], 17);
    assert_eq!(payload["sessions"][0]["closeReason"], "eof");
}

#[tokio::test]
async fn matrix_shadow_snapshot() {
    let runtime = RuntimeState::default();
    runtime
        .select(SelectionContext {
            session_id: 9,
            inbound: InboundKind::Tcp,
            target: TargetContext::fixed_upstream(SocketAddr::from(([127, 0, 0, 1], 80))),
        })
        .expect("selection succeeds");

    let response = router(runtime)
        .oneshot(
            Request::builder()
                .uri("/api/v1/observability/matrix/shadow")
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("router handles request");

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 4096)
        .await
        .expect("body reads");
    let payload: serde_json::Value = serde_json::from_slice(&body).expect("body is json");
    assert_eq!(payload["decisions"][0]["decisionId"], 1);
    assert_eq!(payload["decisions"][0]["sessionId"], 9);
    assert_eq!(payload["decisions"][0]["actualNodeId"], "default-node");
    assert_eq!(payload["decisions"][0]["shadowTopNodeId"], "default-node");
    assert!(payload["decisions"][0].get("shadowNodeId").is_none());
    assert_eq!(payload["decisions"][0]["shadowDiffersFromActual"], false);
    assert_eq!(
        payload["decisions"][0]["candidates"][0]["reason"],
        "stats-balanced-shadow:no-history"
    );
}

#[tokio::test]
async fn matrix_stats_snapshot() {
    let runtime = RuntimeState::default();
    runtime.events().record(
        IngressEventKind::TcpAccept,
        [
            ("sessionId", "11".to_string()),
            ("decisionId", "5".to_string()),
            ("inbound", "tcp".to_string()),
            ("targetDomain", "GitHub.com".to_string()),
            ("targetIp", "140.82.112.4".to_string()),
            ("selectionGroups", "GitHub".to_string()),
            ("selectionNodes", "airport-us-01".to_string()),
        ],
    );
    runtime.events().record(
        IngressEventKind::TcpClose,
        [
            ("sessionId", "11".to_string()),
            ("decisionId", "5".to_string()),
            ("inbound", "tcp".to_string()),
            ("clientToUpstreamBytes", "23".to_string()),
            ("upstreamToClientBytes", "29".to_string()),
            ("closeReason", "eof".to_string()),
        ],
    );

    let response = router(runtime)
        .oneshot(
            Request::builder()
                .uri("/api/v1/observability/matrix/stats/nodes")
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("router handles request");

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 4096)
        .await
        .expect("body reads");
    let payload: serde_json::Value = serde_json::from_slice(&body).expect("body is json");
    assert_eq!(payload["nodes"][0]["groupId"], "GitHub");
    assert_eq!(payload["nodes"][0]["nodeId"], "airport-us-01");
    assert_eq!(
        payload["nodes"][0]["nodeFingerprint"],
        "node-id:airport-us-01"
    );
    assert_eq!(payload["nodes"][0]["sessionCount"], 1);
    assert_eq!(payload["nodes"][0]["successCount"], 1);
    assert_eq!(payload["nodes"][0]["errorCount"], 0);
    assert_eq!(payload["nodes"][0]["clientToUpstreamBytes"], 23);
    assert_eq!(payload["nodes"][0]["upstreamToClientBytes"], 29);
}

#[tokio::test]
async fn matrix_target_stats_snapshot() {
    let runtime = RuntimeState::default();
    runtime.events().record(
        IngressEventKind::TcpAccept,
        [
            ("sessionId", "12".to_string()),
            ("decisionId", "6".to_string()),
            ("inbound", "tcp".to_string()),
            ("targetDomain", "GitHub.com".to_string()),
            ("targetIp", "140.82.112.4".to_string()),
            ("selectionGroups", "GitHub,Private".to_string()),
            (
                "selectionNodes",
                "airport-us-01,private-fixed-ip".to_string(),
            ),
        ],
    );
    runtime.events().record(
        IngressEventKind::TcpClose,
        [
            ("sessionId", "12".to_string()),
            ("decisionId", "6".to_string()),
            ("inbound", "tcp".to_string()),
            ("clientToUpstreamBytes", "41".to_string()),
            ("upstreamToClientBytes", "43".to_string()),
            ("closeReason", "eof".to_string()),
        ],
    );

    let response = router(runtime)
        .oneshot(
            Request::builder()
                .uri("/api/v1/observability/matrix/stats/targets")
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("router handles request");

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 4096)
        .await
        .expect("body reads");
    let payload: serde_json::Value = serde_json::from_slice(&body).expect("body is json");
    assert_eq!(payload["targets"].as_array().expect("targets").len(), 2);
    assert_eq!(payload["targets"][0]["groupId"], "GitHub");
    assert_eq!(payload["targets"][0]["nodeId"], "airport-us-01");
    assert_eq!(payload["targets"][0]["targetScope"], "domain");
    assert_eq!(payload["targets"][0]["targetValue"], "github.com");
    assert_eq!(payload["targets"][0]["sessionCount"], 1);
    assert_eq!(payload["targets"][1]["groupId"], "Private");
    assert_eq!(payload["targets"][1]["nodeId"], "private-fixed-ip");
    assert_eq!(payload["targets"][1]["targetValue"], "github.com");
}

#[tokio::test]
async fn matrix_error_signals_snapshot() {
    let runtime = RuntimeState::default();
    for decision_id in ["21", "22"] {
        runtime.events().record(
            IngressEventKind::UdpError,
            [
                ("sessionId", "20".to_string()),
                ("decisionId", decision_id.to_string()),
                ("inbound", "socks5".to_string()),
                ("nodeProtocol", "vless".to_string()),
                ("targetDomain", "GitHub.GitHubAssets.com".to_string()),
                ("targetIp", "185.199.108.215".to_string()),
                ("targetPort", "443".to_string()),
                ("selectionGroups", "GitHub".to_string()),
                ("selectionNodes", "airport-vless-01".to_string()),
                ("errorClass", "handshake-failed".to_string()),
                ("errorCode", "vless-reality-handshake-eof".to_string()),
                ("errorSide", "upstream".to_string()),
                ("errorPhase", "handshake".to_string()),
                ("errorProtocolPhase", "reality-handshake".to_string()),
                ("errorScoreImpact", "hard-failure".to_string()),
                ("error", "EOF during REALITY handshake".to_string()),
            ],
        );
    }

    let response = router(runtime)
        .oneshot(
            Request::builder()
                .uri("/api/v1/observability/matrix/signals/error")
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("router handles request");

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 4096)
        .await
        .expect("body reads");
    let payload: serde_json::Value = serde_json::from_slice(&body).expect("body is json");
    assert_eq!(payload["signals"].as_array().expect("signals").len(), 1);
    let signal = &payload["signals"][0];
    assert_eq!(signal["groupId"], "GitHub");
    assert_eq!(signal["nodeId"], "airport-vless-01");
    assert_eq!(signal["targetScope"], "domain");
    assert_eq!(signal["targetValue"], "github.githubassets.com");
    assert_eq!(signal["nodeProtocol"], "vless");
    assert_eq!(signal["errorClass"], "handshake-failed");
    assert_eq!(signal["errorCode"], "vless-reality-handshake-eof");
    assert_eq!(signal["attemptCount"], 2);
    assert_eq!(signal["logicalSessionCount"], 1);
    assert_eq!(signal["effectiveErrorMillis"], 2000);
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
            transport: DnsUpstreamTransport::Udp,
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
    assert!(document
        .paths
        .paths
        .contains_key("/api/v1/observability/sessions"));
    assert!(document
        .paths
        .paths
        .contains_key("/api/v1/observability/matrix/shadow"));
    assert!(document
        .paths
        .paths
        .contains_key("/api/v1/observability/matrix/signals/error"));
    assert!(document
        .paths
        .paths
        .contains_key("/api/v1/observability/matrix/stats/nodes"));
    assert!(document
        .paths
        .paths
        .contains_key("/api/v1/observability/matrix/stats/targets"));
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
