use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use serde_json::json;
use tower::ServiceExt;
use utoipa::OpenApi;

use dynet_api::{router, ApiDoc};
use dynet_ingress::{EventStore, IngressEventKind};

#[tokio::test]
async fn health_payload() {
    let response = router(EventStore::default())
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
    let events = EventStore::default();
    events.record(
        IngressEventKind::TcpAccept,
        [
            ("peer", "127.0.0.1:50000".to_string()),
            ("upstream", "127.0.0.1:80".to_string()),
        ],
    );

    let response = router(events)
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

#[test]
fn openapi_health_path() {
    let document = ApiDoc::openapi();
    assert!(document.paths.paths.contains_key("/api/v1/events"));
    assert!(document.paths.paths.contains_key("/api/v1/health"));
}
