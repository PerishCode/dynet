use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use dynet_api::{router, router_with_config_audit};
use dynet_runtime::{ConfigReloadTrigger, IngressEventKind, RuntimeConfigAudit, RuntimeState};
use tower::ServiceExt;

#[tokio::test]
async fn events_filter_generation() {
    let runtime = RuntimeState::default();
    runtime.events().record(
        IngressEventKind::TcpAccept,
        [
            ("sessionId", "1".to_string()),
            ("configGeneration", "1".to_string()),
        ],
    );
    runtime.events().record(
        IngressEventKind::TcpClose,
        [
            ("sessionId", "2".to_string()),
            ("configGeneration", "2".to_string()),
        ],
    );
    runtime.events().record(
        IngressEventKind::TcpClose,
        [
            ("sessionId", "3".to_string()),
            ("configGeneration", "2".to_string()),
        ],
    );

    let response = router(runtime)
        .oneshot(
            Request::builder()
                .uri("/api/v1/events?kind=tcp-close&configGeneration=2&limit=1")
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
    assert_eq!(payload["events"].as_array().expect("events").len(), 1);
    assert_eq!(payload["events"][0]["fields"]["sessionId"], "3");
}

#[tokio::test]
async fn runtime_audit_redacts() {
    let runtime = RuntimeState::default();
    let audit = RuntimeConfigAudit::new(
        runtime.generation(),
        "config-sha256:abc123".to_string(),
        "/etc/dynet/dynet.toml".to_string(),
    );
    audit.record_restart_required(
        ConfigReloadTrigger::Manual,
        "config-sha256:def456".to_string(),
        vec!["control.bind".to_string()],
        vec!["control.bind".to_string()],
    );
    let app = router_with_config_audit(runtime, audit);

    let status_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/runtime/config")
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("router handles request");
    let status_body = to_bytes(status_response.into_body(), 4096)
        .await
        .expect("body reads");
    let status: serde_json::Value = serde_json::from_slice(&status_body).expect("body is json");
    assert_eq!(status["generation"], 1);
    assert_eq!(status["fingerprint"], "config-sha256:abc123");
    assert_eq!(status["lastReloadOutcome"], "restart-required");

    let reload_response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/runtime/reloads?outcome=restart-required&limit=1")
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("router handles request");
    let reload_body = to_bytes(reload_response.into_body(), 4096)
        .await
        .expect("body reads");
    let reloads: serde_json::Value = serde_json::from_slice(&reload_body).expect("body is json");
    assert_eq!(reloads["reloads"][0]["outcome"], "restart-required");
    assert_eq!(
        reloads["reloads"][0]["restartRequiredFields"][0],
        "control.bind"
    );
    assert!(reloads.to_string().find("127.0.0.1").is_none());
}
