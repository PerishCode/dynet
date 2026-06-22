use axum::{extract::State, routing::get, Json, Router};
use dynet_runtime::{IngressEvent, MatrixShadowDecision, RuntimeState, TrafficSession};
use serde::Serialize;
use tokio::net::TcpListener;
use utoipa::{OpenApi, ToSchema};

pub const API_VERSION: &str = "v1";
pub const API_PREFIX: &str = "/api/v1";

#[derive(OpenApi)]
#[openapi(
    paths(
        health,
        list_events,
        list_observed_dns,
        list_traffic_sessions,
        list_matrix_shadow
    ),
    components(schemas(
        EventsResponse,
        HealthResponse,
        ObservedDnsEntry,
        ObservedDnsResponse,
        TrafficSessionsResponse,
        TrafficSession,
        MatrixShadowResponse,
        MatrixShadowDecision
    )),
    tags((name = "health", description = "Control-plane liveness"))
)]
pub struct ApiDoc;

#[derive(Debug, Clone)]
pub struct ApiState {
    runtime: RuntimeState,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct EventsResponse {
    pub events: Vec<IngressEvent>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HealthResponse {
    pub status: String,
    pub service: String,
    pub api_version: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ObservedDnsEntry {
    pub domain: String,
    pub answer_ips: Vec<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ObservedDnsResponse {
    pub entries: Vec<ObservedDnsEntry>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TrafficSessionsResponse {
    pub sessions: Vec<TrafficSession>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MatrixShadowResponse {
    pub decisions: Vec<MatrixShadowDecision>,
}

impl HealthResponse {
    pub fn healthy() -> Self {
        Self {
            status: "ok".to_string(),
            service: "dynet-api".to_string(),
            api_version: API_VERSION.to_string(),
        }
    }
}

impl ApiState {
    pub fn new(runtime: RuntimeState) -> Self {
        Self { runtime }
    }
}

pub fn router(runtime: RuntimeState) -> Router {
    Router::new()
        .route("/api/v1/dns/observed", get(list_observed_dns))
        .route("/api/v1/events", get(list_events))
        .route("/api/v1/health", get(health))
        .route(
            "/api/v1/observability/matrix-shadow",
            get(list_matrix_shadow),
        )
        .route("/api/v1/observability/sessions", get(list_traffic_sessions))
        .with_state(ApiState::new(runtime))
}

pub async fn serve(listener: TcpListener, runtime: RuntimeState) -> Result<(), std::io::Error> {
    axum::serve(listener, router(runtime)).await
}

#[utoipa::path(
    get,
    path = "/api/v1/events",
    tag = "events",
    responses(
        (status = 200, description = "Recent ingress events", body = EventsResponse)
    )
)]
pub async fn list_events(State(state): State<ApiState>) -> Json<EventsResponse> {
    Json(EventsResponse {
        events: state.runtime.events().snapshot(),
    })
}

#[utoipa::path(
    get,
    path = "/api/v1/dns/observed",
    tag = "dns",
    responses(
        (status = 200, description = "Observed DNS answers", body = ObservedDnsResponse)
    )
)]
pub async fn list_observed_dns(State(state): State<ApiState>) -> Json<ObservedDnsResponse> {
    let entries = state
        .runtime
        .dns_map()
        .snapshot()
        .into_iter()
        .map(|(domain, answer_ips)| ObservedDnsEntry {
            domain,
            answer_ips: answer_ips
                .into_iter()
                .map(|address| address.to_string())
                .collect(),
        })
        .collect();
    Json(ObservedDnsResponse { entries })
}

#[utoipa::path(
    get,
    path = "/api/v1/observability/sessions",
    tag = "observability",
    responses(
        (status = 200, description = "Recent traffic session summaries", body = TrafficSessionsResponse)
    )
)]
pub async fn list_traffic_sessions(State(state): State<ApiState>) -> Json<TrafficSessionsResponse> {
    Json(TrafficSessionsResponse {
        sessions: state.runtime.matrix().traffic_sessions(),
    })
}

#[utoipa::path(
    get,
    path = "/api/v1/observability/matrix-shadow",
    tag = "observability",
    responses(
        (status = 200, description = "Recent matrix shadow decisions", body = MatrixShadowResponse)
    )
)]
pub async fn list_matrix_shadow(State(state): State<ApiState>) -> Json<MatrixShadowResponse> {
    Json(MatrixShadowResponse {
        decisions: state.runtime.matrix().shadow_decisions(),
    })
}

#[utoipa::path(
    get,
    path = "/api/v1/health",
    tag = "health",
    responses(
        (status = 200, description = "Control plane is healthy", body = HealthResponse)
    )
)]
pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse::healthy())
}
