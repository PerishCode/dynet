use axum::{extract::State, routing::get, Json, Router};
use dynet_runtime::{IngressEvent, RuntimeState};
use serde::Serialize;
use tokio::net::TcpListener;
use utoipa::{OpenApi, ToSchema};

pub const API_VERSION: &str = "v1";
pub const API_PREFIX: &str = "/api/v1";

#[derive(OpenApi)]
#[openapi(
    paths(health, list_events),
    components(schemas(EventsResponse, HealthResponse)),
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
        .route("/api/v1/events", get(list_events))
        .route("/api/v1/health", get(health))
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
    path = "/api/v1/health",
    tag = "health",
    responses(
        (status = 200, description = "Control plane is healthy", body = HealthResponse)
    )
)]
pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse::healthy())
}
