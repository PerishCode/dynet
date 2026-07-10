use axum::{
    extract::{Query, State},
    routing::get,
    Json, Router,
};
use dynet_runtime::{
    ConfigReloadAudit, IngressEvent, MatrixErrorSignalStats, MatrixNodeStats, MatrixShadowDecision,
    MatrixTargetNodeStats, RuntimeConfigAudit, RuntimeConfigStatus, RuntimeState, TrafficSession,
};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use utoipa::{IntoParams, OpenApi, ToSchema};

pub const API_VERSION: &str = "v1";
pub const API_PREFIX: &str = "/api/v1";

#[derive(OpenApi)]
#[openapi(
    paths(
        health,
        list_events,
        list_observed_dns,
        list_traffic_sessions,
        list_matrix_shadow,
        list_matrix_error_signals,
        list_matrix_stats,
        list_matrix_target_stats,
        runtime_config_status,
        list_config_reloads
    ),
    components(schemas(
        EventsResponse,
        HealthResponse,
        ObservedDnsEntry,
        ObservedDnsResponse,
        TrafficSessionsResponse,
        TrafficSession,
        MatrixShadowResponse,
        MatrixShadowDecision,
        MatrixErrorSignalsResponse,
        MatrixErrorSignalStats,
        MatrixStatsResponse,
        MatrixNodeStats,
        MatrixTargetStatsResponse,
        MatrixTargetNodeStats,
        RuntimeConfigStatus,
        ConfigReloadsResponse,
        ConfigReloadAudit,
        dynet_runtime::ConfigReloadOutcome,
        dynet_runtime::ConfigReloadTrigger
    )),
    tags((name = "health", description = "Control-plane liveness"))
)]
pub struct ApiDoc;

#[derive(Debug, Clone)]
pub struct ApiState {
    runtime: RuntimeState,
    config_audit: RuntimeConfigAudit,
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

#[derive(Debug, Clone, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MatrixStatsResponse {
    pub nodes: Vec<MatrixNodeStats>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MatrixTargetStatsResponse {
    pub targets: Vec<MatrixTargetNodeStats>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MatrixErrorSignalsResponse {
    pub signals: Vec<MatrixErrorSignalStats>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigReloadsResponse {
    pub reloads: Vec<ConfigReloadAudit>,
}

#[derive(Debug, Default, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct EventsQuery {
    pub after_id: Option<u64>,
    pub limit: Option<usize>,
    pub kind: Option<String>,
    pub session_id: Option<u64>,
    pub config_generation: Option<u64>,
}

#[derive(Debug, Default, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct SessionsQuery {
    pub limit: Option<usize>,
    pub inbound: Option<String>,
    pub session_id: Option<u64>,
    pub config_generation: Option<u64>,
}

#[derive(Debug, Default, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct ReloadsQuery {
    pub after_id: Option<u64>,
    pub limit: Option<usize>,
    pub outcome: Option<String>,
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
    pub fn new(runtime: RuntimeState, config_audit: RuntimeConfigAudit) -> Self {
        Self {
            runtime,
            config_audit,
        }
    }
}

pub fn router(runtime: RuntimeState) -> Router {
    let config_audit = RuntimeConfigAudit::untracked(runtime.generation());
    router_with_config_audit(runtime, config_audit)
}

pub fn router_with_config_audit(runtime: RuntimeState, config_audit: RuntimeConfigAudit) -> Router {
    Router::new()
        .route("/api/v1/dns/observed", get(list_observed_dns))
        .route("/api/v1/events", get(list_events))
        .route("/api/v1/health", get(health))
        .route(
            "/api/v1/observability/matrix/shadow",
            get(list_matrix_shadow),
        )
        .route(
            "/api/v1/observability/matrix/signals/error",
            get(list_matrix_error_signals),
        )
        .route(
            "/api/v1/observability/matrix/stats/nodes",
            get(list_matrix_stats),
        )
        .route(
            "/api/v1/observability/matrix/stats/targets",
            get(list_matrix_target_stats),
        )
        .route("/api/v1/observability/sessions", get(list_traffic_sessions))
        .route("/api/v1/runtime/config", get(runtime_config_status))
        .route("/api/v1/runtime/reloads", get(list_config_reloads))
        .with_state(ApiState::new(runtime, config_audit))
}

pub async fn serve(listener: TcpListener, runtime: RuntimeState) -> Result<(), std::io::Error> {
    axum::serve(listener, router(runtime)).await
}

pub async fn serve_with_config_audit(
    listener: TcpListener,
    runtime: RuntimeState,
    config_audit: RuntimeConfigAudit,
) -> Result<(), std::io::Error> {
    axum::serve(listener, router_with_config_audit(runtime, config_audit)).await
}

#[utoipa::path(
    get,
    path = "/api/v1/runtime/config",
    tag = "runtime",
    responses((status = 200, description = "Current runtime configuration generation", body = RuntimeConfigStatus))
)]
pub async fn runtime_config_status(State(state): State<ApiState>) -> Json<RuntimeConfigStatus> {
    Json(state.config_audit.status())
}

#[utoipa::path(
    get,
    path = "/api/v1/runtime/reloads",
    tag = "runtime",
    responses((status = 200, description = "Recent configuration reload audit records", body = ConfigReloadsResponse)),
    params(ReloadsQuery)
)]
pub async fn list_config_reloads(
    State(state): State<ApiState>,
    Query(query): Query<ReloadsQuery>,
) -> Json<ConfigReloadsResponse> {
    let mut reloads = state.config_audit.snapshot();
    reloads.retain(|reload| {
        query.after_id.is_none_or(|id| reload.id > id)
            && query
                .outcome
                .as_deref()
                .is_none_or(|outcome| reload.outcome.as_str() == outcome)
    });
    retain_latest(&mut reloads, query.limit, 128);
    Json(ConfigReloadsResponse { reloads })
}

#[utoipa::path(
    get,
    path = "/api/v1/events",
    tag = "events",
    responses(
        (status = 200, description = "Recent ingress events", body = EventsResponse)
    ),
    params(EventsQuery)
)]
pub async fn list_events(
    State(state): State<ApiState>,
    Query(query): Query<EventsQuery>,
) -> Json<EventsResponse> {
    let mut events = state.runtime.events().snapshot();
    events.retain(|event| {
        query.after_id.is_none_or(|id| event.id > id)
            && query
                .kind
                .as_deref()
                .is_none_or(|kind| event.kind.as_str() == kind)
            && field_matches(&event.fields, "sessionId", query.session_id)
            && field_matches(&event.fields, "configGeneration", query.config_generation)
    });
    retain_latest(&mut events, query.limit, 1024);
    Json(EventsResponse { events })
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
    ),
    params(SessionsQuery)
)]
pub async fn list_traffic_sessions(
    State(state): State<ApiState>,
    Query(query): Query<SessionsQuery>,
) -> Json<TrafficSessionsResponse> {
    let mut sessions = state.runtime.matrix().traffic_sessions();
    sessions.retain(|session| {
        query
            .inbound
            .as_deref()
            .is_none_or(|inbound| session.inbound == inbound)
            && query.session_id.is_none_or(|id| session.session_id == id)
            && query
                .config_generation
                .is_none_or(|generation| session.config_generation == Some(generation))
    });
    sessions.sort_by_key(|session| session.last_observed_at_unix_ms);
    retain_latest(&mut sessions, query.limit, 1024);
    Json(TrafficSessionsResponse { sessions })
}

#[utoipa::path(
    get,
    path = "/api/v1/observability/matrix/shadow",
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
    path = "/api/v1/observability/matrix/signals/error",
    tag = "observability",
    responses(
        (status = 200, description = "Recent structured matrix error signals grouped by node, target, protocol, and signal class", body = MatrixErrorSignalsResponse)
    )
)]
pub async fn list_matrix_error_signals(
    State(state): State<ApiState>,
) -> Json<MatrixErrorSignalsResponse> {
    Json(MatrixErrorSignalsResponse {
        signals: state.runtime.matrix_error_signal_stats(),
    })
}

#[utoipa::path(
    get,
    path = "/api/v1/observability/matrix/stats/nodes",
    tag = "observability",
    responses(
        (status = 200, description = "Recent node stats derived from traffic sessions", body = MatrixStatsResponse)
    )
)]
pub async fn list_matrix_stats(State(state): State<ApiState>) -> Json<MatrixStatsResponse> {
    Json(MatrixStatsResponse {
        nodes: state.runtime.matrix_node_stats(),
    })
}

#[utoipa::path(
    get,
    path = "/api/v1/observability/matrix/stats/targets",
    tag = "observability",
    responses(
        (status = 200, description = "Recent target-scoped node stats derived from traffic sessions", body = MatrixTargetStatsResponse)
    )
)]
pub async fn list_matrix_target_stats(
    State(state): State<ApiState>,
) -> Json<MatrixTargetStatsResponse> {
    Json(MatrixTargetStatsResponse {
        targets: state.runtime.matrix_target_node_stats(),
    })
}

fn field_matches(
    fields: &std::collections::BTreeMap<String, String>,
    key: &str,
    expected: Option<u64>,
) -> bool {
    expected.is_none_or(|expected| {
        fields.get(key).and_then(|value| value.parse::<u64>().ok()) == Some(expected)
    })
}

fn retain_latest<T>(values: &mut Vec<T>, requested: Option<usize>, maximum: usize) {
    let limit = requested.unwrap_or(maximum).clamp(1, maximum);
    if values.len() > limit {
        values.drain(..values.len() - limit);
    }
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
