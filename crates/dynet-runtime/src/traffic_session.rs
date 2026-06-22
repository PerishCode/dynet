use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
};

use serde::Serialize;
use utoipa::ToSchema;

use crate::{IngressEvent, IngressEventKind};

const TRAFFIC_SESSION_LIMIT: usize = 1024;

#[derive(Debug, Clone, Default)]
pub struct TrafficSessionStore {
    inner: Arc<RwLock<BTreeMap<String, TrafficSession>>>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TrafficSession {
    pub session_key: String,
    pub session_id: u64,
    pub decision_id: Option<u64>,
    pub inbound: String,
    pub node_protocol: Option<String>,
    pub peer: Option<String>,
    pub target: Option<String>,
    pub target_ip: Option<String>,
    pub target_port: Option<u16>,
    pub target_domain: Option<String>,
    pub target_source: Option<String>,
    pub upstream: Option<String>,
    pub selection_groups: Option<String>,
    pub selection_nodes: Option<String>,
    pub selection_trace: Option<String>,
    pub started_at_unix_ms: u128,
    pub closed_at_unix_ms: Option<u128>,
    pub duration_ms: Option<u128>,
    pub close_reason: Option<String>,
    pub error_stage: Option<String>,
    pub error: Option<String>,
    pub client_to_upstream_bytes: u64,
    pub upstream_to_client_bytes: u64,
    pub client_to_upstream_datagrams: u64,
    pub upstream_to_client_datagrams: u64,
    pub first_upstream_at_unix_ms: Option<u128>,
    pub first_downstream_at_unix_ms: Option<u128>,
    pub first_response_latency_ms: Option<u128>,
    pub last_observed_at_unix_ms: u128,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct TrafficSessionUpdate {
    pub session_key: String,
    pub session_id: u64,
    pub decision_id: Option<u64>,
    pub inbound: String,
    pub observed_at_unix_ms: u128,
    pub node_protocol: Option<String>,
    pub peer: Option<String>,
    pub target: Option<String>,
    pub target_ip: Option<String>,
    pub target_port: Option<u16>,
    pub target_domain: Option<String>,
    pub target_source: Option<String>,
    pub upstream: Option<String>,
    pub selection_groups: Option<String>,
    pub selection_nodes: Option<String>,
    pub selection_trace: Option<String>,
    pub close_reason: Option<String>,
    pub error_stage: Option<String>,
    pub error: Option<String>,
    pub client_to_upstream_bytes: Option<u64>,
    pub upstream_to_client_bytes: Option<u64>,
    pub client_to_upstream_datagram: Option<u64>,
    pub upstream_to_client_datagram: Option<u64>,
    pub closes_session: bool,
}

impl TrafficSessionStore {
    pub(crate) fn record_event(&self, event: &IngressEvent) {
        let Some(update) = session_update_from_event(event) else {
            return;
        };
        self.apply_update(update);
    }

    pub fn snapshot(&self) -> Vec<TrafficSession> {
        self.inner
            .read()
            .expect("traffic session store lock poisoned")
            .values()
            .cloned()
            .collect()
    }

    fn apply_update(&self, update: TrafficSessionUpdate) {
        let mut sessions = self
            .inner
            .write()
            .expect("traffic session store lock poisoned");
        if !sessions.contains_key(&update.session_key) && sessions.len() == TRAFFIC_SESSION_LIMIT {
            if let Some(oldest_key) = oldest_session_key(&sessions) {
                sessions.remove(&oldest_key);
            }
        }
        let session = sessions
            .entry(update.session_key.clone())
            .or_insert_with(|| TrafficSession::new(&update));
        session.apply_update(update);
    }
}

fn oldest_session_key(sessions: &BTreeMap<String, TrafficSession>) -> Option<String> {
    sessions
        .iter()
        .min_by(|left, right| {
            left.1
                .last_observed_at_unix_ms
                .cmp(&right.1.last_observed_at_unix_ms)
                .then_with(|| left.0.cmp(right.0))
        })
        .map(|(key, _)| key.clone())
}

impl TrafficSession {
    fn new(update: &TrafficSessionUpdate) -> Self {
        Self {
            session_key: update.session_key.clone(),
            session_id: update.session_id,
            decision_id: update.decision_id,
            inbound: update.inbound.clone(),
            node_protocol: None,
            peer: None,
            target: None,
            target_ip: None,
            target_port: None,
            target_domain: None,
            target_source: None,
            upstream: None,
            selection_groups: None,
            selection_nodes: None,
            selection_trace: None,
            started_at_unix_ms: update.observed_at_unix_ms,
            closed_at_unix_ms: None,
            duration_ms: None,
            close_reason: None,
            error_stage: None,
            error: None,
            client_to_upstream_bytes: 0,
            upstream_to_client_bytes: 0,
            client_to_upstream_datagrams: 0,
            upstream_to_client_datagrams: 0,
            first_upstream_at_unix_ms: None,
            first_downstream_at_unix_ms: None,
            first_response_latency_ms: None,
            last_observed_at_unix_ms: update.observed_at_unix_ms,
        }
    }

    fn apply_update(&mut self, update: TrafficSessionUpdate) {
        self.decision_id = self.decision_id.or(update.decision_id);
        set_if_some(&mut self.node_protocol, update.node_protocol);
        set_if_some(&mut self.peer, update.peer);
        set_if_some(&mut self.target, update.target);
        set_if_some(&mut self.target_ip, update.target_ip);
        self.target_port = self.target_port.or(update.target_port);
        set_if_some(&mut self.target_domain, update.target_domain);
        set_if_some(&mut self.target_source, update.target_source);
        set_if_some(&mut self.upstream, update.upstream);
        set_if_some(&mut self.selection_groups, update.selection_groups);
        set_if_some(&mut self.selection_nodes, update.selection_nodes);
        set_if_some(&mut self.selection_trace, update.selection_trace);
        set_if_some(&mut self.close_reason, update.close_reason);
        set_if_some(&mut self.error_stage, update.error_stage);
        set_if_some(&mut self.error, update.error);

        if let Some(bytes) = update.client_to_upstream_bytes {
            self.client_to_upstream_bytes = bytes;
        }
        if let Some(bytes) = update.upstream_to_client_bytes {
            self.upstream_to_client_bytes = bytes;
        }
        if let Some(bytes) = update.client_to_upstream_datagram {
            self.client_to_upstream_datagrams += 1;
            self.client_to_upstream_bytes += bytes;
            self.first_upstream_at_unix_ms = self
                .first_upstream_at_unix_ms
                .or(Some(update.observed_at_unix_ms));
        }
        if let Some(bytes) = update.upstream_to_client_datagram {
            self.upstream_to_client_datagrams += 1;
            self.upstream_to_client_bytes += bytes;
            self.first_downstream_at_unix_ms = self
                .first_downstream_at_unix_ms
                .or(Some(update.observed_at_unix_ms));
        }
        if self.first_response_latency_ms.is_none() {
            if let Some(first_downstream_at) = self.first_downstream_at_unix_ms {
                self.first_response_latency_ms =
                    Some(first_downstream_at.saturating_sub(self.started_at_unix_ms));
            }
        }
        if update.closes_session {
            self.closed_at_unix_ms = Some(update.observed_at_unix_ms);
            self.duration_ms = Some(
                update
                    .observed_at_unix_ms
                    .saturating_sub(self.started_at_unix_ms),
            );
        }
        self.last_observed_at_unix_ms = update.observed_at_unix_ms;
    }
}

pub(crate) fn session_update_from_event(event: &IngressEvent) -> Option<TrafficSessionUpdate> {
    match event.kind {
        IngressEventKind::TcpAccept
        | IngressEventKind::TcpClose
        | IngressEventKind::TcpError
        | IngressEventKind::UdpSessionStart
        | IngressEventKind::UdpDatagram
        | IngressEventKind::UdpSessionClose
        | IngressEventKind::UdpError => {}
        IngressEventKind::DnsQuery | IngressEventKind::DnsResponse | IngressEventKind::DnsError => {
            return None;
        }
    }

    let session_id = parse_u64(event.fields.get("sessionId")?)?;
    let decision_id = event
        .fields
        .get("decisionId")
        .and_then(|value| parse_u64(value));
    if matches!(event.kind, IngressEventKind::UdpSessionStart) && decision_id.is_none() {
        return None;
    }
    let inbound = event
        .fields
        .get("inbound")
        .cloned()
        .unwrap_or_else(|| "unknown".to_string());
    let session_key = format!(
        "{}:{}:{}",
        inbound,
        session_id,
        decision_id
            .map(|value| value.to_string())
            .unwrap_or_else(|| "none".to_string())
    );
    let direction = event.fields.get("direction").map(String::as_str);
    let datagram_bytes = event.fields.get("bytes").and_then(|value| parse_u64(value));

    Some(TrafficSessionUpdate {
        session_key,
        session_id,
        decision_id,
        inbound,
        observed_at_unix_ms: event.observed_at_unix_ms,
        node_protocol: event.fields.get("nodeProtocol").cloned(),
        peer: event.fields.get("peer").cloned(),
        target: event.fields.get("target").cloned(),
        target_ip: event.fields.get("targetIp").cloned(),
        target_port: event
            .fields
            .get("targetPort")
            .and_then(|value| value.parse::<u16>().ok()),
        target_domain: event.fields.get("targetDomain").cloned(),
        target_source: event.fields.get("targetSource").cloned(),
        upstream: event.fields.get("upstream").cloned(),
        selection_groups: event.fields.get("selectionGroups").cloned(),
        selection_nodes: event.fields.get("selectionNodes").cloned(),
        selection_trace: event.fields.get("selectionTrace").cloned(),
        close_reason: event.fields.get("closeReason").cloned(),
        error_stage: event.fields.get("errorStage").cloned(),
        error: event.fields.get("error").cloned(),
        client_to_upstream_bytes: event
            .fields
            .get("clientToUpstreamBytes")
            .and_then(|value| parse_u64(value)),
        upstream_to_client_bytes: event
            .fields
            .get("upstreamToClientBytes")
            .and_then(|value| parse_u64(value)),
        client_to_upstream_datagram: (direction == Some("client-to-upstream"))
            .then_some(datagram_bytes)
            .flatten(),
        upstream_to_client_datagram: (direction == Some("upstream-to-client"))
            .then_some(datagram_bytes)
            .flatten(),
        closes_session: matches!(
            event.kind,
            IngressEventKind::TcpClose
                | IngressEventKind::TcpError
                | IngressEventKind::UdpSessionClose
                | IngressEventKind::UdpError
        ),
    })
}

fn set_if_some(target: &mut Option<String>, value: Option<String>) {
    if value.is_some() {
        *target = value;
    }
}

fn parse_u64(value: &str) -> Option<u64> {
    value.parse::<u64>().ok()
}
