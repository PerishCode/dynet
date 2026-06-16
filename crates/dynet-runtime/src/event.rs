use std::{
    collections::{BTreeMap, VecDeque},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
};

use serde::Serialize;
use utoipa::ToSchema;

use crate::{persistence, unix_ms};

const EVENT_LIMIT: usize = 1024;

#[derive(Debug, Clone)]
pub struct EventStore {
    inner: Arc<EventInner>,
}

#[derive(Debug)]
struct EventInner {
    next_event_id: AtomicU64,
    next_session_id: AtomicU64,
    events: Mutex<VecDeque<IngressEvent>>,
    observation_sink: Option<persistence::ObservationSink>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct IngressEvent {
    pub id: u64,
    pub observed_at_unix_ms: u128,
    pub kind: IngressEventKind,
    pub fields: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "kebab-case")]
pub enum IngressEventKind {
    DnsQuery,
    DnsResponse,
    DnsError,
    TcpAccept,
    TcpClose,
    TcpError,
    UdpSessionStart,
    UdpDatagram,
    UdpSessionClose,
    UdpError,
}

impl Default for EventStore {
    fn default() -> Self {
        Self::with_sink(None)
    }
}

impl EventStore {
    pub(crate) fn with_sink(observation_sink: Option<persistence::ObservationSink>) -> Self {
        Self {
            inner: Arc::new(EventInner {
                next_event_id: AtomicU64::new(0),
                next_session_id: AtomicU64::new(0),
                events: Mutex::new(VecDeque::new()),
                observation_sink,
            }),
        }
    }

    pub fn next_session_id(&self) -> u64 {
        self.inner.next_session_id.fetch_add(1, Ordering::SeqCst) + 1
    }

    pub fn record(&self, kind: IngressEventKind, fields: impl IntoFields) {
        let event = IngressEvent {
            id: self.inner.next_event_id.fetch_add(1, Ordering::SeqCst) + 1,
            observed_at_unix_ms: unix_ms(),
            kind,
            fields: fields.into_fields(),
        };
        let mut events = self.inner.events.lock().expect("event store lock poisoned");
        if events.len() == EVENT_LIMIT {
            events.pop_front();
        }
        events.push_back(event.clone());
        drop(events);
        if let Some(sink) = &self.inner.observation_sink {
            sink.record_event(event);
        }
    }

    pub fn snapshot(&self) -> Vec<IngressEvent> {
        self.inner
            .events
            .lock()
            .expect("event store lock poisoned")
            .iter()
            .cloned()
            .collect()
    }
}

pub trait IntoFields {
    fn into_fields(self) -> BTreeMap<String, String>;
}

impl<const N: usize> IntoFields for [(&str, String); N] {
    fn into_fields(self) -> BTreeMap<String, String> {
        self.into_iter()
            .map(|(key, value)| (key.to_string(), value))
            .collect()
    }
}

impl IntoFields for Vec<(&'static str, String)> {
    fn into_fields(self) -> BTreeMap<String, String> {
        self.into_iter()
            .map(|(key, value)| (key.to_string(), value))
            .collect()
    }
}
