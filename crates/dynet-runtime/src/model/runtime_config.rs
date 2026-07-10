use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, RwLock,
    },
};

use serde::Serialize;
use utoipa::ToSchema;

use crate::unix_ms;

const RELOAD_AUDIT_LIMIT: usize = 128;

#[derive(Debug, Clone)]
pub struct RuntimeConfigAudit {
    inner: Arc<RuntimeConfigAuditInner>,
}

#[derive(Debug)]
struct RuntimeConfigAuditInner {
    next_id: AtomicU64,
    status: RwLock<RuntimeConfigStatus>,
    audits: Mutex<VecDeque<ConfigReloadAudit>>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeConfigStatus {
    pub generation: u64,
    pub fingerprint: String,
    pub source: String,
    pub started_at_unix_ms: u128,
    pub applied_at_unix_ms: u128,
    pub last_reload_at_unix_ms: Option<u128>,
    pub last_reload_outcome: Option<ConfigReloadOutcome>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigReloadAudit {
    pub id: u64,
    pub observed_at_unix_ms: u128,
    pub trigger: ConfigReloadTrigger,
    pub outcome: ConfigReloadOutcome,
    pub generation_before: u64,
    pub generation_after: u64,
    pub candidate_fingerprint: Option<String>,
    pub changed_fields: Vec<String>,
    pub restart_required_fields: Vec<String>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ConfigReloadTrigger {
    Sighup,
    Manual,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ConfigReloadOutcome {
    Applied,
    #[serde(rename = "no-op")]
    Noop,
    RestartRequired,
    Invalid,
    Failed,
}

impl ConfigReloadOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Noop => "no-op",
            Self::RestartRequired => "restart-required",
            Self::Invalid => "invalid",
            Self::Failed => "failed",
        }
    }
}

impl RuntimeConfigAudit {
    pub fn new(generation: u64, fingerprint: String, source: String) -> Self {
        let now = unix_ms();
        Self {
            inner: Arc::new(RuntimeConfigAuditInner {
                next_id: AtomicU64::new(0),
                status: RwLock::new(RuntimeConfigStatus {
                    generation,
                    fingerprint,
                    source,
                    started_at_unix_ms: now,
                    applied_at_unix_ms: now,
                    last_reload_at_unix_ms: None,
                    last_reload_outcome: None,
                }),
                audits: Mutex::new(VecDeque::new()),
            }),
        }
    }

    pub fn untracked(generation: u64) -> Self {
        Self::new(generation, "untracked".to_string(), "untracked".to_string())
    }

    pub fn status(&self) -> RuntimeConfigStatus {
        self.inner
            .status
            .read()
            .expect("runtime config status lock poisoned")
            .clone()
    }

    pub fn snapshot(&self) -> Vec<ConfigReloadAudit> {
        self.inner
            .audits
            .lock()
            .expect("runtime config audit lock poisoned")
            .iter()
            .cloned()
            .collect()
    }

    pub fn record_applied(
        &self,
        trigger: ConfigReloadTrigger,
        generation: u64,
        fingerprint: String,
        changed_fields: Vec<String>,
    ) {
        let before = self.status().generation;
        let observed_at = unix_ms();
        {
            let mut status = self
                .inner
                .status
                .write()
                .expect("runtime config status lock poisoned");
            status.generation = generation;
            status.fingerprint = fingerprint.clone();
            status.applied_at_unix_ms = observed_at;
            status.last_reload_at_unix_ms = Some(observed_at);
            status.last_reload_outcome = Some(ConfigReloadOutcome::Applied);
        }
        self.push(ConfigReloadAudit {
            id: 0,
            observed_at_unix_ms: observed_at,
            trigger,
            outcome: ConfigReloadOutcome::Applied,
            generation_before: before,
            generation_after: generation,
            candidate_fingerprint: Some(fingerprint),
            changed_fields,
            restart_required_fields: Vec::new(),
            message: None,
        });
    }

    pub fn record_noop(&self, trigger: ConfigReloadTrigger, candidate_fingerprint: String) {
        self.record_unchanged(
            trigger,
            ConfigReloadOutcome::Noop,
            Some(candidate_fingerprint),
            Vec::new(),
            Vec::new(),
            None,
        );
    }

    pub fn record_restart_required(
        &self,
        trigger: ConfigReloadTrigger,
        candidate_fingerprint: String,
        changed_fields: Vec<String>,
        restart_required_fields: Vec<String>,
    ) {
        self.record_unchanged(
            trigger,
            ConfigReloadOutcome::RestartRequired,
            Some(candidate_fingerprint),
            changed_fields,
            restart_required_fields,
            Some("configuration changes require a process restart".to_string()),
        );
    }

    pub fn record_invalid(&self, trigger: ConfigReloadTrigger) {
        self.record_unchanged(
            trigger,
            ConfigReloadOutcome::Invalid,
            None,
            Vec::new(),
            Vec::new(),
            Some("configuration parsing or validation failed".to_string()),
        );
    }

    pub fn record_failed(&self, trigger: ConfigReloadTrigger) {
        self.record_unchanged(
            trigger,
            ConfigReloadOutcome::Failed,
            None,
            Vec::new(),
            Vec::new(),
            Some("runtime configuration commit failed".to_string()),
        );
    }

    fn record_unchanged(
        &self,
        trigger: ConfigReloadTrigger,
        outcome: ConfigReloadOutcome,
        candidate_fingerprint: Option<String>,
        changed_fields: Vec<String>,
        restart_required_fields: Vec<String>,
        message: Option<String>,
    ) {
        let observed_at = unix_ms();
        let generation = {
            let mut status = self
                .inner
                .status
                .write()
                .expect("runtime config status lock poisoned");
            status.last_reload_at_unix_ms = Some(observed_at);
            status.last_reload_outcome = Some(outcome);
            status.generation
        };
        self.push(ConfigReloadAudit {
            id: 0,
            observed_at_unix_ms: observed_at,
            trigger,
            outcome,
            generation_before: generation,
            generation_after: generation,
            candidate_fingerprint,
            changed_fields,
            restart_required_fields,
            message,
        });
    }

    fn push(&self, mut audit: ConfigReloadAudit) {
        audit.id = self.inner.next_id.fetch_add(1, Ordering::SeqCst) + 1;
        let mut audits = self
            .inner
            .audits
            .lock()
            .expect("runtime config audit lock poisoned");
        if audits.len() == RELOAD_AUDIT_LIMIT {
            audits.pop_front();
        }
        audits.push_back(audit);
    }
}
