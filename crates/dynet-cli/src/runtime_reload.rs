use std::{
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use dynet_ingress::ReloadableEgress;
use dynet_runtime::{ConfigReloadTrigger, RuntimeConfigAudit, RuntimeState, RuntimeStore};
use dynet_state::{Config, ReloadDisposition, TunCaptureConfig};
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub struct RuntimeReload {
    inner: Arc<RuntimeReloadInner>,
}

#[derive(Debug)]
struct RuntimeReloadInner {
    current: Mutex<Config>,
    config_path: Option<PathBuf>,
    runtime: RuntimeState,
    store: RuntimeStore,
    egress: ReloadableEgress,
    tun: Arc<RwLock<TunCaptureConfig>>,
    audit: RuntimeConfigAudit,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ReloadResult {
    Applied {
        generation: u64,
        changed_fields: Vec<String>,
    },
    Noop {
        generation: u64,
    },
    RestartRequired {
        generation: u64,
        fields: Vec<String>,
    },
    Invalid {
        generation: u64,
    },
    Failed {
        generation: u64,
    },
}

impl RuntimeReload {
    pub fn new(
        config: Config,
        config_path: Option<PathBuf>,
        runtime: RuntimeState,
        store: RuntimeStore,
    ) -> Result<Self, String> {
        let egress = ReloadableEgress::new(
            runtime.generation(),
            config.forwarding.execution_nodes.clone(),
        )?;
        let tun = Arc::new(RwLock::new(config.capture.tun.clone()));
        let audit = RuntimeConfigAudit::new(
            runtime.generation(),
            config.fingerprint(),
            config_source(config_path.as_deref()),
        );
        Ok(Self {
            inner: Arc::new(RuntimeReloadInner {
                current: Mutex::new(config),
                config_path,
                runtime,
                store,
                egress,
                tun,
                audit,
            }),
        })
    }

    pub fn egress(&self) -> ReloadableEgress {
        self.inner.egress.clone()
    }

    pub fn tun_config(&self) -> Arc<RwLock<TunCaptureConfig>> {
        self.inner.tun.clone()
    }

    pub fn audit(&self) -> RuntimeConfigAudit {
        self.inner.audit.clone()
    }

    pub async fn reload(&self, trigger: ConfigReloadTrigger) -> ReloadResult {
        let mut current = self.inner.current.lock().await;
        let candidate = match Config::from_config_path(self.inner.config_path.as_deref()) {
            Ok(candidate) => candidate,
            Err(_) => {
                self.inner.audit.record_invalid(trigger);
                return ReloadResult::Invalid {
                    generation: self.inner.runtime.generation(),
                };
            }
        };
        let fingerprint = candidate.fingerprint();
        let plan = current.plan_reload(&candidate);
        match plan.disposition {
            ReloadDisposition::Noop => {
                self.inner.audit.record_noop(trigger, fingerprint);
                ReloadResult::Noop {
                    generation: self.inner.runtime.generation(),
                }
            }
            ReloadDisposition::RestartRequired => {
                let changed_fields = string_fields(&plan.changed_fields);
                let restart_fields = string_fields(&plan.restart_required_fields);
                self.inner.audit.record_restart_required(
                    trigger,
                    fingerprint,
                    changed_fields,
                    restart_fields.clone(),
                );
                ReloadResult::RestartRequired {
                    generation: self.inner.runtime.generation(),
                    fields: restart_fields,
                }
            }
            ReloadDisposition::Apply => {
                self.apply_candidate(
                    &mut current,
                    candidate,
                    fingerprint,
                    &plan.changed_fields,
                    trigger,
                )
                .await
            }
        }
    }

    async fn apply_candidate(
        &self,
        current: &mut Config,
        candidate: Config,
        fingerprint: String,
        changed: &[&str],
        trigger: ConfigReloadTrigger,
    ) -> ReloadResult {
        let prepared = self
            .inner
            .runtime
            .prepare_reconfigure(candidate.forwarding.seed.clone());
        let generation = prepared.generation();
        if self
            .inner
            .egress
            .install(generation, candidate.forwarding.execution_nodes.clone())
            .is_err()
        {
            return self.failed(trigger);
        }
        let previous_seed = current.forwarding.seed.clone();
        if self
            .inner
            .store
            .replace_bootstrap(candidate.forwarding.seed.clone())
            .await
            .is_err()
        {
            self.inner.egress.remove(generation);
            return self.failed(trigger);
        }
        if self.inner.runtime.commit_reconfigure(prepared).is_err() {
            self.inner.egress.remove(generation);
            let _ = self.inner.store.replace_bootstrap(previous_seed).await;
            return self.failed(trigger);
        }
        *self
            .inner
            .tun
            .write()
            .expect("runtime TUN config lock poisoned") = candidate.capture.tun.clone();
        let changed_fields = string_fields(changed);
        *current = candidate;
        self.inner
            .audit
            .record_applied(trigger, generation, fingerprint, changed_fields.clone());
        ReloadResult::Applied {
            generation,
            changed_fields,
        }
    }

    fn failed(&self, trigger: ConfigReloadTrigger) -> ReloadResult {
        self.inner.audit.record_failed(trigger);
        ReloadResult::Failed {
            generation: self.inner.runtime.generation(),
        }
    }
}

fn string_fields(fields: &[&str]) -> Vec<String> {
    fields.iter().map(|field| (*field).to_string()).collect()
}

fn config_source(path: Option<&Path>) -> String {
    path.map_or_else(
        || "dynet.toml (default) + inherited environment".to_string(),
        |path| format!("{} + inherited environment", path.display()),
    )
}
