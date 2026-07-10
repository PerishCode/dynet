use std::path::PathBuf;

pub use dynet_state::ServiceManager;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ServiceSpec {
    pub manager: ServiceManager,
    pub user: String,
    pub executable: PathBuf,
    pub config: PathBuf,
    pub runtime_database: PathBuf,
    pub environment_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ServicePaths {
    pub systemd_system_dir: PathBuf,
    pub systemd_runtime_dir: PathBuf,
    pub procd_init_dir: PathBuf,
    pub procd_binary: PathBuf,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ResourceState {
    Ready,
    Missing,
    ManagedUpdate,
    Drifted,
    Foreign,
    Invalid,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ServiceCheck {
    pub id: &'static str,
    pub state: ResourceState,
    pub detail: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ServicePlan {
    pub manager: ServiceManager,
    pub items: Vec<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ServiceStatus {
    pub manager: ServiceManager,
    pub checks: Vec<ServiceCheck>,
    pub enabled: bool,
    pub active: bool,
    pub main_pid: Option<u32>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ServiceApplyReport {
    pub manager: ServiceManager,
    pub changed: Vec<String>,
    pub restart_required: bool,
    pub started: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ServiceCleanupReport {
    pub manager: ServiceManager,
    pub changed: Vec<String>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ServiceIdentity {
    pub uid: u32,
    pub gid: u32,
}

impl Default for ServicePaths {
    fn default() -> Self {
        Self {
            systemd_system_dir: PathBuf::from("/etc/systemd/system"),
            systemd_runtime_dir: PathBuf::from("/run/systemd/system"),
            procd_init_dir: PathBuf::from("/etc/init.d"),
            procd_binary: PathBuf::from("/sbin/procd"),
        }
    }
}

impl ResourceState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Missing => "missing",
            Self::ManagedUpdate => "managed-update",
            Self::Drifted => "drifted",
            Self::Foreign => "foreign",
            Self::Invalid => "invalid",
        }
    }

    pub fn is_hard_failure(self) -> bool {
        matches!(self, Self::Drifted | Self::Foreign | Self::Invalid)
    }
}

pub(crate) fn valid_user_name(user: &str) -> bool {
    !user.is_empty()
        && !user.starts_with('-')
        && user
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}
