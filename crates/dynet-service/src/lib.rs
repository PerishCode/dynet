use std::path::Path;

mod artifact;
mod model;
mod procd;
mod runner;
mod supervisor;
mod systemd;

pub use model::{
    ResourceState, ServiceApplyReport, ServiceCheck, ServiceCleanupReport, ServiceIdentity,
    ServiceManager, ServicePaths, ServicePlan, ServiceSpec, ServiceStatus,
};
pub use runner::{CommandOutput, HostRunner, ServiceRunner};
pub use supervisor::{supervise, supervise_with};

use artifact::{atomic_write, classify, remove_owned};
use runner::run_required;

const SERVICE_NAME: &str = "dynet";
const SYSTEMD_UNIT: &str = "dynet.service";

#[derive(Debug, Clone)]
pub struct ServiceController<R = HostRunner> {
    spec: ServiceSpec,
    paths: ServicePaths,
    runner: R,
}

impl ServiceController<HostRunner> {
    pub fn new(spec: ServiceSpec) -> Self {
        Self::with_runner(spec, ServicePaths::default(), HostRunner)
    }
}

impl<R> ServiceController<R>
where
    R: ServiceRunner,
{
    pub fn with_runner(spec: ServiceSpec, paths: ServicePaths, runner: R) -> Self {
        Self {
            spec,
            paths,
            runner,
        }
    }

    pub fn spec(&self) -> &ServiceSpec {
        &self.spec
    }

    pub fn manager(&self) -> Result<ServiceManager, String> {
        match self.spec.manager {
            ServiceManager::Auto if self.paths.systemd_runtime_dir.is_dir() => {
                Ok(ServiceManager::Systemd)
            }
            ServiceManager::Auto if self.paths.procd_binary.is_file() => Ok(ServiceManager::Procd),
            ServiceManager::Auto => {
                Err("dynet service could not detect systemd or procd".to_string())
            }
            manager => Ok(manager),
        }
    }

    pub fn plan(&self) -> Result<ServicePlan, String> {
        let manager = self.manager()?;
        let artifact = self.artifact(manager)?;
        Ok(ServicePlan {
            manager,
            items: vec![
                format!("verify stable non-root service user {}", self.spec.user),
                format!(
                    "reconcile owned service artifact {}",
                    artifact.path.display()
                ),
                format!("enable {SERVICE_NAME} at boot"),
                "start only when the service is currently inactive".to_string(),
                "reconcile the takeover runtime skeleton before every start".to_string(),
                "clean capture hooks after every terminal process exit".to_string(),
            ],
        })
    }

    pub fn doctor(&self) -> Result<Vec<ServiceCheck>, String> {
        let manager = self.manager()?;
        let mut checks = vec![
            path_check("service.executable", &self.spec.executable, true),
            path_check("service.config", &self.spec.config, true),
            parent_check(
                "service.runtime-database.parent",
                &self.spec.runtime_database,
            ),
            self.identity_check(),
        ];
        if let Some(path) = &self.spec.environment_file {
            checks.push(path_check("service.environment-file", path, true));
        }
        checks.push(match manager {
            ServiceManager::Systemd => {
                directory_check("service.systemd.carrier", &self.paths.systemd_system_dir)
            }
            ServiceManager::Procd => {
                let mut check =
                    directory_check("service.procd.carrier", &self.paths.procd_init_dir);
                if !self.paths.procd_binary.is_file() {
                    check.state = ResourceState::Invalid;
                    check.detail = format!("{} is missing", self.paths.procd_binary.display());
                }
                check
            }
            ServiceManager::Auto => unreachable!("manager is resolved"),
        });
        Ok(checks)
    }

    pub fn status(&self) -> Result<ServiceStatus, String> {
        let manager = self.manager()?;
        let mut checks = self.doctor()?;
        let artifact = self.artifact(manager)?;
        checks.push(ServiceCheck {
            id: artifact.id,
            state: classify(&artifact.path, &artifact.content, artifact.mode)?,
            detail: artifact.path.display().to_string(),
        });
        let (enabled, active, main_pid) = self.manager_status(manager)?;
        Ok(ServiceStatus {
            manager,
            checks,
            enabled,
            active,
            main_pid,
        })
    }

    pub fn apply(&self) -> Result<ServiceApplyReport, String> {
        let manager = self.manager()?;
        self.require_doctor_ready()?;
        let before = self.status()?;
        let artifact = self.artifact(manager)?;
        let state = classify(&artifact.path, &artifact.content, artifact.mode)?;
        if state.is_hard_failure() {
            return Err(format!(
                "{} is {}; refusing to overwrite",
                artifact.path.display(),
                state.label()
            ));
        }
        let mut changed = Vec::new();
        let artifact_changed =
            matches!(state, ResourceState::Missing | ResourceState::ManagedUpdate);
        if artifact_changed {
            atomic_write(&artifact.path, &artifact.content, artifact.mode)?;
            changed.push(format!("wrote {}", artifact.path.display()));
            self.reload_manager_definition(manager)?;
        }
        if !before.enabled {
            self.manager_command(manager, "enable")?;
            changed.push(format!("enabled {SERVICE_NAME}"));
        }
        let mut started = false;
        if !before.active {
            self.manager_command(manager, "start")?;
            changed.push(format!("started {SERVICE_NAME}"));
            started = true;
        }
        Ok(ServiceApplyReport {
            manager,
            changed,
            restart_required: artifact_changed && before.active,
            started,
        })
    }

    pub fn cleanup(&self) -> Result<ServiceCleanupReport, String> {
        let manager = self.manager()?;
        let artifact = self.artifact(manager)?;
        let state = classify(&artifact.path, &artifact.content, artifact.mode)?;
        if state.is_hard_failure() {
            return Err(format!(
                "{} is {}; refusing cleanup",
                artifact.path.display(),
                state.label()
            ));
        }
        let (_, active, _) = self.manager_status(manager)?;
        let mut changed = Vec::new();
        if active {
            self.manager_command(manager, "stop")?;
            changed.push(format!("stopped {SERVICE_NAME}"));
        }
        let (enabled, _, _) = self.manager_status(manager)?;
        if enabled {
            self.manager_command(manager, "disable")?;
            changed.push(format!("disabled {SERVICE_NAME}"));
        }
        if remove_owned(&artifact.path, &artifact.content, artifact.mode)? {
            changed.push(format!("removed {}", artifact.path.display()));
            self.reload_manager_definition(manager)?;
        }
        Ok(ServiceCleanupReport { manager, changed })
    }

    pub fn start(&self) -> Result<(), String> {
        let manager = self.require_applied()?;
        self.manager_command(manager, "start")
    }

    pub fn stop(&self) -> Result<(), String> {
        let manager = self.require_applied()?;
        self.manager_command(manager, "stop")
    }

    pub fn restart(&self) -> Result<(), String> {
        let manager = self.require_applied()?;
        self.manager_command(manager, "restart")
    }

    pub fn reload(&self) -> Result<(), String> {
        let manager = self.manager()?;
        let (_, active, _) = self.manager_status(manager)?;
        if !active {
            return Err("dynet service is not active".to_string());
        }
        self.manager_command(manager, "reload")
    }

    pub fn logs(&self, lines: usize, follow: bool) -> Result<(), String> {
        let manager = self.manager()?;
        match manager {
            ServiceManager::Systemd => {
                let mut args = vec![
                    "-u".to_string(),
                    SYSTEMD_UNIT.to_string(),
                    "-n".to_string(),
                    lines.to_string(),
                    "--no-pager".to_string(),
                ];
                if follow {
                    args.push("-f".to_string());
                }
                self.runner.stream("journalctl", &args)
            }
            ServiceManager::Procd => {
                let mut args = vec![
                    "-e".to_string(),
                    SERVICE_NAME.to_string(),
                    "-l".to_string(),
                    lines.to_string(),
                ];
                if follow {
                    args.push("-f".to_string());
                }
                self.runner.stream("logread", &args)
            }
            ServiceManager::Auto => unreachable!("manager is resolved"),
        }
    }

    pub fn identity(&self) -> Result<ServiceIdentity, String> {
        resolve_identity_with(&self.spec.user, &self.runner)
    }

    fn require_doctor_ready(&self) -> Result<(), String> {
        let failures = self
            .doctor()?
            .into_iter()
            .filter(|check| check.state != ResourceState::Ready)
            .map(|check| format!("{}={} ({})", check.id, check.state.label(), check.detail))
            .collect::<Vec<_>>();
        if failures.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "dynet service doctor failed: {}",
                failures.join("; ")
            ))
        }
    }

    fn require_applied(&self) -> Result<ServiceManager, String> {
        let manager = self.manager()?;
        let artifact = self.artifact(manager)?;
        let state = classify(&artifact.path, &artifact.content, artifact.mode)?;
        if state != ResourceState::Ready {
            return Err(format!(
                "dynet service artifact is {}; run service apply first",
                state.label()
            ));
        }
        Ok(manager)
    }

    fn identity_check(&self) -> ServiceCheck {
        match resolve_identity_with(&self.spec.user, &self.runner) {
            Ok(identity) if identity.uid != 0 => ServiceCheck {
                id: "service.identity",
                state: ResourceState::Ready,
                detail: format!(
                    "{} uid={} gid={}",
                    self.spec.user, identity.uid, identity.gid
                ),
            },
            Ok(_) => ServiceCheck {
                id: "service.identity",
                state: ResourceState::Invalid,
                detail: "service user must not resolve to uid 0".to_string(),
            },
            Err(error) => ServiceCheck {
                id: "service.identity",
                state: ResourceState::Invalid,
                detail: error,
            },
        }
    }

    fn artifact(&self, manager: ServiceManager) -> Result<ServiceArtifact, String> {
        match manager {
            ServiceManager::Systemd => Ok(ServiceArtifact {
                id: "service.systemd.unit",
                path: systemd::unit_path(&self.paths),
                content: systemd::unit_content(&self.spec)?,
                mode: 0o644,
            }),
            ServiceManager::Procd => Ok(ServiceArtifact {
                id: "service.procd.init",
                path: procd::init_path(&self.paths),
                content: procd::init_content(&self.spec)?,
                mode: 0o755,
            }),
            ServiceManager::Auto => unreachable!("manager is resolved"),
        }
    }

    fn manager_status(&self, manager: ServiceManager) -> Result<(bool, bool, Option<u32>), String> {
        let artifact = self.artifact(manager)?;
        let state = classify(&artifact.path, &artifact.content, artifact.mode)?;
        if matches!(
            state,
            ResourceState::Missing
                | ResourceState::Drifted
                | ResourceState::Foreign
                | ResourceState::Invalid
        ) {
            return Ok((false, false, None));
        }
        match manager {
            ServiceManager::Systemd => {
                let enabled =
                    command_success(&self.runner, "systemctl", &["is-enabled", SYSTEMD_UNIT])?;
                let active =
                    command_success(&self.runner, "systemctl", &["is-active", SYSTEMD_UNIT])?;
                let pid = if active {
                    let output = self.runner.run(
                        "systemctl",
                        &strings(&["show", "--property", "MainPID", "--value", SYSTEMD_UNIT]),
                    )?;
                    output.stdout.parse::<u32>().ok().filter(|pid| *pid != 0)
                } else {
                    None
                };
                Ok((enabled, active, pid))
            }
            ServiceManager::Procd => {
                let command = artifact.path.display().to_string();
                let enabled = command_success(&self.runner, &command, &["enabled"])?;
                let active = command_success(&self.runner, &command, &["running"])?;
                Ok((enabled, active, None))
            }
            ServiceManager::Auto => unreachable!("manager is resolved"),
        }
    }

    fn manager_command(&self, manager: ServiceManager, action: &str) -> Result<(), String> {
        match manager {
            ServiceManager::Systemd => {
                run_required(&self.runner, "systemctl", &strings(&[action, SYSTEMD_UNIT]))
                    .map(|_| ())
            }
            ServiceManager::Procd => run_required(
                &self.runner,
                &procd::init_path(&self.paths).display().to_string(),
                &[action.to_string()],
            )
            .map(|_| ()),
            ServiceManager::Auto => unreachable!("manager is resolved"),
        }
    }

    fn reload_manager_definition(&self, manager: ServiceManager) -> Result<(), String> {
        match manager {
            ServiceManager::Systemd => {
                run_required(&self.runner, "systemctl", &strings(&["daemon-reload"])).map(|_| ())
            }
            ServiceManager::Procd => Ok(()),
            ServiceManager::Auto => unreachable!("manager is resolved"),
        }
    }
}

pub fn resolve_identity(user: &str) -> Result<ServiceIdentity, String> {
    resolve_identity_with(user, &HostRunner)
}

pub fn resolve_identity_with(
    user: &str,
    runner: &impl ServiceRunner,
) -> Result<ServiceIdentity, String> {
    if !valid_user_name(user) {
        return Err(
            "service user must contain only ASCII letters, digits, underscore, hyphen, or dot and must not start with a hyphen"
                .to_string(),
        );
    }
    let uid = run_required(runner, "id", &strings(&["-u", user]))?
        .stdout
        .parse::<u32>()
        .map_err(|error| format!("invalid uid for service user {user}: {error}"))?;
    if uid == 0 {
        return Err("service user must not resolve to uid 0".to_string());
    }
    let gid = run_required(runner, "id", &strings(&["-g", user]))?
        .stdout
        .parse::<u32>()
        .map_err(|error| format!("invalid gid for service user {user}: {error}"))?;
    Ok(ServiceIdentity { uid, gid })
}

fn valid_user_name(user: &str) -> bool {
    !user.is_empty()
        && !user.starts_with('-')
        && user
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

struct ServiceArtifact {
    id: &'static str,
    path: std::path::PathBuf,
    content: String,
    mode: u32,
}

fn path_check(id: &'static str, path: &Path, require_file: bool) -> ServiceCheck {
    let state = if !path.is_absolute() {
        ResourceState::Invalid
    } else if require_file && path.is_file() {
        ResourceState::Ready
    } else {
        ResourceState::Invalid
    };
    ServiceCheck {
        id,
        state,
        detail: path.display().to_string(),
    }
}

fn parent_check(id: &'static str, path: &Path) -> ServiceCheck {
    let parent = path.parent();
    let state = if path.is_absolute() && parent.is_some_and(Path::is_dir) {
        ResourceState::Ready
    } else {
        ResourceState::Invalid
    };
    ServiceCheck {
        id,
        state,
        detail: parent.map_or_else(|| path.display().to_string(), |p| p.display().to_string()),
    }
}

fn directory_check(id: &'static str, path: &Path) -> ServiceCheck {
    ServiceCheck {
        id,
        state: if path.is_dir() {
            ResourceState::Ready
        } else {
            ResourceState::Invalid
        },
        detail: path.display().to_string(),
    }
}

fn command_success(
    runner: &impl ServiceRunner,
    command: &str,
    args: &[&str],
) -> Result<bool, String> {
    runner
        .run(command, &strings(args))
        .map(|output| output.success)
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}
