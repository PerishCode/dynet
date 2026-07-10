use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use dynet_service::{
    CommandOutput, ServiceController, ServiceManager, ServicePaths, ServiceRunner, ServiceSpec,
};
use tempfile::TempDir;

pub struct Fixture {
    _directory: TempDir,
    pub root: PathBuf,
    pub spec: ServiceSpec,
    pub paths: ServicePaths,
    pub runner: FakeRunner,
}

impl Fixture {
    pub fn new(manager: ServiceManager) -> Self {
        let directory = TempDir::new().expect("tempdir");
        let root = directory.path().to_path_buf();
        for path in [
            root.join("bin"),
            root.join("etc/dynet"),
            root.join("etc/systemd/system"),
            root.join("run/systemd/system"),
            root.join("etc/init.d"),
            root.join("sbin"),
            root.join("var/lib/dynet"),
        ] {
            fs::create_dir_all(path).expect("fixture directory");
        }
        let executable = root.join("bin/dynet");
        let config = root.join("etc/dynet/dynet.toml");
        let procd_binary = root.join("sbin/procd");
        fs::write(&executable, "binary").expect("executable");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o755))
                .expect("executable mode");
        }
        fs::write(&config, "[service]\nmanager = \"systemd\"\n").expect("config");
        fs::write(&procd_binary, "procd").expect("procd");
        let spec = ServiceSpec {
            manager,
            user: "service".to_string(),
            executable,
            config,
            runtime_database: root.join("var/lib/dynet/dynet.sqlite"),
            environment_file: None,
        };
        let paths = ServicePaths {
            systemd_system_dir: root.join("etc/systemd/system"),
            systemd_runtime_dir: root.join("run/systemd/system"),
            procd_init_dir: root.join("etc/init.d"),
            procd_binary,
        };
        Self {
            _directory: directory,
            root,
            spec,
            paths,
            runner: FakeRunner::default(),
        }
    }

    pub fn controller(&self) -> ServiceController<FakeRunner> {
        ServiceController::with_runner(self.spec.clone(), self.paths.clone(), self.runner.clone())
    }

    pub fn unit(&self) -> PathBuf {
        self.root.join("etc/systemd/system/dynet.service")
    }

    pub fn init(&self) -> PathBuf {
        self.root.join("etc/init.d/dynet")
    }
}

#[derive(Debug, Clone, Default)]
pub struct FakeRunner {
    state: Arc<Mutex<FakeState>>,
}

#[derive(Debug, Clone, Copy)]
pub struct CurrentIdentityRunner;

impl ServiceRunner for CurrentIdentityRunner {
    fn run(&self, command: &str, args: &[String]) -> Result<CommandOutput, String> {
        if command != "id" {
            return if args == ["apply", "--auto"] {
                Ok(success(""))
            } else {
                Err(format!("unexpected command {command}"))
            };
        }
        let root = unsafe { libc::geteuid() } == 0;
        match args.first().map(String::as_str) {
            Some("-u") => Ok(success(
                &(if root {
                    65534
                } else {
                    unsafe { libc::geteuid() }
                })
                .to_string(),
            )),
            Some("-g") => Ok(success(
                &(if root {
                    65534
                } else {
                    unsafe { libc::getegid() }
                })
                .to_string(),
            )),
            _ => Err(format!("unexpected id arguments {}", args.join(" "))),
        }
    }
}

#[derive(Debug, Default)]
struct FakeState {
    calls: Vec<String>,
    enabled: bool,
    active: bool,
}

impl FakeRunner {
    pub fn called(&self, expected: &str) -> bool {
        self.state
            .lock()
            .expect("fake runner lock")
            .calls
            .iter()
            .any(|call| call == expected)
    }

    pub fn clear_calls(&self) {
        self.state.lock().expect("fake runner lock").calls.clear();
    }
}

impl ServiceRunner for FakeRunner {
    fn run(&self, command: &str, args: &[String]) -> Result<CommandOutput, String> {
        let call = format!("{} {}", command, args.join(" "));
        let mut state = self.state.lock().expect("fake runner lock");
        state.calls.push(call);
        if command == "id" {
            return Ok(success("1000"));
        }
        if command == "systemctl" {
            return Ok(match args.first().map(String::as_str) {
                Some("is-enabled") => output(state.enabled, "enabled"),
                Some("is-active") => output(state.active, "active"),
                Some("show") => success("4242"),
                Some("enable") => {
                    state.enabled = true;
                    success("")
                }
                Some("disable") => {
                    state.enabled = false;
                    success("")
                }
                Some("start" | "restart") => {
                    state.active = true;
                    success("")
                }
                Some("stop") => {
                    state.active = false;
                    success("")
                }
                _ => success(""),
            });
        }
        if command == "ubus" {
            return Ok(success(
                r#"{"dynet":{"instances":{"instance1":{"running":true,"pid":4242}}}}"#,
            ));
        }
        if Path::new(command)
            .file_name()
            .is_some_and(|name| name == "dynet")
        {
            return Ok(match args.first().map(String::as_str) {
                Some("enabled") => output(state.enabled, "enabled"),
                Some("running") => output(state.active, "running"),
                Some("enable") => {
                    state.enabled = true;
                    success("")
                }
                Some("disable") => {
                    state.enabled = false;
                    success("")
                }
                Some("start" | "restart") => {
                    state.active = true;
                    success("")
                }
                Some("stop") => {
                    state.active = false;
                    success("")
                }
                _ => success(""),
            });
        }
        Ok(success(""))
    }
}

fn success(stdout: &str) -> CommandOutput {
    output(true, stdout)
}

fn output(success: bool, stdout: &str) -> CommandOutput {
    CommandOutput {
        success,
        stdout: stdout.to_string(),
        stderr: String::new(),
    }
}
