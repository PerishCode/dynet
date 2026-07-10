use std::{
    fs,
    path::PathBuf,
    process::Command,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use dynet_service::{
    supervise_with, ResourceState, ServiceController, ServiceManager, ServiceSpec,
};
use tempfile::TempDir;

mod support;
use support::{CurrentIdentityRunner, Fixture};

#[test]
fn systemd_apply_is_idempotent() {
    let fixture = Fixture::new(ServiceManager::Systemd);
    let controller = fixture.controller();

    let first = controller.apply().expect("first apply");
    assert!(first.started);
    assert!(!first.restart_required);
    assert!(fixture.unit().is_file());
    assert!(fixture.runner.called("systemctl daemon-reload"));
    assert!(fixture.runner.called("systemctl enable dynet.service"));
    assert!(fixture.runner.called("systemctl start dynet.service"));
    let unit = fs::read_to_string(fixture.unit()).expect("unit content");
    assert!(unit.contains("apply --auto"));
    assert!(unit.contains("ExecStartPre=+") && unit.contains("dns-mapping cleanup --config"));
    assert!(unit.contains("ExecStartPre=+") && unit.contains("router-hooks cleanup --config"));
    assert!(unit.contains("ExecStopPost=+") && unit.contains("hooks cleanup --config"));

    fixture.runner.clear_calls();
    let second = controller.apply().expect("second apply");
    assert!(second.changed.is_empty());
    assert!(!second.started);
    assert!(!second.restart_required);
    assert!(!fixture.runner.called("systemctl daemon-reload"));
}

#[tokio::test]
async fn supervisor_fail_open() {
    let directory = TempDir::new().expect("tempdir");
    let config = directory.path().join("dynet.toml");
    fs::write(&config, "").expect("config");
    let spec = ServiceSpec {
        manager: ServiceManager::Procd,
        user: "service".to_string(),
        executable: PathBuf::from("/bin/false"),
        config,
        runtime_database: directory.path().join("dynet.sqlite"),
        environment_file: None,
    };
    let cleanups = Arc::new(AtomicUsize::new(0));
    let cleanup_counter = cleanups.clone();

    let error = supervise_with(&spec, &CurrentIdentityRunner, move || {
        cleanup_counter.fetch_add(1, Ordering::SeqCst);
        Ok(())
    })
    .await
    .expect_err("failed child");

    assert!(error.contains("exited with"));
    assert_eq!(cleanups.load(Ordering::SeqCst), 2);
}

#[test]
fn managed_change_needs_restart() {
    let fixture = Fixture::new(ServiceManager::Systemd);
    fixture.controller().apply().expect("initial apply");
    let mut spec = fixture.spec.clone();
    spec.user = "other-service".to_string();
    fixture.runner.clear_calls();

    let report =
        ServiceController::with_runner(spec, fixture.paths.clone(), fixture.runner.clone())
            .apply()
            .expect("managed update");

    assert!(report.restart_required);
    assert!(!report.started);
    assert!(fixture.runner.called("systemctl daemon-reload"));
    assert!(!fixture.runner.called("systemctl restart dynet.service"));
}

#[test]
fn permission_drift_reconciles() {
    let fixture = Fixture::new(ServiceManager::Systemd);
    fixture.controller().apply().expect("initial apply");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(fixture.unit(), fs::Permissions::from_mode(0o600))
            .expect("change unit mode");
    }

    let report = fixture.controller().apply().expect("reconcile mode");

    assert!(report.restart_required);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(fixture.unit())
                .expect("unit metadata")
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
    }
}

#[cfg(unix)]
#[test]
fn artifact_symlink_rejected() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new(ServiceManager::Systemd);
    let foreign = fixture.root.join("foreign.service");
    fs::write(&foreign, "foreign\n").expect("foreign target");
    symlink(&foreign, fixture.unit()).expect("unit symlink");

    let status = fixture.controller().status().expect("symlink status");

    assert_eq!(
        status
            .checks
            .iter()
            .find(|check| check.id == "service.systemd.unit")
            .expect("unit check")
            .state,
        ResourceState::Invalid
    );
    assert!(fixture.controller().apply().is_err());
    assert_eq!(
        fs::read_to_string(foreign).expect("foreign content"),
        "foreign\n"
    );
}

#[test]
fn unsafe_user_rejected() {
    let fixture = Fixture::new(ServiceManager::Systemd);
    let mut spec = fixture.spec.clone();
    spec.user = "service\nExecStart=/foreign".to_string();
    fixture.runner.clear_calls();

    let error = ServiceController::with_runner(spec, fixture.paths.clone(), fixture.runner.clone())
        .apply()
        .expect_err("unsafe user rejected");

    assert!(error.contains("ASCII letters"));
    assert!(!fixture.runner.called("id -u service\nExecStart=/foreign"));
}

#[test]
fn drift_and_foreign_rejected() {
    let fixture = Fixture::new(ServiceManager::Systemd);
    fixture.controller().apply().expect("initial apply");
    let mut content = fs::read_to_string(fixture.unit()).expect("unit content");
    content.push_str("# external mutation\n");
    fs::write(fixture.unit(), content).expect("mutate unit");

    let status = fixture.controller().status().expect("drift status");
    assert_eq!(
        status
            .checks
            .iter()
            .find(|check| check.id == "service.systemd.unit")
            .expect("unit check")
            .state,
        ResourceState::Drifted
    );
    assert!(fixture.controller().apply().is_err());

    fs::write(fixture.unit(), "[Service]\nExecStart=/foreign\n").expect("foreign unit");
    let error = fixture.controller().apply().expect_err("foreign rejected");
    assert!(error.contains("foreign"));
}

#[test]
fn cleanup_removes_owned() {
    let fixture = Fixture::new(ServiceManager::Systemd);
    fixture.controller().apply().expect("apply");

    let report = fixture.controller().cleanup().expect("cleanup");

    assert!(!fixture.unit().exists());
    assert!(report
        .changed
        .iter()
        .any(|change| change.contains("stopped")));
    assert!(report
        .changed
        .iter()
        .any(|change| change.contains("disabled")));
    assert!(fixture.runner.called("systemctl stop dynet.service"));
}

#[test]
fn procd_supervisor_contract() {
    let fixture = Fixture::new(ServiceManager::Procd);

    fixture.controller().apply().expect("procd apply");

    let content = fs::read_to_string(fixture.init()).expect("init content");
    assert!(content.starts_with("#!/bin/sh /etc/rc.common\n# dynet-owned:"));
    assert!(content.contains("service supervise --config"));
    assert!(content.contains("hooks cleanup --config"));
    assert!(content.contains("router-hooks cleanup --config"));
    assert!(content.contains("dns-mapping cleanup --config"));
    assert!(content.contains("procd_set_param respawn"));
    assert!(content.contains("procd_set_param limits nofile='4096 4096'"));
    assert!(fixture
        .runner
        .called(&format!("{} enable", fixture.init().display())));
    assert!(fixture
        .runner
        .called(&format!("{} start", fixture.init().display())));
    fixture.controller().logs(42, false).expect("procd logs");
    assert!(fixture.runner.called("logread -e dynet -l 42"));
    assert_eq!(
        fixture
            .controller()
            .status()
            .expect("procd status")
            .main_pid,
        Some(4242)
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(fixture.init())
                .expect("init metadata")
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
    }
}

#[test]
fn procd_missing_is_inactive() {
    let fixture = Fixture::new(ServiceManager::Procd);

    let status = fixture.controller().status().expect("missing status");

    assert!(!status.enabled);
    assert!(!status.active);
    assert!(!fixture
        .runner
        .called(&format!("{} enabled", fixture.init().display())));
    assert!(!fixture
        .runner
        .called(&format!("{} running", fixture.init().display())));
}

#[test]
fn procd_foreign_not_executed() {
    let fixture = Fixture::new(ServiceManager::Procd);
    fs::write(fixture.init(), "#!/bin/sh\nexit 0\n").expect("foreign init");

    let status = fixture.controller().status().expect("foreign status");

    assert!(!status.enabled);
    assert!(!status.active);
    assert!(!fixture
        .runner
        .called(&format!("{} enabled", fixture.init().display())));
    assert!(fixture.controller().apply().is_err());
    assert!(!fixture
        .runner
        .called(&format!("{} running", fixture.init().display())));
}

#[test]
fn native_syntax_checks() {
    let systemd = Fixture::new(ServiceManager::Systemd);
    systemd.controller().apply().expect("systemd apply");
    if Command::new("systemd-analyze")
        .arg("--version")
        .output()
        .is_ok()
    {
        let output = Command::new("systemd-analyze")
            .arg("verify")
            .arg(systemd.unit())
            .output()
            .expect("systemd verify");
        assert!(
            output.status.success(),
            "systemd unit verification failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let procd = Fixture::new(ServiceManager::Procd);
    procd.controller().apply().expect("procd apply");
    let output = Command::new("sh")
        .arg("-n")
        .arg(procd.init())
        .output()
        .expect("shell syntax check");
    assert!(
        output.status.success(),
        "procd script syntax failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
