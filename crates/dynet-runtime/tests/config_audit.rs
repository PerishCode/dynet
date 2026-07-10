use dynet_runtime::{ConfigReloadOutcome, ConfigReloadTrigger, RuntimeConfigAudit};

#[test]
fn applied_updates_audit() {
    let audit = RuntimeConfigAudit::new(1, "first".into(), "/etc/dynet.toml".into());

    audit.record_applied(
        ConfigReloadTrigger::Manual,
        2,
        "second".into(),
        vec!["forwarding".into()],
    );

    let status = audit.status();
    assert_eq!(status.generation, 2);
    assert_eq!(status.fingerprint, "second");
    assert_eq!(
        status.last_reload_outcome,
        Some(ConfigReloadOutcome::Applied)
    );
    let records = audit.snapshot();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].generation_before, 1);
    assert_eq!(records[0].generation_after, 2);
    assert_eq!(records[0].changed_fields, ["forwarding"]);
}

#[test]
fn rejected_keeps_status() {
    let audit = RuntimeConfigAudit::new(3, "current".into(), "config".into());

    audit.record_restart_required(
        ConfigReloadTrigger::Manual,
        "candidate".into(),
        vec!["control.bind".into()],
        vec!["control.bind".into()],
    );

    let status = audit.status();
    assert_eq!(status.generation, 3);
    assert_eq!(status.fingerprint, "current");
    assert_eq!(
        status.last_reload_outcome,
        Some(ConfigReloadOutcome::RestartRequired)
    );
}

#[test]
fn audit_history_bounded() {
    let audit = RuntimeConfigAudit::untracked(1);
    for index in 0..140 {
        audit.record_noop(ConfigReloadTrigger::Manual, format!("candidate-{index}"));
    }

    let records = audit.snapshot();
    assert_eq!(records.len(), 128);
    assert_eq!(records[0].id, 13);
    assert_eq!(records.last().expect("last audit").id, 140);
}
