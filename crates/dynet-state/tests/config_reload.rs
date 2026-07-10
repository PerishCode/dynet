use dynet_ingress::EgressNodeConfig;
use dynet_state::{Config, ReloadDisposition};
use std::time::Duration;

#[test]
fn unchanged_config_is_noop() {
    let config = Config::default();
    let plan = config.plan_reload(&config.clone());

    assert_eq!(plan.disposition, ReloadDisposition::Noop);
    assert!(plan.changed_fields.is_empty());
    assert!(plan.restart_required_fields.is_empty());
}

#[test]
fn hot_fields_apply() {
    let current = Config::default();
    let mut next = current.clone();
    next.capture.tun.tcp_idle_timeout = Duration::from_secs(9);
    next.capture.tun.udp_response_timeout = Duration::from_secs(8);
    next.forwarding
        .execution_nodes
        .insert("new-direct".to_string(), EgressNodeConfig::Direct);

    let plan = current.plan_reload(&next);

    assert_eq!(plan.disposition, ReloadDisposition::Apply);
    assert_eq!(
        plan.changed_fields,
        [
            "capture.tun.tcp_idle_timeout",
            "capture.tun.udp_response_timeout",
            "forwarding",
        ]
    );
    assert!(plan.restart_required_fields.is_empty());
}

#[test]
fn restart_fields_reject() {
    let current = Config::default();
    let mut next = current.clone();
    next.control.bind = "127.0.0.1:19977".parse().expect("socket");
    next.capture.tun.interface = "dynet1".to_string();
    next.capture.tun.tcp_idle_timeout = Duration::from_secs(9);

    let plan = current.plan_reload(&next);

    assert_eq!(plan.disposition, ReloadDisposition::RestartRequired);
    assert_eq!(
        plan.changed_fields,
        [
            "control.bind",
            "capture.tun.interface",
            "capture.tun.tcp_idle_timeout",
        ]
    );
    assert_eq!(
        plan.restart_required_fields,
        ["control.bind", "capture.tun.interface"]
    );
}

#[test]
fn service_change_requires_restart() {
    let current = Config::default();
    let mut next = current.clone();
    next.service.user = "service".to_string();

    let plan = current.plan_reload(&next);

    assert_eq!(plan.disposition, ReloadDisposition::RestartRequired);
    assert_eq!(plan.changed_fields, ["service"]);
    assert_eq!(plan.restart_required_fields, ["service"]);
}

#[test]
fn ipv6_change_requires_restart() {
    let current = Config::default();
    let mut next = current.clone();
    next.ipv6.enabled = true;

    let plan = current.plan_reload(&next);

    assert_eq!(plan.disposition, ReloadDisposition::RestartRequired);
    assert_eq!(plan.changed_fields, ["ipv6.enabled"]);
    assert_eq!(plan.restart_required_fields, ["ipv6.enabled"]);
}

#[test]
fn persistence_change_requires_restart() {
    let current = Config::default();
    let mut next = current.clone();
    next.persistence.retention = std::time::Duration::from_secs(12 * 60 * 60);

    let plan = current.plan_reload(&next);

    assert_eq!(plan.disposition, ReloadDisposition::RestartRequired);
    assert_eq!(plan.changed_fields, vec!["persistence"]);
    assert_eq!(plan.restart_required_fields, vec!["persistence"]);
}

#[test]
fn mapping_change_requires_restart() {
    let current = Config::default();
    let mut next = current.clone();
    next.dns_mapping.interface = Some("br-lan".to_string());

    let plan = current.plan_reload(&next);

    assert_eq!(plan.disposition, ReloadDisposition::RestartRequired);
    assert_eq!(plan.changed_fields, vec!["dns_mapping"]);
    assert_eq!(plan.restart_required_fields, vec!["dns_mapping"]);
}

#[test]
fn fingerprint_stable_opaque() {
    let first = Config::default();
    let mut second = first.clone();
    second.capture.tun.tcp_idle_timeout = Duration::from_millis(2345);

    let first_fingerprint = first.fingerprint();
    let duplicate_fingerprint = first.clone().fingerprint();
    let second_fingerprint = second.fingerprint();

    assert_eq!(first_fingerprint, duplicate_fingerprint);
    assert_ne!(first_fingerprint, second_fingerprint);
    assert!(first_fingerprint.starts_with("config-sha256:"));
    assert_eq!(first_fingerprint.len(), "config-sha256:".len() + 64);
}
