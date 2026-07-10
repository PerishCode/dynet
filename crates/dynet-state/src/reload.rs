use sha2::{Digest, Sha256};

use crate::Config;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ReloadDisposition {
    Noop,
    Apply,
    RestartRequired,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ReloadPlan {
    pub disposition: ReloadDisposition,
    pub changed_fields: Vec<&'static str>,
    pub restart_required_fields: Vec<&'static str>,
}

impl ReloadPlan {
    fn new(changed_fields: Vec<&'static str>, restart_required_fields: Vec<&'static str>) -> Self {
        let disposition = if changed_fields.is_empty() {
            ReloadDisposition::Noop
        } else if restart_required_fields.is_empty() {
            ReloadDisposition::Apply
        } else {
            ReloadDisposition::RestartRequired
        };
        Self {
            disposition,
            changed_fields,
            restart_required_fields,
        }
    }
}

pub(crate) fn config_fingerprint(config: &Config) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("{config:#?}").as_bytes());
    format!("config-sha256:{:x}", hasher.finalize())
}

pub(crate) fn plan_reload(current: &Config, next: &Config) -> ReloadPlan {
    let mut changed = Vec::new();
    let mut restart = Vec::new();

    restart_field(
        &mut changed,
        &mut restart,
        "control.bind",
        current.control.bind != next.control.bind,
    );
    restart_field(
        &mut changed,
        &mut restart,
        "ingress.dns.bind",
        current.ingress.dns.bind != next.ingress.dns.bind,
    );
    restart_field(
        &mut changed,
        &mut restart,
        "ingress.dns.max_sessions",
        current.ingress.dns.max_sessions != next.ingress.dns.max_sessions,
    );
    restart_field(
        &mut changed,
        &mut restart,
        "ingress.tcp.bind",
        current.ingress.tcp.bind != next.ingress.tcp.bind,
    );
    restart_field(
        &mut changed,
        &mut restart,
        "ingress.tcp.upstream",
        current.ingress.tcp.upstream != next.ingress.tcp.upstream,
    );
    restart_field(
        &mut changed,
        &mut restart,
        "ingress.tcp.max_sessions",
        current.ingress.tcp.max_sessions != next.ingress.tcp.max_sessions,
    );
    restart_field(
        &mut changed,
        &mut restart,
        "ingress.udp.bind",
        current.ingress.udp.bind != next.ingress.udp.bind,
    );
    restart_field(
        &mut changed,
        &mut restart,
        "ingress.udp.upstream",
        current.ingress.udp.upstream != next.ingress.udp.upstream,
    );
    restart_field(
        &mut changed,
        &mut restart,
        "ingress.udp.idle_timeout",
        current.ingress.udp.idle_timeout != next.ingress.udp.idle_timeout,
    );
    restart_field(
        &mut changed,
        &mut restart,
        "ingress.udp.max_sessions",
        current.ingress.udp.max_sessions != next.ingress.udp.max_sessions,
    );
    restart_field(
        &mut changed,
        &mut restart,
        "ingress.socks5.bind",
        current.ingress.socks5.bind != next.ingress.socks5.bind,
    );
    restart_field(
        &mut changed,
        &mut restart,
        "ingress.socks5.udp_advertise_ip",
        current.ingress.socks5.udp_advertise_ip != next.ingress.socks5.udp_advertise_ip,
    );
    restart_field(
        &mut changed,
        &mut restart,
        "ingress.socks5.idle_timeout",
        current.ingress.socks5.idle_timeout != next.ingress.socks5.idle_timeout,
    );
    restart_field(
        &mut changed,
        &mut restart,
        "ingress.socks5.max_sessions",
        current.ingress.socks5.max_sessions != next.ingress.socks5.max_sessions,
    );
    restart_field(
        &mut changed,
        &mut restart,
        "capture.tun.enabled",
        current.capture.tun.enabled != next.capture.tun.enabled,
    );
    restart_field(
        &mut changed,
        &mut restart,
        "capture.tun.interface",
        current.capture.tun.interface != next.capture.tun.interface,
    );
    restart_field(
        &mut changed,
        &mut restart,
        "capture.router_ingress",
        current.capture.router_ingress != next.capture.router_ingress,
    );
    restart_field(
        &mut changed,
        &mut restart,
        "ipv6.enabled",
        current.ipv6.enabled != next.ipv6.enabled,
    );
    restart_field(
        &mut changed,
        &mut restart,
        "dns_mapping",
        current.dns_mapping != next.dns_mapping,
    );
    restart_field(
        &mut changed,
        &mut restart,
        "persistence",
        current.persistence != next.persistence,
    );
    restart_field(
        &mut changed,
        &mut restart,
        "service",
        current.service != next.service,
    );

    hot_field(
        &mut changed,
        "capture.tun.tcp_idle_timeout",
        current.capture.tun.tcp_idle_timeout != next.capture.tun.tcp_idle_timeout,
    );
    hot_field(
        &mut changed,
        "capture.tun.udp_idle_timeout",
        current.capture.tun.udp_idle_timeout != next.capture.tun.udp_idle_timeout,
    );
    hot_field(
        &mut changed,
        "capture.tun.udp_response_timeout",
        current.capture.tun.udp_response_timeout != next.capture.tun.udp_response_timeout,
    );
    hot_field(
        &mut changed,
        "forwarding",
        current.forwarding != next.forwarding,
    );

    ReloadPlan::new(changed, restart)
}

fn hot_field(changed: &mut Vec<&'static str>, name: &'static str, differs: bool) {
    if differs {
        changed.push(name);
    }
}

fn restart_field(
    changed: &mut Vec<&'static str>,
    restart: &mut Vec<&'static str>,
    name: &'static str,
    differs: bool,
) {
    if differs {
        changed.push(name);
        restart.push(name);
    }
}
