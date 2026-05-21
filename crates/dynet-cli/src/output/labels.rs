use crate::{
    model::DoctorStatus,
    platform::{LifecycleAction, LifecycleStatus},
};

pub(super) fn match_label(matcher: &dynet_core::PlanMatch) -> String {
    let inbound = matcher.inbound.as_deref().unwrap_or("*");
    let mut parts = vec![format!("inbound {inbound}")];
    if let Some(transport) = matcher.transport {
        parts.push(format!("transport {}", transport_label(transport)));
    }
    if let Some(domain) = &matcher.domain {
        parts.push(format!("domain {domain}"));
    }
    if let Some(domain_suffix) = &matcher.domain_suffix {
        parts.push(format!("domain suffix {domain_suffix}"));
    }
    if let Some(domain_keyword) = &matcher.domain_keyword {
        parts.push(format!("domain keyword {domain_keyword}"));
    }
    if let Some(ip_cidr) = &matcher.ip_cidr {
        parts.push(format!("ip cidr {ip_cidr}"));
    }
    if let Some(destination_port) = matcher.destination_port {
        parts.push(format!("destination port {destination_port}"));
    }
    parts.join(", ")
}

pub(super) fn action_label(action: &dynet_core::PlanAction) -> String {
    match action {
        dynet_core::PlanAction::UseOutbound { tag } => format!("use outbound {tag}"),
        dynet_core::PlanAction::Reject => "reject".to_string(),
        dynet_core::PlanAction::NoRoute => "no route".to_string(),
    }
}

pub(super) fn lifecycle_action_label(action: LifecycleAction) -> &'static str {
    match action {
        LifecycleAction::Install => "install",
        LifecycleAction::Status => "status",
        LifecycleAction::Verify => "verify",
        LifecycleAction::Repair => "repair",
        LifecycleAction::Uninstall => "uninstall",
    }
}

pub(super) fn verdict_status_label(status: dynet_core::VerdictStatus) -> &'static str {
    match status {
        dynet_core::VerdictStatus::Accept => "accept",
        dynet_core::VerdictStatus::Deny => "deny",
        dynet_core::VerdictStatus::NoMatch => "no-match",
    }
}

pub(super) fn lifecycle_status_label(status: LifecycleStatus) -> &'static str {
    match status {
        LifecycleStatus::Pass => "pass",
        LifecycleStatus::Warn => "warning",
        LifecycleStatus::Deny => "deny",
    }
}

pub(super) fn severity_label(severity: dynet_core::Severity) -> &'static str {
    match severity {
        dynet_core::Severity::Deny => "deny",
        dynet_core::Severity::Warning => "warning",
    }
}

pub(super) fn doctor_status_label(status: DoctorStatus) -> &'static str {
    match status {
        DoctorStatus::Pass => "pass",
        DoctorStatus::Warn => "warning",
        DoctorStatus::Deny => "deny",
    }
}

fn transport_label(transport: dynet_core::Transport) -> &'static str {
    match transport {
        dynet_core::Transport::Tcp => "tcp",
        dynet_core::Transport::Udp => "udp",
        dynet_core::Transport::Dns => "dns",
    }
}
