use std::fmt::Write as _;

use crate::{
    model::{ApiCapabilityReport, DoctorReport, DoctorStatus, PlanReport, Report, ReportMode},
    platform::{LifecycleAction, LifecycleReport, LifecycleStatus},
};

pub(crate) fn text_report(report: &Report) -> String {
    let mut text = String::new();
    let mode = match report.mode {
        ReportMode::Check => "check",
        ReportMode::Run => "run",
    };

    if report.diagnostics.is_empty() {
        writeln!(&mut text, "dynet {mode} passed: config is valid").expect("write string");
    } else {
        writeln!(
            &mut text,
            "dynet {mode} found {} deny issue(s) and {} warning(s)",
            report.deny_count(),
            report.warning_count()
        )
        .expect("write string");
    }

    writeln!(
        &mut text,
        "config: {}, root: {}",
        report.config_source, report.root
    )
    .expect("write string");
    writeln!(
        &mut text,
        "summary: inbounds {}, outbounds {}, routes {}",
        report.summary.inbounds, report.summary.outbounds, report.summary.routes
    )
    .expect("write string");
    write_network_model(&mut text, &report.network);

    if !report.diagnostics.is_empty() {
        text.push_str("\ndiagnostics:\n");
        for diagnostic in &report.diagnostics {
            writeln!(
                &mut text,
                "{} {} - {}",
                severity_label(diagnostic.severity),
                diagnostic.path,
                diagnostic.message
            )
            .expect("write string");
        }
    }

    text
}

pub(crate) fn text_doctor_report(report: &DoctorReport) -> String {
    let mut text = String::new();
    if report.status_count(DoctorStatus::Deny) == 0 {
        writeln!(
            &mut text,
            "dynet doctor passed with {} warning(s)",
            report.status_count(DoctorStatus::Warn)
        )
        .expect("write string");
    } else {
        writeln!(
            &mut text,
            "dynet doctor found {} deny issue(s) and {} warning(s)",
            report.status_count(DoctorStatus::Deny),
            report.status_count(DoctorStatus::Warn)
        )
        .expect("write string");
    }
    writeln!(
        &mut text,
        "config: {}, root: {}",
        report.config_source, report.root
    )
    .expect("write string");
    writeln!(
        &mut text,
        "summary: inbounds {}, outbounds {}, routes {}",
        report.summary.inbounds, report.summary.outbounds, report.summary.routes
    )
    .expect("write string");
    write_network_model(&mut text, &report.network);
    text.push_str("\nchecks:\n");
    for check in &report.checks {
        writeln!(
            &mut text,
            "{} {} - {}",
            doctor_status_label(check.status),
            check.name,
            check.message
        )
        .expect("write string");
    }
    if !report.diagnostics.is_empty() {
        text.push_str("\nconfig diagnostics:\n");
        for diagnostic in &report.diagnostics {
            writeln!(
                &mut text,
                "{} {} - {}",
                severity_label(diagnostic.severity),
                diagnostic.path,
                diagnostic.message
            )
            .expect("write string");
        }
    }
    text
}

pub(crate) fn text_plan_report(report: &PlanReport) -> String {
    let mut text = String::new();
    if report.deny_count() == 0 {
        writeln!(
            &mut text,
            "dynet plan passed: {} explicit rule(s), {} dynamic rule(s)",
            report.plan_summary.explicit_rules, report.plan_summary.dynamic_rules
        )
        .expect("write string");
    } else {
        writeln!(
            &mut text,
            "dynet plan found {} deny issue(s) and {} warning(s)",
            report.deny_count(),
            report.warning_count()
        )
        .expect("write string");
    }
    writeln!(
        &mut text,
        "config: {}, root: {}",
        report.config_source, report.root
    )
    .expect("write string");
    writeln!(
        &mut text,
        "summary: inbounds {}, outbounds {}, routes {}",
        report.summary.inbounds, report.summary.outbounds, report.summary.routes
    )
    .expect("write string");
    writeln!(
        &mut text,
        "plan model: {} over {}",
        report.plan.schema, report.plan.state_schema
    )
    .expect("write string");
    writeln!(
        &mut text,
        "default rule: {}",
        if report.plan_summary.has_default {
            "set"
        } else {
            "unset"
        }
    )
    .expect("write string");
    if !report.plan.rules.is_empty() {
        text.push_str("\nrules:\n");
        for rule in &report.plan.rules {
            writeln!(
                &mut text,
                "{}. match {} -> {} ({})",
                rule.order,
                match_label(&rule.matcher),
                action_label(&rule.action),
                rule.reason
            )
            .expect("write string");
        }
    }
    if !report.diagnostics.is_empty() {
        text.push_str("\nconfig diagnostics:\n");
        for diagnostic in &report.diagnostics {
            writeln!(
                &mut text,
                "{} {} - {}",
                severity_label(diagnostic.severity),
                diagnostic.path,
                diagnostic.message
            )
            .expect("write string");
        }
    }
    text
}

pub(crate) fn text_api_capabilities(report: &ApiCapabilityReport) -> String {
    let mut text = String::new();
    writeln!(
        &mut text,
        "dynet API {} default bind {}",
        report.schema, report.default_bind
    )
    .expect("write string");
    for capability in &report.capabilities {
        writeln!(
            &mut text,
            "{} {} - {}",
            capability.method, capability.path, capability.purpose
        )
        .expect("write string");
    }
    text
}

pub(crate) fn text_lifecycle_report(report: &LifecycleReport) -> String {
    let mut text = String::new();
    let action = lifecycle_action_label(report.action);
    if report.deny_count() == 0 {
        writeln!(
            &mut text,
            "dynet {action} passed with {} warning(s)",
            report.warning_count()
        )
        .expect("write string");
    } else {
        writeln!(
            &mut text,
            "dynet {action} found {} deny issue(s) and {} warning(s)",
            report.deny_count(),
            report.warning_count()
        )
        .expect("write string");
    }
    if let Some(config_source) = &report.config_source {
        writeln!(
            &mut text,
            "config: {}, root: {}",
            config_source,
            report.root.as_deref().unwrap_or("-")
        )
        .expect("write string");
    }
    if let Some(summary) = report.summary {
        writeln!(
            &mut text,
            "summary: inbounds {}, outbounds {}, routes {}",
            summary.inbounds, summary.outbounds, summary.routes
        )
        .expect("write string");
    }
    text.push_str("\nchecks:\n");
    for check in &report.checks {
        writeln!(
            &mut text,
            "{} {} - {}",
            lifecycle_status_label(check.status),
            check.name,
            check.message
        )
        .expect("write string");
    }
    text.push_str("\nowned resources:\n");
    for resource in &report.resources {
        let presence = if resource.present {
            "present"
        } else {
            "absent"
        };
        writeln!(
            &mut text,
            "{} {} {} - {}",
            presence, resource.kind, resource.name, resource.detail
        )
        .expect("write string");
    }
    if let Some(desired_state) = &report.desired_state {
        writeln!(
            &mut text,
            "\ndesired state: {} ({})",
            desired_state.schema, desired_state.mutation_mode
        )
        .expect("write string");
        writeln!(
            &mut text,
            "takeover: {} manifest {}",
            desired_state.takeover.schema, desired_state.takeover.manifest.path
        )
        .expect("write string");
        writeln!(
            &mut text,
            "effective config: nft {}, tun {}, fwmark {}, table {}, dns {}",
            desired_state.takeover.config.nft_table,
            desired_state.takeover.config.tun_name,
            desired_state.takeover.config.route_mark,
            desired_state.takeover.config.route_table,
            desired_state.takeover.config.dns_endpoint()
        )
        .expect("write string");
        text.push_str("takeover steps:\n");
        for step in &desired_state.takeover.steps {
            writeln!(
                &mut text,
                "{} {} - {}",
                step.phase, step.name, step.operation
            )
            .expect("write string");
        }
        text.push_str("desired resources:\n");
        for resource in &desired_state.resources {
            writeln!(
                &mut text,
                "{} {} {} - {}",
                resource.operation, resource.kind, resource.name, resource.detail
            )
            .expect("write string");
        }
        text.push_str("\ndesired artifacts:\n");
        for artifact in &desired_state.artifacts {
            writeln!(
                &mut text,
                "{} {} -> {} ({} bytes)",
                artifact.kind,
                artifact.name,
                artifact.target,
                artifact.content.len()
            )
            .expect("write string");
        }
        text.push_str("\ndesired validations:\n");
        for validation in &desired_state.validations {
            writeln!(
                &mut text,
                "{} {} {} - {}",
                lifecycle_status_label(validation.status),
                validation.artifact,
                validation.name,
                validation.message
            )
            .expect("write string");
        }
    }
    if !report.diagnostics.is_empty() {
        text.push_str("\nconfig diagnostics:\n");
        for diagnostic in &report.diagnostics {
            writeln!(
                &mut text,
                "{} {} - {}",
                severity_label(diagnostic.severity),
                diagnostic.path,
                diagnostic.message
            )
            .expect("write string");
        }
    }
    text
}

fn write_network_model(text: &mut String, network: &dynet_core::NetworkModel) {
    writeln!(text, "network model: {}", network.schema).expect("write string");
    if !network.inbounds.is_empty() {
        text.push_str("inbounds:\n");
        for node in &network.inbounds {
            writeln!(
                text,
                "- {} {} [{}]",
                node.tag,
                node.kind,
                node.capabilities.join(", ")
            )
            .expect("write string");
        }
    }
    if !network.outbounds.is_empty() {
        text.push_str("outbounds:\n");
        for node in &network.outbounds {
            writeln!(
                text,
                "- {} {} [{}]",
                node.tag,
                node.kind,
                node.capabilities.join(", ")
            )
            .expect("write string");
        }
    }
}

fn match_label(matcher: &dynet_core::PlanMatch) -> String {
    let inbound = matcher.inbound.as_deref().unwrap_or("*");
    match matcher.transport {
        Some(transport) => format!(
            "inbound {inbound}, transport {}",
            transport_label(transport)
        ),
        None => format!("inbound {inbound}"),
    }
}

fn action_label(action: &dynet_core::PlanAction) -> String {
    match action {
        dynet_core::PlanAction::UseOutbound { tag } => format!("use outbound {tag}"),
        dynet_core::PlanAction::NoRoute => "no route".to_string(),
    }
}

fn transport_label(transport: dynet_core::Transport) -> &'static str {
    match transport {
        dynet_core::Transport::Tcp => "tcp",
        dynet_core::Transport::Udp => "udp",
        dynet_core::Transport::Dns => "dns",
    }
}

fn lifecycle_action_label(action: LifecycleAction) -> &'static str {
    match action {
        LifecycleAction::Install => "install",
        LifecycleAction::Status => "status",
        LifecycleAction::Verify => "verify",
        LifecycleAction::Repair => "repair",
        LifecycleAction::Uninstall => "uninstall",
    }
}

fn lifecycle_status_label(status: LifecycleStatus) -> &'static str {
    match status {
        LifecycleStatus::Pass => "pass",
        LifecycleStatus::Warn => "warning",
        LifecycleStatus::Deny => "deny",
    }
}

fn severity_label(severity: dynet_core::Severity) -> &'static str {
    match severity {
        dynet_core::Severity::Deny => "deny",
        dynet_core::Severity::Warning => "warning",
    }
}

fn doctor_status_label(status: DoctorStatus) -> &'static str {
    match status {
        DoctorStatus::Pass => "pass",
        DoctorStatus::Warn => "warning",
        DoctorStatus::Deny => "deny",
    }
}
