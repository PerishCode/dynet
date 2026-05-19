use std::fmt::Write as _;

use serde::Serialize;

use crate::{
    cli::OutputFormat,
    model::{ApiCapabilityReport, DoctorReport, DoctorStatus, PlanReport, Report, ReportMode},
    platform::{LifecycleAction, LifecycleReport, LifecycleStatus},
};

pub(crate) fn print_report(report: &Report, format: OutputFormat) -> Result<(), String> {
    match format {
        OutputFormat::Text => {
            print!("{}", text_report(report));
            Ok(())
        }
        OutputFormat::Json => print_json(report),
    }
}

pub(crate) fn print_doctor_report(
    report: &DoctorReport,
    format: OutputFormat,
) -> Result<(), String> {
    match format {
        OutputFormat::Text => {
            print!("{}", text_doctor_report(report));
            Ok(())
        }
        OutputFormat::Json => print_json(report),
    }
}

pub(crate) fn print_plan_report(report: &PlanReport, format: OutputFormat) -> Result<(), String> {
    match format {
        OutputFormat::Text => {
            print!("{}", text_plan_report(report));
            Ok(())
        }
        OutputFormat::Json => print_json(report),
    }
}

pub(crate) fn print_api_capabilities(
    report: &ApiCapabilityReport,
    format: OutputFormat,
) -> Result<(), String> {
    match format {
        OutputFormat::Text => {
            print!("{}", text_api_capabilities(report));
            Ok(())
        }
        OutputFormat::Json => print_json(report),
    }
}

pub(crate) fn print_lifecycle_report(
    report: &LifecycleReport,
    format: OutputFormat,
) -> Result<(), String> {
    match format {
        OutputFormat::Text => {
            print!("{}", text_lifecycle_report(report));
            Ok(())
        }
        OutputFormat::Json => print_json(report),
    }
}

pub(crate) fn json_string<T: Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_string_pretty(value)
        .map_err(|error| format!("failed to serialize dynet report: {error}"))
}

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
            "dynet plan passed: {} explicit rule(s)",
            report.plan_summary.rules
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
    if let Some(final_outbound) = &report.plan.final_outbound {
        writeln!(&mut text, "final: {final_outbound}").expect("write string");
    } else {
        writeln!(&mut text, "final: unset").expect("write string");
    }
    if !report.plan.rules.is_empty() {
        text.push_str("\nrules:\n");
        for rule in &report.plan.rules {
            let inbound = rule.inbound.as_deref().unwrap_or("*");
            writeln!(
                &mut text,
                "{}. inbound {} -> outbound {} ({})",
                rule.order, inbound, rule.outbound, rule.reason
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

fn print_json<T: Serialize>(value: &T) -> Result<(), String> {
    println!("{}", json_string(value)?);
    Ok(())
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
