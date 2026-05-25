use std::fmt::Write as _;

use crate::{
    model::{ApiCapabilityReport, DoctorReport, DoctorStatus, PlanReport, Report, ReportMode},
    platform::LifecycleReport,
};

use super::labels::{
    action_label, doctor_status_label, lifecycle_action_label, lifecycle_status_label, match_label,
    severity_label, verdict_status_label,
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
    write_summary(&mut text, report.summary);
    write_network_model(&mut text, &report.network);
    write_dns_model(&mut text, &report.dns);

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
    write_summary(&mut text, report.summary);
    write_network_model(&mut text, &report.network);
    write_dns_model(&mut text, &report.dns);
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
            "dynet plan passed: {} explicit rule(s), {} dynamic rule(s), {} reject rule(s), {} DNS-sensitive rule(s)",
            report.plan_summary.explicit_rules,
            report.plan_summary.dynamic_rules,
            report.plan_summary.reject_rules,
            report.plan_summary.dns_sensitive_rules
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
    write_summary(&mut text, report.summary);
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
            let dns_sensitive = if rule.dns_sensitive {
                " [dns-sensitive]"
            } else {
                ""
            };
            writeln!(
                &mut text,
                "{}. match {} -> {}{} ({})",
                rule.order,
                match_label(&rule.matcher),
                action_label(&rule.action),
                dns_sensitive,
                rule.reason
            )
            .expect("write string");
        }
    }
    if let Some(verdict) = &report.verdict {
        writeln!(
            &mut text,
            "\nverdict: {} via {} ({})",
            verdict_status_label(verdict.status),
            action_label(&verdict.action),
            verdict.reason
        )
        .expect("write string");
        if let Some(outbound) = &verdict.outbound {
            writeln!(
                &mut text,
                "outbound: {} {} {}",
                outbound.tag, outbound.kind, outbound.fingerprint
            )
            .expect("write string");
        }
    }
    if let Some(path) = &report.outbound_path {
        writeln!(
            &mut text,
            "outbound path: {} -> {}",
            path.requested, path.selected
        )
        .expect("write string");
    }
    if let Some(path) = &report.dialer_bound_path {
        writeln!(
            &mut text,
            "dialer bound path: {} -> {}",
            path.requested, path.selected
        )
        .expect("write string");
    }
    if let Some(feedback) = &report.quality_feedback {
        writeln!(
            &mut text,
            "quality feedback: mode={} penalties={} fallback signals={} recovered={} non-retry-safe={}",
            feedback.mode.as_deref().unwrap_or("unknown"),
            feedback.penalty_observations,
            feedback.fallback_signals,
            feedback.recovered_fallback_signals,
            feedback.non_retry_safe_fallback_signals
        )
        .expect("write string");
    }
    if !report.quality_signals.is_empty() {
        text.push_str("quality signals:\n");
        for signal in &report.quality_signals {
            if signal.fallback_type.is_some() {
                writeln!(
                    &mut text,
                    "- {} action={} failed={} recovered={} replaySafe={}",
                    signal.signal_type,
                    signal.action.as_deref().unwrap_or("observe"),
                    signal.failed_bound.as_deref().unwrap_or("*"),
                    signal.recovered_bound.as_deref().unwrap_or("*"),
                    signal.replay_safe.as_deref().unwrap_or("*")
                )
                .expect("write string");
            } else {
                writeln!(
                    &mut text,
                    "- {} action={}",
                    signal.signal_type,
                    signal.action.as_deref().unwrap_or("observe")
                )
                .expect("write string");
            }
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
        write_summary(&mut text, summary);
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
            "effective config: nft {}, main {}, drop-in {}, tun {}, fwmark {}, table {}, dns {}",
            desired_state.takeover.config.nft_table,
            desired_state.takeover.config.nft_main_config,
            desired_state.takeover.config.nft_dropin_path,
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

fn write_summary(text: &mut String, summary: dynet_core::ConfigSummary) {
    writeln!(
        text,
        "summary: inbounds {}, outbounds {}, rules {}, routes {}, dns chains {}",
        summary.inbounds, summary.outbounds, summary.rules, summary.routes, summary.dns_chains
    )
    .expect("write string");
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

fn write_dns_model(text: &mut String, dns: &dynet_core::DnsModel) {
    writeln!(text, "dns model: {}", dns.schema).expect("write string");
    if !dns.chains.is_empty() {
        text.push_str("dns chains:\n");
        for chain in &dns.chains {
            let endpoint = chain.endpoint.as_deref().unwrap_or("-");
            writeln!(text, "- {} {} {}", chain.tag, chain.kind, endpoint).expect("write string");
        }
    }
}
