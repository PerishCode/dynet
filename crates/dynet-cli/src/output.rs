use std::fmt::Write as _;

use dynet_core::Severity;

use crate::{
    cli::OutputFormat,
    model::{Report, ReportMode},
};

pub(crate) fn print_report(report: &Report, format: OutputFormat) -> Result<(), String> {
    match format {
        OutputFormat::Text => {
            print!("{}", text_report(report));
            Ok(())
        }
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(report)
                .map_err(|error| format!("failed to serialize dynet report: {error}"))?;
            println!("{json}");
            Ok(())
        }
    }
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

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Deny => "deny",
        Severity::Warning => "warning",
    }
}
