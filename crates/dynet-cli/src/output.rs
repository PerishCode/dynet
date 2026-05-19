#[path = "output/json.rs"]
pub(crate) mod json;
#[path = "output/text.rs"]
mod text;

use crate::{
    cli::OutputFormat,
    model::{ApiCapabilityReport, DoctorReport, PlanReport, Report},
    platform::LifecycleReport,
};

pub(crate) use text::{
    text_api_capabilities, text_doctor_report, text_lifecycle_report, text_plan_report, text_report,
};

pub(crate) fn print_report(report: &Report, format: OutputFormat) -> Result<(), String> {
    match format {
        OutputFormat::Text => {
            print!("{}", text_report(report));
            Ok(())
        }
        OutputFormat::Json => json::print_json(report),
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
        OutputFormat::Json => json::print_json(report),
    }
}

pub(crate) fn print_plan_report(report: &PlanReport, format: OutputFormat) -> Result<(), String> {
    match format {
        OutputFormat::Text => {
            print!("{}", text_plan_report(report));
            Ok(())
        }
        OutputFormat::Json => json::print_json(report),
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
        OutputFormat::Json => json::print_json(report),
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
        OutputFormat::Json => json::print_json(report),
    }
}
