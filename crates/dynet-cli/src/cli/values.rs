use super::{LogLevel, OutputFormat, ProbeProtocol};

pub(super) fn parse_format(value: &str) -> Result<OutputFormat, String> {
    match value {
        "text" => Ok(OutputFormat::Text),
        "json" => Ok(OutputFormat::Json),
        other => Err(format!("unsupported output format: {other}")),
    }
}

pub(super) fn parse_log_level(value: &str) -> Result<LogLevel, String> {
    match value {
        "off" => Ok(LogLevel::Off),
        "error" => Ok(LogLevel::Error),
        "warn" | "warning" => Ok(LogLevel::Warn),
        "info" => Ok(LogLevel::Info),
        "debug" => Ok(LogLevel::Debug),
        "trace" => Ok(LogLevel::Trace),
        other => Err(format!("unsupported log level: {other}")),
    }
}

pub(super) fn parse_probe_protocol(value: &str) -> Result<ProbeProtocol, String> {
    match value {
        "https-head" => Ok(ProbeProtocol::HttpsHead),
        "tls-handshake" => Ok(ProbeProtocol::TlsHandshake),
        other => Err(format!("unsupported probe protocol: {other}")),
    }
}

pub(super) fn parse_u64(flag: &str, value: &str) -> Result<u64, String> {
    value
        .parse()
        .map_err(|_| format!("{flag} must be a non-negative integer"))
}

pub(super) fn parse_u32(flag: &str, value: &str) -> Result<u32, String> {
    value
        .parse()
        .map_err(|_| format!("{flag} must be a non-negative integer"))
}

pub(super) fn parse_u16(flag: &str, value: &str) -> Result<u16, String> {
    match value.parse::<u16>() {
        Ok(0) | Err(_) => Err(format!("{flag} must be a positive integer <= 65535")),
        Ok(value) => Ok(value),
    }
}

pub(super) fn parse_usize(flag: &str, value: &str) -> Result<usize, String> {
    match value.parse::<usize>() {
        Ok(0) | Err(_) => Err(format!("{flag} must be a positive integer")),
        Ok(value) => Ok(value),
    }
}
