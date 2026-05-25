use std::time::Instant;

use dynet_core::{OutboundDecision, OutboundPath};

use crate::event::RuntimeEvent;

pub(crate) fn hop_tags(path: &OutboundPath) -> String {
    path.hops
        .iter()
        .map(|hop| hop.tag.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

pub(crate) fn hop_kinds(path: &OutboundPath) -> String {
    path.hops
        .iter()
        .map(|hop| hop.kind.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

pub(crate) fn candidate_tags(decision: &OutboundDecision) -> String {
    decision
        .candidates
        .iter()
        .map(|candidate| candidate.to.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

pub(crate) fn json_field<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|error| format!("serialization failed: {error}"))
}

pub(crate) fn elapsed_ms(started: Instant) -> u128 {
    started.elapsed().as_millis()
}

pub(crate) fn annotate_runtime_error_fields(event: RuntimeEvent, error: &str) -> RuntimeEvent {
    let event = match numeric_error_field(error, "pendingRetries=") {
        Some(retries) => event.field("pendingRetries", retries),
        None => event,
    };
    let event = match numeric_error_field(error, "pendingElapsedMs=") {
        Some(elapsed_ms) => event.field("pendingElapsedMs", elapsed_ms),
        None => event,
    };
    match token_error_field(error, "pendingWaitClass=") {
        Some(wait_class) => event.field("pendingWaitClass", wait_class),
        None => event,
    }
}

pub(crate) fn classify_runtime_error(error: &str) -> &'static str {
    let text = error.to_ascii_lowercase();
    if text.contains("operation not permitted") || text.contains("permission denied") {
        "permission"
    } else if text.contains("capability") || text.contains("does not support outbound type") {
        "capability"
    } else if text.contains("shadowsocks") {
        "shadowsocks"
    } else if text.contains("trojan") {
        "trojan"
    } else if text.contains("timed out") || text.contains("timeout") {
        "timeout"
    } else if text.contains("refused") {
        "refused"
    } else if text.contains("reset") {
        "reset"
    } else if text.contains("tls") || text.contains("certificate") {
        "tls"
    } else if text.contains("dns") {
        "dns"
    } else if text.contains("vmess") {
        "vmess"
    } else {
        "other"
    }
}

pub(crate) fn classify_runtime_error_disposition(error: &str) -> &'static str {
    let text = error.to_ascii_lowercase();
    if text.contains("unexpected eof")
        || text.contains("eof")
        || text.contains("end of file")
        || text.contains("close_notify")
        || text.contains("closed connection")
    {
        "remote-eof"
    } else if text.contains("refused") {
        "connection-refused"
    } else if text.contains("no route to host") || text.contains("network is unreachable") {
        "network-unreachable"
    } else if text.contains("invalidcontenttype")
        || text.contains("invalid content type")
        || text.contains("corrupt message")
    {
        "protocol-invalid"
    } else if text.contains("reset") {
        "reset"
    } else if text.contains("certificate") {
        "certificate"
    } else if has_pending_timeout_fields(&text)
        || text.contains("resource temporarily unavailable")
        || text.contains("operation would block")
        || text.contains("would block")
    {
        "pending-timeout"
    } else if text.contains("timed out") || text.contains("timeout") {
        "timeout"
    } else {
        "unknown"
    }
}

fn has_pending_timeout_fields(text: &str) -> bool {
    text.contains("pendingretries=")
        || text.contains("pendingelapsedms=")
        || text.contains("pendingwaitclass=")
}

fn numeric_error_field(error: &str, marker: &str) -> Option<u64> {
    let start = error.find(marker)? + marker.len();
    let digits = error[start..]
        .chars()
        .take_while(|character| character.is_ascii_digit())
        .collect::<String>();
    if digits.is_empty() {
        return None;
    }
    digits.parse().ok()
}

fn token_error_field(error: &str, marker: &str) -> Option<String> {
    let start = error.find(marker)? + marker.len();
    let token = error[start..]
        .chars()
        .take_while(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
        .collect::<String>();
    if token.is_empty() {
        return None;
    }
    Some(token)
}
