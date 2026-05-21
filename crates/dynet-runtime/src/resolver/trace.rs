use std::time::Instant;

use dynet_core::{OutboundDecision, OutboundPath};

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
