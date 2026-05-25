use std::fmt::Write as _;

pub(crate) fn text_runtime_report(report: &dynet_runtime::RuntimeReport) -> String {
    let mut text = String::new();
    let status = match report.status {
        dynet_runtime::RuntimeStatus::Pass => "passed",
        dynet_runtime::RuntimeStatus::Deny => "denied",
    };
    writeln!(&mut text, "dynet runtime {status}: {}", report.reason).expect("write string");
    writeln!(&mut text, "runtime model: {}", report.schema).expect("write string");
    writeln!(
        &mut text,
        "observed: {} tun packet(s), {} dns query(s), {} route decision(s), {} proxied dns query(s), {} dns reverse record(s), {} ipv6 packet denial(s), {} runtime event(s)",
        report.tun_packets,
        report.dns_queries,
        report.route_decisions,
        report.proxied_dns_queries,
        report.dns_records,
        report.ipv6_packets_denied,
        report.events.len()
    )
    .expect("write string");
    writeln!(
        &mut text,
        "tcp forwarding: {} session(s), {} closed session(s), {} failure(s), {} upstream byte(s), {} downstream byte(s)",
        report.tcp_sessions,
        report.tcp_closed_sessions,
        report.tcp_session_failures,
        report.tcp_upstream_bytes,
        report.tcp_downstream_bytes
    )
    .expect("write string");
    writeln!(
        &mut text,
        "tcp listen capacity: ports={:?}, slots/port={}, capacity={}, active max={}, pressure event(s)={}",
        report.tcp_listen_ports,
        report.tcp_listen_slots_per_port,
        report.tcp_listen_capacity,
        report.tcp_active_slots_max,
        report.tcp_slot_pressure_events
    )
    .expect("write string");
    writeln!(
        &mut text,
        "udp forwarding: {} session(s), {} failure(s), {} upstream byte(s), {} downstream byte(s), {} dropped packet(s)",
        report.udp_sessions,
        report.udp_session_failures,
        report.udp_upstream_bytes,
        report.udp_downstream_bytes,
        report.udp_dropped_packets
    )
    .expect("write string");
    if !report.dns_reverse.records.is_empty() {
        text.push_str("dns reverse records:\n");
        for record in &report.dns_reverse.records {
            writeln!(
                &mut text,
                "- {} -> {} ttl {}",
                record.query, record.address, record.ttl_secs
            )
            .expect("write string");
        }
    }
    write_events(&mut text, &report.events);
    text
}

pub(crate) fn text_probe_report(report: &dynet_runtime::ProbeReport) -> String {
    let mut text = String::new();
    let status = match report.status {
        dynet_runtime::RuntimeStatus::Pass => "passed",
        dynet_runtime::RuntimeStatus::Deny => "denied",
    };
    writeln!(&mut text, "dynet probe {status}: {}", report.reason).expect("write string");
    writeln!(&mut text, "probe model: {}", report.schema).expect("write string");
    writeln!(&mut text, "protocol: {}", report.protocol.as_str()).expect("write string");
    if let Some(scope) = report.failure_scope {
        writeln!(&mut text, "failure scope: {}", scope.as_str()).expect("write string");
    }
    writeln!(
        &mut text,
        "target: https://{}:{}{}",
        report.target.host, report.target.port, report.target.path
    )
    .expect("write string");
    writeln!(
        &mut text,
        "observed: {} route decision(s), {} outbound attempt(s), {} runtime event(s)",
        report.route_decisions,
        report.outbound_attempts,
        report.events.len()
    )
    .expect("write string");
    if !report.read_policy.is_default() {
        writeln!(
            &mut text,
            "read policy: pollTimeoutMs={} pendingBudgetMs={} pendingSleepMs={}",
            report.read_policy.poll_timeout_ms,
            report.read_policy.pending_budget_ms,
            report.read_policy.pending_sleep_ms
        )
        .expect("write string");
    }
    if report.retry.enabled {
        writeln!(
            &mut text,
            "retry: attempts={} recoveredAfterRetry={} unresolvedDirectTlsEof={}",
            report.retry.attempts_used,
            report.retry.recovered_after_retry,
            report.retry.unresolved_direct_tls_eof,
        )
        .expect("write string");
    }
    write_events(&mut text, &report.events);
    text
}

fn write_events(text: &mut String, events: &[dynet_runtime::RuntimeEvent]) {
    if events.is_empty() {
        return;
    }
    text.push_str("runtime events:\n");
    for event in events {
        let sequence = event
            .sequence
            .map(|value| value.to_string())
            .unwrap_or_else(|| "?".to_string());
        writeln!(text, "- #{} {:?}", sequence, event.kind).expect("write string");
        for (key, value) in &event.fields {
            writeln!(text, "  {key}: {value}").expect("write string");
        }
    }
}
