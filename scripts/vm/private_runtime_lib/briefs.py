from __future__ import annotations

from collections import Counter

from private_runtime_lib.common import SELECTION_EVENT_KINDS, STABILITY_PATTERNS


def runtime_brief(report: dict) -> dict:
    return {
        "status": report.get("status"),
        "reason": report.get("reason"),
        "tunPackets": report.get("tunPackets"),
        "dnsQueries": report.get("dnsQueries"),
        "routeDecisions": report.get("routeDecisions"),
        "proxiedDnsQueries": report.get("proxiedDnsQueries"),
        "dnsRecords": report.get("dnsRecords"),
        "ipv6PacketsDenied": report.get("ipv6PacketsDenied"),
        "tcpSessions": report.get("tcpSessions"),
        "tcpSessionFailures": report.get("tcpSessionFailures"),
        "tcpUpstreamBytes": report.get("tcpUpstreamBytes"),
        "tcpDownstreamBytes": report.get("tcpDownstreamBytes"),
        "udpSessions": report.get("udpSessions"),
        "udpSessionFailures": report.get("udpSessionFailures"),
        "udpUpstreamBytes": report.get("udpUpstreamBytes"),
        "udpDownstreamBytes": report.get("udpDownstreamBytes"),
        "udpDroppedPackets": report.get("udpDroppedPackets"),
    }

def selection_brief(report: dict) -> dict:
    rows = []
    for event in report.get("events", []):
        if not isinstance(event, dict):
            continue
        kind = event.get("kind")
        if kind not in SELECTION_EVENT_KINDS:
            continue
        fields = event.get("fields", {})
        if isinstance(fields, dict):
            rows.append({"kind": kind, "fields": fields})
    return {"events": rows}

def fields(event: dict) -> dict[str, str]:
    value = event.get("fields", {})
    if not isinstance(value, dict):
        return {}
    return {str(key): str(item) for key, item in value.items()}

def stability_brief(
    report: dict,
    log_text: str,
    tcp_probe_report: dict,
    udp_probe_report: dict,
    ipv6_probe_report: dict,
    workload_probe_report: dict,
) -> dict:
    events = [event for event in report.get("events", []) if isinstance(event, dict)]
    close_reasons: Counter[str] = Counter()
    failure_types: Counter[str] = Counter()
    udp_close_reasons: Counter[str] = Counter()
    udp_failure_types: Counter[str] = Counter()
    ip_denials = 0
    session_marks: dict[str, dict[str, int]] = {}
    for event in events:
        kind = str(event.get("kind"))
        event_fields = fields(event)
        session = event_fields.get("session")
        if kind == "ip-packet-denied":
            ip_denials += 1
        if kind == "tcp-session-closed":
            close_reasons[event_fields.get("reason", "<unknown>")] += 1
        if kind == "tcp-session-failed":
            failure_types[event_fields.get("errorType", "<unknown>")] += 1
        if kind == "udp-session-closed":
            udp_close_reasons[event_fields.get("reason", "<unknown>")] += 1
        if kind in {"udp-session-denied", "udp-session-failed"}:
            udp_failure_types[event_fields.get("errorType", "<unknown>")] += 1
        if session and kind.startswith("tcp-session-"):
            timestamp = event.get("emittedAtUnixMs")
            if isinstance(timestamp, int):
                session_marks.setdefault(session, {})[kind] = timestamp

    session_timings = []
    for session, marks in sorted(session_marks.items()):
        start = marks.get("tcp-session-started")
        if start is None:
            continue
        row = {"session": session}
        for key, value in {
            "attributedMs": marks.get("tcp-session-attributed"),
            "establishedMs": marks.get("tcp-session-established"),
            "firstPayloadMs": marks.get("tcp-session-payload-first-write"),
            "firstDownstreamMs": marks.get("tcp-session-payload-received"),
            "closedMs": marks.get("tcp-session-closed"),
            "failedMs": marks.get("tcp-session-failed"),
        }.items():
            if value is not None:
                row[key] = value - start
        session_timings.append(row)

    tcp_results = [
        item for item in tcp_probe_report.get("results", []) if isinstance(item, dict)
    ]
    https_ok = {
        str(item.get("name")): bool(item.get("https", {}).get("ok"))
        for item in tcp_results
    }
    workload_totals = workload_probe_report.get("totals", {})
    result = {
        name: log_text.count(pattern) for name, pattern in STABILITY_PATTERNS.items()
    }
    result.update(
        {
            "tcpClosedSessions": sum(close_reasons.values()),
            "closeReasons": dict(close_reasons),
            "tcpFailureTypes": dict(failure_types),
            "udpCloseReasons": dict(udp_close_reasons),
            "udpFailureTypes": dict(udp_failure_types),
            "ipDenials": ip_denials,
            "udpOk": bool(udp_probe_report.get("ok")) if udp_probe_report else None,
            "ipv6NoLeakOk": bool(ipv6_probe_report.get("ok")) if ipv6_probe_report else None,
            "workloadSuccessRate": workload_totals.get("successRate")
            if workload_probe_report
            else None,
            "workloadErrors": workload_probe_report.get("errors", [])
            if workload_probe_report
            else [],
            "httpsOk": https_ok,
            "sessionTimings": session_timings,
        }
    )
    return result
