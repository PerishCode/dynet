from __future__ import annotations

import ipaddress
from collections import Counter

from private_runtime_lib.common import SELECTION_EVENT_KINDS, STABILITY_PATTERNS
from private_runtime_lib.tcp_flow.selection import bound_selection_brief, cascade_attempt_brief

PRIVATE_CONNECT_STAGES = {
    "private-vmess-connect",
    "private-ss-connect",
    "private-trojan-connect",
}


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
        "tcpClosedSessions": report.get("tcpClosedSessions"),
        "tcpSessionFailures": report.get("tcpSessionFailures"),
        "tcpUpstreamBytes": report.get("tcpUpstreamBytes"),
        "tcpDownstreamBytes": report.get("tcpDownstreamBytes"),
        "tcpListenPorts": report.get("tcpListenPorts"),
        "tcpListenSlotsPerPort": report.get("tcpListenSlotsPerPort"),
        "tcpListenCapacity": report.get("tcpListenCapacity"),
        "tcpActiveSlotsMax": report.get("tcpActiveSlotsMax"),
        "tcpSlotPressureEvents": report.get("tcpSlotPressureEvents"),
        "udpSessions": report.get("udpSessions"),
        "udpSessionFailures": report.get("udpSessionFailures"),
        "udpUpstreamBytes": report.get("udpUpstreamBytes"),
        "udpDownstreamBytes": report.get("udpDownstreamBytes"),
        "udpDroppedPackets": report.get("udpDroppedPackets"),
    }

def selection_brief(report: dict) -> dict:
    rows = []
    events = []
    for event in report.get("events", []):
        if not isinstance(event, dict):
            continue
        events.append(event)
        kind = event.get("kind")
        if kind not in SELECTION_EVENT_KINDS:
            continue
        fields = event.get("fields", {})
        if isinstance(fields, dict):
            rows.append({"kind": kind, "fields": fields})
    return {
        "events": rows,
        "boundSelection": bound_selection_brief(events),
        "cascadeAttempts": cascade_attempt_brief(events),
    }

def fields(event: dict) -> dict[str, str]:
    value = event.get("fields", {})
    if not isinstance(value, dict):
        return {}
    return {str(key): str(item) for key, item in value.items()}


def tcp_target_identity_brief(report: dict) -> dict:
    events = [event for event in report.get("events", []) if isinstance(event, dict)]
    rows = [
        tcp_target_identity_row(event)
        for event in events
        if event.get("kind") in {"tcp-session-outbound-connecting", "tcp-session-established"}
    ]
    adapter_rows = []
    for event in events:
        row = tcp_adapter_target_row(event)
        if row:
            adapter_rows.append(row)
    connecting = [row for row in rows if row.get("kind") == "tcp-session-outbound-connecting"]
    established = [row for row in rows if row.get("kind") == "tcp-session-established"]
    target_chain = tcp_target_chain_brief(connecting, adapter_rows)
    return {
        "connectingEvents": len(connecting),
        "establishedEvents": len(established),
        "withConnectTarget": sum(1 for row in connecting if row.get("connectTarget")),
        "withIdentityDomain": sum(1 for row in connecting if row.get("identityDomain")),
        "withTargetAddressSource": sum(1 for row in connecting if row.get("targetAddressSource")),
        "domainConnectTargets": sum(1 for row in connecting if row.get("connectTargetIsDomain")),
        "socketConnectTargets": sum(1 for row in connecting if row.get("connectTargetIsSocket")),
        "bySource": aggregate_rows(connecting, "targetAddressSource"),
        "domainTargets": sorted(
            {
                row["connectTarget"]
                for row in connecting
                if row.get("connectTargetIsDomain") and row.get("connectTarget")
            }
        ),
        "adapterConnectEvents": len(adapter_rows),
        "withAdapterTarget": sum(1 for row in adapter_rows if row.get("adapterTarget")),
        "adapterDomainTargets": sum(1 for row in adapter_rows if row.get("adapterTargetIsDomain")),
        "adapterSocketTargets": sum(1 for row in adapter_rows if row.get("adapterTargetIsSocket")),
        "adapterTargets": sorted(
            {
                row["adapterTarget"]
                for row in adapter_rows
                if row.get("adapterTargetIsDomain") and row.get("adapterTarget")
            }
        ),
        **target_chain,
    }


def tcp_target_identity_row(event: dict) -> dict:
    event_fields = fields(event)
    connect_target = event_fields.get("connectTarget")
    connect_host = target_host(connect_target)
    connect_target_is_socket = connect_host_is_ip(connect_host)
    return {
        "kind": str(event.get("kind")),
        "flowId": event_fields.get("flowId"),
        "connectTarget": connect_target,
        "identityDomain": event_fields.get("identityDomain"),
        "targetAddressSource": event_fields.get("targetAddressSource"),
        "connectTargetIsDomain": bool(connect_host) and not connect_target_is_socket,
        "connectTargetIsSocket": connect_target_is_socket,
    }


def tcp_adapter_target_row(event: dict) -> dict:
    if event.get("kind") != "outbound-stage-finished":
        return {}
    event_fields = fields(event)
    if event_fields.get("stage") not in PRIVATE_CONNECT_STAGES:
        return {}
    flow_id = event_fields.get("flowId")
    if not flow_id or not flow_id.startswith("tcp-session-"):
        return {}
    adapter_target = event_fields.get("adapterTarget")
    adapter_host = target_host(adapter_target)
    adapter_kind = event_fields.get("adapterTargetKind")
    adapter_is_socket = adapter_kind == "socket" or connect_host_is_ip(adapter_host)
    adapter_is_domain = adapter_kind == "domain" or (
        bool(adapter_host) and not adapter_is_socket
    )
    return {
        "kind": str(event.get("kind")),
        "flowId": flow_id,
        "outbound": event_fields.get("outbound"),
        "stage": event_fields.get("stage"),
        "adapterTarget": adapter_target,
        "adapterTargetKind": adapter_kind,
        "adapterTargetIsDomain": adapter_is_domain,
        "adapterTargetIsSocket": adapter_is_socket,
    }


def tcp_target_chain_brief(connecting: list[dict], adapter_rows: list[dict]) -> dict:
    adapters_by_flow: dict[str, list[dict]] = {}
    for row in adapter_rows:
        flow_id = row.get("flowId")
        if flow_id:
            adapters_by_flow.setdefault(str(flow_id), []).append(row)
    matched = 0
    mismatched = 0
    missing_adapter = 0
    missing_connect = 0
    duplicate_adapter_flows = 0
    chain_flows = 0
    for row in connecting:
        flow_id = row.get("flowId")
        if not flow_id:
            continue
        chain_flows += 1
        connect_target = row.get("connectTarget")
        adapter_targets = [
            adapter.get("adapterTarget")
            for adapter in adapters_by_flow.get(str(flow_id), [])
            if adapter.get("adapterTarget")
        ]
        if len(adapter_targets) > 1:
            duplicate_adapter_flows += 1
        if not connect_target:
            missing_connect += 1
            continue
        if not adapter_targets:
            missing_adapter += 1
            continue
        if connect_target in adapter_targets:
            matched += 1
        else:
            mismatched += 1
    return {
        "targetChainFlows": chain_flows,
        "targetChainAdapterFlows": len(adapters_by_flow),
        "targetChainMatched": matched,
        "targetChainMismatched": mismatched,
        "targetChainMissingAdapter": missing_adapter,
        "targetChainMissingConnect": missing_connect,
        "targetChainDuplicateAdapterFlows": duplicate_adapter_flows,
    }


def target_host(value: str | None) -> str | None:
    if not value:
        return None
    if value.startswith("[") and "]" in value:
        return value[1:value.index("]")]
    if ":" not in value:
        return value
    return value.rsplit(":", 1)[0]


def connect_host_is_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def aggregate_rows(rows: list[dict], field: str) -> list[dict]:
    counter = Counter(str(row.get(field) or "unknown") for row in rows)
    return [{"key": key, "count": count} for key, count in sorted(counter.items())]


def workload_brief(report: dict) -> dict:
    totals = report.get("totals", {}) if isinstance(report, dict) else {}
    results = [item for item in report.get("results", []) if isinstance(item, dict)] if isinstance(report, dict) else []
    failed = [item for item in results if item.get("ok") is False]
    return {
        "attempted": int(totals.get("count") or 0),
        "success": int(totals.get("success") or 0),
        "failure": int(totals.get("failure") or 0),
        "successRate": totals.get("successRate"),
        "errors": report.get("errors", []) if isinstance(report, dict) else [],
        "failedByProbe": aggregate_rows(failed, "probe"),
        "failedByStage": aggregate_failed_stage(failed),
        "failedBySurface": aggregate_failed_surface(failed),
        "tunWitnessedFailures": sum(1 for item in failed if tun_witnessed(item)),
        "routeViaDynetFailures": sum(1 for item in failed if route_via_dynet(item)),
    }


def workload_failure_stage(item: dict) -> str:
    stage = item.get("errorStage")
    if isinstance(stage, str) and stage:
        return stage
    stages = item.get("stages", [])
    if isinstance(stages, list):
        for row in reversed(stages):
            if isinstance(row, dict) and row.get("ok") is False:
                name = row.get("name")
                if isinstance(name, str) and name:
                    return name
    return "unknown"


def workload_failure_surface(item: dict) -> str:
    probe = str(item.get("probe") or "unknown")
    stage = workload_failure_stage(item)
    error_type = str(item.get("errorType") or "unknown")
    route = "route-dynet" if route_via_dynet(item) else "route-unknown"
    witness = "tun-witnessed" if tun_witnessed(item) else "tun-unwitnessed"
    return f"{probe}:{stage}:{error_type}:{route}:{witness}"


def route_via_dynet(item: dict) -> bool:
    if item.get("routeViaDynet") is True:
        return True
    route_after = item.get("routeAfter")
    return isinstance(route_after, dict) and route_after.get("routeViaDynet") is True


def tun_witnessed(item: dict) -> bool:
    witness = item.get("tunWitness")
    return isinstance(witness, dict) and witness.get("observed") is True


def aggregate_failed_stage(rows: list[dict]) -> list[dict]:
    counter = Counter(workload_failure_stage(row) for row in rows)
    return [{"key": key, "count": counter[key]} for key in sorted(counter)]


def aggregate_failed_surface(rows: list[dict]) -> list[dict]:
    counter = Counter(workload_failure_surface(row) for row in rows)
    return [{"key": key, "count": counter[key]} for key in sorted(counter)]


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
            "tcpForwarderPressureEvents": sum(
                1 for event in events if event.get("kind") == "tcp-forwarder-pressure"
            ),
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
