from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from dynet_trace.common import (
    SUMMARY_SCHEMA,
    count_kind,
    event_fields,
    event_kind,
    int_field,
    latency_summary,
    split_csv,
    top,
)
from dynet_trace.workload import workload_attribution


def build_summary(
    report: dict[str, Any],
    workload_probe: dict[str, Any] | None = None,
) -> dict[str, Any]:
    events = [event for event in report.get("events", []) if isinstance(event, dict)]
    return {
        "schema": SUMMARY_SCHEMA,
        "runtimeSchema": report.get("schema"),
        "runtimeStatus": report.get("status"),
        "runtimeReason": report.get("reason"),
        "totals": {
            "events": len(events),
            "dnsQueries": report.get("dnsQueries"),
            "routeDecisions": report.get("routeDecisions"),
            "proxiedDnsQueries": report.get("proxiedDnsQueries"),
            "outboundAttempts": count_kind(events, "outbound-attempt-finished"),
        },
        "probe": probe_summary(report, events),
        "eventKinds": top(Counter(event_kind(event) for event in events)),
        "rules": rule_summary(events),
        "routes": route_summary(events),
        "plans": plan_summary(events),
        "dialers": dialer_summary(events),
        "outbounds": outbound_summary(events),
        "stages": stage_summary(events),
        "failures": failure_summary(events),
        "workloadAttribution": workload_attribution(events, workload_probe),
        "attributionReadiness": attribution_readiness(events),
    }

def route_summary(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for event in events:
        if event_kind(event) != "route-matched":
            continue
        fields = event_fields(event)
        rows.append(
            {
                "query": fields.get("query"),
                "target": fields.get("target"),
                "status": fields.get("status"),
                "outbound": fields.get("outbound"),
                "reason": fields.get("reason"),
            }
        )
    return rows

def rule_summary(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for event in events:
        if event_kind(event) != "rule-matched":
            continue
        fields = event_fields(event)
        rows.append(
            {
                "rule": fields.get("rule"),
                "order": int_field(fields, "order"),
                "query": fields.get("query"),
                "target": fields.get("target"),
                "outbound": fields.get("outbound"),
                "bypassesPlan": fields.get("bypassesPlan") == "true",
                "reason": fields.get("reason"),
            }
        )
    return rows

def plan_summary(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for event in events:
        if event_kind(event) != "outbound-candidate-set":
            continue
        fields = event_fields(event)
        rows.append(
            {
                "plan": fields.get("plan"),
                "scope": fields.get("scope"),
                "strategy": "/".join(
                    item
                    for item in [
                        fields.get("strategySource"),
                        fields.get("strategyKey"),
                        fields.get("strategyVersion"),
                    ]
                    if item
                ),
                "selector": fields.get("selector"),
                "candidateCount": int_field(fields, "candidateCount"),
                "candidates": split_csv(fields.get("candidates")),
                "selected": fields.get("selected"),
                "selectedEdgeType": fields.get("selectedEdgeType"),
            }
        )
    return rows

def dialer_summary(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for event in events:
        if event_kind(event) != "dialer-cascade-selected":
            continue
        fields = event_fields(event)
        rows.append(
            {
                "dialer": fields.get("dialer"),
                "bound": fields.get("bound"),
                "boundSelected": fields.get("boundSelected"),
                "private": fields.get("private"),
                "target": fields.get("target"),
                "bypassesPlan": fields.get("bypassesPlan") == "true",
            }
        )
    return rows

def outbound_summary(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
    for event in events:
        kind = event_kind(event)
        if kind not in {"outbound-attempt-started", "outbound-attempt-finished"}:
            continue
        fields = event_fields(event)
        outbound = fields.get("outbound")
        if outbound:
            grouped[outbound].append({"eventKind": kind, **fields})
    rows = []
    for outbound, items in sorted(grouped.items()):
        finishes = [
            item for item in items if item["eventKind"] == "outbound-attempt-finished"
        ]
        failures = [item for item in finishes if item.get("status") == "failed"]
        latencies = [
            value
            for item in finishes
            for value in [int_field(item, "elapsedMs")]
            if value is not None
        ]
        rows.append(
            {
                "outbound": outbound,
                "attempts": len(finishes),
                "failures": len(failures),
                "failureTypes": top(Counter(item.get("errorType", "unknown") for item in failures)),
                "latencyMs": latency_summary(latencies),
            }
        )
    return rows

def stage_summary(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for event in events:
        if event_kind(event) != "outbound-stage-finished":
            continue
        fields = event_fields(event)
        key = (fields.get("outbound", "unknown"), fields.get("stage", "unknown"))
        grouped[key].append(fields)
    rows = []
    for (outbound, stage), items in sorted(grouped.items()):
        failures = [item for item in items if item.get("status") == "failed"]
        latencies = [
            value
            for item in items
            for value in [int_field(item, "elapsedMs")]
            if value is not None
        ]
        rows.append(
            {
                "outbound": outbound,
                "stage": stage,
                "count": len(items),
                "failures": len(failures),
                "failureTypes": top(Counter(item.get("errorType", "unknown") for item in failures)),
                "latencyMs": latency_summary(latencies),
            }
        )
    return rows

def failure_summary(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for event in events:
        fields = event_fields(event)
        failed = fields.get("status") == "failed" or event_kind(event) == "dns-resolve-failed"
        if not failed:
            continue
        rows.append(
            {
                "kind": event_kind(event),
                "sequence": event.get("sequence"),
                "query": fields.get("query"),
                "target": fields.get("target"),
                "scope": fields.get("scope"),
                "outbound": fields.get("outbound"),
                "stage": fields.get("stage"),
                "errorType": fields.get("errorType"),
                "error": fields.get("error") or fields.get("reason"),
                "elapsedMs": int_field(fields, "elapsedMs"),
            }
        )
    return rows

def probe_summary(report: dict[str, Any], events: list[dict[str, Any]]) -> dict[str, Any] | None:
    target = report.get("target")
    probe_events = [
        event
        for event in events
        if event_kind(event) in {"probe-started", "probe-completed"}
    ]
    if target is None and not probe_events:
        return None
    completed = [
        event_fields(event)
        for event in probe_events
        if event_kind(event) == "probe-completed"
    ]
    latest = completed[-1] if completed else {}
    return {
        "target": target,
        "status": report.get("status") or latest.get("status"),
        "reason": report.get("reason") or latest.get("reason"),
        "events": len(probe_events),
    }

def attribution_readiness(events: list[dict[str, Any]]) -> dict[str, Any]:
    kinds = {event_kind(event) for event in events}
    has_rule_decision = "rule-matched" in kinds
    has_plan_decision = "outbound-candidate-set" in kinds or any(
        int_field(event_fields(event), "decisions") not in (None, 0)
        for event in events
        if event_kind(event) == "outbound-graph-selected"
    )
    present = {
        "routeOrRule": "route-matched" in kinds or has_rule_decision,
        "planBypass": not has_rule_decision or "plan-bypassed" in kinds,
        "candidateSet": not has_plan_decision or "outbound-candidate-set" in kinds,
        "graphSelection": "outbound-graph-selected" in kinds,
        "admission": "outbound-admission-passed" in kinds,
        "egress": "outbound-egress-passed" in kinds,
        "dialerCascade": not has_rule_decision or "dialer-cascade-selected" in kinds,
        "attempts": "outbound-attempt-finished" in kinds,
        "stages": "outbound-stage-finished" in kinds,
        "failures": any(
            event_kind(event) == "dns-resolve-failed"
            or event_fields(event).get("status") == "failed"
            for event in events
        ),
    }
    missing = [key for key, value in present.items() if not value and key != "failures"]
    return {
        "canExplainPlanVsNodeForObservedPath": not missing,
        "canExplainPlanVsNodeForObservedDns": not missing,
        "present": present,
        "missing": missing,
        "note": "This summarizes dynet runtime/probe events for observed paths; full forwarding attribution still requires real traffic through dynet's forwarding plane.",
    }
