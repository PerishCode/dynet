#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


SUMMARY_SCHEMA = "dynet-trace-attribution-summary/v1alpha1"
BATCH_SCHEMA = "dynet-trace-attribution-batch/v1alpha1"
BATCH_MANIFEST_SCHEMA = "dynet-trace-attribution-batch-manifest/v1alpha1"
DEFAULT_OUTPUT_JSON = ".task/resources/dynet-trace-attribution-summary.json"
DEFAULT_OUTPUT_MD = ".task/resources/dynet-trace-attribution-summary.md"
DEFAULT_BATCH_OUTPUT_JSON = ".task/resources/dynet-trace-attribution-batch.json"
DEFAULT_BATCH_OUTPUT_MD = ".task/resources/dynet-trace-attribution-batch.md"
DEFAULT_MIN_REPEAT_RUNS = 2
DEFAULT_MAX_UNKNOWN_RATE = 0.1
DEFAULT_MAX_MISSING_CORRELATION_RATE = 0.25


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def load_manifest(path: Path) -> dict[str, Any]:
    manifest = load_json(path)
    if manifest.get("schema") not in {BATCH_MANIFEST_SCHEMA, None}:
        raise SystemExit(
            f"unsupported batch manifest schema in {path}: {manifest.get('schema')}"
        )
    summaries = manifest.get("summaries")
    if not isinstance(summaries, list) or not summaries:
        raise SystemExit(f"batch manifest must contain a non-empty summaries list: {path}")
    if any(not isinstance(item, str) or not item for item in summaries):
        raise SystemExit(f"batch manifest summaries must be non-empty strings: {path}")
    return manifest


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True))


def event_kind(event: dict[str, Any]) -> str:
    return str(event.get("kind", "unknown"))


def event_fields(event: dict[str, Any]) -> dict[str, str]:
    fields = event.get("fields", {})
    if not isinstance(fields, dict):
        return {}
    return {str(key): str(value) for key, value in fields.items()}


def int_field(fields: dict[str, str], key: str) -> int | None:
    value = fields.get(key)
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


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


def workload_attribution(
    events: list[dict[str, Any]],
    workload_probe: dict[str, Any] | None,
) -> dict[str, Any]:
    if not workload_probe:
        return {"enabled": False}
    results = [
        item
        for item in workload_probe.get("results", [])
        if isinstance(item, dict)
    ]
    sessions = runtime_sessions(events)
    sessions_by_domain: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for session in sessions:
        for domain in session["domains"]:
            sessions_by_domain[domain].append(session)
    dns_flows = runtime_dns_flows(events)
    dns_flows_by_query: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for flow in dns_flows:
        query = flow.get("query")
        if query:
            dns_flows_by_query[str(query)].append(flow)
    items = [
        classify_workload_result(
            item,
            matching_sessions(item, sessions_by_domain.get(str(item.get("domain")), [])),
            matching_dns_flows(item, dns_flows_by_query.get(str(item.get("domain")), [])),
        )
        for item in results
    ]
    failures = [item for item in items if item["classification"] != "healthy"]
    missing = Counter(
        field
        for item in failures
        for field in item.get("missingFields", [])
    )
    return {
        "enabled": True,
        "schema": "dynet-workload-attribution/v1alpha1",
        "totals": {
            "items": len(items),
            "failures": len(failures),
            "healthy": sum(1 for item in items if item["classification"] == "healthy"),
        },
        "byClass": top(Counter(item["classification"] for item in items)),
        "byCandidate": candidate_correlation(items),
        "missingFields": top(missing),
        "items": items,
    }


def runtime_sessions(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for event in events:
        fields = event_fields(event)
        session = fields.get("session")
        if not session:
            continue
        row = grouped.setdefault(
            session,
            {
                "session": session,
                "flowId": fields.get("flowId"),
                "transport": fields.get("sessionTransport"),
                "target": fields.get("target"),
                "domains": set(),
                "outbounds": set(),
                "selectedCandidates": set(),
                "selectedOutbounds": set(),
                "closeReasons": [],
                "failures": [],
                "stageFailures": [],
                "eventKinds": Counter(),
                "startedAtUnixMs": None,
                "finishedAtUnixMs": None,
            },
        )
        timestamp = event.get("emittedAtUnixMs")
        if isinstance(timestamp, int):
            if row["startedAtUnixMs"] is None or timestamp < row["startedAtUnixMs"]:
                row["startedAtUnixMs"] = timestamp
            if row["finishedAtUnixMs"] is None or timestamp > row["finishedAtUnixMs"]:
                row["finishedAtUnixMs"] = timestamp
        row["eventKinds"][event_kind(event)] += 1
        for key in ("domain", "query"):
            value = fields.get(key)
            if value and value != "<none>" and value != "<unparsed>":
                row["domains"].add(value)
        for key in ("outbound", "selected", "boundSelected"):
            value = fields.get(key)
            if value and value != "<none>":
                row["outbounds"].add(value)
        selected = fields.get("selected")
        if event_kind(event) == "outbound-candidate-set" and selected and selected != "<none>":
            row["selectedCandidates"].add(selected)
        if event_kind(event) == "outbound-graph-selected" and selected and selected != "<none>":
            row["selectedOutbounds"].add(selected)
        bound_selected = fields.get("boundSelected")
        if (
            event_kind(event) == "dialer-cascade-selected"
            and bound_selected
            and bound_selected != "<none>"
        ):
            row["selectedCandidates"].add(bound_selected)
        if event_kind(event) in {"tcp-session-closed", "udp-session-closed"}:
            row["closeReasons"].append(fields.get("reason", "<unknown>"))
        failed = fields.get("status") == "failed" or event_kind(event).endswith("-failed")
        if failed:
            failure = {
                "kind": event_kind(event),
                "outbound": fields.get("outbound"),
                "stage": fields.get("stage"),
                "errorType": fields.get("errorType"),
                "reason": fields.get("reason") or fields.get("error"),
            }
            row["failures"].append(failure)
            if event_kind(event) == "outbound-stage-finished":
                row["stageFailures"].append(failure)
    output = []
    for row in grouped.values():
        output.append(
            {
                **row,
                "domains": sorted(row["domains"]),
                "outbounds": sorted(row["outbounds"]),
                "selectedCandidates": sorted(row["selectedCandidates"]),
                "selectedOutbounds": sorted(row["selectedOutbounds"]),
                "eventKinds": dict(row["eventKinds"]),
            }
        )
    return sorted(output, key=lambda item: int(item["session"]) if str(item["session"]).isdigit() else 0)


def runtime_dns_flows(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for event in events:
        fields = event_fields(event)
        dns_query_id = fields.get("dnsQueryId")
        if not dns_query_id:
            continue
        row = grouped.setdefault(
            dns_query_id,
            {
                "dnsQueryId": dns_query_id,
                "flowId": fields.get("flowId"),
                "query": fields.get("query"),
                "listener": fields.get("listener"),
                "outbounds": set(),
                "selectedCandidates": set(),
                "selectedOutbounds": set(),
                "failures": [],
                "stageFailures": [],
                "eventKinds": Counter(),
                "startedAtUnixMs": None,
                "finishedAtUnixMs": None,
            },
        )
        timestamp = event.get("emittedAtUnixMs")
        if isinstance(timestamp, int):
            if row["startedAtUnixMs"] is None or timestamp < row["startedAtUnixMs"]:
                row["startedAtUnixMs"] = timestamp
            if row["finishedAtUnixMs"] is None or timestamp > row["finishedAtUnixMs"]:
                row["finishedAtUnixMs"] = timestamp
        row["eventKinds"][event_kind(event)] += 1
        for key in ("outbound", "selected", "boundSelected"):
            value = fields.get(key)
            if value and value != "<none>":
                row["outbounds"].add(value)
        selected = fields.get("selected")
        if event_kind(event) == "outbound-candidate-set" and selected and selected != "<none>":
            row["selectedCandidates"].add(selected)
        if event_kind(event) == "outbound-graph-selected" and selected and selected != "<none>":
            row["selectedOutbounds"].add(selected)
        bound_selected = fields.get("boundSelected")
        if (
            event_kind(event) == "dialer-cascade-selected"
            and bound_selected
            and bound_selected != "<none>"
        ):
            row["selectedCandidates"].add(bound_selected)
        failed = fields.get("status") == "failed" or event_kind(event) == "dns-resolve-failed"
        if failed:
            failure = {
                "kind": event_kind(event),
                "outbound": fields.get("outbound"),
                "stage": fields.get("stage"),
                "errorType": fields.get("errorType"),
                "reason": fields.get("reason") or fields.get("error"),
            }
            row["failures"].append(failure)
            if event_kind(event) == "outbound-stage-finished":
                row["stageFailures"].append(failure)
    output = []
    for row in grouped.values():
        output.append(
            {
                **row,
                "outbounds": sorted(row["outbounds"]),
                "selectedCandidates": sorted(row["selectedCandidates"]),
                "selectedOutbounds": sorted(row["selectedOutbounds"]),
                "eventKinds": dict(row["eventKinds"]),
            }
        )
    return sorted(
        output,
        key=lambda item: int(item["dnsQueryId"])
        if str(item["dnsQueryId"]).isdigit()
        else 0,
    )


def matching_sessions(
    result: dict[str, Any],
    candidates: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    started = int_value(result.get("startedAtUnixMs"))
    finished = int_value(result.get("finishedAtUnixMs"))
    if started is None or finished is None:
        return candidates
    lower = started - 2_000
    upper = finished + 2_000
    matched = [
        session
        for session in candidates
        if session.get("startedAtUnixMs") is not None
        and lower <= int(session["startedAtUnixMs"]) <= upper
    ]
    return matched


def matching_dns_flows(
    result: dict[str, Any],
    candidates: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    started = int_value(result.get("startedAtUnixMs"))
    finished = int_value(result.get("finishedAtUnixMs"))
    if started is None or finished is None:
        return candidates
    lower = started - 2_000
    upper = finished + 2_000
    return [
        flow
        for flow in candidates
        if flow.get("startedAtUnixMs") is not None
        and lower <= int(flow["startedAtUnixMs"]) <= upper
    ]




def classify_workload_result(
    result: dict[str, Any],
    sessions: list[dict[str, Any]],
    dns_flows: list[dict[str, Any]],
) -> dict[str, Any]:
    if result.get("ok") is True:
        return workload_item(result, "healthy", [], sessions, dns_flows, "request succeeded")
    policy = result.get("targetPolicy", {}) if isinstance(result.get("targetPolicy"), dict) else {}
    probe = str(result.get("probe") or "unknown")
    error_stage = str(result.get("errorStage") or "unknown")
    error_type = str(result.get("errorType") or "unknown")
    missing = missing_fields_for_failure(result, sessions, dns_flows)
    if policy.get("faultSignal") in {"weak", "informational"}:
        return workload_item(
            result,
            "target-or-probe-suspect",
            missing,
            sessions,
            dns_flows,
            "target policy marked this black-box signal as weak or informational",
        )
    if dns_runtime_node_signal(dns_flows):
        return workload_item(
            result,
            "node-suspect",
            missing,
            sessions,
            dns_flows,
            "matching DNS flow failed while connecting the selected outbound candidate",
        )
    if dns_runtime_infra_signal(dns_flows):
        return workload_item(
            result,
            "dynet-infra-suspect",
            missing,
            sessions,
            dns_flows,
            "matching DNS flow failed inside dynet runtime without candidate-specific evidence",
        )
    if probe == "tcp-connect":
        return workload_item(
            result,
            "experiment-shape-suspect",
            missing,
            sessions,
            dns_flows,
            "pure tcp-connect is a known weak VM forwarding workload shape",
        )
    if missing_runtime_session_after_route(result, sessions, dns_flows):
        return workload_item(
            result,
            "experiment-shape-suspect",
            missing,
            sessions,
            dns_flows,
            "black-box failed after route setup but dynet observed no matching runtime session",
        )
    if runtime_infra_signal(sessions):
        return workload_item(
            result,
            "dynet-infra-suspect",
            missing,
            sessions,
            dns_flows,
            "matching runtime session has failure, timeout, or forwarding lifecycle evidence",
        )
    if error_stage.startswith("tls") or error_type.startswith("tls.") or error_type in {"tls", "eof"}:
        if (
            sessions
            and any(session["selectedCandidates"] for session in sessions)
            and any(session["closeReasons"] for session in sessions)
            and not any(session["failures"] for session in sessions)
        ):
            return workload_item(
                result,
                "target-or-probe-suspect",
                missing,
                sessions,
                dns_flows,
                "TLS failed in the black-box probe while matching runtime sessions have no failure event",
            )
    return workload_item(
        result,
        "unknown",
        missing,
        sessions,
        dns_flows,
        "insufficient repeat correlation and runtime stage detail for a safe blame assignment",
    )


def missing_fields_for_failure(
    result: dict[str, Any],
    sessions: list[dict[str, Any]],
    dns_flows: list[dict[str, Any]],
) -> list[str]:
    missing = ["repeat-correlation"]
    if str(result.get("errorStage")) == "dns" and not dns_flows:
        missing.append("dns-query")
    if str(result.get("errorStage")) != "dns" and str(result.get("probe")) != "dns" and not sessions:
        missing.append("session")
    if sessions and not any(session["selectedCandidates"] for session in sessions):
        missing.append("selected-candidate")
    if dns_flows and not any(flow["selectedCandidates"] for flow in dns_flows):
        missing.append("selected-candidate")
    if sessions and not any(session["closeReasons"] for session in sessions):
        missing.append("close-reason")
    if sessions and not any(session["stageFailures"] for session in sessions):
        missing.append("runtime-stage-failure")
    if dns_flows and not any(flow["stageFailures"] for flow in dns_flows):
        missing.append("runtime-stage-failure")
    return missing


def runtime_infra_signal(sessions: list[dict[str, Any]]) -> bool:
    for session in sessions:
        if any(
            reason in {"hard-ttl", "idle-timeout"}
            for reason in session.get("closeReasons", [])
        ):
            return True
        for failure in session.get("failures", []):
            if failure.get("kind") in {"tcp-session-failed", "udp-session-failed"}:
                return True
            if failure.get("errorType") in {"permission", "capability"}:
                return True
    return False


def missing_runtime_session_after_route(
    result: dict[str, Any],
    sessions: list[dict[str, Any]],
    dns_flows: list[dict[str, Any]],
) -> bool:
    if sessions or dns_flows:
        return False
    if str(result.get("errorStage") or "") not in {
        "tcp-connect",
        "tls-handshake",
    }:
        return False
    return result_stage_ok(result, "route") or result.get("routeInstalled") is True


def experiment_shape_witness(result: dict[str, Any]) -> bool:
    if not (result_stage_ok(result, "route") or result.get("routeInstalled") is True):
        return False
    if isinstance(result.get("tunWitness"), dict):
        return True
    return any(
        isinstance(stage, dict)
        and stage.get("name") == "route"
        and (
            "routeViaDynet" in stage
            or "routeObserved" in stage
            or isinstance(stage.get("routeAfter"), dict)
        )
        for stage in result.get("stages", [])
    )


def result_stage_ok(result: dict[str, Any], name: str) -> bool:
    for stage in result.get("stages", []):
        if isinstance(stage, dict) and stage.get("name") == name:
            return stage.get("ok") is True
    return False


def dns_runtime_node_signal(dns_flows: list[dict[str, Any]]) -> bool:
    for flow in dns_flows:
        if not flow.get("selectedCandidates"):
            continue
        for failure in flow.get("failures", []):
            if failure.get("stage") == "tcp-connect" and failure.get("errorType") in {
                "timeout",
                "refused",
                "reset",
            }:
                return True
    return False


def dns_runtime_infra_signal(dns_flows: list[dict[str, Any]]) -> bool:
    for flow in dns_flows:
        for failure in flow.get("failures", []):
            if failure.get("errorType") in {"permission", "capability"}:
                return True
    return False


def candidate_correlation(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in items:
        candidates = sorted(
            {
                candidate
                for session in item.get("sessions", [])
                for candidate in session.get("selectedCandidates", [])
            }
            | {
                candidate
                for flow in item.get("dnsFlows", [])
                for candidate in flow.get("selectedCandidates", [])
            }
        )
        if not candidates:
            grouped["<missing>"].append(item)
            continue
        for candidate in candidates:
            grouped[candidate].append(item)
    rows = []
    for candidate, rows_for_candidate in sorted(grouped.items()):
        failures = [
            item
            for item in rows_for_candidate
            if item.get("classification") != "healthy"
        ]
        rows.append(
            {
                "candidate": candidate,
                "items": len(rows_for_candidate),
                "failures": len(failures),
                "failureRate": round(len(failures) / len(rows_for_candidate), 4)
                if rows_for_candidate
                else 0,
                "classes": top(Counter(str(item["classification"]) for item in rows_for_candidate)),
                "domains": top(Counter(str(item.get("domain")) for item in failures)),
            }
        )
    return rows


def workload_item(
    result: dict[str, Any],
    classification: str,
    missing: list[str],
    sessions: list[dict[str, Any]],
    dns_flows: list[dict[str, Any]],
    reason: str,
) -> dict[str, Any]:
    route = route_witness(result)
    tun = result.get("tunWitness") if isinstance(result.get("tunWitness"), dict) else None
    return {
        "id": result.get("id"),
        "domain": result.get("domain"),
        "probe": result.get("probe"),
        "bucket": result.get("bucket"),
        "behavior": result.get("behavior"),
        "ok": result.get("ok") is True,
        "errorStage": result.get("errorStage"),
        "errorType": result.get("errorType"),
        "classification": classification,
        "reason": reason,
        "missingFields": class_missing_fields(classification, missing, result),
        "routeWitness": route,
        "tunWitness": tun,
        "peerMatchesSelectedAddress": result.get("peerMatchesSelectedAddress"),
        "selectedAddressCount": result.get("selectedAddressCount"),
        "selectedAddressStored": result.get("selectedAddressStored"),
        "sessions": [
            {
                "session": session["session"],
                "flowId": session.get("flowId"),
                "target": session.get("target"),
                "startedAtUnixMs": session.get("startedAtUnixMs"),
                "finishedAtUnixMs": session.get("finishedAtUnixMs"),
                "domains": session.get("domains", []),
                "outbounds": session.get("outbounds", []),
                "selectedCandidates": session.get("selectedCandidates", []),
                "selectedOutbounds": session.get("selectedOutbounds", []),
                "closeReasons": session.get("closeReasons", []),
                "failureTypes": top(Counter(
                    str(failure.get("errorType") or "unknown")
                    for failure in session.get("failures", [])
                )),
                "stageFailures": session.get("stageFailures", []),
            }
            for session in sessions
        ],
        "dnsFlows": [
            {
                "dnsQueryId": flow["dnsQueryId"],
                "flowId": flow.get("flowId"),
                "query": flow.get("query"),
                "listener": flow.get("listener"),
                "startedAtUnixMs": flow.get("startedAtUnixMs"),
                "finishedAtUnixMs": flow.get("finishedAtUnixMs"),
                "outbounds": flow.get("outbounds", []),
                "selectedCandidates": flow.get("selectedCandidates", []),
                "selectedOutbounds": flow.get("selectedOutbounds", []),
                "failureTypes": top(Counter(
                    str(failure.get("errorType") or "unknown")
                    for failure in flow.get("failures", [])
                )),
                "stageFailures": flow.get("stageFailures", []),
            }
            for flow in dns_flows
        ],
    }


def class_missing_fields(
    classification: str,
    missing: list[str],
    result: dict[str, Any],
) -> list[str]:
    normalized = set(missing)
    if classification in {"target-or-probe-suspect", "experiment-shape-suspect"}:
        normalized.discard("repeat-correlation")
    if classification == "experiment-shape-suspect" and experiment_shape_witness(result):
        normalized.discard("session")
    return sorted(normalized)


def route_witness(result: dict[str, Any]) -> dict[str, Any] | None:
    witness = {
        key: result.get(key)
        for key in ["routeInstalled", "routeViaDynet", "routeDev"]
        if key in result
    }
    route_stage = next(
        (
            stage
            for stage in result.get("stages", [])
            if isinstance(stage, dict) and stage.get("name") == "route"
        ),
        None,
    )
    if isinstance(route_stage, dict):
        for key in ["routeInstalled", "routeViaDynet", "routeDev", "routeBefore", "routeAfter"]:
            if key in route_stage:
                witness[key] = route_stage[key]
    return witness or None


def build_batch(
    summary_paths: list[Path],
    min_repeat_runs: int,
    max_unknown_rate: float,
    max_missing_correlation_rate: float,
) -> dict[str, Any]:
    runs = []
    all_items = []
    for path in summary_paths:
        summary = load_json(path)
        workload = summary.get("workloadAttribution", {})
        items = workload.get("items", []) if isinstance(workload, dict) else []
        run_label = path.parent.name
        annotated = [
            {**item, "runLabel": run_label, "summaryPath": str(path)}
            for item in items
            if isinstance(item, dict)
        ]
        runs.append(
            {
                "label": run_label,
                "summaryPath": str(path),
                "runtimeStatus": summary.get("runtimeStatus"),
                "runtimeReason": summary.get("runtimeReason"),
                "ruleBypassOk": all(
                    rule.get("bypassesPlan") is True
                    for rule in summary.get("rules", [])
                    if isinstance(rule, dict)
                ),
                "dialerSelections": len(summary.get("dialers", [])),
                "items": len(annotated),
                "failures": sum(
                    1
                    for item in annotated
                    if item.get("classification") != "healthy"
                ),
                "classes": top(Counter(str(item.get("classification")) for item in annotated)),
            }
        )
        all_items.extend(annotated)

    failures = [item for item in all_items if item.get("classification") != "healthy"]
    repeated_keys = repeated_evidence_keys(failures, min_repeat_runs)
    missing_repeat = [
        item
        for item in failures
        if "repeat-correlation" in item.get("missingFields", [])
        and item.get("classification") != "node-suspect"
        and evidence_key(item) not in repeated_keys
    ]
    node_missing_repeat = [
        item
        for item in failures
        if item.get("classification") == "node-suspect"
        and "repeat-correlation" in item.get("missingFields", [])
        and evidence_key(item) not in repeated_keys
    ]
    unknown_items = [
        item for item in all_items if item.get("classification") == "unknown"
    ]
    candidate_signals = candidate_batch_signals(
        all_items,
        repeated_keys,
        min_repeat_runs,
    )
    gates = batch_gates(
        runs,
        all_items,
        failures,
        unknown_items,
        missing_repeat,
        node_missing_repeat,
        candidate_signals,
        min_repeat_runs,
        max_unknown_rate,
        max_missing_correlation_rate,
    )
    return {
        "schema": BATCH_SCHEMA,
        "inputs": [str(path) for path in summary_paths],
        "thresholds": {
            "minRepeatRuns": min_repeat_runs,
            "maxUnknownRate": max_unknown_rate,
            "maxMissingCorrelationRate": max_missing_correlation_rate,
        },
        "totals": {
            "runs": len(runs),
            "items": len(all_items),
            "failures": len(failures),
            "healthy": sum(
                1 for item in all_items if item.get("classification") == "healthy"
            ),
            "unknown": len(unknown_items),
            "missingRepeatCorrelation": len(missing_repeat),
            "nodeMissingRepeatCorrelation": len(node_missing_repeat),
        },
        "runs": runs,
        "byClass": top(Counter(str(item.get("classification")) for item in all_items)),
        "missingFields": top(Counter(
            str(field)
            for item in failures
            for field in item.get("missingFields", [])
        )),
        "gates": gates,
        "candidateSignals": candidate_signals,
        "repeatedEvidence": repeated_evidence_rows(failures, repeated_keys),
    }


def repeated_evidence_keys(
    failures: list[dict[str, Any]],
    min_repeat_runs: int,
) -> set[tuple[str, ...]]:
    runs_by_key: dict[tuple[str, ...], set[str]] = defaultdict(set)
    for item in failures:
        if not has_runtime_repeat_evidence(item):
            continue
        runs_by_key[evidence_key(item)].add(str(item.get("runLabel")))
    return {
        key
        for key, runs in runs_by_key.items()
        if len(runs) >= min_repeat_runs
    }


def evidence_key(item: dict[str, Any]) -> tuple[str, ...]:
    candidates = ",".join(candidate_names(item))
    runtime_signature = ",".join(runtime_evidence_signatures(item)) or "<no-runtime-evidence>"
    return (
        candidates,
        str(item.get("classification") or "unknown"),
        str(item.get("domain") or "<none>"),
        str(item.get("errorStage") or "<none>"),
        str(item.get("errorType") or "<none>"),
        runtime_signature,
    )


def has_runtime_repeat_evidence(item: dict[str, Any]) -> bool:
    return candidate_names(item) != ["<missing>"] and bool(runtime_evidence_signatures(item))


def candidate_names(item: dict[str, Any]) -> list[str]:
    candidates = {
        candidate
        for session in item.get("sessions", [])
        for candidate in session.get("selectedCandidates", [])
    } | {
        candidate
        for flow in item.get("dnsFlows", [])
        for candidate in flow.get("selectedCandidates", [])
    }
    return sorted(candidates) or ["<missing>"]


def runtime_evidence_signatures(item: dict[str, Any]) -> list[str]:
    stage_signatures = stage_failure_signatures(item)
    if stage_signatures:
        return stage_signatures
    close_reasons = {
        f"close/{reason}"
        for session in item.get("sessions", [])
        for reason in session.get("closeReasons", [])
        if reason
    }
    return sorted(close_reasons)


def stage_failure_signatures(item: dict[str, Any]) -> list[str]:
    failures = []
    for session in item.get("sessions", []):
        failures.extend(session.get("stageFailures", []))
    for flow in item.get("dnsFlows", []):
        failures.extend(flow.get("stageFailures", []))
    return sorted(
        {
            "/".join(
                str(part or "<none>")
                for part in [
                    failure.get("outbound"),
                    failure.get("stage"),
                    failure.get("errorType"),
                ]
            )
            for failure in failures
            if isinstance(failure, dict)
        }
    )


def batch_gates(
    runs: list[dict[str, Any]],
    items: list[dict[str, Any]],
    failures: list[dict[str, Any]],
    unknown_items: list[dict[str, Any]],
    missing_repeat: list[dict[str, Any]],
    node_missing_repeat: list[dict[str, Any]],
    candidate_signals: list[dict[str, Any]],
    min_repeat_runs: int,
    max_unknown_rate: float,
    max_missing_correlation_rate: float,
) -> list[dict[str, Any]]:
    item_count = len(items)
    non_node_failure_count = sum(
        1 for item in failures if item.get("classification") != "node-suspect"
    )
    unknown_rate = round(len(unknown_items) / item_count, 4) if item_count else 0.0
    missing_rate = (
        round(len(missing_repeat) / non_node_failure_count, 4)
        if non_node_failure_count
        else 0.0
    )
    unsafe_planner_signals = [
        signal
        for signal in candidate_signals
        if signal.get("plannerAction") == "penalize-candidate"
        and (
            signal.get("confidence") != "repeat-stage-correlated"
            or int_value(signal.get("repeatedNodeSuspectItems")) in (None, 0)
        )
    ]
    return [
        {
            "name": "min-repeat-runs",
            "passed": len(runs) >= min_repeat_runs,
            "value": len(runs),
            "required": min_repeat_runs,
        },
        {
            "name": "unknown-rate",
            "passed": unknown_rate <= max_unknown_rate,
            "value": unknown_rate,
            "required": max_unknown_rate,
        },
        {
            "name": "non-node-missing-correlation-rate",
            "passed": missing_rate <= max_missing_correlation_rate,
            "value": missing_rate,
            "required": max_missing_correlation_rate,
        },
        {
            "name": "node-repeat-required-before-penalty",
            "passed": True,
            "value": len(node_missing_repeat),
            "required": "node-suspect without repeat remains observe-only",
        },
        {
            "name": "runtime-reports-present",
            "passed": all(run.get("runtimeStatus") is not None for run in runs),
            "value": sum(1 for run in runs if run.get("runtimeStatus") is not None),
            "required": len(runs),
        },
        {
            "name": "planner-signals-repeat-only",
            "passed": not unsafe_planner_signals,
            "value": len(unsafe_planner_signals),
            "required": "candidate penalty requires repeated node-suspect evidence",
        },
        {
            "name": "no-silent-fallback-suspect",
            "passed": not silent_fallback_suspect(runs, failures),
            "value": "checked",
            "required": "user-rule path failures keep selected-candidate evidence",
        },
    ]


def silent_fallback_suspect(
    runs: list[dict[str, Any]],
    failures: list[dict[str, Any]],
) -> bool:
    if any(run.get("ruleBypassOk") is False for run in runs):
        return True
    hard_failures = {
        "node-suspect",
        "dynet-infra-suspect",
        "plan-suspect",
    }
    return any(
        item.get("classification") in hard_failures
        and candidate_names(item) == ["<missing>"]
        for item in failures
    )


def candidate_batch_signals(
    items: list[dict[str, Any]],
    repeated_keys: set[tuple[str, ...]],
    min_repeat_runs: int,
) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in items:
        for candidate in candidate_names(item):
            grouped[candidate].append(item)
    rows = []
    for candidate, candidate_items in sorted(grouped.items()):
        failures = [
            item
            for item in candidate_items
            if item.get("classification") != "healthy"
        ]
        node_suspects = [
            item
            for item in failures
            if item.get("classification") == "node-suspect"
        ]
        repeated_node = [
            item
            for item in node_suspects
            if evidence_key(item) in repeated_keys
        ]
        node_runs = {str(item.get("runLabel")) for item in node_suspects}
        planner_action = "observe"
        confidence = "none"
        if repeated_node and len(node_runs) >= min_repeat_runs:
            planner_action = "penalize-candidate"
            confidence = "repeat-stage-correlated"
        elif node_suspects:
            confidence = "single-run-suspect"
        rows.append(
            {
                "candidate": candidate,
                "items": len(candidate_items),
                "failures": len(failures),
                "failureRate": round(len(failures) / len(candidate_items), 4)
                if candidate_items
                else 0,
                "classes": top(Counter(str(item.get("classification")) for item in candidate_items)),
                "nodeSuspectItems": len(node_suspects),
                "nodeSuspectRuns": len(node_runs),
                "repeatedNodeSuspectItems": len(repeated_node),
                "stageFailures": top(Counter(
                    signature
                    for item in failures
                    for signature in stage_failure_signatures(item)
                )),
                "domains": top(Counter(str(item.get("domain")) for item in failures)),
                "plannerAction": planner_action,
                "confidence": confidence,
            }
        )
    return rows


def repeated_evidence_rows(
    failures: list[dict[str, Any]],
    repeated_keys: set[tuple[str, ...]],
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, ...], list[dict[str, Any]]] = defaultdict(list)
    for item in failures:
        key = evidence_key(item)
        if key in repeated_keys:
            grouped[key].append(item)
    rows = []
    for key, key_items in sorted(grouped.items()):
        rows.append(
            {
                "key": list(key),
                "runs": sorted({str(item.get("runLabel")) for item in key_items}),
                "items": len(key_items),
                "ids": [
                    f"{item.get('runLabel')}:{item.get('id')}"
                    for item in key_items
                ],
            }
        )
    return rows


def int_value(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None


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


def latency_summary(values: list[int]) -> dict[str, int | None]:
    if not values:
        return {"p50": None, "p95": None, "max": None}
    ordered = sorted(values)
    return {
        "p50": percentile(ordered, 50),
        "p95": percentile(ordered, 95),
        "max": ordered[-1],
    }


def percentile(ordered: list[int], target: int) -> int:
    index = round((len(ordered) - 1) * (target / 100))
    return ordered[index]


def split_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [item for item in value.split(",") if item]


def top(counter: Counter[str], limit: int = 20) -> list[dict[str, Any]]:
    return [{"key": key, "count": count} for key, count in counter.most_common(limit)]


def count_kind(events: list[dict[str, Any]], kind: str) -> int:
    return sum(1 for event in events if event_kind(event) == kind)


def write_report(path: Path, summary: dict[str, Any]) -> None:
    lines = [
        "# Dynet Trace Attribution Summary",
        "",
        f"- Runtime: `{summary['runtimeSchema']}` status=`{summary['runtimeStatus']}`",
        f"- Events: `{summary['totals']['events']}`",
        f"- Readiness: `{summary['attributionReadiness']['canExplainPlanVsNodeForObservedPath']}`",
        "",
    ]
    if summary["probe"]:
        lines.extend(
            [
                "## Probe",
                "",
                f"- status=`{summary['probe']['status']}` reason=`{summary['probe']['reason']}`",
                "",
            ]
        )
    if summary["rules"]:
        lines.extend(["## Rules", ""])
        for item in summary["rules"]:
            lines.append(
                f"- `{item['rule']}` outbound=`{item['outbound']}` "
                f"bypassesPlan={item['bypassesPlan']}"
            )
        lines.append("")
    lines.extend(["## Plans", ""])
    for item in summary["plans"]:
        lines.append(
            f"- `{item['plan']}` strategy=`{item['strategy']}` "
            f"selected=`{item['selected']}` candidates={','.join(item['candidates'])}"
        )
    if summary["dialers"]:
        lines.extend(["", "## Dialers", ""])
        for item in summary["dialers"]:
            lines.append(
                f"- `{item['dialer']}` bound=`{item['bound']}` "
                f"selected=`{item['boundSelected']}` private=`{item['private']}`"
            )
    lines.extend(["", "## Outbounds", ""])
    for item in summary["outbounds"]:
        lines.append(
            f"- `{item['outbound']}` attempts={item['attempts']} failures={item['failures']} "
            f"p95={item['latencyMs']['p95']}ms"
        )
    lines.extend(["", "## Stages", ""])
    for item in summary["stages"]:
        lines.append(
            f"- `{item['outbound']}` stage=`{item['stage']}` count={item['count']} "
            f"failures={item['failures']} p95={item['latencyMs']['p95']}ms"
        )
    if summary["failures"]:
        lines.extend(["", "## Failures", ""])
        for item in summary["failures"]:
            lines.append(
                f"- kind=`{item['kind']}` outbound=`{item['outbound']}` "
                f"stage=`{item['stage']}` error=`{item['errorType']}` "
                f"elapsed={item['elapsedMs']}ms"
            )
    if summary["attributionReadiness"]["missing"]:
        lines.extend(["", "## Missing", ""])
        for item in summary["attributionReadiness"]["missing"]:
            lines.append(f"- `{item}`")
    workload = summary.get("workloadAttribution", {})
    if workload.get("enabled"):
        lines.extend(["", "## Workload Attribution", ""])
        for item in workload.get("byClass", []):
            lines.append(f"- `{item['key']}`: {item['count']}")
        if workload.get("byCandidate"):
            lines.extend(["", "### By Candidate", ""])
            for item in workload.get("byCandidate", []):
                lines.append(
                    f"- `{item['candidate']}` failures={item['failures']}/{item['items']} "
                    f"rate={item['failureRate']} classes={item['classes']}"
                )
        failures = [
            item
            for item in workload.get("items", [])
            if item.get("classification") != "healthy"
        ]
        if failures:
            lines.extend(["", "### Workload Failures", ""])
            for item in failures:
                sessions = ",".join(
                    str(session.get("session")) for session in item.get("sessions", [])
                )
                dns_flows = ",".join(
                    str(flow.get("dnsQueryId")) for flow in item.get("dnsFlows", [])
                )
                lines.append(
                    f"- `{item['id']}` {item['domain']} probe=`{item['probe']}` "
                    f"class=`{item['classification']}` stage=`{item['errorStage']}` "
                    f"error=`{item['errorType']}` sessions=`{sessions or '<none>'}` "
                    f"dns=`{dns_flows or '<none>'}` "
                    f"missing={','.join(item.get('missingFields', []))}"
                )
    path.write_text("\n".join(lines) + "\n")


def write_batch_report(path: Path, batch: dict[str, Any]) -> None:
    lines = [
        "# Dynet Trace Attribution Batch",
        "",
        f"- Runs: `{batch['totals']['runs']}`",
        f"- Items: `{batch['totals']['items']}` failures=`{batch['totals']['failures']}`",
        f"- Unknown: `{batch['totals']['unknown']}`",
        f"- Missing repeat correlation: `{batch['totals']['missingRepeatCorrelation']}`",
        "",
        "## Gates",
        "",
    ]
    for gate in batch["gates"]:
        lines.append(
            f"- `{gate['name']}` passed={gate['passed']} "
            f"value=`{gate['value']}` required=`{gate['required']}`"
        )
    lines.extend(["", "## Classes", ""])
    for item in batch["byClass"]:
        lines.append(f"- `{item['key']}`: {item['count']}")
    lines.extend(["", "## Candidate Signals", ""])
    for item in batch["candidateSignals"]:
        lines.append(
            f"- `{item['candidate']}` action=`{item['plannerAction']}` "
            f"confidence=`{item['confidence']}` failures={item['failures']}/{item['items']} "
            f"nodeSuspectRuns={item['nodeSuspectRuns']} "
            f"repeatedNodeSuspectItems={item['repeatedNodeSuspectItems']}"
        )
    if batch["repeatedEvidence"]:
        lines.extend(["", "## Repeated Evidence", ""])
        for item in batch["repeatedEvidence"]:
            lines.append(
                f"- key=`{' | '.join(item['key'])}` runs={','.join(item['runs'])} "
                f"items={item['items']}"
            )
    path.write_text("\n".join(lines) + "\n")


def manifest_input_path(raw: str, manifest_path: Path) -> Path:
    path = Path(raw)
    if path.is_absolute() or path.exists():
        return path
    return manifest_path.parent / path


def manifest_output_path(raw: str, manifest_path: Path) -> Path:
    path = Path(raw)
    if path.is_absolute():
        return path
    if path.parts and path.parts[0].startswith("."):
        return path
    return manifest_path.parent / path


def batch_paths_from_args(
    args: argparse.Namespace,
) -> tuple[list[Path], dict[str, Any] | None, Path | None]:
    manifest = None
    manifest_path = None
    paths: list[Path] = []
    if args.manifest:
        manifest_path = Path(args.manifest)
        manifest = load_manifest(manifest_path)
        paths.extend(
            manifest_input_path(path, manifest_path)
            for path in manifest.get("summaries", [])
        )
    paths.extend(Path(path) for path in args.summary or [])
    if not paths:
        raise SystemExit("batch requires at least one --summary or a --manifest")
    return paths, manifest, manifest_path


def manifest_section(manifest: dict[str, Any] | None, key: str) -> dict[str, Any]:
    if not manifest:
        return {}
    section = manifest.get(key, {})
    return section if isinstance(section, dict) else {}


def int_setting(
    cli_value: int | None,
    manifest: dict[str, Any] | None,
    key: str,
    default: int,
) -> int:
    if cli_value is not None:
        return cli_value
    value = manifest_section(manifest, "thresholds").get(key)
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        raise SystemExit(f"invalid integer threshold {key}: {value}") from None


def float_setting(
    cli_value: float | None,
    manifest: dict[str, Any] | None,
    key: str,
    default: float,
) -> float:
    if cli_value is not None:
        return cli_value
    value = manifest_section(manifest, "thresholds").get(key)
    if value is None:
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        raise SystemExit(f"invalid float threshold {key}: {value}") from None


def output_path_setting(
    cli_value: str | None,
    manifest: dict[str, Any] | None,
    manifest_path: Path | None,
    key: str,
    default: str,
) -> Path:
    if cli_value is not None:
        return Path(cli_value)
    value = manifest_section(manifest, "outputs").get(key)
    if isinstance(value, str) and value:
        if manifest_path:
            return manifest_output_path(value, manifest_path)
        return Path(value)
    return Path(default)


def failed_gate_names(batch: dict[str, Any]) -> list[str]:
    return [gate["name"] for gate in batch["gates"] if not gate["passed"]]


def command_summary(args: argparse.Namespace) -> int:
    report = load_json(Path(args.runtime_report))
    workload_probe = load_json(Path(args.workload_probe)) if args.workload_probe else None
    summary = build_summary(report, workload_probe)
    output_json = Path(args.output_json)
    output_md = Path(args.output_md)
    write_json(output_json, summary)
    write_report(output_md, summary)
    print(
        json.dumps(
            {
                "outputJson": str(output_json),
                "outputMd": str(output_md),
                "events": summary["totals"]["events"],
                "ready": summary["attributionReadiness"][
                    "canExplainPlanVsNodeForObservedPath"
                ],
            },
            sort_keys=True,
        )
    )
    return 0


def command_batch(args: argparse.Namespace) -> int:
    paths, manifest, manifest_path = batch_paths_from_args(args)
    batch = build_batch(
        paths,
        int_setting(
            args.min_repeat_runs,
            manifest,
            "minRepeatRuns",
            DEFAULT_MIN_REPEAT_RUNS,
        ),
        float_setting(
            args.max_unknown_rate,
            manifest,
            "maxUnknownRate",
            DEFAULT_MAX_UNKNOWN_RATE,
        ),
        float_setting(
            args.max_missing_correlation_rate,
            manifest,
            "maxMissingCorrelationRate",
            DEFAULT_MAX_MISSING_CORRELATION_RATE,
        ),
    )
    output_json = output_path_setting(
        args.output_json,
        manifest,
        manifest_path,
        "json",
        DEFAULT_BATCH_OUTPUT_JSON,
    )
    output_md = output_path_setting(
        args.output_md,
        manifest,
        manifest_path,
        "md",
        DEFAULT_BATCH_OUTPUT_MD,
    )
    write_json(output_json, batch)
    write_batch_report(output_md, batch)
    failed_gates = failed_gate_names(batch)
    print(
        json.dumps(
            {
                "outputJson": str(output_json),
                "outputMd": str(output_md),
                "runs": batch["totals"]["runs"],
                "items": batch["totals"]["items"],
                "failedGates": failed_gates,
            },
            sort_keys=True,
        )
    )
    return 1 if args.fail_on_gate and failed_gates else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Summarize dynet runtime events for plan-vs-node attribution."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    summary_parser = subparsers.add_parser("summary", help="summarize one runtime JSON report")
    summary_parser.add_argument("--runtime-report", required=True)
    summary_parser.add_argument("--workload-probe")
    summary_parser.add_argument("--output-json", default=DEFAULT_OUTPUT_JSON)
    summary_parser.add_argument("--output-md", default=DEFAULT_OUTPUT_MD)
    summary_parser.set_defaults(handler=command_summary)

    batch_parser = subparsers.add_parser(
        "batch",
        help="aggregate multiple attribution summaries into planner-safe evidence",
    )
    batch_parser.add_argument("--summary", action="append")
    batch_parser.add_argument(
        "--manifest",
        help="JSON manifest with summaries, thresholds, and optional outputs",
    )
    batch_parser.add_argument("--output-json")
    batch_parser.add_argument("--output-md")
    batch_parser.add_argument("--min-repeat-runs", type=int)
    batch_parser.add_argument("--max-unknown-rate", type=float)
    batch_parser.add_argument("--max-missing-correlation-rate", type=float)
    batch_parser.add_argument(
        "--fail-on-gate",
        action="store_true",
        help="return non-zero when any batch gate fails",
    )
    batch_parser.set_defaults(handler=command_batch)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
