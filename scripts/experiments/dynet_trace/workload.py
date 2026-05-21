from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from dynet_trace.common import int_value, top
from dynet_trace.workload_runtime import (
    matching_dns_flows,
    matching_sessions,
    runtime_dns_flows,
    runtime_sessions,
)


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
    if missing_routed_session(result, sessions, dns_flows):
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

def missing_routed_session(
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
