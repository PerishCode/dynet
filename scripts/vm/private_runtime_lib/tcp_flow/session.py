from __future__ import annotations

from collections import Counter

from private_runtime_lib.briefs import fields

FLOW_FLAG_KINDS = {
    "tcp-session-started": "started",
    "tcp-session-attributed": "attributed",
    "tcp-session-outbound-connecting": "connecting",
    "tcp-session-established": "established",
    "tcp-session-failed": "failed",
}

PATH_FLAG_KINDS = {
    "rule-matched": "ruleMatched",
    "route-matched": "routeMatched",
    "plan-bypassed": "planBypassed",
    "dialer-cascade-selected": "cascadeSelected",
    "outbound-attempt-started": "boundAttemptStarted",
}

PRIVATE_CONNECT_STAGES = {
    "private-vmess-connect",
    "private-ss-connect",
    "private-trojan-connect",
}


def tcp_flow_brief(report: dict) -> dict:
    rows = tcp_flow_rows(report)
    payload_rows = [row for row in rows if row["firstWriteEvents"] > 0]
    failed_rows = [row for row in rows if row["failed"]]
    stage_failed_rows = [row for row in rows if row["stageFailed"]]
    return {
        "flows": len(rows),
        "startedFlows": sum(1 for row in rows if row["started"]),
        "attributedFlows": sum(1 for row in rows if row["attributed"]),
        "connectingFlows": sum(1 for row in rows if row["connecting"]),
        "establishedFlows": sum(1 for row in rows if row["established"]),
        "closedFlows": sum(1 for row in rows if row["closed"]),
        "failedFlows": sum(1 for row in rows if row["failed"]),
        "lifecycleCompleteFlows": sum(1 for row in rows if flow_lifecycle_complete(row)),
        "pathCompleteFlows": sum(1 for row in rows if flow_path_complete(row)),
        "ruleMatchedFlows": sum(1 for row in rows if row["ruleMatched"]),
        "routeMatchedFlows": sum(1 for row in rows if row["routeMatched"]),
        "planBypassedFlows": sum(1 for row in rows if row["planBypassed"]),
        "routeCandidateSetFlows": sum(1 for row in rows if row["routeCandidateSet"]),
        "routeGraphSelectedFlows": sum(1 for row in rows if row["routeGraphSelected"]),
        "routeFallbackCandidateFlows": sum(1 for row in rows if row["routeFallbackCandidateCount"] > 1),
        "routeFallbackAttemptEvents": sum(
            row["routeFallbackAttemptEvents"]
            for row in rows
            if row["routeFallbackCandidateCount"] > 1
        ),
        "routeFallbackUsedFlows": sum(1 for row in rows if route_fallback_used(row)),
        "routeFallbackEstablishedFlows": sum(
            1 for row in rows if route_fallback_used(row) and row["established"]
        ),
        "routeFallbackFailedFlows": sum(1 for row in rows if route_fallback_used(row) and row["failed"]),
        "routeFallbackByRouteSelected": aggregate_route_fallback_field(rows, "routeFallbackRouteSelected"),
        "routeFallbackByFinalOutbound": aggregate_route_fallback_field(rows, "routeFallbackFinalOutbound"),
        "routeFallbackByAttemptedOutbound": aggregate_fallback_outbounds(rows),
        "boundCandidateSetFlows": sum(1 for row in rows if row["boundCandidateSet"]),
        "boundGraphSelectedFlows": sum(1 for row in rows if row["boundGraphSelected"]),
        "cascadeSelectedFlows": sum(1 for row in rows if row["cascadeSelected"]),
        "boundAttemptStartedFlows": sum(1 for row in rows if row["boundAttemptStarted"]),
        "boundAttemptSucceededFlows": sum(1 for row in rows if row["boundAttemptSucceeded"]),
        "privateConnectFlows": sum(1 for row in rows if row["privateConnect"]),
        "closedWithByteTotals": sum(1 for row in rows if flow_close_has_totals(row)),
        "closedByReason": aggregate_field([row for row in rows if row["closed"]], "closeReason"),
        "closedWithoutPayloadFlows": sum(1 for row in rows if flow_closed_without_payload(row)),
        "closedWithoutPayloadByReason": aggregate_field(
            [row for row in rows if flow_closed_without_payload(row)],
            "closeReason",
        ),
        "payloadStartedFlows": len(payload_rows),
        "payloadReceivedFlows": sum(1 for row in payload_rows if row["receivedEvents"] > 0),
        "payloadBidirectionalFlows": sum(1 for row in payload_rows if flow_payload_bidirectional(row)),
        "payloadCloseConsistent": sum(1 for row in payload_rows if flow_close_consistent(row)),
        "duplicateClosedFlows": sum(1 for row in rows if row["closeEvents"] > 1),
        "failedAfterUpstreamOnly": sum(1 for row in failed_rows if failed_upstream_only(row)),
        "failedAfterPathComplete": sum(1 for row in failed_rows if flow_path_complete(row)),
        "failedByErrorType": aggregate_error_types(failed_rows),
        "failedByPhase": aggregate_field(failed_rows, "failurePhase"),
        "failedByCleanupAction": aggregate_field(failed_rows, "failureCleanupAction"),
        "failedByReplaySafe": aggregate_field(failed_rows, "failureReplaySafe"),
        "failedByFailureStage": aggregate_field(failed_rows, "failureStage"),
        "failedByFailureStageOutbound": aggregate_field(failed_rows, "failureStageOutbound"),
        "failedByFailureStageKind": aggregate_field(failed_rows, "failureStageKind"),
        "failedByFailureStageErrorType": aggregate_field(failed_rows, "failureStageErrorType"),
        "failedByFailureStageDisposition": aggregate_field(failed_rows, "failureStageDisposition"),
        "failedBySurface": aggregate_surfaces(failed_rows),
        "stageFailedFlows": len(stage_failed_rows),
        "stageFailureByErrorType": aggregate_field(stage_failed_rows, "stageFailureErrorType"),
        "stageFailureByDisposition": aggregate_field(stage_failed_rows, "stageFailureDisposition"),
        "stageFailureByStage": aggregate_field(stage_failed_rows, "stageFailureStage"),
        "stageFailureBySurface": aggregate_stage_surfaces(stage_failed_rows),
    }


def tcp_flow_rows(report: dict) -> list[dict]:
    flows: dict[str, dict] = {}
    for event in report.get("events", []):
        if not isinstance(event, dict):
            continue
        event_fields = fields(event)
        flow_id = event_fields.get("flowId")
        if not flow_id or not flow_id.startswith("tcp-session-"):
            continue
        observe_flow_event(flows.setdefault(flow_id, new_flow(flow_id)), event.get("kind"), event_fields)
    return list(flows.values())


def new_flow(flow_id: str) -> dict:
    return {
        "flowId": flow_id,
        "clientPort": None,
        "domain": None,
        "started": False,
        "attributed": False,
        "connecting": False,
        "established": False,
        "closed": False,
        "failed": False,
        "closeEvents": 0,
        "firstWriteEvents": 0,
        "receivedEvents": 0,
        "firstWriteBytes": 0,
        "receivedBytes": 0,
        "closeUpstreamBytes": None,
        "closeDownstreamBytes": None,
        "failureUpstreamBytes": None,
        "failureDownstreamBytes": None,
        "failureErrorType": None,
        "failurePhase": None,
        "failureCleanupAction": None,
        "failureReplaySafe": None,
        "failureStage": None,
        "failureStageOutbound": None,
        "failureStageKind": None,
        "failureStageErrorType": None,
        "failureStageDisposition": None,
        "closeReason": None,
        "stageFailed": False,
        "stageFailureErrorType": None,
        "stageFailureDisposition": None,
        "stageFailureStage": None,
        "stageFailureOutbound": None,
        "ruleMatched": False,
        "routeMatched": False,
        "planBypassed": False,
        "routeCandidateSet": False,
        "routeGraphSelected": False,
        "routeFallbackCandidateCount": 0,
        "routeFallbackAttemptMax": 0,
        "routeFallbackAttemptEvents": 0,
        "routeFallbackRouteSelected": None,
        "routeFallbackFinalOutbound": None,
        "routeFallbackAttemptedOutbounds": [],
        "boundCandidateSet": False,
        "boundGraphSelected": False,
        "cascadeSelected": False,
        "boundAttemptStarted": False,
        "boundAttemptSucceeded": False,
        "privateConnect": False,
    }


def observe_flow_event(row: dict, kind: object, event_fields: dict[str, str]) -> None:
    port = client_port(event_fields)
    if port is not None:
        row["clientPort"] = port
    if kind == "tcp-session-failed":
        row["failed"] = True
        row["failureUpstreamBytes"] = optional_int(event_fields.get("upstreamBytes"))
        row["failureDownstreamBytes"] = optional_int(event_fields.get("downstreamBytes"))
        row["failureErrorType"] = event_fields.get("errorType") or "unknown"
        row["failurePhase"] = event_fields.get("failurePhase") or "unknown"
        row["failureCleanupAction"] = event_fields.get("cleanupAction") or "unknown"
        row["failureReplaySafe"] = event_fields.get("replaySafe") or "unknown"
        row["failureStage"] = event_fields.get("failureStage") or row.get("failureStage")
        row["failureStageOutbound"] = event_fields.get("failureStageOutbound") or row.get(
            "failureStageOutbound"
        )
        row["failureStageKind"] = event_fields.get("failureStageKind") or row.get("failureStageKind")
        row["failureStageErrorType"] = event_fields.get("failureStageErrorType") or row.get(
            "failureStageErrorType"
        )
        row["failureStageDisposition"] = event_fields.get("failureStageDisposition") or row.get(
            "failureStageDisposition"
        )
        row["routeFallbackFinalOutbound"] = event_fields.get("outbound") or row.get(
            "routeFallbackFinalOutbound"
        )
    elif kind == "tcp-session-outbound-connecting":
        row["connecting"] = True
        observe_route_fallback(row, event_fields)
    elif kind == "tcp-session-established":
        row["established"] = True
        row["routeFallbackFinalOutbound"] = event_fields.get("outbound") or row.get(
            "routeFallbackFinalOutbound"
        )
    elif kind == "outbound-stage-finished" and event_fields.get("status") == "failed":
        row["stageFailed"] = True
        row["failureErrorType"] = event_fields.get("errorType") or "unknown"
        row["stageFailureErrorType"] = event_fields.get("errorType") or "unknown"
        row["stageFailureDisposition"] = event_fields.get("errorDisposition") or "unknown"
        row["stageFailureStage"] = event_fields.get("stage") or "unknown"
        row["stageFailureOutbound"] = event_fields.get("outbound") or "unknown"
    elif kind == "tcp-session-attributed":
        row["attributed"] = True
        row["domain"] = event_fields.get("domain") or row.get("domain")
    elif kind in FLOW_FLAG_KINDS:
        row[FLOW_FLAG_KINDS[str(kind)]] = True
    elif kind in PATH_FLAG_KINDS:
        row[PATH_FLAG_KINDS[str(kind)]] = True
    elif kind == "outbound-candidate-set" and event_fields.get("scope") == "tcp-route":
        row["routeCandidateSet"] = True
    elif kind == "outbound-graph-selected" and event_fields.get("scope") == "tcp-route":
        row["routeGraphSelected"] = True
    elif kind == "outbound-candidate-set" and event_fields.get("scope") == "dialer-bound":
        row["boundCandidateSet"] = True
    elif kind == "outbound-graph-selected" and event_fields.get("scope") == "dialer-bound":
        row["boundGraphSelected"] = True
    elif kind == "outbound-attempt-finished" and event_fields.get("status") == "success":
        row["boundAttemptSucceeded"] = True
    elif kind == "outbound-stage-finished" and event_fields.get("stage") in PRIVATE_CONNECT_STAGES:
        row["privateConnect"] = event_fields.get("status") == "success"
    elif kind == "tcp-session-payload-first-write":
        row["firstWriteEvents"] += 1
        row["firstWriteBytes"] += int_value(event_fields.get("bytes"))
    elif kind == "tcp-session-payload-received":
        row["receivedEvents"] += 1
        row["receivedBytes"] += int_value(event_fields.get("bytes"))
    elif kind == "tcp-session-closed":
        row["closed"] = True
        row["closeEvents"] += 1
        row["closeUpstreamBytes"] = optional_int(event_fields.get("upstreamBytes"))
        row["closeDownstreamBytes"] = optional_int(event_fields.get("downstreamBytes"))
        row["closeReason"] = event_fields.get("reason") or "unknown"


def observe_route_fallback(row: dict, event_fields: dict[str, str]) -> None:
    attempt = optional_int(event_fields.get("routeFallbackAttempt"))
    candidate_count = optional_int(event_fields.get("routeFallbackCandidateCount"))
    if attempt is None and candidate_count is None:
        return
    row["routeFallbackAttemptEvents"] += 1
    row["routeFallbackAttemptMax"] = max(row["routeFallbackAttemptMax"], attempt or 0)
    row["routeFallbackCandidateCount"] = max(
        row["routeFallbackCandidateCount"],
        candidate_count or 0,
    )
    row["routeFallbackRouteSelected"] = event_fields.get("routeSelected") or row.get(
        "routeFallbackRouteSelected"
    )
    outbound = event_fields.get("outbound")
    if outbound:
        row["routeFallbackAttemptedOutbounds"].append(outbound)


def route_fallback_used(row: dict) -> bool:
    return row["routeFallbackAttemptMax"] > 1


def flow_lifecycle_complete(row: dict) -> bool:
    return (
        row["started"]
        and row["attributed"]
        and row["connecting"]
        and row["established"]
        and row["closed"]
        and not row["failed"]
    )


def flow_path_complete(row: dict) -> bool:
    if direct_fallback_path_complete(row):
        return True
    return (
        flow_route_entry_complete(row)
        and row["boundCandidateSet"]
        and row["boundGraphSelected"]
        and row["cascadeSelected"]
        and row["boundAttemptStarted"]
        and row["boundAttemptSucceeded"]
        and row["privateConnect"]
    )


def direct_fallback_path_complete(row: dict) -> bool:
    return (
        route_fallback_used(row)
        and row["routeFallbackFinalOutbound"] == "direct"
        and flow_route_entry_complete(row)
        and row["boundCandidateSet"]
        and row["boundGraphSelected"]
        and row["cascadeSelected"]
        and row["boundAttemptStarted"]
        and row["established"]
    )


def flow_route_entry_complete(row: dict) -> bool:
    return (row["ruleMatched"] and row["planBypassed"]) or (
        row["routeMatched"] and row["routeGraphSelected"]
    )


def flow_close_has_totals(row: dict) -> bool:
    return row["closed"] and row["closeUpstreamBytes"] is not None and row["closeDownstreamBytes"] is not None


def flow_closed_without_payload(row: dict) -> bool:
    return row["closed"] and row["firstWriteEvents"] == 0


def flow_payload_bidirectional(row: dict) -> bool:
    return row["firstWriteBytes"] > 0 and row["receivedBytes"] > 0


def flow_close_consistent(row: dict) -> bool:
    return (
        flow_payload_bidirectional(row)
        and row["closeUpstreamBytes"] is not None
        and row["closeDownstreamBytes"] is not None
        and row["closeUpstreamBytes"] >= row["firstWriteBytes"]
        and row["closeDownstreamBytes"] == row["receivedBytes"]
    )


def failed_upstream_only(row: dict) -> bool:
    return (
        row["failed"]
        and int_value(row["failureUpstreamBytes"]) > 0
        and int_value(row["failureDownstreamBytes"]) == 0
    )


def failure_surface(row: dict) -> str:
    error_type = str(row.get("failureErrorType") or "unknown")
    if flow_path_complete(row) and failed_upstream_only(row):
        return f"path-complete-upstream-only-{error_type}"
    if flow_path_complete(row):
        return f"path-complete-{error_type}"
    return f"path-incomplete-{error_type}"


def aggregate_error_types(rows: list[dict]) -> list[dict]:
    return aggregate_field(rows, "failureErrorType")


def aggregate_surfaces(rows: list[dict]) -> list[dict]:
    counter = Counter(failure_surface(row) for row in rows)
    return [{"key": key, "count": counter[key]} for key in sorted(counter)]


def aggregate_stage_surfaces(rows: list[dict]) -> list[dict]:
    counter = Counter(
        f"{row.get('stageFailureStage') or 'unknown'}:{row.get('stageFailureErrorType') or 'unknown'}"
        for row in rows
    )
    return [{"key": key, "count": counter[key]} for key in sorted(counter)]


def aggregate_route_fallback_field(rows: list[dict], field: str) -> list[dict]:
    return aggregate_field([row for row in rows if route_fallback_used(row)], field)


def aggregate_fallback_outbounds(rows: list[dict]) -> list[dict]:
    counter: Counter[str] = Counter()
    for row in rows:
        if route_fallback_used(row):
            counter.update(str(item) for item in row["routeFallbackAttemptedOutbounds"])
    return [{"key": key, "count": counter[key]} for key in sorted(counter)]


def aggregate_field(rows: list[dict], field: str) -> list[dict]:
    counter = Counter(str(row.get(field) or "unknown") for row in rows)
    return [{"key": key, "count": counter[key]} for key in sorted(counter)]


def client_port(fields_value: dict[str, str]) -> int | None:
    port = optional_int(fields_value.get("clientPort"))
    if port is not None:
        return port
    client = fields_value.get("client")
    if not client or ":" not in client:
        return None
    return optional_int(client.rsplit(":", 1)[1])


def int_value(value: str | None) -> int:
    return optional_int(value) or 0


def optional_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None
