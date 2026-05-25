from __future__ import annotations

from typing import Any


CASCADE_COUNT_KEYS = [
    "failedByScope",
    "failedByDisposition",
    "failedByStage",
    "failedByStageSurface",
    "failedByStageDisposition",
    "failedByStopReason",
    "stoppedFlowByStopReason",
    "stoppedFlowByStageSurface",
    "stoppedFlowByAttemptCount",
]

CASCADE_TOTAL_KEYS = [
    "failedAttempts",
    "retryableFailures",
    "stoppedFailures",
    "stoppedFlows",
    "stoppedBoundExhaustedFlows",
    "recoveredFlows",
]

CASCADE_KEYS = CASCADE_TOTAL_KEYS + CASCADE_COUNT_KEYS


def cascade_counts(source: dict[str, Any]) -> dict[str, Any]:
    return {key: source.get(key) for key in CASCADE_KEYS}


def cascade_control_counts(source: dict[str, Any]) -> dict[str, Any]:
    stopped = [row for row in source.get("stoppedRows") or [] if isinstance(row, dict)]
    return {
        "stoppedNonBoundFlows": count_for(
            source.get("stoppedFlowByStopReason"),
            "non-bound-failure",
        ),
        "stoppedRetryableFailures": sum(
            int_value(row.get("retryableFailureCount")) for row in stopped
        ),
    }


def cascade_stop_index(cascade: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = {}
    for item in cascade.get("stoppedRows") or []:
        if not isinstance(item, dict):
            continue
        flow_id = item.get("flowId")
        if flow_id:
            rows[str(flow_id)] = item
    return rows


def cascade_stop_for_flow(
    flow_row: dict[str, Any],
    stopped: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    flow_id = flow_row.get("flowId")
    if flow_id and str(flow_id) in stopped:
        return stopped[str(flow_id)]
    for item in flow_row.get("flowIds") or []:
        if str(item) in stopped:
            return stopped[str(item)]
    return {}


def cascade_stop_fields(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "cascadeStoppedFlowMatched": bool(row),
        "cascadeStoppedFlowStopReason": row.get("stopReason"),
        "cascadeStoppedFlowCandidateExhausted": bool(row.get("candidateExhausted")),
        "cascadeStoppedFlowAttemptCount": int_value(row.get("attemptCount")),
        "cascadeStoppedFlowFailedAttemptCount": int_value(row.get("failedAttemptCount")),
        "cascadeStoppedFlowRetryableFailureCount": int_value(row.get("retryableFailureCount")),
        "cascadeStoppedFlowCandidateCount": int_value(row.get("candidateCount")),
        "cascadeStoppedFlowFailureScope": row.get("failureScope"),
        "cascadeStoppedFlowDisposition": row.get("errorDisposition"),
        "cascadeStoppedFlowStageSurface": row.get("failureStageSurface"),
        "cascadeStoppedFlowPendingWaitClass": row.get("pendingWaitClass"),
        "cascadeStoppedFlowFailureStagePendingWaitClass": row.get(
            "failureStagePendingWaitClass"
        ),
        "cascadeStoppedFlowBoundSelectedSequence": list(row.get("boundSelectedSequence") or []),
        "cascadeStoppedFlowFailedSelectedSequence": list(row.get("failedSelectedSequence") or []),
        "cascadeStoppedFlowRetryableSelectedSequence": list(
            row.get("retryableSelectedSequence") or []
        ),
        "cascadeStoppedFlowLastBoundSelected": row.get("lastBoundSelected"),
    }


def int_value(value: Any) -> int:
    if value is None:
        return 0
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def count_items(items: list[dict[str, Any]]) -> int:
    return sum(int(item.get("count") or 0) for item in items)


def count_for(rows: Any, key: str) -> int:
    return sum(
        int_value(row.get("count"))
        for row in rows or []
        if isinstance(row, dict) and row.get("key") == key
    )


def aggregate_lists(groups: Any) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for values in groups:
        for item in values or []:
            key = str(item.get("key") or "unknown")
            counts[key] = counts.get(key, 0) + int(item.get("count") or 0)
    return [{"key": key, "count": counts[key]} for key in sorted(counts)]


def aggregate_strings(values: Any) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for value in values:
        key = str(value or "unknown")
        counts[key] = counts.get(key, 0) + 1
    return [{"key": key, "count": counts[key]} for key in sorted(counts)]


def int_fields(row: dict[str, Any], fields: list[str]) -> dict[str, int]:
    return {field: int_value(row.get(field)) for field in fields}
