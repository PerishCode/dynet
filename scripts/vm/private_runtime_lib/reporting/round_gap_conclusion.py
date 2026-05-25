from __future__ import annotations

from typing import Any


def cascade_brief(summary: dict[str, Any]) -> dict[str, Any]:
    selection = summary.get("selection", {})
    cascade = selection.get("cascadeAttempts", {}) if isinstance(selection, dict) else {}
    if not isinstance(cascade, dict):
        cascade = {}
    return {
        "startedAttempts": int_value(cascade.get("startedAttempts")),
        "finishedAttempts": int_value(cascade.get("finishedAttempts")),
        "successAttempts": int_value(cascade.get("successAttempts")),
        "failedAttempts": int_value(cascade.get("failedAttempts")),
        "retryableFailures": int_value(cascade.get("retryableFailures")),
        "stoppedFailures": int_value(cascade.get("stoppedFailures")),
        "stoppedFlows": int_value(cascade.get("stoppedFlows")),
        "stoppedBoundExhaustedFlows": int_value(cascade.get("stoppedBoundExhaustedFlows")),
        "recoveredFlows": int_value(cascade.get("recoveredFlows")),
        "failedByScope": list(cascade.get("failedByScope") or []),
        "failedByDisposition": list(cascade.get("failedByDisposition") or []),
        "failedByStage": list(cascade.get("failedByStage") or []),
        "failedByStageSurface": list(cascade.get("failedByStageSurface") or []),
        "failedByStageDisposition": list(cascade.get("failedByStageDisposition") or []),
        "failedByStopReason": list(cascade.get("failedByStopReason") or []),
        "stoppedFlowByStopReason": list(cascade.get("stoppedFlowByStopReason") or []),
        "stoppedFlowByStageSurface": list(cascade.get("stoppedFlowByStageSurface") or []),
        "stoppedFlowByAttemptCount": list(cascade.get("stoppedFlowByAttemptCount") or []),
    }


def cascade_totals(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "cascadeStartedAttempts": sum_cascade_field(rows, "startedAttempts"),
        "cascadeFinishedAttempts": sum_cascade_field(rows, "finishedAttempts"),
        "cascadeSuccessAttempts": sum_cascade_field(rows, "successAttempts"),
        "cascadeFailedAttempts": sum_cascade_field(rows, "failedAttempts"),
        "cascadeRetryableFailures": sum_cascade_field(rows, "retryableFailures"),
        "cascadeStoppedFailures": sum_cascade_field(rows, "stoppedFailures"),
        "cascadeStoppedFlows": sum_cascade_field(rows, "stoppedFlows"),
        "cascadeStoppedBoundExhaustedFlows": sum_cascade_field(rows, "stoppedBoundExhaustedFlows"),
        "cascadeRecoveredFlows": sum_cascade_field(rows, "recoveredFlows"),
        "cascadeFailedByScope": aggregate_cascade_nested(rows, "failedByScope"),
        "cascadeFailedByDisposition": aggregate_cascade_nested(rows, "failedByDisposition"),
        "cascadeFailedByStage": aggregate_cascade_nested(rows, "failedByStage"),
        "cascadeFailedByStageSurface": aggregate_cascade_nested(rows, "failedByStageSurface"),
        "cascadeFailedByStageDisposition": aggregate_cascade_nested(
            rows,
            "failedByStageDisposition",
        ),
        "cascadeFailedByStopReason": aggregate_cascade_nested(rows, "failedByStopReason"),
        "cascadeStoppedFlowByStopReason": aggregate_cascade_nested(
            rows,
            "stoppedFlowByStopReason",
        ),
        "cascadeStoppedFlowByStageSurface": aggregate_cascade_nested(
            rows,
            "stoppedFlowByStageSurface",
        ),
        "cascadeStoppedFlowByAttemptCount": aggregate_cascade_nested(
            rows,
            "stoppedFlowByAttemptCount",
        ),
    }


def sum_cascade_field(rows: list[dict[str, Any]], field: str) -> int:
    return sum(int(row["cascade"].get(field) or 0) for row in rows)


def aggregate_cascade_nested(rows: list[dict[str, Any]], field: str) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for row in rows:
        for item in row["cascade"].get(field) or []:
            key = str(item.get("key") or "unknown")
            counts[key] = counts.get(key, 0) + int(item.get("count") or 0)
    return [{"key": key, "count": counts[key]} for key in sorted(counts)]


def round_gap_conclusion(
    rows: list[dict[str, Any]],
    totals: dict[str, Any],
    reason: str,
) -> dict[str, Any]:
    status = round_gap_batch_status(rows)
    cascade = cascade_conclusion(totals)
    return {
        "status": status,
        "nextAction": round_gap_next_action(status, cascade["status"]),
        "reason": reason,
        "cascade": cascade,
        "plannerPenaltySafe": False,
        "qualityPenaltySafe": False,
        "runs": totals["runs"],
        "cleanRuns": totals["cleanRuns"],
        "failedRuns": totals["failedRuns"],
        "classifications": totals["classifications"],
    }


def round_gap_batch_status(rows: list[dict[str, Any]]) -> str:
    classes = {str(row.get("classification") or "unknown") for row in rows}
    if not rows:
        return "empty"
    if classes == {"clean"}:
        return "clean"
    if len(classes) == 1:
        return next(iter(classes))
    if "clean" in classes:
        return "mixed-with-clean-controls"
    return "mixed-runtime-mechanism"


def round_gap_next_action(status: str, cascade_status: str = "none") -> str:
    if status == "clean" and cascade_status == "non-bound-stop-observed":
        return "preserve-non-bound-cascade-stop-and-return-to-product-effect"
    if status == "clean" and cascade_status == "bound-exhausted-cascade-stop-observed":
        return "inspect-bound-candidate-exhaustion-before-product-effect"
    if status == "clean" and cascade_status.startswith("retryable-bound"):
        return "observe-cascade-recovery-and-return-to-product-effect"
    if status == "clean" and cascade_status != "none":
        return "inspect-cascade-mechanism-before-product-effect"
    actions = {
        "clean": "return-to-mainline-product-effect",
        "stage-pressure-with-schedule-lag": "separate-schedule-pressure-from-outbound-stage",
        "outbound-stage-pressure": "harden-outbound-stage-failure-path",
        "preflow-terminal-before-runtime-session": "harden-pre-session-terminal-path",
        "preflow-terminal-with-runtime-failures": "split-terminal-and-runtime-failure-paths",
        "recovered-hidden-stage-pressure": "inspect-recovered-runtime-stage-pressure",
        "workload-protocol-surface": "classify-workload-protocol-surface",
        "mixed-with-clean-controls": "compare-mechanism-deltas-with-clean-controls",
        "mixed-runtime-mechanism": "split-round-gap-mechanisms-before-policy",
    }
    return actions.get(status, "continue-runtime-mechanism-attribution")


def cascade_conclusion(totals: dict[str, Any]) -> dict[str, Any]:
    failed = int_value(totals.get("cascadeFailedAttempts"))
    retryable = int_value(totals.get("cascadeRetryableFailures"))
    stopped = int_value(totals.get("cascadeStoppedFailures"))
    stopped_bound_exhausted = int_value(totals.get("cascadeStoppedBoundExhaustedFlows"))
    recovered = int_value(totals.get("cascadeRecoveredFlows"))
    scopes = item_keys(totals.get("cascadeFailedByScope"))
    stop_reasons = item_keys(totals.get("cascadeFailedByStopReason"))
    status = cascade_status(
        failed,
        retryable,
        stopped,
        stopped_bound_exhausted,
        recovered,
        scopes,
        stop_reasons,
    )
    return {
        "status": status,
        "nextAction": cascade_next_action(status),
        "reason": cascade_reason(status),
        "failedAttempts": failed,
        "retryableFailures": retryable,
        "stoppedFailures": stopped,
        "stoppedFlows": int_value(totals.get("cascadeStoppedFlows")),
        "stoppedBoundExhaustedFlows": stopped_bound_exhausted,
        "recoveredFlows": recovered,
        "failedByScope": list(totals.get("cascadeFailedByScope") or []),
        "failedByDisposition": list(totals.get("cascadeFailedByDisposition") or []),
        "failedByStageSurface": list(totals.get("cascadeFailedByStageSurface") or []),
        "failedByStageDisposition": list(
            totals.get("cascadeFailedByStageDisposition") or []
        ),
        "failedByStopReason": list(totals.get("cascadeFailedByStopReason") or []),
        "stoppedFlowByStopReason": list(totals.get("cascadeStoppedFlowByStopReason") or []),
        "stoppedFlowByStageSurface": list(
            totals.get("cascadeStoppedFlowByStageSurface") or []
        ),
        "stoppedFlowByAttemptCount": list(totals.get("cascadeStoppedFlowByAttemptCount") or []),
    }


def cascade_status(
    failed: int,
    retryable: int,
    stopped: int,
    stopped_bound_exhausted: int,
    recovered: int,
    scopes: set[str],
    stop_reasons: set[str],
) -> str:
    if failed == 0:
        return "none"
    if stopped and "downstream" in scopes and "non-bound-failure" in stop_reasons:
        return "non-bound-stop-observed"
    if stopped_bound_exhausted:
        return "bound-exhausted-cascade-stop-observed"
    if stopped:
        return "stopped-cascade-failure-observed"
    if retryable and scopes and scopes <= {"bound"} and recovered:
        return "retryable-bound-recovery-observed"
    if retryable and scopes and scopes <= {"bound"}:
        return "retryable-bound-failure-observed"
    return "cascade-failure-observed"


def cascade_next_action(status: str) -> str:
    actions = {
        "none": "none",
        "non-bound-stop-observed": "preserve-non-bound-cascade-stop",
        "bound-exhausted-cascade-stop-observed": "inspect-bound-candidate-exhaustion-flow",
        "stopped-cascade-failure-observed": "inspect-cascade-stop-scope",
        "retryable-bound-recovery-observed": "observe-recovered-bound-cascade-failures",
        "retryable-bound-failure-observed": "observe-bound-cascade-failures",
        "cascade-failure-observed": "inspect-cascade-failure-scope",
    }
    return actions.get(status, "inspect-cascade-failure-scope")


def cascade_reason(status: str) -> str:
    reasons = {
        "none": "no cascade failure evidence in this round-gap batch",
        "non-bound-stop-observed": (
            "cascade stopped on a non-bound downstream failure; retry must remain limited to bound failures"
        ),
        "bound-exhausted-cascade-stop-observed": (
            "cascade exhausted bound candidates for at least one flow; preserve the full candidate sequence before policy"
        ),
        "stopped-cascade-failure-observed": (
            "cascade contains stopped failures whose scope must stay visible before policy changes"
        ),
        "retryable-bound-recovery-observed": (
            "cascade recovered after retryable bound failures; this is fallback-path evidence, not penalty evidence"
        ),
        "retryable-bound-failure-observed": (
            "cascade saw retryable bound failures; this is mechanism pressure, not candidate penalty evidence"
        ),
        "cascade-failure-observed": (
            "cascade failures are present but do not match a narrower retry or stop pattern"
        ),
    }
    return reasons.get(status, "cascade failure evidence needs scope inspection before policy changes")


def penalty_reason(rows: list[dict[str, Any]]) -> str:
    if all(row["classification"] == "clean" for row in rows) and cascade_failed(rows):
        return "batch is clean but contains cascade mechanism evidence; cascade failures are observe-only control evidence, not stable candidate penalties"
    if any(row["classification"] == "clean" for row in rows):
        return "batch contains clean controls; pressure surfaces are not stable candidate penalties"
    classes = {str(row.get("classification") or "unknown") for row in rows}
    if len(classes) > 1:
        return "round-gap batch contains mixed runtime mechanism evidence, not repeated runtime-backed quality-gap evidence"
    classification = next(iter(classes), "unknown")
    if classification == "stage-pressure-with-schedule-lag":
        return "round-gap batch is schedule-lag pressure evidence, not repeated runtime-backed quality-gap evidence"
    if classification == "outbound-stage-pressure":
        return "round-gap batch is outbound-stage pressure evidence, not repeated runtime-backed quality-gap evidence"
    if classification.startswith("preflow-terminal"):
        return "round-gap batch is pre-session terminal mechanism evidence, not repeated runtime-backed quality-gap evidence"
    return "round-gap batch is runtime mechanism evidence, not repeated runtime-backed quality-gap evidence"


def cascade_failed(rows: list[dict[str, Any]]) -> bool:
    return any(int_value(row.get("cascade", {}).get("failedAttempts")) > 0 for row in rows)


def item_keys(items: Any) -> set[str]:
    return {str(item.get("key") or "unknown") for item in items or []}


def int_value(value: Any) -> int:
    if value is None:
        return 0
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
