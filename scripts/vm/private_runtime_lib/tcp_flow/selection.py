from __future__ import annotations

import json
from collections import Counter


def fields(event: dict) -> dict[str, str]:
    value = event.get("fields", {})
    if not isinstance(value, dict):
        return {}
    return {str(key): str(item) for key, item in value.items()}


def bound_selection_brief(events: list[dict]) -> dict:
    rows = mark_selection_roles([
        bound_candidate_row(event)
        for event in events
        if event.get("kind") == "outbound-candidate-set"
        and fields(event).get("scope") == "dialer-bound"
    ])
    rows = [row for row in rows if row]
    primary_rows = [row for row in rows if row.get("selectionRole") == "primary"]
    fallback_rows = [row for row in rows if row.get("selectionRole") == "fallback"]
    return {
        "candidateSets": len(primary_rows),
        "attemptCandidateSets": len(rows),
        "fallbackCandidateSets": len(fallback_rows),
        "withBoundSelected": selected_count(primary_rows),
        "selectedWithQuality": selected_quality_count(primary_rows),
        "selectedBest": selected_best_count(primary_rows),
        "selectedBehind": selected_behind_count(primary_rows),
        "fallbackSelectedWithQuality": selected_quality_count(fallback_rows),
        "fallbackSelectedBehind": selected_behind_count(fallback_rows),
        "bySelected": aggregate_rows(primary_rows, "selected"),
        "byAttemptSelected": aggregate_rows(rows, "selected"),
        "rows": rows,
    }


def cascade_attempt_brief(events: list[dict]) -> dict:
    rows = [
        cascade_attempt_row(event)
        for event in events
        if event.get("kind") == "dialer-cascade-attempt-finished"
    ]
    rows = infer_cascade_failure_stages(rows, events)
    stopped_flow_rows_value = stopped_flow_rows(rows)
    started = [
        event
        for event in events
        if event.get("kind") == "dialer-cascade-attempt-started"
    ]
    failed = [row for row in rows if row.get("status") == "failed"]
    success = [row for row in rows if row.get("status") == "success"]
    retryable = [row for row in failed if row.get("retryAllowed") is True]
    stopped = [row for row in failed if row.get("retryAllowed") is False]
    return {
        "startedAttempts": len(started),
        "finishedAttempts": len(rows),
        "successAttempts": len(success),
        "failedAttempts": len(failed),
        "retryableFailures": len(retryable),
        "stoppedFailures": len(stopped),
        "stoppedFlows": len(stopped_flow_rows_value),
        "stoppedBoundExhaustedFlows": sum(
            1 for row in stopped_flow_rows_value if row.get("candidateExhausted")
        ),
        "recoveredFlows": recovered_flow_count(rows),
        "failedByScope": aggregate_rows(failed, "failureScope"),
        "failedByDisposition": aggregate_rows(failed, "errorDisposition"),
        "failedByStage": aggregate_rows(failed, "failureStage"),
        "failedByStageSurface": aggregate_stage_surface(failed),
        "failedByStageDisposition": aggregate_rows(failed, "failureStageDisposition"),
        "failedByStopReason": aggregate_rows(failed, "retryStopReason"),
        "stoppedFlowByStopReason": aggregate_rows(stopped_flow_rows_value, "stopReason"),
        "stoppedFlowByStageSurface": aggregate_rows(stopped_flow_rows_value, "failureStageSurface"),
        "stoppedFlowByAttemptCount": aggregate_rows(stopped_flow_rows_value, "failedAttemptCount"),
        "successBySelected": aggregate_rows(success, "boundSelected"),
        "failedBySelected": aggregate_rows(failed, "boundSelected"),
        "stoppedRows": stopped_flow_rows_value,
        "rows": rows,
    }


def cascade_attempt_row(event: dict) -> dict:
    event_fields = fields(event)
    return {
        "flowId": event_fields.get("flowId"),
        "sequence": int_or_none(event.get("sequence")),
        "dialer": event_fields.get("dialer"),
        "boundSelected": event_fields.get("boundSelected"),
        "attempt": int_or_none(event_fields.get("attempt")),
        "candidateCount": int_or_none(event_fields.get("candidateCount")),
        "status": event_fields.get("status") or "unknown",
        "failureScope": event_fields.get("failureScope") or "unknown",
        "errorType": event_fields.get("errorType"),
        "errorDisposition": event_fields.get("errorDisposition"),
        "failureStage": event_fields.get("failureStage"),
        "failureStageOutbound": event_fields.get("failureStageOutbound"),
        "failureStageKind": event_fields.get("failureStageKind"),
        "failureStageErrorType": event_fields.get("failureStageErrorType"),
        "failureStageDisposition": event_fields.get("failureStageDisposition"),
        "pendingWaitClass": event_fields.get("pendingWaitClass"),
        "failureStagePendingWaitClass": event_fields.get("failureStagePendingWaitClass"),
        "retryAllowed": bool_or_none(event_fields.get("retryAllowed")),
        "retryStopReason": event_fields.get("retryStopReason"),
    }


def infer_cascade_failure_stages(rows: list[dict], events: list[dict]) -> list[dict]:
    stages_by_flow = failed_stage_rows(events)
    previous_by_flow: dict[str, int] = {}
    inferred = []
    for row in sorted(rows, key=lambda item: int(item.get("sequence") or 0)):
        row = dict(row)
        if row.get("status") == "failed" and not row.get("failureStage"):
            stage = infer_cascade_failure_stage(row, stages_by_flow, previous_by_flow)
            if stage:
                row.update(stage)
        flow_id = row.get("flowId")
        sequence = row.get("sequence")
        if flow_id and sequence is not None:
            previous_by_flow[str(flow_id)] = int(sequence)
        inferred.append(row)
    return inferred


def failed_stage_rows(events: list[dict]) -> dict[str, list[dict]]:
    rows: dict[str, list[dict]] = {}
    for event in events:
        event_fields = fields(event)
        if event.get("kind") != "outbound-stage-finished":
            continue
        if event_fields.get("status") != "failed":
            continue
        flow_id = event_fields.get("flowId")
        sequence = int_or_none(event.get("sequence"))
        if not flow_id or sequence is None:
            continue
        rows.setdefault(str(flow_id), []).append({
            "sequence": sequence,
            "failureStage": event_fields.get("stage"),
            "failureStageOutbound": event_fields.get("outbound"),
            "failureStageKind": event_fields.get("kind"),
            "failureStageErrorType": event_fields.get("errorType"),
            "failureStageDisposition": event_fields.get("errorDisposition"),
        })
    return rows


def infer_cascade_failure_stage(
    row: dict,
    stages_by_flow: dict[str, list[dict]],
    previous_by_flow: dict[str, int],
) -> dict | None:
    flow_id = row.get("flowId")
    sequence = row.get("sequence")
    if not flow_id or sequence is None:
        return None
    lower = previous_by_flow.get(str(flow_id), 0)
    candidates = [
        stage
        for stage in stages_by_flow.get(str(flow_id), [])
        if lower < int(stage["sequence"]) < int(sequence)
    ]
    if row.get("failureScope") == "bound":
        candidates = [
            stage
            for stage in candidates
            if stage.get("failureStageOutbound") == row.get("boundSelected")
        ]
    if not candidates:
        return None
    return {key: value for key, value in candidates[-1].items() if key != "sequence"}


def recovered_flow_count(rows: list[dict]) -> int:
    by_flow: dict[str, list[dict]] = {}
    for row in rows:
        flow_id = row.get("flowId")
        if flow_id:
            by_flow.setdefault(str(flow_id), []).append(row)
    return sum(1 for flow_rows in by_flow.values() if recovered_flow(flow_rows))


def recovered_flow(rows: list[dict]) -> bool:
    saw_retryable = False
    for row in sorted(rows, key=lambda item: int(item.get("attempt") or 0)):
        if row.get("status") == "failed" and row.get("retryAllowed") is True:
            saw_retryable = True
        if saw_retryable and row.get("status") == "success":
            return True
    return False


def stopped_flow_rows(rows: list[dict]) -> list[dict]:
    by_flow: dict[str, list[dict]] = {}
    for row in rows:
        flow_id = row.get("flowId")
        if flow_id:
            by_flow.setdefault(str(flow_id), []).append(row)
    stopped = []
    for flow_id, flow_rows in sorted(by_flow.items()):
        row = stopped_flow_row(flow_id, flow_rows)
        if row:
            stopped.append(row)
    return stopped


def stopped_flow_row(flow_id: str, rows: list[dict]) -> dict:
    ordered = sorted(rows, key=attempt_sort_key)
    stopped = [
        row
        for row in ordered
        if row.get("status") == "failed" and row.get("retryAllowed") is False
    ]
    if not stopped:
        return {}
    last = stopped[-1]
    failed = [row for row in ordered if row.get("status") == "failed"]
    retryable = [row for row in failed if row.get("retryAllowed") is True]
    failed_selected = compact(row.get("boundSelected") for row in failed)
    return {
        "flowId": flow_id,
        "dialer": last.get("dialer"),
        "attemptCount": len(ordered),
        "failedAttemptCount": len(failed),
        "retryableFailureCount": len(retryable),
        "candidateCount": int_or_none(last.get("candidateCount")),
        "candidateExhausted": candidate_exhausted(last, failed_selected),
        "stopReason": last.get("retryStopReason") or "unknown",
        "failureScope": last.get("failureScope") or "unknown",
        "errorDisposition": last.get("errorDisposition") or "unknown",
        "failureStage": last.get("failureStage") or "unknown",
        "failureStageOutbound": last.get("failureStageOutbound") or "unknown",
        "failureStageKind": last.get("failureStageKind") or "unknown",
        "failureStageDisposition": last.get("failureStageDisposition") or "unknown",
        "failureStageSurface": stage_surface(last),
        "pendingWaitClass": last.get("pendingWaitClass") or "unknown",
        "failureStagePendingWaitClass": last.get("failureStagePendingWaitClass") or "unknown",
        "boundSelectedSequence": compact(row.get("boundSelected") for row in ordered),
        "failedSelectedSequence": failed_selected,
        "retryableSelectedSequence": compact(row.get("boundSelected") for row in retryable),
        "lastBoundSelected": last.get("boundSelected"),
    }


def attempt_sort_key(row: dict) -> tuple[int, int]:
    return (int(row.get("attempt") or 0), int(row.get("sequence") or 0))


def candidate_exhausted(last: dict, failed_selected: list[str]) -> bool:
    if last.get("retryStopReason") == "bound-candidates-exhausted":
        return True
    candidate_count = int_or_none(last.get("candidateCount")) or 0
    return (
        last.get("failureScope") == "bound"
        and candidate_count > 0
        and len(set(failed_selected)) >= candidate_count
    )


def stage_surface(row: dict) -> str:
    stage = row.get("failureStage") or "unknown"
    error_type = (
        row.get("failureStageErrorType")
        or row.get("errorType")
        or row.get("failureStageKind")
        or "unknown"
    )
    return f"{stage}:{error_type}"


def compact(values) -> list[str]:
    return [str(value) for value in values if value]


def mark_selection_roles(rows: list[dict]) -> list[dict]:
    seen_flows = set()
    marked = []
    for row in rows:
        flow_id = row.get("flowId")
        role = "fallback" if flow_id in seen_flows else "primary"
        if flow_id:
            seen_flows.add(flow_id)
        marked.append({**row, "selectionRole": role})
    return marked


def selected_count(rows: list[dict]) -> int:
    return sum(1 for row in rows if row.get("selected"))


def selected_quality_count(rows: list[dict]) -> int:
    return sum(1 for row in rows if row.get("selectedHasQuality"))


def selected_best_count(rows: list[dict]) -> int:
    return sum(1 for row in rows if row.get("selectedBest"))


def selected_behind_count(rows: list[dict]) -> int:
    return sum(1 for row in rows if row.get("selectedBehind"))


def bound_candidate_row(event: dict) -> dict:
    event_fields = fields(event)
    selected = event_fields.get("selected")
    candidates = candidate_rows(event_fields.get("candidatesJson"), selected)
    selected_row = selected_candidate(candidates)
    best_row = best_candidate(candidates)
    selected_score = candidate_score(selected_row)
    best_score = candidate_score(best_row)
    return {
        "session": event_fields.get("session"),
        "flowId": event_fields.get("flowId"),
        "plan": event_fields.get("plan"),
        "selected": selected,
        "candidateCount": candidate_count(event_fields, candidates),
        "selectedScore": selected_score,
        "bestScore": best_score,
        "selectedBest": selected_score is not None and selected_score == best_score,
        "selectedBehind": (
            selected_score is not None and best_score is not None and selected_score < best_score
        ),
        "selectedHasQuality": candidate_has_quality(selected_row),
        "selectedReason": candidate_reason(selected_row),
    }


def candidate_rows(raw: str | None, selected: str | None) -> list[dict]:
    if raw is None:
        return []
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if not isinstance(value, list):
        return []
    rows = []
    for candidate in value:
        if isinstance(candidate, dict):
            row = dict(candidate)
            row["selected"] = row.get("to") == selected
            rows.append(row)
    return rows


def selected_candidate(candidates: list[dict]) -> dict:
    for candidate in candidates:
        if candidate.get("selected"):
            return candidate
    return {}


def best_candidate(candidates: list[dict]) -> dict:
    scored = [candidate for candidate in candidates if candidate_score(candidate) is not None]
    if not scored:
        return {}
    return max(scored, key=lambda item: (candidate_score(item) or 0, bool(item.get("selected"))))


def candidate_count(event_fields: dict[str, str], candidates: list[dict]) -> int:
    value = event_fields.get("candidateCount")
    if value is not None:
        try:
            return int(value)
        except ValueError:
            pass
    return len(candidates)


def int_or_none(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def bool_or_none(value: str | None) -> bool | None:
    if value == "true":
        return True
    if value == "false":
        return False
    return None


def candidate_score(candidate: dict) -> int | None:
    quality = candidate.get("quality")
    if not isinstance(quality, dict):
        return None
    score = quality.get("score")
    return score if isinstance(score, int) else None


def candidate_has_quality(candidate: dict) -> bool:
    quality = candidate.get("quality")
    if not isinstance(quality, dict):
        return False
    matches = quality.get("matches")
    return isinstance(matches, list) and bool(matches)


def candidate_reason(candidate: dict) -> str | None:
    quality = candidate.get("quality")
    if not isinstance(quality, dict):
        return None
    reason = quality.get("reason")
    return reason if isinstance(reason, str) else None


def aggregate_rows(rows: list[dict], field: str) -> list[dict]:
    counter = Counter(str(row.get(field) or "unknown") for row in rows)
    return [{"key": key, "count": count} for key, count in sorted(counter.items())]


def aggregate_stage_surface(rows: list[dict]) -> list[dict]:
    counter: Counter[str] = Counter()
    for row in rows:
        stage = row.get("failureStage")
        kind = row.get("failureStageKind")
        if stage and kind:
            counter[f"{stage}:{kind}"] += 1
    return [{"key": key, "count": count} for key, count in sorted(counter.items())]
