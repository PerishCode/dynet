from __future__ import annotations

import json
from collections import Counter
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
MAX_MISSING_CORRELATION_RATE = 0.25


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())

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

def int_value(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None

def json_list_field(value: str | None) -> list[dict[str, Any]]:
    if not value:
        return []
    try:
        data = json.loads(value)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, list):
        return []
    return [item for item in data if isinstance(item, dict)]

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


def event_list(events: list[dict[str, Any]], kind: str) -> list[dict[str, Any]]:
    return [event for event in events if event_kind(event) == kind]


def dialer_attempts(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    selected = cascade_selected_by_flow(events)
    starts = cascade_start_sequences(events)
    rows = []
    for event in event_list(events, "dialer-cascade-attempt-finished"):
        fields = event_fields(event)
        key = cascade_key(fields)
        bound = fields.get("boundSelected") or "<unknown>"
        scoped_stages = stage_evidence_between(
            events,
            starts.get(key, {}).get("sequence"),
            event.get("sequence"),
        )
        selection = selected.get((key[0], bound), {})
        rows.append({
            "attempt": int_field(fields, "attempt"),
            "flowId": fields.get("flowId"),
            "replaySafe": starts.get(key, {}).get("replaySafe"),
            "dialer": fields.get("dialer") or selection.get("dialer"),
            "bound": selection.get("bound"),
            "private": selection.get("private"),
            "boundSelected": bound,
            "status": fields.get("status"),
            "errorType": fields.get("errorType"),
            "failureScope": fields.get("failureScope")
            or dialer_failure_scope(fields, bound, scoped_stages),
        })
    return rows


def fallback_signals(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    attempts = dialer_attempts(events)
    by_flow: dict[str, list[dict[str, Any]]] = {}
    for attempt in attempts:
        flow_id = str(attempt.get("flowId") or "<unknown>")
        by_flow.setdefault(flow_id, []).append(attempt)
    signals = []
    for flow_id, rows in sorted(by_flow.items()):
        signals.extend(recovered_fallback_signals(flow_id, rows))
        signals.extend(non_retry_safe_signals(flow_id, rows))
    return signals


def recovered_fallback_signals(
    flow_id: str,
    rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    recoveries = []
    for index, row in enumerate(rows):
        if not pre_replay_bound_failure(row):
            continue
        recovered = next_success(rows[index + 1 :])
        if not recovered:
            continue
        recoveries.append(recovery_signal(flow_id, row, recovered))
    return recoveries


def next_success(rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    return next(
        (
            row
            for row in rows
            if row.get("status") == "success"
            and row.get("failureScope") == "none"
        ),
        None,
    )


def recovery_signal(
    flow_id: str,
    failed: dict[str, Any],
    recovered: dict[str, Any],
) -> dict[str, Any]:
    return {
        "type": "pre-replay-bound-failure-recovered",
        "action": "observe",
        "plannerAction": "observe",
        "flowId": flow_id,
        "replaySafe": failed.get("replaySafe"),
        "dialer": failed.get("dialer"),
        "failedBound": failed.get("boundSelected"),
        "recoveredBound": recovered.get("boundSelected"),
        "failureScope": failed.get("failureScope"),
        "errorType": failed.get("errorType"),
        "reason": "bound candidate failed before replay point and cascade recovered",
    }


def non_retry_safe_signals(
    flow_id: str,
    rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    signals = []
    for row in rows:
        if row.get("status") != "failed":
            continue
        if pre_replay_bound_failure(row):
            continue
        signals.append(non_retry_safe_signal(flow_id, row))
    return signals


def non_retry_safe_signal(flow_id: str, row: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "not-retry-safe-cascade-failure",
        "action": "observe",
        "plannerAction": "observe",
        "flowId": flow_id,
        "replaySafe": row.get("replaySafe") or "<unknown>",
        "dialer": row.get("dialer"),
        "boundSelected": row.get("boundSelected"),
        "failureScope": row.get("failureScope") or "unknown",
        "errorType": row.get("errorType"),
        "reason": "cascade failure is outside the pre-replay bound-failure recovery gate",
    }


def pre_replay_bound_failure(row: dict[str, Any]) -> bool:
    return (
        row.get("status") == "failed"
        and row.get("failureScope") == "bound"
        and row.get("replaySafe") in {"pre-query", "pre-payload"}
    )


def failure_scope(dialers: list[dict[str, Any]]) -> str | None:
    scopes = [str(item.get("failureScope")) for item in dialers if item.get("failureScope")]
    if "bound" in scopes:
        return "bound"
    if "downstream" in scopes:
        return "downstream"
    if "unknown" in scopes:
        return "unknown"
    return scopes[0] if scopes else None


def suspect_component(row: dict[str, Any]) -> str | None:
    if row.get("status") == "pass":
        return None
    if private_source_policy_signal(row):
        return "private-source-policy"
    classification = row.get("classification")
    if classification == "plan-suspect":
        return "planner"
    if classification == "dynet-infra-suspect":
        return "dynet-runtime"
    if classification == "target-or-probe-suspect":
        return "target-or-probe"
    if classification == "node-suspect":
        return "selected-outbound"
    return None


def private_source_policy_signal(row: dict[str, Any]) -> bool:
    return any(
        item.get("failureScope") == "downstream" and item.get("private")
        for item in row.get("dialerAttempts", [])
    )


def cascade_selected_by_bound(events: list[dict[str, Any]]) -> dict[str, dict[str, str]]:
    rows = {}
    for event in event_list(events, "dialer-cascade-selected"):
        fields = event_fields(event)
        bound = fields.get("boundSelected")
        if bound:
            rows[bound] = fields
    return rows


def cascade_selected_by_flow(events: list[dict[str, Any]]) -> dict[tuple[str | None, str], dict[str, str]]:
    rows = {}
    for event in event_list(events, "dialer-cascade-selected"):
        fields = event_fields(event)
        bound = fields.get("boundSelected")
        if bound:
            rows[(fields.get("flowId"), bound)] = fields
    return rows


def cascade_start_sequences(events: list[dict[str, Any]]) -> dict[tuple[str | None, str | None], dict[str, Any]]:
    rows = {}
    for event in event_list(events, "dialer-cascade-attempt-started"):
        fields = event_fields(event)
        rows[cascade_key(fields)] = {
            "sequence": event.get("sequence"),
            "replaySafe": fields.get("replaySafe"),
        }
    return rows


def cascade_key(fields: dict[str, str]) -> tuple[str | None, str | None]:
    return (fields.get("flowId"), fields.get("attempt"))


def stage_evidence_between(
    events: list[dict[str, Any]],
    start_sequence: int | None,
    end_sequence: int | None,
) -> list[dict[str, Any]]:
    rows = []
    for event in event_list(events, "outbound-stage-finished"):
        sequence = event.get("sequence")
        if start_sequence is not None and isinstance(sequence, int) and sequence < start_sequence:
            continue
        if end_sequence is not None and isinstance(sequence, int) and sequence > end_sequence:
            continue
        rows.append(stage_row(event))
    return rows


def stage_row(event: dict[str, Any]) -> dict[str, Any]:
    fields = event_fields(event)
    return {
        "stage": fields.get("stage"),
        "status": fields.get("status"),
        "outbound": fields.get("outbound"),
        "protocol": fields.get("protocol"),
        "elapsedMs": int_field(fields, "elapsedMs"),
        "errorType": fields.get("errorType"),
    }


def dialer_failure_scope(
    fields: dict[str, str],
    bound: str,
    stages: list[dict[str, Any]],
) -> str:
    if fields.get("status") == "success":
        return "none"
    failed = [item for item in stages if item.get("status") == "failed"]
    if any(item.get("outbound") == bound for item in failed):
        return "bound"
    if failed:
        return "downstream"
    return "unknown"
