from __future__ import annotations

from typing import Any


SLOW_STAGE_MS = 5000


def stage_rows(run: dict[str, Any]) -> list[dict[str, Any]]:
    events = [event for event in run["events"] if isinstance(event, dict)]
    success_sequences = {}
    for event in events:
        flow_id = field(event, "flowId")
        if event.get("kind") == "dialer-cascade-attempt-finished" and field(event, "status") == "success":
            success_sequences.setdefault(flow_id, []).append(event_sequence(event))
    return [
        stage_row(run, event, success_sequences)
        for event in events
        if event.get("kind") == "dialer-cascade-attempt-finished"
        and field(event, "status") == "failed"
    ]


def stage_row(
    run: dict[str, Any],
    event: dict[str, Any],
    success_sequences: dict[str, list[int]],
) -> dict[str, Any]:
    flow_id = field(event, "flowId")
    sequence = event_sequence(event)
    return {
        "source": run["source"],
        "run": run["label"],
        "flowId": flow_id,
        "attempt": int_value(field(event, "attempt")),
        "candidate": field(event, "boundSelected") or "unknown",
        "candidateCount": int_value(field(event, "candidateCount")),
        "target": field(event, "target") or "unknown",
        "stage": field(event, "failureStage") or "unknown",
        "scope": field(event, "failureScope") or "unknown",
        "disposition": field(event, "failureStageDisposition")
        or field(event, "errorDisposition")
        or "unknown",
        "errorType": field(event, "errorType") or "unknown",
        "stopReason": field(event, "retryStopReason") or "none",
        "retryAllowed": bool_field(event, "retryAllowed"),
        "sequence": sequence,
        "recovered": recovered_after(sequence, success_sequences.get(flow_id, [])),
    }


def slot_rows(run: dict[str, Any]) -> list[dict[str, Any]]:
    counts: dict[tuple[str, int, int], int] = {}
    for event in run["events"]:
        if not isinstance(event, dict) or event.get("kind") != "tcp-forwarder-pressure":
            continue
        key = (
            field(event, "pressurePorts") or "unknown",
            int_value(field(event, "activeSlots")),
            int_value(field(event, "capacity")),
        )
        counts[key] = counts.get(key, 0) + 1
    return [
        {
            "run": run["label"],
            "ports": ports,
            "activeSlots": active,
            "capacity": capacity,
            "events": count,
        }
        for (ports, active, capacity), count in sorted(counts.items())
    ]


def slow_stage_rows(run: dict[str, Any]) -> list[dict[str, Any]]:
    rows: dict[tuple[str, str, int], int] = {}
    for event in run["events"]:
        if not isinstance(event, dict) or event.get("kind") != "outbound-stage-finished":
            continue
        elapsed_ms = int_value(field(event, "elapsedMs"))
        if elapsed_ms < SLOW_STAGE_MS:
            continue
        surface = ":".join([
            field(event, "stage") or "unknown",
            field(event, "status") or "unknown",
            field(event, "errorType") or "none",
        ])
        key = (run["label"], surface, elapsed_ms)
        rows[key] = rows.get(key, 0) + 1
    return [
        {
            "run": run,
            "surface": surface,
            "elapsedMs": elapsed_ms,
            "events": events,
        }
        for (run, surface, elapsed_ms), events in sorted(rows.items())
    ]


def field(event: dict[str, Any], key: str) -> str:
    fields = event.get("fields")
    if not isinstance(fields, dict):
        return ""
    return str(fields.get(key) or "")


def bool_field(event: dict[str, Any], key: str) -> bool:
    value = field(event, key).lower()
    return value in {"true", "1", "yes"}


def event_sequence(event: dict[str, Any]) -> int:
    return int_value(event.get("sequence"))


def recovered_after(failure_sequence: int, success_sequences: list[int]) -> bool:
    if not success_sequences:
        return False
    if failure_sequence == 0:
        return True
    return any(sequence == 0 or sequence > failure_sequence for sequence in success_sequences)


def int_value(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0
