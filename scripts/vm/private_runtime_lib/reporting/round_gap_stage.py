from __future__ import annotations

import json
from pathlib import Path
from typing import Any


SLOW_STAGE_MS = 5000


def load_runtime_events(run_dir: Path, summary: dict[str, Any]) -> list[dict[str, Any]]:
    runtime_report = summary.get("runtimeReport")
    if isinstance(runtime_report, dict):
        events = runtime_report.get("events")
        return events if isinstance(events, list) else []
    if not run_dir.is_dir():
        return []
    path = run_dir / "runtime-report.json"
    if not path.exists():
        return []
    with path.open() as fh:
        data = json.load(fh)
    events = data.get("events")
    return events if isinstance(events, list) else []


def slow_stage_rows(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for event in events:
        if not isinstance(event, dict) or event.get("kind") != "outbound-stage-finished":
            continue
        event_fields = event.get("fields")
        if not isinstance(event_fields, dict):
            continue
        elapsed_ms = int_value(event_fields.get("elapsedMs"))
        if elapsed_ms < SLOW_STAGE_MS:
            continue
        rows.append(slow_stage_row(event_fields, elapsed_ms))
    return rows


def stage_blocking_summary(run_dir: Path, summary: dict[str, Any]) -> dict[str, Any]:
    rows = slow_stage_rows(load_runtime_events(run_dir, summary))
    pending_rows = [row for row in rows if row.get("pendingRetriesObserved")]
    return {
        "slowStageThresholdMs": SLOW_STAGE_MS,
        "slowStageEvents": len(rows),
        "slowFailedStageEvents": sum(1 for row in rows if row.get("status") == "failed"),
        "slowStageMaxMs": max((int(row.get("elapsedMs") or 0) for row in rows), default=0),
        "slowStageElapsedMs": sum(int(row.get("elapsedMs") or 0) for row in rows),
        "slowStageBySurface": aggregate_lists([aggregate_strings(row.get("surface") for row in rows)]),
        "pendingRetryEvents": len(pending_rows),
        "pendingRetries": sum(int(row.get("pendingRetries") or 0) for row in rows),
        "pendingRetriesMax": max((int(row.get("pendingRetries") or 0) for row in rows), default=0),
        "pendingElapsedMs": sum(int(row.get("pendingElapsedMs") or 0) for row in rows),
        "pendingElapsedMaxMs": max(
            (int(row.get("pendingElapsedMs") or 0) for row in rows),
            default=0,
        ),
        "pendingBudgetMs": max((int(row.get("pendingBudgetMs") or 0) for row in rows), default=0),
        "pendingSleepMs": max((int(row.get("pendingSleepMs") or 0) for row in rows), default=0),
        "pendingWaitClasses": aggregate_strings(
            row.get("pendingWaitClass") for row in rows if row.get("pendingWaitClass")
        ),
    }


def stage_blocking_totals(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "slowStageEvents": sum(int(row["stageBlocking"].get("slowStageEvents") or 0) for row in rows),
        "slowFailedStageEvents": sum(
            int(row["stageBlocking"].get("slowFailedStageEvents") or 0) for row in rows
        ),
        "slowStageMaxMs": max(
            (int(row["stageBlocking"].get("slowStageMaxMs") or 0) for row in rows),
            default=0,
        ),
        "slowStageElapsedMs": sum(
            int(row["stageBlocking"].get("slowStageElapsedMs") or 0) for row in rows
        ),
        "slowStageBySurface": aggregate_lists(
            row["stageBlocking"]["slowStageBySurface"] for row in rows
        ),
        "pendingRetryEvents": sum(
            int(row["stageBlocking"].get("pendingRetryEvents") or 0) for row in rows
        ),
        "pendingRetries": sum(
            int(row["stageBlocking"].get("pendingRetries") or 0) for row in rows
        ),
        "pendingRetriesMax": max(
            (int(row["stageBlocking"].get("pendingRetriesMax") or 0) for row in rows),
            default=0,
        ),
        "pendingElapsedMs": sum(
            int(row["stageBlocking"].get("pendingElapsedMs") or 0) for row in rows
        ),
        "pendingElapsedMaxMs": max(
            (int(row["stageBlocking"].get("pendingElapsedMaxMs") or 0) for row in rows),
            default=0,
        ),
        "pendingBudgetMs": max(
            (int(row["stageBlocking"].get("pendingBudgetMs") or 0) for row in rows),
            default=0,
        ),
        "pendingSleepMs": max(
            (int(row["stageBlocking"].get("pendingSleepMs") or 0) for row in rows),
            default=0,
        ),
        "pendingWaitClasses": aggregate_lists(
            row["stageBlocking"]["pendingWaitClasses"] for row in rows
        ),
    }


def slow_stage_row(
    fields: dict[str, Any],
    elapsed_ms: int,
) -> dict[str, Any]:
    return {
        "status": fields.get("status"),
        "elapsedMs": elapsed_ms,
        "surface": stage_surface(fields),
        "pendingRetriesObserved": "pendingRetries" in fields,
        "pendingRetries": int_value(fields.get("pendingRetries")),
        "pendingElapsedMs": int_value(fields.get("pendingElapsedMs")),
        "pendingBudgetMs": int_value(fields.get("pendingBudgetMs")),
        "pendingSleepMs": int_value(fields.get("pendingSleepMs")),
        "pendingWaitClass": fields.get("pendingWaitClass"),
    }


def stage_surface(row: dict[str, Any]) -> str:
    stage = str(row.get("stage") or "unknown")
    status = str(row.get("status") or "unknown")
    error_type = str(row.get("errorType") or "none")
    return f"{stage}:{status}:{error_type}"


def int_value(value: Any) -> int:
    if value is None:
        return 0
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


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
