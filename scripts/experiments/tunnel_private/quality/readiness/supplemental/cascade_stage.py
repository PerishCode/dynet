"""Supplemental cascade-stage evidence for adapter maturity."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def source_summary(path: Path) -> dict[str, Any]:
    summary = load_json(path)
    totals = summary.get("totals") or {}
    cascade = cascade_from_summary(summary)
    failed_by_stop = count_rows_from(
        totals.get("cascadeFailedByStopReason") or cascade.get("failedByStopReason")
    )
    return {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "failedAttempts": int(
            totals.get("cascadeFailedAttempts") or cascade.get("failedAttempts") or 0
        ),
        "retryableFailures": int(
            totals.get("cascadeRetryableFailures")
            or cascade.get("retryableFailures")
            or 0
        ),
        "stoppedFailures": int(
            totals.get("cascadeStoppedFailures") or cascade.get("stoppedFailures") or 0
        ),
        "recoveredFlows": int(
            totals.get("cascadeRecoveredFlows") or cascade.get("recoveredFlows") or 0
        ),
        "failedByScope": count_rows_from(
            totals.get("cascadeFailedByScope") or cascade.get("failedByScope")
        ),
        "failedByStageSurface": count_rows_from(
            totals.get("cascadeFailedByStageSurface")
            or cascade.get("failedByStageSurface")
        ),
        "failedByStageDisposition": count_rows_from(
            totals.get("cascadeFailedByStageDisposition")
            or cascade.get("failedByStageDisposition")
        ),
        "failedByStopReason": failed_by_stop,
        "nonBoundStopObserved": non_bound_stop_observed(cascade, failed_by_stop),
    }


def cascade_from_summary(summary: dict[str, Any]) -> dict[str, Any]:
    conclusion_cascade = (summary.get("conclusion") or {}).get("cascade") or {}
    if isinstance(conclusion_cascade, dict) and conclusion_cascade:
        return conclusion_cascade
    selection_cascade = (summary.get("selection") or {}).get("cascadeAttempts") or {}
    if isinstance(selection_cascade, dict):
        return selection_cascade
    return {}


def merge_runtime_summary(
    runtime: dict[str, Any],
    sources: list[dict[str, Any]],
) -> dict[str, Any]:
    summary = evidence_summary(sources)
    merged = dict(runtime)
    merged["cascadeStageSourceCount"] = summary["sourceCount"]
    merged["cascadeStageFailedAttempts"] = summary["failedAttempts"]
    merged["cascadeStageRetryableFailures"] = summary["retryableFailures"]
    merged["cascadeStageStoppedFailures"] = summary["stoppedFailures"]
    merged["cascadeStageRecoveredFlows"] = summary["recoveredFlows"]
    merged["cascadeStageNonBoundStopObserved"] = summary["nonBoundStopObserved"]
    merged["cascadeStageFailedByScope"] = summary["failedByScope"]
    merged["cascadeStageFailedByStageSurface"] = summary["failedByStageSurface"]
    merged["cascadeStageFailedByStageDisposition"] = (
        summary["failedByStageDisposition"]
    )
    merged["cascadeStageFailedByStopReason"] = summary["failedByStopReason"]
    return merged


def evidence_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "failedAttempts": sum(int(source["failedAttempts"]) for source in sources),
        "retryableFailures": sum(
            int(source["retryableFailures"]) for source in sources
        ),
        "stoppedFailures": sum(int(source["stoppedFailures"]) for source in sources),
        "recoveredFlows": sum(int(source["recoveredFlows"]) for source in sources),
        "failedByScope": count_rows(merge_count_rows([
            source["failedByScope"] for source in sources
        ])),
        "failedByStageSurface": count_rows(merge_count_rows([
            source["failedByStageSurface"] for source in sources
        ])),
        "failedByStageDisposition": count_rows(merge_count_rows([
            source["failedByStageDisposition"] for source in sources
        ])),
        "failedByStopReason": count_rows(merge_count_rows([
            source["failedByStopReason"] for source in sources
        ])),
        "nonBoundStopObserved": any(
            bool(source["nonBoundStopObserved"]) for source in sources
        ),
    }


def non_bound_stop_observed(
    cascade: dict[str, Any],
    failed_by_stop: list[dict[str, Any]],
) -> bool:
    if str(cascade.get("status") or "") == "non-bound-stop-observed":
        return True
    return any(
        row.get("key") == "non-bound-failure" and int(row.get("count") or 0) > 0
        for row in failed_by_stop
    )


def count_rows_from(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, list):
        return [
            {"key": str(row.get("key")), "count": int(row.get("count") or 0)}
            for row in raw
            if isinstance(row, dict) and row.get("key")
        ]
    if isinstance(raw, dict):
        return count_rows({
            str(key): int(value or 0)
            for key, value in raw.items()
            if key and int(value or 0) > 0
        })
    return []


def merge_count_rows(count_sets: list[list[dict[str, Any]]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for count_set in count_sets:
        for row in count_set:
            key = str(row.get("key") or "")
            if key:
                counts[key] = counts.get(key, 0) + int(row.get("count") or 0)
    return dict(sorted(counts.items()))


def count_rows(counts: dict[str, int]) -> list[dict[str, Any]]:
    return [{"key": key, "count": count} for key, count in sorted(counts.items())]


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text())
