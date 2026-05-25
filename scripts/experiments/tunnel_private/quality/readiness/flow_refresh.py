"""Supplemental flow-refresh evidence for adapter maturity."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def source_summary(path: Path) -> dict[str, Any]:
    summary = load_json(path)
    runs = [run for run in summary.get("runs", []) if isinstance(run, dict)]
    totals = summary.get("totals") or {}
    return {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "changedRuns": int(totals.get("changedRuns") or 0),
        "classifications": classifications(summary, runs),
        "recoveredStageSeparatedRuns": int(
            totals.get("recoveredStageSeparatedRuns") or 0
        ),
        "tcpFlowStageFailed": sum_current_value(
            runs,
            "tcpFlow",
            "stageFailedFlows",
        ),
        "workloadFlowMatchedRecoveredFailureEntries": sum_current_value(
            runs,
            "workloadFlow",
            "matchedRecoveredFailureEntries",
        ),
        "workloadFlowMatchedFlowStageFailedAttempts": sum_current_value(
            runs,
            "workloadFlow",
            "matchedFlowStageFailedAttempts",
        ),
    }


def merge_runtime_summary(
    runtime: dict[str, Any],
    sources: list[dict[str, Any]],
) -> dict[str, Any]:
    summary = evidence_summary(sources)
    merged = dict(runtime)
    merged["flowRefreshSourceCount"] = summary["sourceCount"]
    merged["flowRefreshChangedRuns"] = summary["changedRuns"]
    merged["flowRefreshClassifications"] = summary["classifications"]
    merged["flowRefreshRecoveredStageSeparatedRuns"] = (
        summary["recoveredStageSeparatedRuns"]
    )
    merged["tcpFlowStageFailed"] = (
        int(merged["tcpFlowStageFailed"]) + summary["tcpFlowStageFailed"]
    )
    merged["workloadFlowMatchedRecoveredFailureEntries"] = (
        int(merged["workloadFlowMatchedRecoveredFailureEntries"])
        + summary["workloadFlowMatchedRecoveredFailureEntries"]
    )
    merged["workloadFlowMatchedFlowStageFailedAttempts"] = (
        int(merged["workloadFlowMatchedFlowStageFailedAttempts"])
        + summary["workloadFlowMatchedFlowStageFailedAttempts"]
    )
    return merged


def evidence_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "changedRuns": sum(int(source["changedRuns"]) for source in sources),
        "classifications": count_rows(merge_count_rows([
            source["classifications"] for source in sources
        ])),
        "recoveredStageSeparatedRuns": sum(
            int(source["recoveredStageSeparatedRuns"]) for source in sources
        ),
        "tcpFlowStageFailed": sum(
            int(source["tcpFlowStageFailed"]) for source in sources
        ),
        "workloadFlowMatchedRecoveredFailureEntries": sum(
            int(source["workloadFlowMatchedRecoveredFailureEntries"])
            for source in sources
        ),
        "workloadFlowMatchedFlowStageFailedAttempts": sum(
            int(source["workloadFlowMatchedFlowStageFailedAttempts"])
            for source in sources
        ),
    }


def classifications(
    summary: dict[str, Any],
    runs: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    rows = (summary.get("totals") or {}).get("classifications")
    if isinstance(rows, list):
        return [row for row in rows if isinstance(row, dict)]
    counts: dict[str, int] = {}
    for run in runs:
        classification = str(run.get("classification") or "")
        if classification:
            counts[classification] = counts.get(classification, 0) + 1
    return count_rows(counts)


def sum_current_value(
    runs: list[dict[str, Any]],
    section: str,
    field: str,
) -> int:
    total = 0
    for run in runs:
        current = run.get("current")
        if not isinstance(current, dict):
            continue
        values = current.get(section)
        if isinstance(values, dict):
            total += int(values.get(field) or 0)
    return total


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
