"""Runtime evidence readers for adapter readiness."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def source_summary(path: Path) -> dict[str, Any]:
    summary = load_json(path)
    totals = summary.get("totals") or {}
    runs = summary.get("runs") or []
    tcp_closed = sum(int(run.get("tcpClosedSessions") or 0) for run in runs)
    tcp_upstream = sum(int(run.get("tcpUpstreamBytes") or 0) for run in runs)
    tcp_downstream = sum(int(run.get("tcpDownstreamBytes") or 0) for run in runs)
    quality_sets = int(totals.get("qualityBoundCandidateSets") or 0)
    selected_with_quality = int(totals.get("qualityBoundSelectedWithQuality") or 0)
    selected_behind = int(totals.get("qualityBoundSelectedBehind") or 0)
    failed_runs = int(totals.get("failedRuns") or 0)
    workload_failed = int(totals.get("workloadFailedRuns") or 0)
    workload_failure = int(totals.get("workloadFailure") or 0)
    workload_attempted = int(totals.get("workloadAttempted") or 0)
    workload_success = int(totals.get("workloadSuccess") or 0)
    workload_flow_entries = int(totals.get("workloadFlowEntries") or 0)
    workload_flow_matched = int(totals.get("workloadFlowMatchedEntries") or 0)
    workload_flow_covered = int(totals.get("workloadFlowCoveredEntries") or 0)
    workload_failed_by_surface = count_rows_from(totals.get("workloadFailedBySurface"))
    workload_failed_by_stage = count_rows_from(totals.get("workloadFailedByStage"))
    workload_errors = count_rows_from(totals.get("workloadErrors"))
    workload_unmatched_surfaces = count_rows_from(
        totals.get("workloadFlowUnmatchedFailureSurfaces")
    )
    route_graph = int(totals.get("tcpFlowRouteGraphSelected") or 0)
    path_complete = int(totals.get("tcpFlowPathComplete") or 0)
    payload_bidirectional = int(totals.get("tcpFlowPayloadBidirectional") or 0)
    tcp_flow_failed = int(totals.get("tcpFlowFailed") or 0)
    tcp_flow_stage_failed = int(totals.get("tcpFlowStageFailed") or 0)
    workload_recovered = int(totals.get("workloadFlowMatchedRecoveredFailureEntries") or 0)
    workload_stage_failed = int(totals.get("workloadFlowMatchedFlowStageFailedAttempts") or 0)
    tcp_failures = sum(int(run.get("tcpSessionFailures") or 0) for run in runs)
    slot_pressure = int(totals.get("tcpSlotPressureEvents") or 0)
    fallback_sets = sum_bound(runs, "fallbackCandidateSets")
    fallback_selected_behind = sum_bound(runs, "fallbackSelectedBehind")
    fallback_selected_with_quality = sum_bound(runs, "fallbackSelectedWithQuality")
    source = {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "runs": int(totals.get("runs") or len(runs)),
        "passedRuns": int(totals.get("passedRuns") or 0),
        "failedRuns": failed_runs,
        "workloadFailedRuns": workload_failed,
        "workloadAttempted": workload_attempted,
        "workloadSuccess": workload_success,
        "workloadFailure": workload_failure,
        "workloadFlowEntries": workload_flow_entries,
        "workloadFlowMatchedEntries": workload_flow_matched,
        "workloadFlowCoveredEntries": workload_flow_covered,
        "workloadFailedBySurface": workload_failed_by_surface,
        "workloadFailedByStage": workload_failed_by_stage,
        "workloadErrors": workload_errors,
        "workloadFlowUnmatchedFailureSurfaces": workload_unmatched_surfaces,
        "qualityBoundCandidateSets": quality_sets,
        "qualityBoundSelectedWithQuality": selected_with_quality,
        "qualityBoundSelectedBehind": selected_behind,
        "qualityBoundFallbackCandidateSets": fallback_sets,
        "qualityBoundFallbackSelectedWithQuality": fallback_selected_with_quality,
        "qualityBoundFallbackSelectedBehind": fallback_selected_behind,
        "tcpFlowRouteGraphSelected": route_graph,
        "tcpFlowPathComplete": path_complete,
        "tcpFlowPayloadBidirectional": payload_bidirectional,
        "tcpFlowFailed": tcp_flow_failed,
        "tcpFlowStageFailed": tcp_flow_stage_failed,
        "workloadFlowMatchedRecoveredFailureEntries": workload_recovered,
        "workloadFlowMatchedFlowStageFailedAttempts": workload_stage_failed,
        "tcpClosedSessions": tcp_closed,
        "tcpSessionFailures": tcp_failures,
        "tcpSlotPressureEvents": slot_pressure,
        "tcpUpstreamBytes": tcp_upstream,
        "tcpDownstreamBytes": tcp_downstream,
    }
    source["clean"] = source_clean(source)
    return source


def source_clean(source: dict[str, Any]) -> bool:
    return clean_runtime(
        failed_runs=int(source["failedRuns"]),
        workload_failed=int(source["workloadFailedRuns"]),
        workload_failure=int(source["workloadFailure"]),
        selected_behind=int(source["qualityBoundSelectedBehind"]),
        quality_sets=int(source["qualityBoundCandidateSets"]),
        selected_with_quality=int(source["qualityBoundSelectedWithQuality"]),
        tcp_closed=int(source["tcpClosedSessions"]),
        tcp_failures=int(source["tcpSessionFailures"]),
        slot_pressure=int(source["tcpSlotPressureEvents"]),
        tcp_flow_failed=int(source["tcpFlowFailed"]),
        route_graph=int(source["tcpFlowRouteGraphSelected"]),
        path_complete=int(source["tcpFlowPathComplete"]),
        payload_bidirectional=int(source["tcpFlowPayloadBidirectional"]),
        workload_attempted=int(source["workloadAttempted"]),
        workload_success=int(source["workloadSuccess"]),
        workload_flow_entries=int(source["workloadFlowEntries"]),
        workload_flow_matched=int(source["workloadFlowMatchedEntries"]),
        workload_flow_covered=int(source["workloadFlowCoveredEntries"]),
    )


def clean_runtime(
    *,
    failed_runs: int,
    workload_failed: int,
    workload_failure: int,
    selected_behind: int,
    quality_sets: int,
    selected_with_quality: int,
    tcp_closed: int,
    tcp_failures: int,
    slot_pressure: int,
    tcp_flow_failed: int,
    route_graph: int,
    path_complete: int,
    payload_bidirectional: int,
    workload_attempted: int,
    workload_success: int,
    workload_flow_entries: int,
    workload_flow_matched: int,
    workload_flow_covered: int,
) -> bool:
    workload_clean = runtime_workload_clean(
        workload_attempted,
        workload_success,
        workload_flow_entries,
        workload_flow_matched,
        workload_flow_covered,
    )
    pressure_clean = slot_pressure == 0 or (
        workload_attempted > 0
        and workload_clean
        and tcp_flow_failed == 0
        and path_complete >= quality_sets
        and payload_bidirectional >= quality_sets
    )
    return (
        failed_runs == 0
        and workload_failed == 0
        and workload_failure == 0
        and selected_behind == 0
        and quality_sets > 0
        and selected_with_quality == quality_sets
        and tcp_closed > 0
        and tcp_failures == 0
        and pressure_clean
        and tcp_flow_failed == 0
        and route_graph >= quality_sets
        and path_complete >= quality_sets
        and payload_bidirectional >= quality_sets
        and workload_clean
    )


def runtime_workload_clean(
    attempted: int,
    success: int,
    entries: int,
    matched: int,
    covered: int,
) -> bool:
    return attempted == 0 or (
        success == attempted
        and matched == entries
        and covered == entries
    )


def evidence_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "runs": sum(int(source["runs"]) for source in sources),
        "passedRuns": sum(int(source["passedRuns"]) for source in sources),
        "failedRuns": sum(int(source["failedRuns"]) for source in sources),
        "workloadFailedRuns": sum(int(source["workloadFailedRuns"]) for source in sources),
        "workloadAttempted": sum(int(source["workloadAttempted"]) for source in sources),
        "workloadSuccess": sum(int(source["workloadSuccess"]) for source in sources),
        "workloadFailure": sum(int(source["workloadFailure"]) for source in sources),
        "workloadFlowEntries": sum(int(source["workloadFlowEntries"]) for source in sources),
        "workloadFlowMatchedEntries": sum(int(source["workloadFlowMatchedEntries"]) for source in sources),
        "workloadFlowCoveredEntries": sum(int(source["workloadFlowCoveredEntries"]) for source in sources),
        "workloadFailedBySurface": count_rows(merge_count_rows([
            source["workloadFailedBySurface"] for source in sources
        ])),
        "workloadFailedByStage": count_rows(merge_count_rows([
            source["workloadFailedByStage"] for source in sources
        ])),
        "workloadErrors": count_rows(merge_count_rows([
            source["workloadErrors"] for source in sources
        ])),
        "workloadFlowUnmatchedFailureSurfaces": count_rows(merge_count_rows([
            source["workloadFlowUnmatchedFailureSurfaces"] for source in sources
        ])),
        "qualityBoundCandidateSets": sum(int(source["qualityBoundCandidateSets"]) for source in sources),
        "qualityBoundSelectedWithQuality": sum(int(source["qualityBoundSelectedWithQuality"]) for source in sources),
        "qualityBoundSelectedBehind": sum(int(source["qualityBoundSelectedBehind"]) for source in sources),
        "qualityBoundFallbackCandidateSets": sum(int(source["qualityBoundFallbackCandidateSets"]) for source in sources),
        "qualityBoundFallbackSelectedWithQuality": sum(int(source["qualityBoundFallbackSelectedWithQuality"]) for source in sources),
        "qualityBoundFallbackSelectedBehind": sum(int(source["qualityBoundFallbackSelectedBehind"]) for source in sources),
        "tcpFlowRouteGraphSelected": sum(int(source["tcpFlowRouteGraphSelected"]) for source in sources),
        "tcpFlowPathComplete": sum(int(source["tcpFlowPathComplete"]) for source in sources),
        "tcpFlowPayloadBidirectional": sum(int(source["tcpFlowPayloadBidirectional"]) for source in sources),
        "tcpFlowFailed": sum(int(source["tcpFlowFailed"]) for source in sources),
        "tcpFlowStageFailed": sum(int(source["tcpFlowStageFailed"]) for source in sources),
        "workloadFlowMatchedRecoveredFailureEntries": sum(
            int(source["workloadFlowMatchedRecoveredFailureEntries"]) for source in sources
        ),
        "workloadFlowMatchedFlowStageFailedAttempts": sum(
            int(source["workloadFlowMatchedFlowStageFailedAttempts"]) for source in sources
        ),
        "tcpClosedSessions": sum(int(source["tcpClosedSessions"]) for source in sources),
        "tcpSessionFailures": sum(int(source["tcpSessionFailures"]) for source in sources),
        "tcpSlotPressureEvents": sum(int(source["tcpSlotPressureEvents"]) for source in sources),
        "tcpUpstreamBytes": sum(int(source["tcpUpstreamBytes"]) for source in sources),
        "tcpDownstreamBytes": sum(int(source["tcpDownstreamBytes"]) for source in sources),
        "clean": bool(sources) and all(bool(source["clean"]) for source in sources),
    }


def sum_bound(runs: list[Any], field: str) -> int:
    total = 0
    for run in runs:
        if not isinstance(run, dict):
            continue
        bound = run.get("boundSelection")
        if isinstance(bound, dict):
            total += int(bound.get(field) or 0)
    return total


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
