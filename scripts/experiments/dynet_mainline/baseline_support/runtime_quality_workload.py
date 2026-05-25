from __future__ import annotations

from pathlib import Path
from typing import Any

from dynet_mainline.baseline_support.runtime_quality_plan import (
    adapter_types,
    candidate_control_clean,
    load_json,
    repeat_privacy_flags,
    run_summaries,
)


def runtime_quality_workload_source(path: Path) -> dict[str, Any]:
    summary = load_json(path)
    totals = summary.get("totals") or {}
    runs = run_summaries(path, summary)
    source = {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "label": str(summary.get("label") or ""),
        "runtimeDnsMode": str(summary.get("runtimeDnsMode") or ""),
        "tcpForward": bool(summary.get("tcpForward")),
        "qualityStateUsed": bool(summary.get("qualityStateUsed")),
        "runs": int(totals.get("runs") or (1 if runs else 0)),
        "passedRuns": int(totals.get("passedRuns") or 0),
        "failedRuns": int(totals.get("failedRuns") or 0),
        "runSummaryCount": len(runs),
        "candidateControlClean": candidate_control_clean(summary.get("candidateControl")),
        "adapterTypes": adapter_types(runs),
        "workloadAttempted": int(totals.get("workloadAttempted") or 0),
        "workloadSuccess": int(totals.get("workloadSuccess") or 0),
        "workloadFailure": int(totals.get("workloadFailure") or 0),
        "workloadStrictFailedRuns": int(totals.get("workloadStrictFailedRuns") or 0),
        "qualityBoundCandidateSets": int(totals.get("qualityBoundCandidateSets") or 0),
        "qualityBoundSelectedWithQuality": int(
            totals.get("qualityBoundSelectedWithQuality") or 0
        ),
        "qualityBoundSelectedBehind": int(totals.get("qualityBoundSelectedBehind") or 0),
        "tcpFlowRouteGraphSelected": int(totals.get("tcpFlowRouteGraphSelected") or 0),
        "tcpFlowRouteMatched": int(totals.get("tcpFlowRouteMatched") or 0),
        "tcpFlowRuleMatched": int(totals.get("tcpFlowRuleMatched") or 0),
        "tcpFlowPlanBypassed": int(totals.get("tcpFlowPlanBypassed") or 0),
        "tcpFlowFailed": int(totals.get("tcpFlowFailed") or 0),
        "tcpFlowFailedAfterPathComplete": int(
            totals.get("tcpFlowFailedAfterPathComplete") or 0
        ),
        "tcpFlowFailedAfterUpstreamOnly": int(
            totals.get("tcpFlowFailedAfterUpstreamOnly") or 0
        ),
        "workloadFlowEntries": int(totals.get("workloadFlowEntries") or 0),
        "workloadFlowTcpAttemptedEntries": int(
            totals.get("workloadFlowTcpAttemptedEntries") or 0
        ),
        "workloadFlowTcpAttemptedCoveredEntries": int(
            totals.get("workloadFlowTcpAttemptedCoveredEntries") or 0
        ),
        "workloadFlowMatchedEntries": int(totals.get("workloadFlowMatchedEntries") or 0),
        "workloadFlowCoveredEntries": int(totals.get("workloadFlowCoveredEntries") or 0),
        "workloadFlowRuntimePreflowMatchedEntries": int(
            totals.get("workloadFlowRuntimePreflowMatchedEntries") or 0
        ),
        "workloadFlowRuntimePacketHandshakeEntries": int(
            totals.get("workloadFlowRuntimePacketHandshakeEntries") or 0
        ),
        "workloadFlowTunCaptureMatchedEntries": int(
            totals.get("workloadFlowTunCaptureMatchedEntries") or 0
        ),
        "workloadFlowUnmatchedEntries": int(
            totals.get("workloadFlowUnmatchedEntries") or 0
        ),
        "workloadFlowRuntimePacketTerminalEntries": int(
            totals.get("workloadFlowRuntimePacketTerminalEntries") or 0
        ),
        "workloadFlowMatchedFailures": int(
            totals.get("workloadFlowMatchedFailures") or 0
        ),
        "workloadFlowUnmatchedFailures": int(
            totals.get("workloadFlowUnmatchedFailures") or 0
        ),
        "workloadFlowMatchedFlowFailedAttempts": int(
            totals.get("workloadFlowMatchedFlowFailedAttempts") or 0
        ),
        "workloadFlowMatchedFlowStageFailedAttempts": int(
            totals.get("workloadFlowMatchedFlowStageFailedAttempts") or 0
        ),
        "workloadFlowMatchedRecoveredFailureEntries": int(
            totals.get("workloadFlowMatchedRecoveredFailureEntries") or 0
        ),
        "privacy": repeat_privacy_flags(runs),
    }
    source["clean"] = runtime_quality_workload_clean(source)
    return source


def runtime_quality_workload_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "clean": bool(sources) and all(source["clean"] for source in sources),
        "adapterTypes": sorted({
            adapter
            for source in sources
            for adapter in source["adapterTypes"]
            if adapter
        }),
        "runtimeDnsModes": sorted({
            source["runtimeDnsMode"] for source in sources if source["runtimeDnsMode"]
        }),
        "runs": sum(source["runs"] for source in sources),
        "passedRuns": sum(source["passedRuns"] for source in sources),
        "failedRuns": sum(source["failedRuns"] for source in sources),
        "workloadAttempted": sum(source["workloadAttempted"] for source in sources),
        "workloadFailure": sum(source["workloadFailure"] for source in sources),
        "qualityBoundCandidateSets": sum(
            source["qualityBoundCandidateSets"] for source in sources
        ),
        "qualityBoundSelectedBehind": sum(
            source["qualityBoundSelectedBehind"] for source in sources
        ),
        "tcpFlowRouteGraphSelected": sum(
            source["tcpFlowRouteGraphSelected"] for source in sources
        ),
        "workloadFlowTcpAttemptedEntries": sum(
            source["workloadFlowTcpAttemptedEntries"] for source in sources
        ),
        "workloadFlowMatchedEntries": sum(
            source["workloadFlowMatchedEntries"] for source in sources
        ),
        "workloadFlowUnmatchedEntries": sum(
            source["workloadFlowUnmatchedEntries"] for source in sources
        ),
        "workloadFlowRuntimePacketTerminalEntries": sum(
            source["workloadFlowRuntimePacketTerminalEntries"] for source in sources
        ),
        "workloadFlowMatchedFlowStageFailedAttempts": sum(
            source["workloadFlowMatchedFlowStageFailedAttempts"] for source in sources
        ),
        "workloadFlowMatchedRecoveredFailureEntries": sum(
            source["workloadFlowMatchedRecoveredFailureEntries"] for source in sources
        ),
        "sources": sources,
    }


def runtime_quality_workload_clean(source: dict[str, Any]) -> bool:
    quality_sets = int(source["qualityBoundCandidateSets"])
    tcp_attempted = int(source["workloadFlowTcpAttemptedEntries"])
    recovered_stage = int(source["workloadFlowMatchedRecoveredFailureEntries"])
    stage_failed = int(source["workloadFlowMatchedFlowStageFailedAttempts"])
    return (
        source["runtimeDnsMode"] == "config-chain"
        and source["tcpForward"]
        and source["qualityStateUsed"]
        and source["runs"] > 0
        and source["passedRuns"] == source["runs"]
        and source["failedRuns"] == 0
        and source["runSummaryCount"] >= source["runs"]
        and source["candidateControlClean"]
        and bool(source["adapterTypes"])
        and source["workloadAttempted"] > 0
        and source["workloadSuccess"] == source["workloadAttempted"]
        and source["workloadFailure"] == 0
        and source["workloadStrictFailedRuns"] == 0
        and quality_sets > 0
        and source["qualityBoundSelectedWithQuality"] == quality_sets
        and source["qualityBoundSelectedBehind"] == 0
        and source["tcpFlowRouteGraphSelected"] >= quality_sets
        and source["tcpFlowRouteMatched"] >= quality_sets
        and source["tcpFlowRuleMatched"] == 0
        and source["tcpFlowPlanBypassed"] == 0
        and source["tcpFlowFailed"] == 0
        and source["tcpFlowFailedAfterPathComplete"] == 0
        and source["tcpFlowFailedAfterUpstreamOnly"] == 0
        and source["workloadFlowEntries"] >= source["workloadAttempted"]
        and tcp_attempted > 0
        and source["workloadFlowTcpAttemptedCoveredEntries"] == tcp_attempted
        and source["workloadFlowMatchedEntries"] == source["workloadAttempted"]
        and source["workloadFlowCoveredEntries"] == source["workloadAttempted"]
        and source["workloadFlowRuntimePreflowMatchedEntries"] == tcp_attempted
        and source["workloadFlowRuntimePacketHandshakeEntries"] == tcp_attempted
        and source["workloadFlowTunCaptureMatchedEntries"] == tcp_attempted
        and source["workloadFlowUnmatchedEntries"] == 0
        and source["workloadFlowRuntimePacketTerminalEntries"] == 0
        and source["workloadFlowMatchedFailures"] == 0
        and source["workloadFlowUnmatchedFailures"] == 0
        and source["workloadFlowMatchedFlowFailedAttempts"] == 0
        and recovered_stage >= stage_failed
        and not any(source["privacy"].values())
    )
