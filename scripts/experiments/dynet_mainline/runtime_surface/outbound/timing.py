from __future__ import annotations

from pathlib import Path
from typing import Any

from scripts.lib.jsonio import load_summary
from scripts.lib.nv import count_keys, merge_items
from scripts.lib.privacy import (
    empty_surface_privacy_flags as empty_privacy_flags,
)


OUTBOUND_TIMING_SCHEMA = "dynet-vm-private-runtime-outbound-timing-surface/v1alpha1"


def runtime_outbound_timing_source(path: Path) -> dict[str, Any]:
    summary = load_summary(path)
    totals = summary.get("totals") or {}
    conclusion = summary.get("conclusion") or {}
    source = {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "label": str(summary.get("label") or ""),
        "status": str(conclusion.get("status") or ""),
        "runs": int(totals.get("runs") or 0),
        "cleanRuns": int(totals.get("cleanRuns") or 0),
        "failedRuns": int(totals.get("failedRuns") or 0),
        "flows": int(totals.get("flows") or 0),
        "attemptEvents": int(totals.get("attemptEvents") or 0),
        "successfulAttemptEvents": int(totals.get("successfulAttemptEvents") or 0),
        "failedAttemptEvents": int(totals.get("failedAttemptEvents") or 0),
        "attemptFlows": int(totals.get("attemptFlows") or 0),
        "successfulAttemptFlows": int(totals.get("successfulAttemptFlows") or 0),
        "cascadeEvents": int(totals.get("cascadeEvents") or 0),
        "successfulCascadeEvents": int(totals.get("successfulCascadeEvents") or 0),
        "failedCascadeEvents": int(totals.get("failedCascadeEvents") or 0),
        "cascadeFlows": int(totals.get("cascadeFlows") or 0),
        "successfulCascadeFlows": int(totals.get("successfulCascadeFlows") or 0),
        "stageEvents": int(totals.get("stageEvents") or 0),
        "successStageEvents": int(totals.get("successStageEvents") or 0),
        "failedStageEvents": int(totals.get("failedStageEvents") or 0),
        "stageFlows": int(totals.get("stageFlows") or 0),
        "failureFlows": int(totals.get("failureFlows") or 0),
        "recoveredFailureFlows": int(totals.get("recoveredFailureFlows") or 0),
        "unrecoveredFailureFlows": int(totals.get("unrecoveredFailureFlows") or 0),
        "pathCompleteFlows": int(totals.get("pathCompleteFlows") or 0),
        "lifecycleCompleteFlows": int(totals.get("lifecycleCompleteFlows") or 0),
        "payloadBidirectionalFlows": int(totals.get("payloadBidirectionalFlows") or 0),
        "failedFlows": int(totals.get("failedFlows") or 0),
        "attemptP95Ms": timing_value(totals, "successfulAttemptElapsedMs", "p95"),
        "cascadeP95Ms": timing_value(totals, "successfulCascadeElapsedMs", "p95"),
        "stageP95Ms": timing_value(totals, "successfulStageElapsedMs", "p95"),
        "classifications": count_keys(totals.get("classifications")),
        "failedByCascadeScope": count_keys(totals.get("failedByCascadeScope")),
        "failedAttemptByProtocol": count_keys(totals.get("failedAttemptByProtocol")),
        "failedStageBySurface": count_keys(totals.get("failedStageBySurface")),
        "failedStageByDisposition": count_keys(totals.get("failedStageByDisposition")),
        "privacy": empty_privacy_flags(),
    }
    source["clean"] = runtime_outbound_timing_clean(source)
    return source


def runtime_outbound_timing_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "clean": bool(sources) and all(source["clean"] for source in sources),
        "statuses": sorted({source["status"] for source in sources if source["status"]}),
        "runs": sum(source["runs"] for source in sources),
        "cleanRuns": sum(source["cleanRuns"] for source in sources),
        "failedRuns": sum(source["failedRuns"] for source in sources),
        "flows": sum(source["flows"] for source in sources),
        "attemptEvents": sum(source["attemptEvents"] for source in sources),
        "successfulAttemptEvents": sum(
            source["successfulAttemptEvents"] for source in sources
        ),
        "failedAttemptEvents": sum(source["failedAttemptEvents"] for source in sources),
        "attemptFlows": sum(source["attemptFlows"] for source in sources),
        "successfulAttemptFlows": sum(
            source["successfulAttemptFlows"] for source in sources
        ),
        "cascadeEvents": sum(source["cascadeEvents"] for source in sources),
        "successfulCascadeEvents": sum(
            source["successfulCascadeEvents"] for source in sources
        ),
        "failedCascadeEvents": sum(source["failedCascadeEvents"] for source in sources),
        "cascadeFlows": sum(source["cascadeFlows"] for source in sources),
        "successfulCascadeFlows": sum(
            source["successfulCascadeFlows"] for source in sources
        ),
        "stageEvents": sum(source["stageEvents"] for source in sources),
        "successStageEvents": sum(source["successStageEvents"] for source in sources),
        "failedStageEvents": sum(source["failedStageEvents"] for source in sources),
        "stageFlows": sum(source["stageFlows"] for source in sources),
        "failureFlows": sum(source["failureFlows"] for source in sources),
        "recoveredFailureFlows": sum(source["recoveredFailureFlows"] for source in sources),
        "unrecoveredFailureFlows": sum(
            source["unrecoveredFailureFlows"] for source in sources
        ),
        "pathCompleteFlows": sum(source["pathCompleteFlows"] for source in sources),
        "lifecycleCompleteFlows": sum(
            source["lifecycleCompleteFlows"] for source in sources
        ),
        "payloadBidirectionalFlows": sum(
            source["payloadBidirectionalFlows"] for source in sources
        ),
        "failedFlows": sum(source["failedFlows"] for source in sources),
        "attemptP95Ms": max([source["attemptP95Ms"] for source in sources], default=0),
        "cascadeP95Ms": max([source["cascadeP95Ms"] for source in sources], default=0),
        "stageP95Ms": max([source["stageP95Ms"] for source in sources], default=0),
        "classifications": merge_items(sources, "classifications"),
        "failedByCascadeScope": merge_items(sources, "failedByCascadeScope"),
        "failedAttemptByProtocol": merge_items(sources, "failedAttemptByProtocol"),
        "failedStageBySurface": merge_items(sources, "failedStageBySurface"),
        "failedStageByDisposition": merge_items(sources, "failedStageByDisposition"),
        "sources": sources,
    }


def runtime_outbound_timing_clean(source: dict[str, Any]) -> bool:
    flows = source["flows"]
    return (
        source["schema"] == OUTBOUND_TIMING_SCHEMA
        and source["status"] == "clean"
        and source["runs"] > 0
        and source["cleanRuns"] == source["runs"]
        and source["failedRuns"] == 0
        and source["classifications"] == ["clean"]
        and flows > 0
        and source["attemptFlows"] == flows
        and source["successfulAttemptFlows"] == flows
        and source["cascadeFlows"] == flows
        and source["successfulCascadeFlows"] == flows
        and source["stageFlows"] == flows
        and source["stageEvents"] > 0
        and source["successStageEvents"] > 0
        and source["unrecoveredFailureFlows"] == 0
        and source["failedFlows"] == 0
        and source["pathCompleteFlows"] == flows
        and source["lifecycleCompleteFlows"] == flows
        and source["payloadBidirectionalFlows"] == flows
        and not any(source["privacy"].values())
    )


def timing_value(totals: dict[str, Any], key: str, value: str) -> int:
    timings = totals.get("timings") or {}
    return int(((timings.get(key) or {}).get(value)) or 0)
