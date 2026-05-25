from __future__ import annotations

from pathlib import Path
from typing import Any

from scripts.lib.jsonio import load_summary
from scripts.lib.nv import count_keys, merge_items
from scripts.lib.privacy import (
    empty_surface_privacy_flags as empty_privacy_flags,
)


STAGE_SURFACE_SCHEMA = "dynet-vm-private-runtime-stage-surface/v1alpha1"


def runtime_stage_surface_source(path: Path) -> dict[str, Any]:
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
        "stageFlows": int(totals.get("stageFlows") or 0),
        "stageEvents": int(totals.get("stageEvents") or 0),
        "successStageEvents": int(totals.get("successStageEvents") or 0),
        "failedStageEvents": int(totals.get("failedStageEvents") or 0),
        "stageFailedFlows": int(totals.get("stageFailedFlows") or 0),
        "recoveredStageFailedFlows": int(
            totals.get("recoveredStageFailedFlows") or 0
        ),
        "unrecoveredStageFailedFlows": int(
            totals.get("unrecoveredStageFailedFlows") or 0
        ),
        "pathCompleteFlows": int(totals.get("pathCompleteFlows") or 0),
        "lifecycleCompleteFlows": int(totals.get("lifecycleCompleteFlows") or 0),
        "payloadBidirectionalFlows": int(totals.get("payloadBidirectionalFlows") or 0),
        "failedFlows": int(totals.get("failedFlows") or 0),
        "classifications": count_keys(totals.get("classifications")),
        "failedBySurface": count_keys(totals.get("failedBySurface")),
        "failedByDisposition": count_keys(totals.get("failedByDisposition")),
        "privacy": empty_privacy_flags(),
    }
    source["clean"] = runtime_stage_surface_clean(source)
    return source


def runtime_stage_surface_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "clean": bool(sources) and all(source["clean"] for source in sources),
        "statuses": sorted({source["status"] for source in sources if source["status"]}),
        "runs": sum(source["runs"] for source in sources),
        "cleanRuns": sum(source["cleanRuns"] for source in sources),
        "failedRuns": sum(source["failedRuns"] for source in sources),
        "flows": sum(source["flows"] for source in sources),
        "stageFlows": sum(source["stageFlows"] for source in sources),
        "stageEvents": sum(source["stageEvents"] for source in sources),
        "successStageEvents": sum(
            source["successStageEvents"] for source in sources
        ),
        "failedStageEvents": sum(source["failedStageEvents"] for source in sources),
        "stageFailedFlows": sum(source["stageFailedFlows"] for source in sources),
        "recoveredStageFailedFlows": sum(
            source["recoveredStageFailedFlows"] for source in sources
        ),
        "unrecoveredStageFailedFlows": sum(
            source["unrecoveredStageFailedFlows"] for source in sources
        ),
        "pathCompleteFlows": sum(source["pathCompleteFlows"] for source in sources),
        "lifecycleCompleteFlows": sum(
            source["lifecycleCompleteFlows"] for source in sources
        ),
        "payloadBidirectionalFlows": sum(
            source["payloadBidirectionalFlows"] for source in sources
        ),
        "failedFlows": sum(source["failedFlows"] for source in sources),
        "classifications": merge_items(sources, "classifications"),
        "failedBySurface": merge_items(sources, "failedBySurface"),
        "failedByDisposition": merge_items(sources, "failedByDisposition"),
        "sources": sources,
    }


def runtime_stage_surface_clean(source: dict[str, Any]) -> bool:
    flows = source["flows"]
    return (
        source["schema"] == STAGE_SURFACE_SCHEMA
        and source["status"] == "clean"
        and source["runs"] > 0
        and source["cleanRuns"] == source["runs"]
        and source["failedRuns"] == 0
        and source["classifications"] == ["clean"]
        and flows > 0
        and source["stageFlows"] == flows
        and source["stageEvents"] > 0
        and source["successStageEvents"] > 0
        and source["unrecoveredStageFailedFlows"] == 0
        and source["failedFlows"] == 0
        and source["pathCompleteFlows"] == flows
        and source["lifecycleCompleteFlows"] == flows
        and source["payloadBidirectionalFlows"] == flows
        and not any(source["privacy"].values())
    )
