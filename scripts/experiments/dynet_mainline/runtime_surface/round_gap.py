from __future__ import annotations

from pathlib import Path
from typing import Any

from scripts.lib.jsonio import load_summary
from scripts.lib.nv import count_keys
from scripts.lib.privacy import (
    empty_privacy_flags,
    raw_detail_keys as find_raw_detail_keys,
)


ROUND_GAP_SCHEMA = "dynet-vm-private-runtime-round-gap-batch/v1alpha1"
RAW_DETAIL_KEYS = {
    "boundSelected",
    "boundSelectedSequence",
    "clientPort",
    "domain",
    "failedSelectedSequence",
    "failedWorkloadRows",
    "flowId",
    "flowIds",
    "lastBoundSelected",
    "outbound",
    "recoveredFlowRows",
    "retryableSelectedSequence",
    "slowStageRows",
    "stoppedRows",
}


def runtime_round_gap_source(path: Path) -> dict[str, Any]:
    summary = load_summary(path)
    totals = summary.get("totals") or {}
    conclusion = summary.get("conclusion") or {}
    policy = summary.get("policy") or {}
    raw_keys = sorted(find_raw_detail_keys(summary, RAW_DETAIL_KEYS))
    source = {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "label": str(summary.get("label") or ""),
        "status": str(conclusion.get("status") or ""),
        "nextAction": str(conclusion.get("nextAction") or ""),
        "runs": int(totals.get("runs") or 0),
        "cleanRuns": int(totals.get("cleanRuns") or 0),
        "failedRuns": int(totals.get("failedRuns") or 0),
        "classifications": count_keys(totals.get("classifications")),
        "failedWorkloadMechanisms": count_keys(totals.get("failedWorkloadMechanisms")),
        "recoveredFlowMechanisms": count_keys(totals.get("recoveredFlowMechanisms")),
        "pendingWaitClasses": count_keys(totals.get("pendingWaitClasses")),
        "cascadeFailedAttempts": int(totals.get("cascadeFailedAttempts") or 0),
        "cascadeRetryableFailures": int(totals.get("cascadeRetryableFailures") or 0),
        "cascadeStoppedFailures": int(totals.get("cascadeStoppedFailures") or 0),
        "cascadeRecoveredFlows": int(totals.get("cascadeRecoveredFlows") or 0),
        "cascadeStoppedBoundExhaustedFlows": int(
            totals.get("cascadeStoppedBoundExhaustedFlows") or 0
        ),
        "plannerPenaltySafe": bool(policy.get("plannerPenaltySafe")),
        "qualityPenaltySafe": bool(policy.get("qualityPenaltySafe")),
        "rawDetailKeys": raw_keys,
        "privacy": empty_privacy_flags(),
    }
    source["clean"] = runtime_round_gap_clean(source)
    return source


def runtime_round_gap_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "clean": bool(sources) and all(source["clean"] for source in sources),
        "statuses": sorted({source["status"] for source in sources if source["status"]}),
        "runs": sum(source["runs"] for source in sources),
        "cleanRuns": sum(source["cleanRuns"] for source in sources),
        "failedRuns": sum(source["failedRuns"] for source in sources),
        "classifications": sorted({
            item for source in sources for item in source["classifications"]
        }),
        "failedWorkloadMechanisms": sorted({
            item for source in sources for item in source["failedWorkloadMechanisms"]
        }),
        "recoveredFlowMechanisms": sorted({
            item for source in sources for item in source["recoveredFlowMechanisms"]
        }),
        "pendingWaitClasses": sorted({
            item for source in sources for item in source["pendingWaitClasses"]
        }),
        "cascadeFailedAttempts": sum(source["cascadeFailedAttempts"] for source in sources),
        "cascadeRetryableFailures": sum(
            source["cascadeRetryableFailures"] for source in sources
        ),
        "cascadeStoppedFailures": sum(source["cascadeStoppedFailures"] for source in sources),
        "cascadeRecoveredFlows": sum(source["cascadeRecoveredFlows"] for source in sources),
        "cascadeStoppedBoundExhaustedFlows": sum(
            source["cascadeStoppedBoundExhaustedFlows"] for source in sources
        ),
        "rawDetailKeys": sorted({
            key for source in sources for key in source["rawDetailKeys"]
        }),
        "sources": sources,
    }


def runtime_round_gap_clean(source: dict[str, Any]) -> bool:
    return (
        source["schema"] == ROUND_GAP_SCHEMA
        and source["runs"] > 0
        and bool(source["status"])
        and bool(source["classifications"])
        and not source["plannerPenaltySafe"]
        and not source["qualityPenaltySafe"]
        and not source["rawDetailKeys"]
        and not any(source["privacy"].values())
    )
