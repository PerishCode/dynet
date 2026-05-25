from __future__ import annotations

from pathlib import Path
from typing import Any

from scripts.lib.jsonio import load_summary
from scripts.lib.nv import count_keys, merge_items
from scripts.lib.privacy import (
    empty_privacy_flags,
    raw_detail_keys as find_raw_detail_keys,
)


CASCADE_STOP_SCHEMA = "dynet-vm-private-runtime-cascade-stop-surface/v1alpha1"
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
}
COUNT_FIELDS = """
sourceCount roundGapRuns stoppedRows boundExhaustedRows nonBoundRows
candidateExhaustedRows matchedFailedWorkloadRows attemptCount failedAttemptCount
retryableFailureCount missingRequiredFields boundOrderLengthMismatches
failedOrderLengthMismatches retryableOrderLengthMismatches
uniqueCandidateCountMismatches lastCandidateMismatches
finalFailureAccountingMismatches exhaustedFlagMismatches scopeStopMismatches
emptyBoundOrderRows
""".split()


def runtime_cascade_stop_source(path: Path) -> dict[str, Any]:
    summary = load_summary(path)
    totals = summary.get("totals") or {}
    conclusion = summary.get("conclusion") or {}
    policy = summary.get("policy") or {}
    source = {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "label": str(summary.get("label") or ""),
        "status": str(conclusion.get("status") or ""),
        "nextAction": str(conclusion.get("nextAction") or ""),
        **{field: int(totals.get(field) or 0) for field in COUNT_FIELDS},
        "classifications": count_keys(totals.get("classifications")),
        "stopReasons": count_keys(totals.get("stopReasons")),
        "failureScopes": count_keys(totals.get("failureScopes")),
        "stageSurfaces": count_keys(totals.get("stageSurfaces")),
        "pendingWaitClasses": count_keys(totals.get("pendingWaitClasses")),
        "failureStagePendingWaitClasses": count_keys(
            totals.get("failureStagePendingWaitClasses")
        ),
        "plannerPenaltySafe": bool(conclusion.get("plannerPenaltySafe"))
        or bool(policy.get("plannerPenaltySafe")),
        "qualityPenaltySafe": bool(conclusion.get("qualityPenaltySafe"))
        or bool(policy.get("qualityPenaltySafe")),
        "rawDetailKeys": sorted(find_raw_detail_keys(summary, RAW_DETAIL_KEYS)),
        "privacy": empty_privacy_flags(),
    }
    source["clean"] = runtime_cascade_stop_clean(source)
    return source


def runtime_cascade_stop_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "clean": bool(sources) and all(source["clean"] for source in sources),
        "statuses": sorted({source["status"] for source in sources if source["status"]}),
        **{field: sum(source[field] for source in sources) for field in COUNT_FIELDS},
        "classifications": merge_items(sources, "classifications"),
        "stopReasons": merge_items(sources, "stopReasons"),
        "failureScopes": merge_items(sources, "failureScopes"),
        "stageSurfaces": merge_items(sources, "stageSurfaces"),
        "pendingWaitClasses": merge_items(sources, "pendingWaitClasses"),
        "failureStagePendingWaitClasses": merge_items(
            sources, "failureStagePendingWaitClasses"
        ),
        "rawDetailKeys": merge_items(sources, "rawDetailKeys"),
        "sources": sources,
    }


def runtime_cascade_stop_clean(source: dict[str, Any]) -> bool:
    return stopped_cascade_shape_clean(source) or no_cascade_stop_clean(source)


def stopped_cascade_shape_clean(source: dict[str, Any]) -> bool:
    return common_cascade_stop_clean(source) and (
        source["schema"] == CASCADE_STOP_SCHEMA
        and source["status"] == "cascade-stop-shape-clean"
        and source["stoppedRows"] > 0
        and source["boundExhaustedRows"] > 0
        and source["candidateExhaustedRows"] == source["boundExhaustedRows"]
        and source["attemptCount"] == source["failedAttemptCount"]
        and source["retryableFailureCount"] + source["boundExhaustedRows"] == source["failedAttemptCount"]
        and all(source[field] == 0 for field in blocker_fields())
    )


def no_cascade_stop_clean(source: dict[str, Any]) -> bool:
    return common_cascade_stop_clean(source) and (
        source["status"] == "no-cascade-stop-evidence"
        and source["stoppedRows"] == 0
        and source["boundExhaustedRows"] == 0
        and source["nonBoundRows"] == 0
        and source["candidateExhaustedRows"] == 0
        and source["attemptCount"] == 0
        and source["failedAttemptCount"] == 0
        and source["retryableFailureCount"] == 0
    )


def common_cascade_stop_clean(source: dict[str, Any]) -> bool:
    return (
        source["schema"] == CASCADE_STOP_SCHEMA
        and all(source[field] == 0 for field in blocker_fields())
        and not source["plannerPenaltySafe"]
        and not source["qualityPenaltySafe"]
        and not source["rawDetailKeys"]
        and not any(source["privacy"].values())
    )


def blocker_fields() -> list[str]:
    return """
missingRequiredFields boundOrderLengthMismatches failedOrderLengthMismatches
retryableOrderLengthMismatches uniqueCandidateCountMismatches
lastCandidateMismatches finalFailureAccountingMismatches exhaustedFlagMismatches
scopeStopMismatches emptyBoundOrderRows
""".split()
