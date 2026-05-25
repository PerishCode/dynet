from __future__ import annotations

from pathlib import Path
from typing import Any

from dynet_mainline.runtime_surface.round_gap import RAW_DETAIL_KEYS
from scripts.lib.jsonio import load_summary
from scripts.lib.nv import count_keys, merge_items, merge_keys
from scripts.lib.privacy import (
    empty_privacy_flags,
    raw_detail_keys as find_raw_detail_keys,
)


STAGE_PRESSURE_SCHEMA = "dynet-vm-private-runtime-stage-pressure-profile/v1alpha1"
COUNT_FIELDS = """
roundGapRuns cleanControlRuns failedRuns stageFailureEvents workloadFailure
recoveredFlowCount cascadeFailedAttempts cascadeRetryableFailures
cascadeStoppedFailures cascadeStoppedBoundExhaustedFlows selectedBehind
tcpSlotPressureEvents scheduleLagMaxMs profileCount schemaMismatchSources
penaltySafeSources
""".split()


def runtime_stage_pressure_source(path: Path) -> dict[str, Any]:
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
        "stageSurfaces": count_keys(totals.get("stageSurfaces")),
        "stageDispositions": count_keys(totals.get("stageDispositions")),
        "cascadeScopes": count_keys(totals.get("cascadeScopes")),
        "cascadeStopReasons": count_keys(totals.get("cascadeStopReasons")),
        "replayScopes": count_keys(totals.get("replayScopes")),
        "pendingWaitClasses": count_keys(totals.get("pendingWaitClasses")),
        "plannerPenaltySafe": bool(conclusion.get("plannerPenaltySafe"))
        or bool(policy.get("plannerPenaltySafe")),
        "qualityPenaltySafe": bool(conclusion.get("qualityPenaltySafe"))
        or bool(policy.get("qualityPenaltySafe")),
        "rawDetailKeys": sorted(find_raw_detail_keys(summary, RAW_DETAIL_KEYS)),
        "privacy": empty_privacy_flags(),
    }
    source["clean"] = runtime_stage_pressure_clean(source)
    return source


def runtime_stage_pressure_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "clean": bool(sources) and all(source["clean"] for source in sources),
        "statuses": merge_keys(sources, "status"),
        **{field: sum(source[field] for source in sources) for field in COUNT_FIELDS},
        "classifications": merge_items(sources, "classifications"),
        "stageSurfaces": merge_items(sources, "stageSurfaces"),
        "stageDispositions": merge_items(sources, "stageDispositions"),
        "cascadeScopes": merge_items(sources, "cascadeScopes"),
        "cascadeStopReasons": merge_items(sources, "cascadeStopReasons"),
        "replayScopes": merge_items(sources, "replayScopes"),
        "pendingWaitClasses": merge_items(sources, "pendingWaitClasses"),
        "rawDetailKeys": merge_items(sources, "rawDetailKeys"),
        "sources": sources,
    }


def runtime_stage_pressure_clean(source: dict[str, Any]) -> bool:
    return focused_stage_pressure_clean(source) or product_stage_pressure_clean(source)


def focused_stage_pressure_clean(source: dict[str, Any]) -> bool:
    return common_stage_pressure_clean(source) and (
        source["schema"] == STAGE_PRESSURE_SCHEMA
        and source["status"] == "stage-pressure-profile-clean"
        and source["roundGapRuns"] > 0
        and source["cleanControlRuns"] > 0
        and source["stageFailureEvents"] > 0
        and source["profileCount"] == 1
        and source["stageDispositions"] == ["pending-timeout"]
        and source["cascadeScopes"] == ["bound"]
        and source["replayScopes"] == ["pre-payload"]
        and source["selectedBehind"] == 0
        and source["tcpSlotPressureEvents"] == 0
    )


def product_stage_pressure_clean(source: dict[str, Any]) -> bool:
    stage_shape_ok = (
        source["stageFailureEvents"] == 0
        or (
            source["profileCount"] == 1
            and source["stageDispositions"] == ["pending-timeout"]
            and source["cascadeScopes"] == ["bound"]
        )
    )
    return common_stage_pressure_clean(source) and (
        source["status"] == "stage-pressure-product-clean"
        and source["failedRuns"] == 0
        and source["cleanControlRuns"] == source["roundGapRuns"]
        and source["workloadFailure"] == 0
        and source["cascadeStoppedFailures"] == 0
        and source["cascadeStoppedBoundExhaustedFlows"] == 0
        and source["classifications"] == ["clean"]
        and source["selectedBehind"] == 0
        and stage_shape_ok
    )


def common_stage_pressure_clean(source: dict[str, Any]) -> bool:
    return (
        source["schema"] == STAGE_PRESSURE_SCHEMA
        and source["roundGapRuns"] > 0
        and source["cleanControlRuns"] > 0
        and source["schemaMismatchSources"] == 0
        and source["penaltySafeSources"] == 0
        and not source["plannerPenaltySafe"]
        and not source["qualityPenaltySafe"]
        and not source["rawDetailKeys"]
        and not any(source["privacy"].values())
    )
