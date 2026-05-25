from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def adapter_product_effect_source(path: Path) -> dict[str, Any]:
    summary = load_json(path)
    conclusion = summary.get("conclusion") or {}
    runtime = summary.get("dynetRuntimeProduct") or {}
    paired = summary.get("pairedProductEffect") or {}
    return {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "status": str(summary.get("status") or "missing"),
        "adapterType": str(summary.get("adapterType") or ""),
        "recommendedUse": str(summary.get("recommendedUse") or ""),
        "productEffectParityClaimSafe": bool(
            conclusion.get("productEffectParityClaimSafe")
        ),
        "plannerPenaltySafe": bool(summary.get("plannerPenaltySafe")),
        "notReadyReasons": [str(item) for item in conclusion.get("notReadyReasons", [])],
        "runtimeClean": bool(runtime.get("clean")),
        "runtimeWorkloadAttempted": int(runtime.get("workloadAttempted") or 0),
        "runtimeWorkloadFailure": int(runtime.get("workloadFailure") or 0),
        "runtimeTcpFlowFailed": int(runtime.get("tcpFlowFailed") or 0),
        "runtimeSlotPressureEvents": int(runtime.get("tcpSlotPressureEvents") or 0),
        "pairedWindows": int(paired.get("windows") or 0),
        "pairedEntries": int(paired.get("pairedEntries") or 0),
        "pairedParityCandidate": bool(paired.get("parityCandidate")),
        "privacy": summary.get("privacy") or {},
    }


def adapter_product_effect_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "clean": bool(sources) and all(adapter_product_effect_clean(source) for source in sources),
        "adapterTypes": sorted({
            source["adapterType"] for source in sources if source["adapterType"]
        }),
        "runtimeWorkloadAttempted": sum(
            source["runtimeWorkloadAttempted"] for source in sources
        ),
        "runtimeWorkloadFailure": sum(source["runtimeWorkloadFailure"] for source in sources),
        "runtimeTcpFlowFailed": sum(source["runtimeTcpFlowFailed"] for source in sources),
        "runtimeSlotPressureEvents": sum(
            source["runtimeSlotPressureEvents"] for source in sources
        ),
        "pairedWindows": sum(source["pairedWindows"] for source in sources),
        "pairedEntries": sum(source["pairedEntries"] for source in sources),
        "sources": sources,
    }


def adapter_product_effect_clean(source: dict[str, Any]) -> bool:
    return (
        source["status"] == "product-effect-parity-candidate"
        and source["productEffectParityClaimSafe"]
        and not source["plannerPenaltySafe"]
        and not source["notReadyReasons"]
        and source["runtimeClean"]
        and source["runtimeWorkloadAttempted"] > 0
        and source["runtimeWorkloadFailure"] == 0
        and source["runtimeTcpFlowFailed"] == 0
        and source["pairedWindows"] > 0
        and source["pairedEntries"] > 0
        and source["pairedParityCandidate"]
    )


def runtime_pressure_source(path: Path) -> dict[str, Any]:
    summary = load_json(path)
    totals = summary.get("totals") or {}
    policy = summary.get("policy") or {}
    conclusion = summary.get("conclusion") or {}
    return {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "status": str(summary.get("status") or "missing"),
        "pressureShape": str(conclusion.get("pressureShape") or ""),
        "workloadAttempted": int(totals.get("workloadAttempted") or 0),
        "workloadFailure": int(totals.get("workloadFailure") or 0),
        "tcpFlowFailed": int(totals.get("tcpFlowFailed") or 0),
        "stageFailures": int(totals.get("stageFailures") or 0),
        "stageUnrecoveredFailures": int(totals.get("stageUnrecoveredFailures") or 0),
        "slotPressureEvents": int(totals.get("slotPressureEvents") or 0),
        "slowStageEvents": int(totals.get("slowStageEvents") or 0),
        "slowFailedStageEvents": int(totals.get("slowFailedStageEvents") or 0),
        "slowStageMaxMs": int(totals.get("slowStageMaxMs") or 0),
        "scheduleLagMaxMs": int(totals.get("scheduleLagMaxMs") or 0),
        "runsWithStageWithoutSlotPressure": int(
            totals.get("runsWithStageWithoutSlotPressure") or 0
        ),
        "runsWithSlotWithoutStagePressure": int(
            totals.get("runsWithSlotWithoutStagePressure") or 0
        ),
        "runsWithStageAndSlotPressure": int(
            totals.get("runsWithStageAndSlotPressure") or 0
        ),
        "runsAtPortSlotLimit": int(totals.get("runsAtPortSlotLimit") or 0),
        "slotActiveAtCapacityEvents": int(totals.get("slotActiveAtCapacityEvents") or 0),
        "slotActiveOverCapacityEvents": int(totals.get("slotActiveOverCapacityEvents") or 0),
        "slotCapacityMissingEvents": int(totals.get("slotCapacityMissingEvents") or 0),
        "classifications": count_keys(totals.get("classifications")),
        "plannerPenaltySafe": bool(policy.get("plannerPenaltySafe")),
        "qualityPenaltySafe": bool(policy.get("qualityPenaltySafe")),
        "productEffectClaimSafe": bool(policy.get("productEffectClaimSafe")),
        "privacy": summary.get("privacy") or {},
    }


def runtime_pressure_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "clean": bool(sources) and all(runtime_pressure_clean(source) for source in sources),
        "workloadAttempted": sum(source["workloadAttempted"] for source in sources),
        "workloadFailure": sum(source["workloadFailure"] for source in sources),
        "tcpFlowFailed": sum(source["tcpFlowFailed"] for source in sources),
        "stageFailures": sum(source["stageFailures"] for source in sources),
        "stageUnrecoveredFailures": sum(
            source["stageUnrecoveredFailures"] for source in sources
        ),
        "slotPressureEvents": sum(source["slotPressureEvents"] for source in sources),
        "slowStageEvents": sum(source["slowStageEvents"] for source in sources),
        "slowFailedStageEvents": sum(source["slowFailedStageEvents"] for source in sources),
        "slowStageMaxMs": max((source["slowStageMaxMs"] for source in sources), default=0),
        "scheduleLagMaxMs": max((source["scheduleLagMaxMs"] for source in sources), default=0),
        "pressureShapes": sorted({
            source["pressureShape"] for source in sources if source["pressureShape"]
        }),
        "classifications": sorted({
            item for source in sources for item in source["classifications"]
        }),
        "runsWithStageWithoutSlotPressure": sum(
            source["runsWithStageWithoutSlotPressure"] for source in sources
        ),
        "runsWithSlotWithoutStagePressure": sum(
            source["runsWithSlotWithoutStagePressure"] for source in sources
        ),
        "runsWithStageAndSlotPressure": sum(
            source["runsWithStageAndSlotPressure"] for source in sources
        ),
        "runsAtPortSlotLimit": sum(source["runsAtPortSlotLimit"] for source in sources),
        "slotActiveAtCapacityEvents": sum(
            source["slotActiveAtCapacityEvents"] for source in sources
        ),
        "slotActiveOverCapacityEvents": sum(
            source["slotActiveOverCapacityEvents"] for source in sources
        ),
        "slotCapacityMissingEvents": sum(
            source["slotCapacityMissingEvents"] for source in sources
        ),
        "sources": sources,
    }


def runtime_pressure_clean(source: dict[str, Any]) -> bool:
    return (
        source["status"] in {"clean", "observe-only-product-clean"}
        and source["workloadAttempted"] > 0
        and source["workloadFailure"] == 0
        and source["tcpFlowFailed"] == 0
        and source["stageUnrecoveredFailures"] == 0
        and not source["plannerPenaltySafe"]
        and not source["qualityPenaltySafe"]
        and not source["productEffectClaimSafe"]
    )


def count_keys(rows: Any) -> list[str]:
    if isinstance(rows, list) and all(isinstance(row, str) for row in rows):
        return sorted({row for row in rows if row})
    return sorted({
        str(row.get("key") or "")
        for row in rows or []
        if isinstance(row, dict) and row.get("key")
    })


def paired_read_surface_source(path: Path) -> dict[str, Any]:
    summary = load_json(path)
    conclusion = summary.get("conclusion") or {}
    actionable = summary.get("actionableConclusion") or {}
    boundary = summary.get("pressureBoundary") or {}
    totals = summary.get("totals") or {}
    return {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "readSurfaceStatus": str(conclusion.get("status") or ""),
        "actionableStatus": str(actionable.get("status") or ""),
        "action": str(actionable.get("action") or ""),
        "actionableReadFailureCount": int(actionable.get("readFailureCount") or 0),
        "excludedReadFailureCount": int(actionable.get("excludedReadFailureCount") or 0),
        "totalReadFailureCount": int(totals.get("readFailureCount") or 0),
        "classificationClean": bool(conclusion.get("classificationClean")),
        "pressureBoundaryStatus": str(boundary.get("status") or ""),
        "pressureBoundarySourceCount": int(boundary.get("sourceCount") or 0),
        "plannerFeedback": str(actionable.get("plannerFeedback") or ""),
        "qualityFeedback": str(actionable.get("qualityFeedback") or ""),
        "runtimePolicy": str(actionable.get("runtimePolicy") or ""),
        "privacy": summary.get("privacy") or {},
    }


def paired_read_surface_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "clean": bool(sources) and all(paired_read_surface_clean(source) for source in sources),
        "actionableReadFailureCount": sum(
            source["actionableReadFailureCount"] for source in sources
        ),
        "excludedReadFailureCount": sum(
            source["excludedReadFailureCount"] for source in sources
        ),
        "totalReadFailureCount": sum(source["totalReadFailureCount"] for source in sources),
        "sources": sources,
    }


def paired_read_surface_clean(source: dict[str, Any]) -> bool:
    return (
        source["actionableStatus"] in {
            "actionable-pressure-clean",
            "fresh-config-clean-noncurrent-controls-excluded",
        }
        and source["actionableReadFailureCount"] == 0
        and source["classificationClean"]
        and source["pressureBoundarySourceCount"] > 0
        and source["plannerFeedback"] == "none"
        and source["qualityFeedback"] == "none"
        and source["runtimePolicy"] == "do-not-change-from-this-artifact-alone"
    )


def recommendation_source(path: Path) -> dict[str, Any]:
    summary = load_json(path)
    recommendation = summary.get("recommendation") or {}
    paired = recommendation.get("pairedPressure") or {}
    return {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "status": str(recommendation.get("status") or ""),
        "action": str(recommendation.get("action") or ""),
        "plannerFeedback": str(recommendation.get("plannerFeedback") or ""),
        "qualityFeedback": str(recommendation.get("qualityFeedback") or ""),
        "runtimePolicy": str(recommendation.get("runtimePolicy") or ""),
        "probePolicy": str(recommendation.get("probePolicy") or ""),
        "pairedPressureActionableStatus": str(paired.get("actionableStatus") or ""),
        "pairedPressureClean": bool((paired.get("freshConfig") or {}).get("clean")),
        "privacy": summary.get("privacy") or {},
    }


def recommendation_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "clean": bool(sources) and all(recommendation_clean(source) for source in sources),
        "statuses": sorted({source["status"] for source in sources if source["status"]}),
        "actions": sorted({source["action"] for source in sources if source["action"]}),
        "sources": sources,
    }


def recommendation_clean(source: dict[str, Any]) -> bool:
    return (
        source["status"] in {
            "observe-saved-config-drift-repeat-clean",
            "observe-protocol-read-paired-shape",
        }
        and source["plannerFeedback"] == "none"
        and source["qualityFeedback"] == "none"
        and source["runtimePolicy"] == "do-not-change-from-this-artifact-alone"
        and source["probePolicy"] == "no-product-retry-from-this-artifact-alone"
        and source["pairedPressureClean"]
    )


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text())


def print_summary(output_dir: Path, summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "outputDir": str(output_dir),
        "status": summary["status"],
        "recommendedUse": summary["recommendedUse"],
        "plannerPenaltySafe": summary["plannerPenaltySafe"],
        "qualityPenaltySafe": summary["qualityPenaltySafe"],
    }


def recommended_use(status: str) -> str:
    if status == "mainline-baseline-current-clean":
        return "use-as-mainline-baseline-for-next-runtime-slice"
    return "fill-missing-or-unclean-baseline-evidence"


def next_actions(failed: list[str]) -> list[dict[str, Any]]:
    if failed:
        return [
            {
                "id": "repair-mainline-baseline-input",
                "evidence": "baseline",
                "priority": "required",
                "reason": f"Gate `{gate_id}` is not satisfied.",
                "plannerPenaltySafe": False,
            }
            for gate_id in failed
        ]
    return [
        {
            "id": "expand-non-direct-runtime-or-adapter-coverage",
            "evidence": "runtime",
            "priority": "next",
            "reason": (
                "Current Trojan and VMess baselines are policy-clean; move to "
                "the next runtime-owned execution surface."
            ),
            "plannerPenaltySafe": False,
        },
        {
            "id": "keep-pressure-and-read-surfaces-observe-only",
            "evidence": "policy",
            "priority": "required",
            "reason": (
                "Baseline evidence is clean or recovered observe-only evidence, "
                "not repeated unrecovered candidate failure proof."
            ),
            "plannerPenaltySafe": False,
        },
    ]


def privacy_summary(*sections: dict[str, Any]) -> dict[str, Any]:
    sources = [
        source
        for section in sections
        for source in section.get("sources", [])
        if isinstance(source, dict)
    ]
    return {
        "rawLogsStored": any_privacy_flag(sources, "rawLogsStored"),
        "rawPacketsStored": any_privacy_flag(sources, "rawPacketsStored"),
        "rawSecretsStored": any_privacy_flag(sources, "rawSecretsStored"),
        "responseBodiesStored": any_privacy_flag(sources, "responseBodiesStored")
        or any_privacy_flag(sources, "rawResponseBodiesStored"),
        "identityInformationSent": any_privacy_flag(sources, "identityInformationSent"),
        "cookiesSent": any_privacy_flag(sources, "cookiesSent"),
        "authorizationSent": any_privacy_flag(sources, "authorizationSent"),
        "rawResponseHeadersStored": any_privacy_flag(
            sources,
            "rawResponseHeadersStored",
        ),
        "accountStateStored": any_privacy_flag(sources, "accountStateStored"),
    }


def any_privacy_flag(sources: list[dict[str, Any]], flag: str) -> bool:
    return any(bool((source.get("privacy") or {}).get(flag)) for source in sources)
