from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from dynet_mainline.runtime_fallback import runtime_fallback_source
from tunnel_private.quality.readiness import maturity as adapter_maturity


BASELINE_CLEAN_FIELDS = """
runtimeFallbackClean runtimeDnsProductClean runtimeDnsRefreshClean runtimeDnsForwardClean
runtimeQualityPlanClean runtimeRouteRefreshClean runtimeSelectionRefreshClean runtimeWorkloadFlowClean
runtimeQualityWorkloadClean runtimeWorkloadSurfaceClean runtimeCloseSurfaceClean runtimePayloadSurfaceClean
runtimeStageSurfaceClean runtimeEventStreamClean runtimeEventCorrelationClean runtimeEventCausalityClean
runtimeFailureAttributionClean runtimeFailureImpactClean runtimeTimingSurfaceClean runtimeDnsTimingClean
runtimeOutboundTimingClean runtimeOutboundAttemptClean runtimeCandidateSetClean runtimeCandidateQualityClean
runtimeFailurePropagationClean runtimeStageChainClean runtimeStageOrderClean runtimeRouteDecisionClean
runtimeOutboundGateClean runtimeOutboundRetryClean runtimePacketSurfaceClean runtimeTcpPressureClean
runtimeTcpTargetClean runtimeStagePressureClean runtimeUdpSessionClean runtimeIpv6DenialClean runtimeTakeoverLifecycleClean
runtimeRetainedArtifactClean runtimeExitLimitClean runtimeCollectionStageClean runtimeCascadeStopClean runtimeRoundGapClean
runtimeRoundGapCompareClean runtimeFlowRefreshClean runtimeCascadeRefreshClean runtimeTargetIdentityClean qualityFeedbackBoundaryClean
planQualityStateBridgeClean runtimeUdpDirectClean runtimeIpv6NoLeakClean runtimeGuardrailClean
""".split()


def mainline_baseline_source(path: Path) -> dict[str, Any]:
    summary = load_json(path)
    adapter = summary.get("adapterProductEffect") or {}
    conclusion = summary.get("conclusion") or {}
    return {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "status": str(summary.get("status") or "missing"),
        "recommendedUse": str(summary.get("recommendedUse") or ""),
        "adapterTypes": [normalize_type(item) for item in adapter.get("adapterTypes", []) if item],
        **{field: bool(conclusion.get(field)) for field in BASELINE_CLEAN_FIELDS},
        "plannerPenaltySafe": bool(summary.get("plannerPenaltySafe")),
        "qualityPenaltySafe": bool(summary.get("qualityPenaltySafe")),
    }


def mainline_baseline_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "statuses": sorted({source["status"] for source in sources if source["status"]}),
        "adapterTypes": sorted({
            adapter
            for source in sources
            for adapter in source.get("adapterTypes", [])
            if adapter
        }),
        "clean": bool(sources)
        and all(source["status"] == "mainline-baseline-current-clean" for source in sources),
        "sources": sources,
    }


def provider_meta_source(path: Path) -> dict[str, Any]:
    summary = load_json(path)
    counts = summary.get("counts") or {}
    candidates = [item for item in summary.get("candidates", []) if isinstance(item, dict)]
    return {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "matched": int(counts.get("matched") or 0),
        "supported": int(counts.get("supported") or 0),
        "selected": int(counts.get("selected") or len(candidates)),
        "matchedByType": normalized_count_map(counts.get("matchedByType")),
        "selectedByType": count_types([normalize_type(item.get("type")) for item in candidates]),
    }


def provider_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    matched = merge_count_maps([source["matchedByType"] for source in sources])
    selected = merge_count_maps([source["selectedByType"] for source in sources])
    return {
        "sourceCount": len(sources),
        "matched": sum(source["matched"] for source in sources),
        "supported": sum(source["supported"] for source in sources),
        "selected": sum(source["selected"] for source in sources),
        "matchedByType": count_rows(matched),
        "selectedByType": count_rows(selected),
        "matchedTypeCounts": matched,
        "selectedTypeCounts": selected,
        "sources": sources,
    }


def provider_availability_source(path: Path) -> dict[str, Any]:
    summary = load_json(path)
    current = summary.get("currentProvider") or {}
    return {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "status": str(summary.get("status") or "missing"),
        "currentMatchedByType": normalized_count_map(current.get("matchedTypeCounts")),
        "currentCompatibleByType": normalized_count_map(current.get("compatibleTypeCounts")),
        "adapters": [availability_adapter_row(row) for row in summary.get("adapters", []) if isinstance(row, dict)],
    }


def provider_availability_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    current_matched = merge_count_maps([source["currentMatchedByType"] for source in sources])
    current_compatible = merge_count_maps([source["currentCompatibleByType"] for source in sources])
    adapters = availability_adapter_summary(sources)
    return {
        "sourceCount": len(sources),
        "statuses": sorted({source["status"] for source in sources if source["status"]}),
        "currentMatchedByType": count_rows(current_matched),
        "currentCompatibleByType": count_rows(current_compatible),
        "currentMatchedTypeCounts": current_matched,
        "currentCompatibleTypeCounts": current_compatible,
        "adapterAvailability": {adapter: row["availability"] for adapter, row in adapters.items()},
        "adapterNextActions": {adapter: row["nextAction"] for adapter, row in adapters.items()},
        "adapterGaps": {adapter: row["gaps"] for adapter, row in adapters.items()},
        "sources": sources,
    }


def availability_adapter_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "adapterType": normalize_type(row.get("adapterType")),
        "availability": str(row.get("availability") or ""),
        "currentMatched": int(row.get("currentMatched") or 0),
        "currentCompatible": int(row.get("currentCompatible") or 0),
        "historicalMatched": int(row.get("historicalMatched") or 0),
        "gaps": [str(item) for item in row.get("gaps", [])],
        "nextAction": str(row.get("nextAction") or ""),
    }


def availability_adapter_summary(
    sources: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for source in sources:
        for row in source["adapters"]:
            adapter_type = row["adapterType"]
            if not adapter_type:
                continue
            current = rows.setdefault(adapter_type, empty_availability_row())
            current["currentMatched"] += row["currentMatched"]
            current["currentCompatible"] += row["currentCompatible"]
            current["historicalMatched"] += row["historicalMatched"]
            current["gaps"].extend(row["gaps"])
            current["availability"] = strongest_availability(
                current["availability"],
                row["availability"],
            )
            current["nextAction"] = strongest_next_action(
                current["nextAction"],
                row["nextAction"],
                current["availability"],
            )
    for row in rows.values():
        row["gaps"] = unique(row["gaps"])
    return rows


def empty_availability_row() -> dict[str, Any]:
    return {
        "availability": "",
        "currentMatched": 0,
        "currentCompatible": 0,
        "historicalMatched": 0,
        "gaps": [],
        "nextAction": "",
    }


def strongest_availability(left: str, right: str) -> str:
    order = {
        "current-compatible": 4,
        "current-provider-shape-blocked": 3,
        "historical-only": 2,
        "missing": 1,
        "": 0,
    }
    return left if order.get(left, 0) >= order.get(right, 0) else right


def strongest_next_action(left: str, right: str, availability: str) -> str:
    if not right:
        return left
    if not left:
        return right
    preferred = {
        "current-compatible": "use-current-provider-candidate-for-runtime-work",
        "current-provider-shape-blocked": (
            "fix-provider-candidate-shape-before-runtime-work"
        ),
        "historical-only": "reacquire-current-provider-candidate-before-runtime-work",
        "missing": "acquire-current-provider-candidate-before-runtime-work",
    }
    return preferred.get(availability, left)


def product_effect_source(path: Path) -> dict[str, Any]:
    summary = load_json(path)
    conclusion = summary.get("conclusion") or {}
    runtime = summary.get("dynetRuntimeProduct") or {}
    paired = summary.get("pairedProductEffect") or {}
    return {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "adapterType": normalize_type(summary.get("adapterType")),
        "status": str(summary.get("status") or "missing"),
        "clean": product_effect_clean(summary, conclusion, runtime, paired),
        "workloadAttempted": int(runtime.get("workloadAttempted") or 0),
        "workloadFailure": int(runtime.get("workloadFailure") or 0),
        "pairedWindows": int(paired.get("windows") or 0),
        "pairedEntries": int(paired.get("pairedEntries") or 0),
        "notReadyReasons": [
            str(item) for item in conclusion.get("notReadyReasons", [])
        ],
    }


def product_effect_clean(
    summary: dict[str, Any],
    conclusion: dict[str, Any],
    runtime: dict[str, Any],
    paired: dict[str, Any],
) -> bool:
    return (
        summary.get("status") == "product-effect-parity-candidate"
        and bool(conclusion.get("productEffectParityClaimSafe"))
        and not bool(summary.get("plannerPenaltySafe"))
        and not conclusion.get("notReadyReasons", [])
        and bool(runtime.get("clean"))
        and int(runtime.get("workloadAttempted") or 0) > 0
        and int(runtime.get("workloadFailure") or 0) == 0
        and int(runtime.get("tcpFlowFailed") or 0) == 0
        and bool(paired.get("parityCandidate"))
    )


def adapter_readiness_source(path: Path) -> dict[str, Any]:
    summary = load_json(path)
    product = (summary.get("productEvidence") or {}).get("product-e2e") or {}
    runtime = summary.get("runtimeEvidence") or {}
    conclusion = summary.get("conclusion") or {}
    return {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "adapterType": normalize_type(summary.get("adapterType")),
        "status": str(summary.get("status") or "missing"),
        "readyForMainlineAdapterWork": bool(conclusion.get("readyForMainlineAdapterWork")),
        "productRuns": int(product.get("runs") or 0),
        "productFailed": int(product.get("failed") or 0),
        "runtimeClean": bool(runtime.get("clean")),
        "runtimeRuns": int(runtime.get("runs") or 0),
    }


def adapter_maturity_source(path: Path) -> dict[str, Any]:
    summary = load_json(path)
    runtime = summary.get("runtime") or {}
    conclusion = summary.get("conclusion") or {}
    return {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "adapterType": normalize_type(summary.get("adapterType")),
        "status": str(summary.get("status") or "missing"),
        "candidateMature": bool(conclusion.get("candidateMature")),
        "promotionEvaluationEligible": bool(conclusion.get("promotionEvaluationEligible")),
        "runtimeRuns": int(runtime.get("runs") or 0),
        "runtimeWorkloadAttempted": int(runtime.get("workloadAttempted") or 0),
        "runtimeWorkloadFailure": int(runtime.get("workloadFailure") or 0),
        "uniquePrimarySelectedCandidates": int(
            runtime.get("uniquePrimarySelectedCandidates") or 0
        ),
        "notMatureReasons": [
            str(item) for item in conclusion.get("notMatureReasons", [])
        ],
    }


def runtime_repeat_source(spec: str) -> dict[str, Any]:
    adapter_type, path = typed_path(spec)
    source = adapter_maturity.runtime_source(path)
    return {
        "path": str(path),
        "schema": source["schema"],
        "adapterType": adapter_type,
        "clean": bool(source["clean"]),
        "runs": int(source["runs"]),
        "failedRuns": int(source["failedRuns"]),
        "workloadAttempted": int(source["workloadAttempted"]),
        "workloadFailure": int(source["workloadFailure"]),
        "tcpFlowFailed": int(source["tcpFlowFailed"]),
        "tcpFlowStageFailed": int(source["tcpFlowStageFailed"]),
        "qualityBoundCandidateSets": int(source["qualityBoundCandidateSets"]),
        "qualityBoundSelectedWithQuality": int(source["qualityBoundSelectedWithQuality"]),
        "qualityBoundSelectedBehind": int(source["qualityBoundSelectedBehind"]),
        "runtimeTargetHosts": source.get("runtimeTargetHosts", []),
        "runtimeTargetHostCount": int(source.get("runtimeTargetHostCount") or 0),
        "primarySelectedCandidates": source.get("primarySelectedCandidates", []),
        "uniquePrimarySelectedCandidates": int(
            source.get("uniquePrimarySelectedCandidates") or 0
        ),
    }


def product_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "clean": bool(sources) and all(source["clean"] for source in sources),
        "statuses": sorted({source["status"] for source in sources if source["status"]}),
        "workloadAttempted": sum(source["workloadAttempted"] for source in sources),
        "workloadFailure": sum(source["workloadFailure"] for source in sources),
        "pairedWindows": sum(source["pairedWindows"] for source in sources),
        "pairedEntries": sum(source["pairedEntries"] for source in sources),
        "sources": sources,
    }


def readiness_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "ready": bool(sources) and all(source["readyForMainlineAdapterWork"] for source in sources),
        "statuses": sorted({source["status"] for source in sources if source["status"]}),
        "productRuns": sum(source["productRuns"] for source in sources),
        "productFailed": sum(source["productFailed"] for source in sources),
        "runtimeRuns": sum(source["runtimeRuns"] for source in sources),
        "sources": sources,
    }


def maturity_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "candidateMature": bool(sources) and all(source["candidateMature"] for source in sources),
        "promotionEvaluationEligible": bool(sources)
        and all(source["promotionEvaluationEligible"] for source in sources),
        "statuses": sorted({source["status"] for source in sources if source["status"]}),
        "runtimeRuns": sum(source["runtimeRuns"] for source in sources),
        "runtimeWorkloadAttempted": sum(source["runtimeWorkloadAttempted"] for source in sources),
        "runtimeWorkloadFailure": sum(source["runtimeWorkloadFailure"] for source in sources),
        "uniquePrimarySelectedCandidates": max(
            (source["uniquePrimarySelectedCandidates"] for source in sources),
            default=0,
        ),
        "notMatureReasons": sorted({
            reason
            for source in sources
            for reason in source.get("notMatureReasons", [])
        }),
        "sources": sources,
    }


def runtime_repeat_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    selected = merge_count_rows([
        source.get("primarySelectedCandidates", []) for source in sources
    ])
    target_hosts = {
        host for source in sources for host in source.get("runtimeTargetHosts", [])
    }
    return {
        "sourceCount": len(sources),
        "clean": bool(sources) and all(source["clean"] for source in sources),
        "runs": sum(source["runs"] for source in sources),
        "failedRuns": sum(source["failedRuns"] for source in sources),
        "workloadAttempted": sum(source["workloadAttempted"] for source in sources),
        "workloadFailure": sum(source["workloadFailure"] for source in sources),
        "tcpFlowFailed": sum(source["tcpFlowFailed"] for source in sources),
        "tcpFlowStageFailed": sum(source["tcpFlowStageFailed"] for source in sources),
        "qualityBoundCandidateSets": sum(source["qualityBoundCandidateSets"] for source in sources),
        "qualityBoundSelectedWithQuality": sum(
            source["qualityBoundSelectedWithQuality"] for source in sources
        ),
        "qualityBoundSelectedBehind": sum(source["qualityBoundSelectedBehind"] for source in sources),
        "runtimeTargetHosts": sorted(target_hosts),
        "runtimeTargetHostCount": len(target_hosts),
        "primarySelectedCandidates": count_rows(selected),
        "uniquePrimarySelectedCandidates": len(selected),
        "sources": sources,
    }


def fallback_sources(paths: list[Path]) -> list[dict[str, Any]]:
    return [runtime_fallback_source(path) for path in paths]


def typed_path(spec: str) -> tuple[str, Path]:
    if "=" not in spec:
        return "", Path(spec)
    adapter_type, path = spec.split("=", 1)
    return normalize_type(adapter_type), Path(path)


def normalized_count_map(raw: object) -> dict[str, int]:
    if not isinstance(raw, dict):
        return {}
    result: dict[str, int] = {}
    for key, value in raw.items():
        adapter_type = normalize_type(key)
        if adapter_type:
            result[adapter_type] = result.get(adapter_type, 0) + int(value or 0)
    return dict(sorted(result.items()))


def count_types(types: list[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for adapter_type in types:
        if adapter_type:
            counts[adapter_type] = counts.get(adapter_type, 0) + 1
    return dict(sorted(counts.items()))


def merge_count_maps(maps: list[dict[str, int]]) -> dict[str, int]:
    result: dict[str, int] = {}
    for item in maps:
        for key, value in item.items():
            result[key] = result.get(key, 0) + int(value)
    return dict(sorted(result.items()))


def merge_count_rows(rows: list[list[dict[str, Any]]]) -> dict[str, int]:
    result: dict[str, int] = {}
    for row_set in rows:
        for row in row_set:
            key = str(row.get("key") or "")
            if key:
                result[key] = result.get(key, 0) + int(row.get("count") or 0)
    return dict(sorted(result.items()))


def count_rows(counts: dict[str, int]) -> list[dict[str, Any]]:
    return [
        {"key": key, "count": count}
        for key, count in sorted(counts.items())
        if count > 0
    ]


def normalize_type(raw: object) -> str:
    value = str(raw or "").lower()
    if value in {"shadowsocks", "ss"}:
        return "ss"
    return value


def unique(values: list[str]) -> list[str]:
    result = []
    for value in values:
        if value and value not in result:
            result.append(value)
    return result


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text())
