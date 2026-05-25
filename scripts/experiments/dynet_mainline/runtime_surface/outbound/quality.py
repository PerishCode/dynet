from __future__ import annotations

from pathlib import Path
from typing import Any

from scripts.lib.jsonio import load_summary
from scripts.lib.nv import count_keys, merge_items
from scripts.lib.privacy import (
    empty_surface_privacy_flags as empty_privacy_flags,
)


QUALITY_SCHEMA = "dynet-vm-private-runtime-outbound-candidate-quality-surface/v1alpha1"
COUNT_FIELDS = """
runs cleanRuns failedRuns eventReports runtimePass events candidateSets
qualityCandidateSets staticCandidateSets candidateRows qualityRows
candidatesWithQuality selectedWithQuality selectedBest selectedBehind
primaryQualityCandidateSets primarySelectedBest primarySelectedBehind
fallbackQualityCandidateSets fallbackSelectedBest fallbackSelectedBehind
recoveredSelectedBehind unrecoveredSelectedBehind jsonParseFailures
missingQuality missingScore missingReason staleQuality missingMatchScope
selectedMissingQuality
""".split()


def runtime_candidate_quality_source(path: Path) -> dict[str, Any]:
    summary = load_summary(path)
    totals = summary.get("totals") or {}
    conclusion = summary.get("conclusion") or {}
    source = {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "label": str(summary.get("label") or ""),
        "status": str(conclusion.get("status") or ""),
        **{field: int(totals.get(field) or 0) for field in COUNT_FIELDS},
        "classifications": count_keys(totals.get("classifications")),
        "qualityReasons": count_keys(totals.get("qualityReasons")),
        "qualityVerdicts": count_keys(totals.get("qualityVerdicts")),
        "qualityConfidences": count_keys(totals.get("qualityConfidences")),
        "qualityMatchScopes": count_keys(totals.get("qualityMatchScopes")),
        "candidateTypes": count_keys(totals.get("candidateTypes")),
        "privacy": empty_privacy_flags(),
    }
    source["clean"] = runtime_candidate_quality_clean(source)
    return source


def runtime_candidate_quality_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "clean": bool(sources) and all(source["clean"] for source in sources),
        "statuses": sorted({source["status"] for source in sources if source["status"]}),
        **{field: sum(source[field] for source in sources) for field in COUNT_FIELDS},
        "classifications": merge_items(sources, "classifications"),
        "qualityReasons": merge_items(sources, "qualityReasons"),
        "qualityVerdicts": merge_items(sources, "qualityVerdicts"),
        "qualityConfidences": merge_items(sources, "qualityConfidences"),
        "qualityMatchScopes": merge_items(sources, "qualityMatchScopes"),
        "candidateTypes": merge_items(sources, "candidateTypes"),
        "sources": sources,
    }


def runtime_candidate_quality_clean(source: dict[str, Any]) -> bool:
    return (
        source["schema"] == QUALITY_SCHEMA
        and source["status"] == "clean"
        and source["runs"] > 0
        and source["cleanRuns"] == source["runs"]
        and source["failedRuns"] == 0
        and source["eventReports"] == source["runs"]
        and source["runtimePass"] == source["runs"]
        and source["qualityCandidateSets"] > 0
        and source["selectedWithQuality"] == source["qualityCandidateSets"]
        and source["classifications"] == ["clean"]
        and all(source[field] == 0 for field in blocker_fields())
        and not any(source["privacy"].values())
    )


def blocker_fields() -> list[str]:
    return """
jsonParseFailures missingQuality missingScore missingReason staleQuality
missingMatchScope selectedMissingQuality primarySelectedBehind
unrecoveredSelectedBehind
""".split()
