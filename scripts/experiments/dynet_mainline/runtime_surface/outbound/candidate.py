from __future__ import annotations

from pathlib import Path
from typing import Any

from scripts.lib.jsonio import load_summary
from scripts.lib.nv import count_keys, merge_items
from scripts.lib.privacy import (
    empty_surface_privacy_flags as empty_privacy_flags,
)


CANDIDATE_SCHEMA = "dynet-vm-private-runtime-outbound-candidate-set-surface/v1alpha1"
COUNT_FIELDS = """
runs cleanRuns failedRuns eventReports runtimePass events candidateSets
tcpRouteCandidateSets dialerBoundCandidateSets missingScope missingSelected
missingCandidateCount candidateCountMismatches selectedMissingFromList
selectedMissingFromJson jsonCandidateCountMismatches missingStrategyFields
missingPlan missingGraph missingEgress routeCandidateMissingRoute
dialerCandidateMissingCascadeSelected dialerCandidateMissingCascadeAttempt
jsonParseFailures candidatesWithQuality selectedWithQuality
""".split()


def runtime_candidate_set_source(path: Path) -> dict[str, Any]:
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
        "scopes": count_keys(totals.get("scopes")),
        "candidateCounts": count_keys(totals.get("candidateCounts")),
        "candidateTypes": count_keys(totals.get("candidateTypes")),
        "strategyKeys": count_keys(totals.get("strategyKeys")),
        "selectors": count_keys(totals.get("selectors")),
        "privacy": empty_privacy_flags(),
    }
    source["clean"] = runtime_candidate_set_clean(source)
    return source


def runtime_candidate_set_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "clean": bool(sources) and all(source["clean"] for source in sources),
        "statuses": sorted({source["status"] for source in sources if source["status"]}),
        **{field: sum(source[field] for source in sources) for field in COUNT_FIELDS},
        "classifications": merge_items(sources, "classifications"),
        "scopes": merge_items(sources, "scopes"),
        "candidateCounts": merge_items(sources, "candidateCounts"),
        "candidateTypes": merge_items(sources, "candidateTypes"),
        "strategyKeys": merge_items(sources, "strategyKeys"),
        "selectors": merge_items(sources, "selectors"),
        "sources": sources,
    }


def runtime_candidate_set_clean(source: dict[str, Any]) -> bool:
    return (
        source["schema"] == CANDIDATE_SCHEMA
        and source["status"] == "clean"
        and source["runs"] > 0
        and source["cleanRuns"] == source["runs"]
        and source["failedRuns"] == 0
        and source["eventReports"] == source["runs"]
        and source["runtimePass"] == source["runs"]
        and source["candidateSets"] > 0
        and source["classifications"] == ["clean"]
        and all(source[field] == 0 for field in blocker_fields())
        and not any(source["privacy"].values())
    )


def blocker_fields() -> list[str]:
    return """
missingScope missingSelected missingCandidateCount candidateCountMismatches
selectedMissingFromList selectedMissingFromJson jsonCandidateCountMismatches
missingStrategyFields missingPlan missingGraph missingEgress
routeCandidateMissingRoute dialerCandidateMissingCascadeSelected
dialerCandidateMissingCascadeAttempt jsonParseFailures
""".split()
