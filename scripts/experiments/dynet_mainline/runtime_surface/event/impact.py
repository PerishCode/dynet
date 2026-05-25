from __future__ import annotations

from pathlib import Path
from typing import Any

from scripts.lib.jsonio import load_summary
from scripts.lib.nv import count_keys, merge_items
from scripts.lib.privacy import (
    empty_surface_privacy_flags as empty_privacy_flags,
)


IMPACT_SCHEMA = "dynet-vm-private-runtime-failure-impact-surface/v1alpha1"
COUNT_FIELDS = """
runs cleanRuns failedRuns eventReports runtimePass events failureSignals
classifiedSignals unknownSignals missingEvidenceSignals recoveredSignals
controlledSignals unboundedSignals nodeSuspectSignals recoveredNodeSuspectSignals
maskedNodeSuspectSignals unboundedNodeSuspectSignals experimentShapeSignals
unboundedExperimentShapeSignals targetOrProbeSignals dynetInfraSignals
planSuspectSignals unsafePenaltySignals terminalFailureSignals
""".split()


def runtime_failure_impact_source(path: Path) -> dict[str, Any]:
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
        "categories": count_keys(totals.get("categories")),
        "surfaces": count_keys(totals.get("surfaces")),
        "impacts": count_keys(totals.get("impacts")),
        "missingEvidence": count_keys(totals.get("missingEvidence")),
        "privacy": empty_privacy_flags(),
    }
    source["clean"] = runtime_failure_impact_clean(source)
    return source


def runtime_failure_impact_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "clean": bool(sources) and all(source["clean"] for source in sources),
        "statuses": sorted({source["status"] for source in sources if source["status"]}),
        **{field: sum(source[field] for source in sources) for field in COUNT_FIELDS},
        "classifications": merge_items(sources, "classifications"),
        "categories": merge_items(sources, "categories"),
        "surfaces": merge_items(sources, "surfaces"),
        "impacts": merge_items(sources, "impacts"),
        "missingEvidence": merge_items(sources, "missingEvidence"),
        "sources": sources,
    }


def runtime_failure_impact_clean(source: dict[str, Any]) -> bool:
    return (
        source["schema"] == IMPACT_SCHEMA
        and source["status"] == "clean"
        and source["runs"] > 0
        and source["cleanRuns"] == source["runs"]
        and source["failedRuns"] == 0
        and source["eventReports"] == source["runs"]
        and source["runtimePass"] == source["runs"]
        and source["failureSignals"] > 0
        and source["classifiedSignals"] == source["failureSignals"]
        and source["classifications"] == ["clean"]
        and all(source[field] == 0 for field in blocker_fields())
        and not any(source["privacy"].values())
    )


def blocker_fields() -> list[str]:
    return """
unknownSignals missingEvidenceSignals unboundedNodeSuspectSignals
unboundedExperimentShapeSignals planSuspectSignals unsafePenaltySignals
""".split()
