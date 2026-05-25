from __future__ import annotations

from pathlib import Path
from typing import Any

from scripts.lib.jsonio import load_summary
from scripts.lib.nv import count_keys, merge_items
from scripts.lib.privacy import (
    empty_surface_privacy_flags as empty_privacy_flags,
)


STAGE_CHAIN_SCHEMA = "dynet-vm-private-runtime-outbound-stage-chain-surface/v1alpha1"
COUNT_FIELDS = """
runs cleanRuns failedRuns eventReports runtimePass events stageEvents
attempts knownProfileAttempts unknownProfileAttempts successAttempts
failedAttempts successMissingRequiredStages failedMissingFailureStage
stageStatusMissing stageKindMissing stageNameMissing stageReferenceMissing
stageOutboundMissing stageElapsedMissing stageFailureDispositionMissing
stageFailureErrorTypeMissing
""".split()


def runtime_stage_chain_source(path: Path) -> dict[str, Any]:
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
        "attemptProfiles": count_keys(totals.get("attemptProfiles")),
        "stageProfiles": count_keys(totals.get("stageProfiles")),
        "missingRequiredStages": count_keys(totals.get("missingRequiredStages")),
        "failedStageProfiles": count_keys(totals.get("failedStageProfiles")),
        "privacy": empty_privacy_flags(),
    }
    source["clean"] = runtime_stage_chain_clean(source)
    return source


def runtime_stage_chain_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "clean": bool(sources) and all(source["clean"] for source in sources),
        "statuses": sorted({source["status"] for source in sources if source["status"]}),
        **{field: sum(source[field] for source in sources) for field in COUNT_FIELDS},
        "classifications": merge_items(sources, "classifications"),
        "attemptProfiles": merge_items(sources, "attemptProfiles"),
        "stageProfiles": merge_items(sources, "stageProfiles"),
        "missingRequiredStages": merge_items(sources, "missingRequiredStages"),
        "failedStageProfiles": merge_items(sources, "failedStageProfiles"),
        "sources": sources,
    }


def runtime_stage_chain_clean(source: dict[str, Any]) -> bool:
    return (
        source["schema"] == STAGE_CHAIN_SCHEMA
        and source["status"] == "clean"
        and source["runs"] > 0
        and source["cleanRuns"] == source["runs"]
        and source["failedRuns"] == 0
        and source["eventReports"] == source["runs"]
        and source["runtimePass"] == source["runs"]
        and source["attempts"] > 0
        and source["knownProfileAttempts"] == source["attempts"]
        and source["stageEvents"] > 0
        and source["classifications"] == ["clean"]
        and all(source[field] == 0 for field in blocker_fields())
        and not any(source["privacy"].values())
    )


def blocker_fields() -> list[str]:
    return """
unknownProfileAttempts successMissingRequiredStages failedMissingFailureStage
stageStatusMissing stageKindMissing stageNameMissing stageReferenceMissing
stageOutboundMissing stageElapsedMissing stageFailureDispositionMissing
stageFailureErrorTypeMissing
""".split()
