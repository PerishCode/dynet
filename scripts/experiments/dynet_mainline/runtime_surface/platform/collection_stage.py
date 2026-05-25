from __future__ import annotations

from pathlib import Path
from typing import Any

from scripts.lib.jsonio import load_summary
from scripts.lib.nv import count_keys, merge_items


COLLECTION_STAGE_SCHEMA = "dynet-vm-private-runtime-collection-stage-surface/v1alpha1"
COUNT_FIELDS = [
    "runs",
    "cleanRuns",
    "failedRuns",
    "stageReports",
    "stageCount",
    "stagePassed",
    "stageFailed",
    "requiredStages",
    "requiredPassed",
    "requiredMissing",
    "collectArtifactExpected",
    "collectArtifactPresent",
    "collectStageExpected",
    "collectStagePassed",
    "collectStageMissing",
    "orderViolations",
    "cleanupLast",
    "timingFieldsComplete",
    "unsafePrivacyFlags",
]


def runtime_collection_stage_source(path: Path) -> dict[str, Any]:
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
        "stageNames": count_keys(totals.get("stageNames")),
        "missingRequiredStages": count_keys(totals.get("missingRequiredStages")),
        "missingCollectStages": count_keys(totals.get("missingCollectStages")),
        "missingArtifacts": count_keys(totals.get("missingArtifacts")),
        "unsafeFlagNames": count_keys(totals.get("unsafeFlagNames")),
    }
    source["privacy"] = privacy_flags(source)
    source["clean"] = runtime_collection_stage_clean(source)
    return source


def runtime_collection_stage_summary(
    sources: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "clean": bool(sources) and all(source["clean"] for source in sources),
        "statuses": sorted({source["status"] for source in sources if source["status"]}),
        **{field: sum(source[field] for source in sources) for field in COUNT_FIELDS},
        "classifications": merge_items(sources, "classifications"),
        "stageNames": merge_items(sources, "stageNames"),
        "missingRequiredStages": merge_items(sources, "missingRequiredStages"),
        "missingCollectStages": merge_items(sources, "missingCollectStages"),
        "missingArtifacts": merge_items(sources, "missingArtifacts"),
        "unsafeFlagNames": merge_items(sources, "unsafeFlagNames"),
        "sources": sources,
    }


def runtime_collection_stage_clean(source: dict[str, Any]) -> bool:
    runs = source["runs"]
    return (
        source["schema"] == COLLECTION_STAGE_SCHEMA
        and source["status"] == "clean"
        and runs > 0
        and source["cleanRuns"] == runs
        and source["failedRuns"] == 0
        and source["classifications"] == ["clean"]
        and source["stageReports"] == runs
        and source["stageFailed"] == 0
        and source["requiredMissing"] == 0
        and source["collectArtifactPresent"] == source["collectArtifactExpected"]
        and source["collectStagePassed"] == source["collectStageExpected"]
        and source["collectStageMissing"] == 0
        and source["orderViolations"] == 0
        and source["cleanupLast"] == runs
        and source["timingFieldsComplete"] == source["stageCount"]
        and source["unsafePrivacyFlags"] == 0
        and not any(source["privacy"].values())
    )


def privacy_flags(source: dict[str, Any]) -> dict[str, bool]:
    names = set(source["unsafeFlagNames"])
    return {
        "rawLogsStored": has_flag(names, "rawLogsStored"),
        "rawPacketsStored": has_flag(names, "rawPacketsStored"),
        "rawSecretsStored": has_flag(names, "rawSecretsStored"),
        "responseBodiesStored": has_flag(names, "responseBodiesStored")
        or has_flag(names, "rawResponseBodiesStored"),
        "identityInformationSent": has_flag(names, "identityInformationSent"),
        "cookiesSent": has_flag(names, "cookiesSent"),
        "authorizationSent": has_flag(names, "authorizationSent"),
        "rawResponseHeadersStored": has_flag(names, "responseHeadersStored")
        or has_flag(names, "rawResponseHeadersStored"),
        "accountStateStored": has_flag(names, "accountStateStored"),
    }


def has_flag(names: set[str], flag: str) -> bool:
    return any(name.endswith(f".{flag}") for name in names)
