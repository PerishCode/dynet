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


COMPARE_SCHEMA = "dynet-vm-private-runtime-round-gap-compare/v1alpha1"
COMPARE_STATUSES = {
    "candidate-clean",
    "mechanism-shifted",
    "mechanism-unchanged",
    "packet-terminal-cleared-stage-remains",
    "schedule-lag-separated-outbound-stage-remains",
}


def round_gap_compare_source(path: Path) -> dict[str, Any]:
    summary = load_summary(path)
    baseline = summary.get("baseline") or {}
    candidate = summary.get("candidate") or {}
    conclusion = summary.get("conclusion") or {}
    policy = summary.get("policy") or {}
    source = {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "label": str(summary.get("label") or ""),
        "status": str(conclusion.get("status") or ""),
        "nextAction": str(conclusion.get("nextAction") or ""),
        "baselineStatus": str(baseline.get("status") or ""),
        "candidateStatus": str(candidate.get("status") or ""),
        "baselineRuns": int(baseline.get("runs") or 0),
        "candidateRuns": int(candidate.get("runs") or 0),
        "improvementKeys": count_keys(conclusion.get("improvements")),
        "remainingMechanisms": count_keys(conclusion.get("remainingMechanisms")),
        "plannerPenaltySafe": bool(conclusion.get("plannerPenaltySafe"))
        or bool(policy.get("plannerPenaltySafe")),
        "qualityPenaltySafe": bool(conclusion.get("qualityPenaltySafe"))
        or bool(policy.get("qualityPenaltySafe")),
        "rawDetailKeys": sorted(find_raw_detail_keys(summary, RAW_DETAIL_KEYS)),
        "privacy": empty_privacy_flags(),
    }
    source["clean"] = round_gap_compare_clean(source)
    return source


def round_gap_compare_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "clean": bool(sources) and all(source["clean"] for source in sources),
        "statuses": merge_keys(sources, "status"),
        "baselineStatuses": merge_keys(sources, "baselineStatus"),
        "candidateStatuses": merge_keys(sources, "candidateStatus"),
        "baselineRuns": sum(source["baselineRuns"] for source in sources),
        "candidateRuns": sum(source["candidateRuns"] for source in sources),
        "improvementKeys": merge_items(sources, "improvementKeys"),
        "remainingMechanisms": merge_items(sources, "remainingMechanisms"),
        "rawDetailKeys": merge_items(sources, "rawDetailKeys"),
        "sources": sources,
    }


def round_gap_compare_clean(source: dict[str, Any]) -> bool:
    return (
        source["schema"] == COMPARE_SCHEMA
        and source["status"] in COMPARE_STATUSES
        and bool(source["nextAction"])
        and bool(source["baselineStatus"])
        and bool(source["candidateStatus"])
        and source["baselineRuns"] > 0
        and source["candidateRuns"] > 0
        and not source["plannerPenaltySafe"]
        and not source["qualityPenaltySafe"]
        and not source["rawDetailKeys"]
        and not any(source["privacy"].values())
    )
