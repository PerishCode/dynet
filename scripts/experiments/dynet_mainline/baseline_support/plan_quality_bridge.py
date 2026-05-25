from __future__ import annotations

import json
from pathlib import Path
from typing import Any


COMPARISON_SCHEMA = "dynet-tunnel-private-plan-quality-comparison/v1alpha1"
INSPECTION_SCHEMA = "dynet-tunnel-private-plan-quality-inspection/v1alpha1"
QUALITY_STATE_SCHEMA = "dynet-outbound-quality-state/v1alpha1"


def plan_quality_bridge_source(path: Path) -> dict[str, Any]:
    summary = load_json(path)
    rows = [
        plan_quality_row(path, item)
        for item in summary.get("rows", [])
        if isinstance(item, dict)
    ]
    source = {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "status": str(summary.get("status") or ""),
        "nextLever": str((summary.get("conclusion") or {}).get("nextLever") or ""),
        "rows": rows,
        "rowCount": len(rows),
        "passedRows": sum(1 for row in rows if row["status"] == "pass"),
        "failedRows": sum(1 for row in rows if row["status"] != "pass"),
        "adapterTypes": sorted({
            item for row in rows for item in row["adapterTypes"] if item
        }),
        "feedbackModes": sorted({
            row["feedbackMode"] for row in rows if row["feedbackMode"]
        }),
        "requestedModes": sorted({
            row["requestedFeedbackMode"]
            for row in rows
            if row["requestedFeedbackMode"]
        }),
        "selectedBehind": sum(row["selectedBehind"] for row in rows),
        "withQuality": sum(row["withQuality"] for row in rows),
        "promotionEligibleRows": sum(
            1 for row in rows if row["promotionEligible"] is True
        ),
        "penaltyObservations": sum(row["penaltyObservations"] for row in rows),
        "privacy": merged_privacy([row["privacy"] for row in rows]),
    }
    source["clean"] = plan_quality_bridge_clean(source)
    return source


def plan_quality_bridge_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "clean": bool(sources) and all(source["clean"] for source in sources),
        "adapterTypes": sorted({
            item for source in sources for item in source["adapterTypes"] if item
        }),
        "feedbackModes": sorted({
            item for source in sources for item in source["feedbackModes"] if item
        }),
        "requestedModes": sorted({
            item for source in sources for item in source["requestedModes"] if item
        }),
        "rows": sum(source["rowCount"] for source in sources),
        "passedRows": sum(source["passedRows"] for source in sources),
        "failedRows": sum(source["failedRows"] for source in sources),
        "selectedBehind": sum(source["selectedBehind"] for source in sources),
        "withQuality": sum(source["withQuality"] for source in sources),
        "promotionEligibleRows": sum(
            source["promotionEligibleRows"] for source in sources
        ),
        "penaltyObservations": sum(
            source["penaltyObservations"] for source in sources
        ),
        "nextLevers": sorted({
            source["nextLever"] for source in sources if source["nextLever"]
        }),
        "sources": sources,
    }


def plan_quality_bridge_clean(source: dict[str, Any]) -> bool:
    return (
        source["schema"] == COMPARISON_SCHEMA
        and source["status"] == "pass"
        and source["rowCount"] >= 2
        and source["passedRows"] == source["rowCount"]
        and source["failedRows"] == 0
        and source["selectedBehind"] == 0
        and source["withQuality"] >= source["rowCount"]
        and set(source["feedbackModes"]) >= {"observe", "penalize"}
        and "auto" in source["requestedModes"]
        and source["promotionEligibleRows"] > 0
        and not any(source["privacy"].values())
        and all(row_clean(row) for row in source["rows"])
    )


def row_clean(row: dict[str, Any]) -> bool:
    return (
        row["inspectionSchema"] == INSPECTION_SCHEMA
        and row["qualityStateSchema"] == QUALITY_STATE_SCHEMA
        and row["status"] == "pass"
        and row["selectedBest"]
        and row["selectedHasMatches"]
        and row["selectedBehind"] == 0
        and row["withQuality"] > 0
        and not any(row["privacy"].values())
    )


def plan_quality_row(base: Path, row: dict[str, Any]) -> dict[str, Any]:
    inspection_path = resolve_path(base, row.get("path"))
    inspection = load_json(inspection_path)
    quality_state_path = resolve_path(
        inspection_path,
        inspection.get("qualityState") or row.get("qualityState"),
    )
    quality_state = load_json(quality_state_path)
    quality = inspection.get("candidateQuality") or {}
    feedback = inspection.get("plannerFeedback") or row
    return {
        "path": str(inspection_path),
        "status": str(inspection.get("status") or row.get("status") or ""),
        "inspectionSchema": str(inspection.get("schema") or ""),
        "inspectionScope": str(inspection.get("inspectionScope") or ""),
        "qualityState": str(quality_state_path),
        "qualityStateSchema": str(quality_state.get("schema") or ""),
        "adapterTypes": adapter_types(inspection),
        "feedbackMode": str(feedback.get("mode") or row.get("feedbackMode") or ""),
        "requestedFeedbackMode": str(
            feedback.get("requestedMode") or row.get("requestedFeedbackMode") or ""
        ),
        "promotionEligible": feedback.get("promotionEligible")
        if "promotionEligible" in feedback
        else row.get("promotionEligible"),
        "penaltyObservations": as_int(
            feedback.get("penaltyObservations")
            if isinstance(feedback, dict)
            else row.get("penaltyObservations")
        ),
        "selectedBest": bool(quality.get("selectedBest")),
        "selectedBehind": int(quality.get("selectedBehind") or 0),
        "selectedHasMatches": bool(quality.get("selectedHasMatches")),
        "withQuality": int(quality.get("withQuality") or 0),
        "privacy": merged_privacy([
            privacy_flags(inspection),
            privacy_flags(quality_state),
        ]),
    }


def adapter_types(inspection: dict[str, Any]) -> list[str]:
    metadata = inspection.get("metadata") or {}
    rows = metadata.get("candidates") or []
    if not rows:
        rows = ((inspection.get("candidateQuality") or {}).get("candidates")) or []
    return sorted({
        str(item.get("type"))
        for item in rows
        if isinstance(item, dict) and item.get("type")
    })


def resolve_path(base: Path, raw: Any) -> Path:
    path = Path(str(raw or ""))
    if path.exists() or path.is_absolute():
        return path
    if base.is_dir():
        return base / path
    return base.parent / path


def as_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def merged_privacy(items: list[dict[str, bool]]) -> dict[str, bool]:
    flags = empty_privacy()
    for item in items:
        for key, value in item.items():
            flags[key] = flags.get(key, False) or value
    return flags


def privacy_flags(summary: dict[str, Any]) -> dict[str, bool]:
    privacy = summary.get("privacy") or {}
    return {
        "rawLogsStored": bool(privacy.get("rawLogsStored")),
        "rawPacketsStored": bool(privacy.get("rawPacketsStored")),
        "rawSecretsStored": bool(privacy.get("rawSecretsStored")),
        "responseBodiesStored": bool(privacy.get("responseBodiesStored"))
        or bool(privacy.get("rawResponseBodiesStored")),
        "rawResponseHeadersStored": bool(privacy.get("rawResponseHeadersStored"))
        or bool(privacy.get("responseHeadersStored")),
        "identityInformationSent": bool(privacy.get("identityInformationSent")),
        "cookiesSent": bool(privacy.get("cookiesSent")),
        "authorizationSent": bool(privacy.get("authorizationSent")),
        "accountStateStored": bool(privacy.get("accountStateStored")),
        "rawPlanStored": bool(privacy.get("rawPlanStored")),
    }


def empty_privacy() -> dict[str, bool]:
    return {
        "rawLogsStored": False,
        "rawPacketsStored": False,
        "rawSecretsStored": False,
        "responseBodiesStored": False,
        "rawResponseHeadersStored": False,
        "identityInformationSent": False,
        "cookiesSent": False,
        "authorizationSent": False,
        "accountStateStored": False,
        "rawPlanStored": False,
    }


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text())
