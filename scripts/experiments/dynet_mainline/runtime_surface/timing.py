from __future__ import annotations

from pathlib import Path
from typing import Any

from scripts.lib.jsonio import load_summary
from scripts.lib.nv import count_keys, merge_items
from scripts.lib.privacy import (
    empty_surface_privacy_flags as empty_privacy_flags,
)


TIMING_SURFACE_SCHEMA = "dynet-vm-private-runtime-timing-surface/v1alpha1"


def runtime_timing_surface_source(path: Path) -> dict[str, Any]:
    summary = load_summary(path)
    totals = summary.get("totals") or {}
    conclusion = summary.get("conclusion") or {}
    source = {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "label": str(summary.get("label") or ""),
        "status": str(conclusion.get("status") or ""),
        "runs": int(totals.get("runs") or 0),
        "cleanRuns": int(totals.get("cleanRuns") or 0),
        "failedRuns": int(totals.get("failedRuns") or 0),
        "flows": int(totals.get("flows") or 0),
        "startedFlows": int(totals.get("startedFlows") or 0),
        "attributedFlows": int(totals.get("attributedFlows") or 0),
        "connectingFlows": int(totals.get("connectingFlows") or 0),
        "establishedFlows": int(totals.get("establishedFlows") or 0),
        "firstPayloadFlows": int(totals.get("firstPayloadFlows") or 0),
        "firstDownstreamFlows": int(totals.get("firstDownstreamFlows") or 0),
        "closedFlows": int(totals.get("closedFlows") or 0),
        "failedFlows": int(totals.get("failedFlows") or 0),
        "orderedFlows": int(totals.get("orderedFlows") or 0),
        "closedP95Ms": timing_value(totals, "closedMs", "p95"),
        "firstDownstreamP95Ms": timing_value(totals, "firstDownstreamMs", "p95"),
        "classifications": count_keys(totals.get("classifications")),
        "privacy": empty_privacy_flags(),
    }
    source["clean"] = runtime_timing_surface_clean(source)
    return source


def runtime_timing_surface_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "clean": bool(sources) and all(source["clean"] for source in sources),
        "statuses": sorted({source["status"] for source in sources if source["status"]}),
        "runs": sum(source["runs"] for source in sources),
        "cleanRuns": sum(source["cleanRuns"] for source in sources),
        "failedRuns": sum(source["failedRuns"] for source in sources),
        "flows": sum(source["flows"] for source in sources),
        "startedFlows": sum(source["startedFlows"] for source in sources),
        "attributedFlows": sum(source["attributedFlows"] for source in sources),
        "connectingFlows": sum(source["connectingFlows"] for source in sources),
        "establishedFlows": sum(source["establishedFlows"] for source in sources),
        "firstPayloadFlows": sum(source["firstPayloadFlows"] for source in sources),
        "firstDownstreamFlows": sum(
            source["firstDownstreamFlows"] for source in sources
        ),
        "closedFlows": sum(source["closedFlows"] for source in sources),
        "failedFlows": sum(source["failedFlows"] for source in sources),
        "orderedFlows": sum(source["orderedFlows"] for source in sources),
        "closedP95Ms": max([source["closedP95Ms"] for source in sources], default=0),
        "firstDownstreamP95Ms": max(
            [source["firstDownstreamP95Ms"] for source in sources],
            default=0,
        ),
        "classifications": merge_items(sources, "classifications"),
        "sources": sources,
    }


def runtime_timing_surface_clean(source: dict[str, Any]) -> bool:
    flows = source["flows"]
    return (
        source["schema"] == TIMING_SURFACE_SCHEMA
        and source["status"] == "clean"
        and source["runs"] > 0
        and source["cleanRuns"] == source["runs"]
        and source["failedRuns"] == 0
        and source["classifications"] == ["clean"]
        and flows > 0
        and source["startedFlows"] == flows
        and source["attributedFlows"] == flows
        and source["connectingFlows"] == flows
        and source["establishedFlows"] == flows
        and source["firstPayloadFlows"] == flows
        and source["firstDownstreamFlows"] == flows
        and source["closedFlows"] == flows
        and source["failedFlows"] == 0
        and source["orderedFlows"] == flows
        and not any(source["privacy"].values())
    )


def timing_value(totals: dict[str, Any], key: str, value: str) -> int:
    timings = totals.get("timings") or {}
    return int(((timings.get(key) or {}).get(value)) or 0)
