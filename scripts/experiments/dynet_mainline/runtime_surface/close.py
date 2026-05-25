from __future__ import annotations

from pathlib import Path
from typing import Any

from scripts.lib.jsonio import load_summary
from scripts.lib.nv import count_keys, merge_items
from scripts.lib.privacy import (
    empty_surface_privacy_flags as empty_privacy_flags,
)


CLOSE_SURFACE_SCHEMA = "dynet-vm-private-runtime-close-surface/v1alpha1"


def runtime_close_surface_source(path: Path) -> dict[str, Any]:
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
        "establishedFlows": int(totals.get("establishedFlows") or 0),
        "closedFlows": int(totals.get("closedFlows") or 0),
        "failedFlows": int(totals.get("failedFlows") or 0),
        "terminalEvents": int(totals.get("terminalEvents") or 0),
        "closedReasonFlows": int(totals.get("closedReasonFlows") or 0),
        "closedWithByteTotals": int(totals.get("closedWithByteTotals") or 0),
        "payloadBidirectionalFlows": int(totals.get("payloadBidirectionalFlows") or 0),
        "payloadCloseConsistent": int(totals.get("payloadCloseConsistent") or 0),
        "lifecycleCompleteFlows": int(totals.get("lifecycleCompleteFlows") or 0),
        "pathCompleteFlows": int(totals.get("pathCompleteFlows") or 0),
        "closedWithoutPayloadFlows": int(totals.get("closedWithoutPayloadFlows") or 0),
        "duplicateClosedFlows": int(totals.get("duplicateClosedFlows") or 0),
        "classifications": count_keys(totals.get("classifications")),
        "closedByReason": count_keys(totals.get("closedByReason")),
        "failedBySurface": count_keys(totals.get("failedBySurface")),
        "privacy": empty_privacy_flags(),
    }
    source["clean"] = runtime_close_surface_clean(source)
    return source


def runtime_close_surface_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "clean": bool(sources) and all(source["clean"] for source in sources),
        "statuses": sorted({source["status"] for source in sources if source["status"]}),
        "runs": sum(source["runs"] for source in sources),
        "cleanRuns": sum(source["cleanRuns"] for source in sources),
        "failedRuns": sum(source["failedRuns"] for source in sources),
        "flows": sum(source["flows"] for source in sources),
        "startedFlows": sum(source["startedFlows"] for source in sources),
        "establishedFlows": sum(source["establishedFlows"] for source in sources),
        "closedFlows": sum(source["closedFlows"] for source in sources),
        "failedFlows": sum(source["failedFlows"] for source in sources),
        "terminalEvents": sum(source["terminalEvents"] for source in sources),
        "closedReasonFlows": sum(source["closedReasonFlows"] for source in sources),
        "closedWithByteTotals": sum(
            source["closedWithByteTotals"] for source in sources
        ),
        "payloadBidirectionalFlows": sum(
            source["payloadBidirectionalFlows"] for source in sources
        ),
        "payloadCloseConsistent": sum(
            source["payloadCloseConsistent"] for source in sources
        ),
        "lifecycleCompleteFlows": sum(
            source["lifecycleCompleteFlows"] for source in sources
        ),
        "pathCompleteFlows": sum(source["pathCompleteFlows"] for source in sources),
        "closedWithoutPayloadFlows": sum(
            source["closedWithoutPayloadFlows"] for source in sources
        ),
        "duplicateClosedFlows": sum(
            source["duplicateClosedFlows"] for source in sources
        ),
        "classifications": merge_items(sources, "classifications"),
        "closedByReason": merge_items(sources, "closedByReason"),
        "failedBySurface": merge_items(sources, "failedBySurface"),
        "sources": sources,
    }


def runtime_close_surface_clean(source: dict[str, Any]) -> bool:
    flows = source["flows"]
    return (
        source["schema"] == CLOSE_SURFACE_SCHEMA
        and source["status"] == "clean"
        and source["runs"] > 0
        and source["cleanRuns"] == source["runs"]
        and source["failedRuns"] == 0
        and source["classifications"] == ["clean"]
        and flows > 0
        and source["startedFlows"] == flows
        and source["establishedFlows"] == flows
        and source["closedFlows"] == flows
        and source["terminalEvents"] == flows
        and source["closedReasonFlows"] == flows
        and source["closedWithByteTotals"] == flows
        and source["payloadBidirectionalFlows"] == flows
        and source["payloadCloseConsistent"] == flows
        and source["lifecycleCompleteFlows"] == flows
        and source["pathCompleteFlows"] == flows
        and source["closedWithoutPayloadFlows"] == 0
        and source["duplicateClosedFlows"] == 0
        and source["failedFlows"] == 0
        and not any(source["privacy"].values())
    )
