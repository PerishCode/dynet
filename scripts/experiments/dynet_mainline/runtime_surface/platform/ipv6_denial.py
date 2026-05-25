from __future__ import annotations

from pathlib import Path
from typing import Any

from scripts.lib.jsonio import load_summary
from scripts.lib.nv import count_keys, merge_items
from scripts.lib.privacy import (
    empty_surface_privacy_flags as empty_privacy_flags,
)


IPV6_DENIAL_SCHEMA = "dynet-vm-private-runtime-ipv6-denial-surface/v1alpha1"
COUNT_FIELDS = [
    "runs",
    "cleanRuns",
    "failedRuns",
    "denials",
    "reportedIpv6PacketsDenied",
    "ipv6Denials",
    "nonIpv6Denials",
    "missingFieldEvents",
    "flows",
    "startedFlows",
    "establishedFlows",
    "closedFlows",
    "lifecycleCompleteFlows",
    "pathCompleteFlows",
    "payloadBidirectionalFlows",
    "failedFlows",
    "stageFailedFlows",
]


def runtime_ipv6_denial_source(path: Path) -> dict[str, Any]:
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
        "byIpVersion": count_keys(totals.get("byIpVersion")),
        "byProtocol": count_keys(totals.get("byProtocol")),
        "byDestinationPort": count_keys(totals.get("byDestinationPort")),
        "byReasonBucket": count_keys(totals.get("byReasonBucket")),
        "privacy": empty_privacy_flags(),
    }
    source["clean"] = runtime_ipv6_denial_clean(source)
    return source


def runtime_ipv6_denial_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "clean": bool(sources) and all(source["clean"] for source in sources),
        "statuses": sorted({source["status"] for source in sources if source["status"]}),
        **{field: sum(source[field] for source in sources) for field in COUNT_FIELDS},
        "classifications": merge_items(sources, "classifications"),
        "byIpVersion": merge_items(sources, "byIpVersion"),
        "byProtocol": merge_items(sources, "byProtocol"),
        "byDestinationPort": merge_items(sources, "byDestinationPort"),
        "byReasonBucket": merge_items(sources, "byReasonBucket"),
        "sources": sources,
    }


def runtime_ipv6_denial_clean(source: dict[str, Any]) -> bool:
    flows = source["flows"]
    return (
        source["schema"] == IPV6_DENIAL_SCHEMA
        and source["status"] == "clean"
        and source["runs"] > 0
        and source["cleanRuns"] == source["runs"]
        and source["failedRuns"] == 0
        and source["classifications"] == ["clean"]
        and source["denials"] > 0
        and source["reportedIpv6PacketsDenied"] == source["ipv6Denials"]
        and source["ipv6Denials"] == source["denials"]
        and source["nonIpv6Denials"] == 0
        and source["missingFieldEvents"] == 0
        and flows > 0
        and source["startedFlows"] == flows
        and source["establishedFlows"] == flows
        and source["closedFlows"] == flows
        and source["lifecycleCompleteFlows"] == flows
        and source["pathCompleteFlows"] == flows
        and source["payloadBidirectionalFlows"] == flows
        and source["failedFlows"] == 0
        and source["stageFailedFlows"] == 0
        and not any(source["privacy"].values())
    )
