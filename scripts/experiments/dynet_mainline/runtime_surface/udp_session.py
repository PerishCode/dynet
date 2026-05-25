from __future__ import annotations

from pathlib import Path
from typing import Any

from scripts.lib.jsonio import load_summary
from scripts.lib.nv import count_keys, merge_items
from scripts.lib.privacy import (
    empty_surface_privacy_flags as empty_privacy_flags,
)


UDP_SESSION_SCHEMA = "dynet-vm-private-runtime-udp-session-surface/v1alpha1"
COUNT_FIELDS = [
    "runs",
    "cleanRuns",
    "failedRuns",
    "sessions",
    "reportedSessions",
    "startedSessions",
    "attributedSessions",
    "connectingSessions",
    "establishedSessions",
    "payloadSentSessions",
    "payloadReceivedSessions",
    "payloadBidirectionalSessions",
    "closedSessions",
    "closedWithByteTotals",
    "failedSessions",
    "deniedSessions",
    "failedEvents",
    "deniedEvents",
    "sentEvents",
    "receivedEvents",
    "sentBytes",
    "receivedBytes",
    "reportedUpstreamBytes",
    "reportedDownstreamBytes",
    "reportedFailures",
    "reportedDroppedPackets",
]


def runtime_udp_session_source(path: Path) -> dict[str, Any]:
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
        "closedByReason": count_keys(totals.get("closedByReason")),
        "failedByErrorType": count_keys(totals.get("failedByErrorType")),
        "deniedByErrorType": count_keys(totals.get("deniedByErrorType")),
        "privacy": empty_privacy_flags(),
    }
    source["clean"] = runtime_udp_session_clean(source)
    return source


def runtime_udp_session_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "clean": bool(sources) and all(source["clean"] for source in sources),
        "statuses": sorted({source["status"] for source in sources if source["status"]}),
        **{field: sum(source[field] for source in sources) for field in COUNT_FIELDS},
        "classifications": merge_items(sources, "classifications"),
        "closedByReason": merge_items(sources, "closedByReason"),
        "failedByErrorType": merge_items(sources, "failedByErrorType"),
        "deniedByErrorType": merge_items(sources, "deniedByErrorType"),
        "sources": sources,
    }


def runtime_udp_session_clean(source: dict[str, Any]) -> bool:
    sessions = source["sessions"]
    return (
        source["schema"] == UDP_SESSION_SCHEMA
        and source["status"] == "clean"
        and source["runs"] > 0
        and source["cleanRuns"] == source["runs"]
        and source["failedRuns"] == 0
        and source["classifications"] == ["clean"]
        and sessions > 0
        and source["reportedSessions"] == sessions
        and source["startedSessions"] == sessions
        and source["attributedSessions"] == sessions
        and source["connectingSessions"] == sessions
        and source["establishedSessions"] == sessions
        and source["payloadSentSessions"] == sessions
        and source["payloadReceivedSessions"] == sessions
        and source["payloadBidirectionalSessions"] == sessions
        and source["sentBytes"] == source["reportedUpstreamBytes"]
        and source["receivedBytes"] == source["reportedDownstreamBytes"]
        and source["failedSessions"] == 0
        and source["deniedSessions"] == 0
        and source["failedEvents"] == 0
        and source["deniedEvents"] == 0
        and source["reportedFailures"] == 0
        and source["reportedDroppedPackets"] == 0
        and not any(source["privacy"].values())
    )
