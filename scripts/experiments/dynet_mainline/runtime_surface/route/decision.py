from __future__ import annotations

from pathlib import Path
from typing import Any

from scripts.lib.jsonio import load_summary
from scripts.lib.nv import count_keys, merge_items
from scripts.lib.privacy import (
    empty_surface_privacy_flags as empty_privacy_flags,
)


ROUTE_DECISION_SCHEMA = "dynet-vm-private-runtime-route-decision-surface/v1alpha1"
COUNT_FIELDS = [
    "runs", "cleanRuns", "failedRuns", "eventReports", "runtimePass", "events",
    "reportedRouteDecisions", "routeMatchedEvents",
    "routeDecisionCounterMismatches", "tcpRouteMatched", "udpRouteMatched",
    "unknownTransportRouteMatched", "routeMatchedMissingStatus",
    "routeMatchedMissingOutbound", "routeMatchedMissingTransport",
    "tcpRouteMissingFlowId", "tcpRouteMissingSession",
    "tcpRouteGraphSelected", "tcpRouteMissingGraph",
    "tcpRouteGraphWithoutRoute", "udpRouteGraphSelected",
    "udpRouteGraphMismatches", "routeGraphMissingSelected",
    "routeGraphMissingRequested", "planBypassedEvents",
    "planCandidateGraphSelected", "planBypassMissingGraph",
    "planGraphWithoutBypass", "routeCandidateSets",
    "routeCandidateMissingGraph", "routeCandidateMissingSelected",
    "routeCandidateMissingCount",
]


def runtime_route_decision_source(path: Path) -> dict[str, Any]:
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
        "decisionPaths": count_keys(totals.get("decisionPaths")),
        "privacy": empty_privacy_flags(),
    }
    source["clean"] = runtime_route_decision_clean(source)
    return source


def runtime_route_decision_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "clean": bool(sources) and all(source["clean"] for source in sources),
        "statuses": sorted({source["status"] for source in sources if source["status"]}),
        **{field: sum(source[field] for source in sources) for field in COUNT_FIELDS},
        "classifications": merge_items(sources, "classifications"),
        "decisionPaths": merge_items(sources, "decisionPaths"),
        "sources": sources,
    }


def runtime_route_decision_clean(source: dict[str, Any]) -> bool:
    return (
        source["schema"] == ROUTE_DECISION_SCHEMA
        and source["status"] == "clean"
        and source["runs"] > 0
        and source["cleanRuns"] == source["runs"]
        and source["failedRuns"] == 0
        and source["eventReports"] == source["runs"]
        and source["runtimePass"] == source["runs"]
        and source["routeMatchedEvents"] > 0
        and source["classifications"] == ["clean"]
        and all(source[field] == 0 for field in blocker_fields())
        and not any(source["privacy"].values())
    )


def blocker_fields() -> list[str]:
    return [
        "routeDecisionCounterMismatches", "unknownTransportRouteMatched",
        "routeMatchedMissingStatus", "routeMatchedMissingOutbound",
        "routeMatchedMissingTransport", "tcpRouteMissingFlowId",
        "tcpRouteMissingSession", "tcpRouteMissingGraph",
        "tcpRouteGraphWithoutRoute", "udpRouteGraphMismatches",
        "routeGraphMissingSelected", "routeGraphMissingRequested",
        "planBypassMissingGraph", "planGraphWithoutBypass",
        "routeCandidateMissingGraph", "routeCandidateMissingSelected",
        "routeCandidateMissingCount",
    ]
