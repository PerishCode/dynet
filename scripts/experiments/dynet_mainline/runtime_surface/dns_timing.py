from __future__ import annotations

from pathlib import Path
from typing import Any

from scripts.lib.jsonio import load_summary
from scripts.lib.nv import count_keys, merge_items
from scripts.lib.privacy import (
    empty_surface_privacy_flags as empty_privacy_flags,
)


DNS_TIMING_SCHEMA = "dynet-vm-private-runtime-dns-timing-surface/v1alpha1"


def runtime_dns_timing_source(path: Path) -> dict[str, Any]:
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
        "queries": int(totals.get("queries") or 0),
        "receivedQueries": int(totals.get("receivedQueries") or 0),
        "completedQueries": int(totals.get("completedQueries") or 0),
        "failedQueries": int(totals.get("failedQueries") or 0),
        "queriesWithRecords": int(totals.get("queriesWithRecords") or 0),
        "records": int(totals.get("records") or 0),
        "orderedQueries": int(totals.get("orderedQueries") or 0),
        "completedWithElapsed": int(totals.get("completedWithElapsed") or 0),
        "resolveP95Ms": timing_value(totals, "resolveMs", "p95"),
        "reportedElapsedP95Ms": timing_value(totals, "reportedElapsedMs", "p95"),
        "classifications": count_keys(totals.get("classifications")),
        "privacy": empty_privacy_flags(),
    }
    source["clean"] = runtime_dns_timing_clean(source)
    return source


def runtime_dns_timing_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "clean": bool(sources) and all(source["clean"] for source in sources),
        "statuses": sorted({source["status"] for source in sources if source["status"]}),
        "runs": sum(source["runs"] for source in sources),
        "cleanRuns": sum(source["cleanRuns"] for source in sources),
        "failedRuns": sum(source["failedRuns"] for source in sources),
        "queries": sum(source["queries"] for source in sources),
        "receivedQueries": sum(source["receivedQueries"] for source in sources),
        "completedQueries": sum(source["completedQueries"] for source in sources),
        "failedQueries": sum(source["failedQueries"] for source in sources),
        "queriesWithRecords": sum(source["queriesWithRecords"] for source in sources),
        "records": sum(source["records"] for source in sources),
        "orderedQueries": sum(source["orderedQueries"] for source in sources),
        "completedWithElapsed": sum(source["completedWithElapsed"] for source in sources),
        "resolveP95Ms": max([source["resolveP95Ms"] for source in sources], default=0),
        "reportedElapsedP95Ms": max(
            [source["reportedElapsedP95Ms"] for source in sources],
            default=0,
        ),
        "classifications": merge_items(sources, "classifications"),
        "sources": sources,
    }


def runtime_dns_timing_clean(source: dict[str, Any]) -> bool:
    queries = source["queries"]
    return (
        source["schema"] == DNS_TIMING_SCHEMA
        and source["status"] == "clean"
        and source["runs"] > 0
        and source["cleanRuns"] == source["runs"]
        and source["failedRuns"] == 0
        and source["classifications"] == ["clean"]
        and queries > 0
        and source["receivedQueries"] == queries
        and source["completedQueries"] == queries
        and source["failedQueries"] == 0
        and source["queriesWithRecords"] == queries
        and source["orderedQueries"] == queries
        and source["completedWithElapsed"] == queries
        and not any(source["privacy"].values())
    )


def timing_value(totals: dict[str, Any], key: str, value: str) -> int:
    timings = totals.get(key) or {}
    return int(timings.get(value) or 0)
