from __future__ import annotations

from typing import Any


def pressure_boundaries(sources: list[dict[str, Any]]) -> dict[str, Any]:
    fresh = sources_by_freshness(sources, "fresh-config")
    saved = sources_by_freshness(sources, "saved-config-drift")
    legacy = [
        source
        for source in sources
        if source_freshness(source) not in {"fresh-config", "saved-config-drift"}
    ]
    actionable = fresh or [
        source
        for source in sources
        if source_freshness(source) != "saved-config-drift"
    ]
    return {
        "actionable": pressure_boundary(
            actionable,
            "fresh-config" if fresh else "exclude-saved-config-drift",
            excluded_labels(sources, actionable),
        ),
        "allSources": pressure_boundary(sources, "all", []),
        "freshConfig": pressure_boundary(
            fresh,
            "fresh-config",
            excluded_labels(sources, fresh),
        ),
        "savedConfigDrift": pressure_boundary(
            saved,
            "saved-config-drift",
            excluded_labels(sources, saved),
        ),
        "legacyOrUnspecified": pressure_boundary(
            legacy,
            "legacy-or-unspecified",
            excluded_labels(sources, legacy),
        ),
    }


def actionable_pressure_conclusion(boundaries: dict[str, Any]) -> dict[str, Any]:
    boundary = boundaries.get("actionable") or {}
    all_boundary = boundaries.get("allSources") or {}
    fresh = boundaries.get("freshConfig") or {}
    saved_drift = boundaries.get("savedConfigDrift") or {}
    status = str(boundary.get("status") or "not-evaluated")
    read_failures = boundary_read_failures(boundary)
    all_failures = boundary_read_failures(all_boundary)
    excluded_failures = max(0, all_failures - read_failures)
    saved_drift_failures = boundary_read_failures(saved_drift)
    has_fresh = int(fresh.get("sourceCount") or 0) > 0
    if status == "not-evaluated":
        conclusion_status = "not-evaluated"
        action = "collect-paired-read-surface-inputs"
    elif status == "no-dynet-read-failure-in-scope":
        if has_fresh and excluded_failures > 0:
            conclusion_status = "fresh-config-clean-noncurrent-controls-excluded"
            action = "exclude-stale-config-controls-from-pressure-bisection"
        elif excluded_failures > 0:
            conclusion_status = "actionable-clean-with-excluded-failures"
            action = "classify-excluded-controls-before-policy"
        else:
            conclusion_status = "actionable-pressure-clean"
            action = "observe-only"
    elif status == "bracketed-clean-above-failure":
        conclusion_status = "actionable-pressure-bracketed"
        action = "bisect-pressure-boundary"
    elif status == "unbracketed-failure":
        conclusion_status = "actionable-pressure-unbracketed"
        action = "collect-clean-control-or-refresh-current-config"
    else:
        conclusion_status = "actionable-pressure-needs-investigation"
        action = "continue-attribution"
    return {
        "status": conclusion_status,
        "action": action,
        "pressureBoundaryStatus": status,
        "configFilter": boundary.get("configFilter"),
        "scope": boundary.get("scope"),
        "sourceCount": int(boundary.get("sourceCount") or 0),
        "readFailureCount": read_failures,
        "excludedReadFailureCount": excluded_failures,
        "savedConfigDriftReadFailureCount": saved_drift_failures,
        "maxFailingStaggerMs": boundary.get("maxFailingStaggerMs"),
        "minCleanStaggerAboveFailureMs": boundary.get(
            "minCleanStaggerAboveFailureMs"
        ),
        "boundaryGapMs": boundary.get("boundaryGapMs"),
        "plannerFeedback": "none",
        "qualityFeedback": "none",
        "runtimePolicy": "do-not-change-from-this-artifact-alone",
    }


def pressure_boundary(
    sources: list[dict[str, Any]],
    config_filter: str = "all",
    excluded: list[str] | None = None,
) -> dict[str, Any]:
    rows = boundary_rows(sources)
    failing = [row for row in rows if row["readFailures"] > 0]
    clean = [row for row in rows if is_dynet_clean(row)]
    max_failing = max((row["staggerMs"] for row in failing), default=None)
    clean_above = [
        row for row in clean
        if max_failing is not None and row["staggerMs"] > max_failing
    ]
    min_clean_above = min((row["staggerMs"] for row in clean_above), default=None)
    return {
        "scope": "parallel-clash-first-dynet-second",
        "configFilter": config_filter,
        "sourceCount": len(sources),
        "excludedSourceLabels": excluded or [],
        "status": boundary_status(rows, failing, min_clean_above),
        "maxFailingStaggerMs": max_failing,
        "minCleanStaggerAboveFailureMs": min_clean_above,
        "boundaryGapMs": boundary_gap(max_failing, min_clean_above),
        "failingStaggerMs": [row["staggerMs"] for row in failing],
        "cleanStaggerMs": [row["staggerMs"] for row in clean],
        "cleanAboveFailureWindowCount": len(clean_above),
        "rows": rows,
    }


def sources_by_freshness(
    sources: list[dict[str, Any]],
    freshness: str,
) -> list[dict[str, Any]]:
    return [source for source in sources if source_freshness(source) == freshness]


def source_freshness(source: dict[str, Any]) -> str:
    value = str(source.get("configFreshness") or "")
    if value:
        return value
    label = str(source.get("label") or "")
    if "fresh-config" in label:
        return "fresh-config"
    if "saved-config-drift" in label:
        return "saved-config-drift"
    return "legacy-or-unspecified"


def excluded_labels(
    all_sources: list[dict[str, Any]],
    included_sources: list[dict[str, Any]],
) -> list[str]:
    included = {id(source) for source in included_sources}
    return sorted(
        str(source.get("label") or "")
        for source in all_sources
        if id(source) not in included and source.get("label")
    )


def boundary_rows(sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: dict[int, dict[str, Any]] = {}
    for source in sources:
        label = str(source.get("label") or "")
        for item in source.get("items") or []:
            if not in_boundary_scope(item):
                continue
            stagger = int(item.get("parallelSideStaggerMs") or 0)
            row = rows.setdefault(stagger, empty_row(stagger))
            add_item(row, item, label)
    return [finalize_row(row) for row in sorted(rows.values(), key=lambda item: item["staggerMs"])]


def in_boundary_scope(item: dict[str, Any]) -> bool:
    return (
        item.get("sideMode") == "parallel"
        and item.get("sideOrderKey") == "clash,dynet"
    )


def empty_row(stagger_ms: int) -> dict[str, Any]:
    return {
        "staggerMs": stagger_ms,
        "items": 0,
        "readFailures": 0,
        "dynetFailed": 0,
        "clashFailed": 0,
        "sourceLabels": set(),
    }


def add_item(row: dict[str, Any], item: dict[str, Any], label: str) -> None:
    row["items"] += 1
    row["readFailures"] += int(item.get("readFailureCount") or 0)
    row["dynetFailed"] += int(item.get("dynetStatus") != "pass")
    clash_ok = item.get("clashOk")
    row["clashFailed"] += int(clash_ok is False)
    if label:
        row["sourceLabels"].add(label)


def finalize_row(row: dict[str, Any]) -> dict[str, Any]:
    items = int(row["items"])
    failures = int(row["readFailures"])
    return {
        "staggerMs": int(row["staggerMs"]),
        "items": items,
        "readFailures": failures,
        "readFailureRate": round(failures / items, 4) if items else 0,
        "dynetFailed": int(row["dynetFailed"]),
        "clashFailed": int(row["clashFailed"]),
        "sourceLabels": sorted(row["sourceLabels"]),
    }


def is_dynet_clean(row: dict[str, Any]) -> bool:
    return int(row["readFailures"]) == 0 and int(row["dynetFailed"]) == 0


def boundary_status(
    rows: list[dict[str, Any]],
    failing: list[dict[str, Any]],
    min_clean_above: int | None,
) -> str:
    if not rows:
        return "not-evaluated"
    if not failing:
        return "no-dynet-read-failure-in-scope"
    if min_clean_above is not None:
        return "bracketed-clean-above-failure"
    return "unbracketed-failure"


def boundary_gap(max_failing: int | None, min_clean_above: int | None) -> int | None:
    if max_failing is None or min_clean_above is None:
        return None
    return min_clean_above - max_failing


def boundary_read_failures(boundary: dict[str, Any]) -> int:
    return sum(
        int(row.get("readFailures") or 0)
        for row in boundary.get("rows") or []
        if isinstance(row, dict)
    )
