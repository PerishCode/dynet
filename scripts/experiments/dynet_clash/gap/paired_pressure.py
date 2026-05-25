from __future__ import annotations

import re
from typing import Any


def paired_pressure_brief(summary: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(summary, dict):
        return {"present": False}
    boundary = summary.get("pressureBoundary") or {}
    conclusion = summary.get("conclusion") or {}
    actionable = summary.get("actionableConclusion") or {}
    return {
        "present": True,
        "readSurfaceStatus": conclusion.get("status"),
        "actionableStatus": actionable.get("status"),
        "action": actionable.get("action"),
        "scope": boundary.get("scope"),
        "status": boundary.get("status"),
        "maxFailingStaggerMs": int_or_none(boundary.get("maxFailingStaggerMs")),
        "minCleanStaggerAboveFailureMs": int_or_none(
            boundary.get("minCleanStaggerAboveFailureMs")
        ),
        "boundaryGapMs": int_or_none(boundary.get("boundaryGapMs")),
        "suggestedNextStaggerMs": suggested_next_stagger(boundary),
        "failingStaggerMs": boundary.get("failingStaggerMs") or [],
        "cleanStaggerMs": boundary.get("cleanStaggerMs") or [],
        "cleanAboveFailureWindowCount": int_or_none(
            boundary.get("cleanAboveFailureWindowCount")
        ),
        "freshConfig": config_sources(summary, "fresh-config"),
        "savedConfigDrift": config_sources(summary, "saved-config-drift"),
    }


def fresh_paired_clean(summary: dict[str, Any] | None) -> bool:
    return bool(paired_pressure_brief(summary).get("freshConfig", {}).get("clean"))


def config_sources(summary: dict[str, Any], marker: str) -> dict[str, Any]:
    matches = [
        source
        for source in summary.get("sources") or []
        if isinstance(source, dict) and marker in str(source.get("label") or "")
    ]
    if not matches:
        return {"present": False}
    rows = [source_config_row(source) for source in matches]
    return {
        "present": True,
        "sourceCount": len(rows),
        "count": sum(row["count"] for row in rows),
        "dynetPassed": sum(row["dynetPassed"] for row in rows),
        "clashPassed": sum(row["clashPassed"] for row in rows),
        "readFailureCount": sum(row["readFailureCount"] for row in rows),
        "clean": all(row["clean"] for row in rows),
        "cleanStaggerMs": sorted(
            row["staggerMs"] for row in rows if row["clean"] and row["staggerMs"] is not None
        ),
        "failingStaggerMs": sorted(
            row["staggerMs"] for row in rows if not row["clean"] and row["staggerMs"] is not None
        ),
    }


def source_config_row(source: dict[str, Any]) -> dict[str, Any]:
    items = [item for item in source.get("items") or [] if isinstance(item, dict)]
    count = int(source.get("count") or len(items))
    dynet = source_passed(source, "dynetPassed", "dynetStatus", "pass")
    clash = source_passed(source, "clashPassed", "clashOk", True)
    clash_items = source_side_count(source, "clashOk")
    read_failures = int(source.get("readFailureCount") or 0)
    return {
        "count": count,
        "dynetPassed": dynet,
        "clashPassed": clash,
        "readFailureCount": read_failures,
        "staggerMs": source_stagger_ms(source),
        "clean": (
            count > 0
            and read_failures == 0
            and dynet == count
            and (clash_items == 0 or clash == clash_items)
        ),
    }


def source_passed(
    source: dict[str, Any],
    explicit_key: str,
    item_key: str,
    pass_value: Any,
) -> int:
    explicit = int_or_none(source.get(explicit_key))
    if explicit is not None:
        return explicit
    return sum(
        1
        for item in source.get("items") or []
        if isinstance(item, dict) and item.get(item_key) == pass_value
    )


def source_side_count(source: dict[str, Any], item_key: str) -> int:
    return sum(
        1
        for item in source.get("items") or []
        if isinstance(item, dict) and item_key in item
    )


def source_stagger_ms(source: dict[str, Any]) -> int | None:
    explicit = int_or_none(source.get("parallelSideStaggerMs"))
    if explicit is not None:
        return explicit
    match = re.search(r"(\d+)ms", str(source.get("label") or ""))
    if not match:
        return None
    return int(match.group(1))


def paired_pressure_followup_hint(summary: dict[str, Any] | None) -> dict[str, Any]:
    brief = paired_pressure_brief(summary)
    if not brief["present"]:
        return {}
    hint: dict[str, Any] = {
        "pairedPressureBoundary": brief,
    }
    next_stagger = brief.get("suggestedNextStaggerMs")
    if next_stagger is not None:
        hint["suggestedInputs"] = {
            "side-order": "clash,dynet",
            "parallel-side-stagger-ms": next_stagger,
        }
    return hint


def suggested_next_stagger(boundary: dict[str, Any]) -> int | None:
    max_failing = int_or_none(boundary.get("maxFailingStaggerMs"))
    min_clean = int_or_none(boundary.get("minCleanStaggerAboveFailureMs"))
    if max_failing is None or min_clean is None:
        return None
    if min_clean <= max_failing + 1:
        return None
    return (max_failing + min_clean) // 2


def int_or_none(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
