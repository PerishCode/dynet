from __future__ import annotations

from collections import defaultdict
from typing import Any


QUALITY_ENTRY_KEY = tuple


def retained_previous_entries(
    states: list[dict[str, Any]],
    now_ms: int,
) -> list[dict[str, Any]]:
    entries = []
    for state in states:
        if not state_is_fresh(state, now_ms):
            continue
        for item in state.get("outbounds", []):
            if isinstance(item, dict) and item.get("outbound"):
                entries.append(dict(item))
    return entries


def state_is_fresh(state: dict[str, Any], now_ms: int) -> bool:
    expires = int_or_none(state.get("expiresAtUnixMs"))
    if expires is None:
        generated = int_or_none(state.get("generatedAtUnixMs")) or 0
        ttl = int_or_none(state.get("ttlSecs")) or 0
        expires = generated + ttl * 1000
    return now_ms <= expires


def state_expiry(
    now_ms: int,
    ttl_seconds: int,
    retained_states: list[dict[str, Any]],
) -> int:
    expiries = [now_ms + ttl_seconds * 1000]
    for state in retained_states:
        expires = int_or_none(state.get("expiresAtUnixMs"))
        if expires is not None and now_ms <= expires:
            expiries.append(expires)
    return min(expiries)


def quality_entries(observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[QUALITY_ENTRY_KEY, list[dict[str, Any]]] = defaultdict(list)
    for item in observations:
        cascade = item.get("cascade", {})
        base = (
            item["outbound"],
            item.get("scope"),
            cascade.get("dialer"),
            cascade.get("private"),
        )
        grouped[(*base, None, item.get("transport"))].append(item)
        grouped[(*base, item["targetFamily"], item.get("transport"))].append(item)
    return [
        quality_entry(outbound, scope, dialer, private, family, transport, items)
        for (outbound, scope, dialer, private, family, transport), items in sorted(
            grouped.items(), key=group_key
        )
    ]


def merge_quality_entries(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[QUALITY_ENTRY_KEY, list[dict[str, Any]]] = defaultdict(list)
    for item in entries:
        grouped[entry_key(item)].append(item)
    return [
        merge_quality_entry(key, items)
        for key, items in sorted(grouped.items(), key=lambda item: group_key(item))
    ]


def group_key(
    item: tuple[QUALITY_ENTRY_KEY, list[dict[str, Any]]],
) -> tuple[str, str, str, str, str, str]:
    (outbound, scope, dialer, private, family, transport), _ = item
    return (outbound, scope or "", dialer or "", private or "", family or "", transport or "")


def quality_entry(
    outbound: str,
    scope: str | None,
    dialer: str | None,
    private: str | None,
    family: str | None,
    transport: str | None,
    items: list[dict[str, Any]],
) -> dict[str, Any]:
    attempts = len(items)
    failures = sum(1 for item in items if item.get("status") != "pass")
    successes = attempts - failures
    stages = [stage for item in items for stage in item["stages"]]
    return quality_entry_from_counts(
        outbound,
        scope,
        dialer,
        private,
        family,
        transport,
        attempts,
        successes,
        failures,
        stage_quality_from_observations(stages),
    )


def merge_quality_entry(
    key: QUALITY_ENTRY_KEY,
    items: list[dict[str, Any]],
) -> dict[str, Any]:
    outbound, scope, dialer, private, family, transport = key
    attempts = sum_int(items, "attempts")
    successes = sum_int(items, "successes")
    failures = sum_int(items, "failures")
    return quality_entry_from_counts(
        outbound,
        scope,
        dialer,
        private,
        family,
        transport,
        attempts,
        successes,
        failures,
        merge_stage_quality([stage for item in items for stage in item.get("stages", [])]),
    )


def quality_entry_from_counts(
    outbound: str,
    scope: str | None,
    dialer: str | None,
    private: str | None,
    family: str | None,
    transport: str | None,
    attempts: int,
    successes: int,
    failures: int,
    stages: list[dict[str, Any]],
) -> dict[str, Any]:
    error_rate = failures / attempts if attempts else 0.0
    entry = {
        "outbound": outbound,
        "scope": scope,
        "dialer": dialer,
        "private": private,
        "targetFamily": family,
        "transport": transport,
        "verdict": verdict(attempts, error_rate),
        "attempts": attempts,
        "successes": successes,
        "failures": failures,
        "errorRate": round(error_rate, 4),
        "confidence": confidence(attempts),
        "stages": stages,
    }
    return {key: value for key, value in entry.items() if value is not None}


def stage_quality_from_observations(stages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for stage in stages:
        grouped[stage["stage"]].append(stage)
    rows = []
    for stage, items in sorted(grouped.items()):
        attempts = len(items)
        failures = sum(1 for item in items if item.get("status") == "failed")
        elapsed = [item["elapsedMs"] for item in items if item.get("elapsedMs") is not None]
        rows.append(stage_entry(stage, attempts, failures, percentile(elapsed, 95)))
    return rows


def merge_stage_quality(stages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for stage in stages:
        if isinstance(stage, dict) and stage.get("stage"):
            grouped[str(stage["stage"])].append(stage)
    rows = []
    for stage, items in sorted(grouped.items()):
        attempts = sum_int(items, "attempts")
        failures = sum_int(items, "failures")
        p95_values = [
            value
            for value in (int_or_none(item.get("p95Ms")) for item in items)
            if value is not None
        ]
        rows.append(stage_entry(stage, attempts, failures, max(p95_values, default=None)))
    return rows


def stage_entry(
    stage: str,
    attempts: int,
    failures: int,
    p95_ms: int | None,
) -> dict[str, Any]:
    error_rate = failures / attempts if attempts else 0.0
    return {
        "stage": stage,
        "attempts": attempts,
        "failures": failures,
        "errorRate": round(error_rate, 4),
        "p95Ms": p95_ms,
    }


def percentile(values: list[int], target: int) -> int | None:
    if not values:
        return None
    ordered = sorted(values)
    index = round((len(ordered) - 1) * (target / 100))
    return ordered[index]


def verdict(attempts: int, error_rate: float) -> str:
    if attempts == 0:
        return "unknown"
    if error_rate == 0:
        return "healthy"
    if error_rate <= 0.5:
        return "degraded"
    return "unhealthy"


def confidence(attempts: int) -> str:
    if attempts >= 10:
        return "high"
    if attempts >= 3:
        return "medium"
    return "low"


def signals(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    overall = {
        quality_key(item): item
        for item in entries
        if "targetFamily" not in item and item.get("outbound")
    }
    for item in entries:
        family = item.get("targetFamily")
        if not family:
            continue
        parent = overall.get(quality_key(item))
        if item["verdict"] == "unhealthy" and parent and parent["verdict"] != "unhealthy":
            rows.append(
                {
                    "type": "target-family-risk",
                    "outbound": item["outbound"],
                    "scope": item.get("scope"),
                    "dialer": item.get("dialer"),
                    "private": item.get("private"),
                    "targetFamily": family,
                    "reason": "target family is unhealthy while outbound aggregate is not",
                }
            )
    return rows


def entry_key(item: dict[str, Any]) -> QUALITY_ENTRY_KEY:
    return (
        str(item["outbound"]),
        optional_str(item.get("scope")),
        optional_str(item.get("dialer")),
        optional_str(item.get("private")),
        optional_str(item.get("targetFamily")),
        optional_str(item.get("transport")),
    )


def quality_key(item: dict[str, Any]) -> tuple[str, str | None, str | None, str | None, str | None]:
    return (
        str(item["outbound"]),
        optional_str(item.get("scope")),
        optional_str(item.get("dialer")),
        optional_str(item.get("private")),
        optional_str(item.get("transport")),
    )


def optional_str(value: Any) -> str | None:
    return str(value) if value is not None else None


def int_or_none(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None


def sum_int(items: list[dict[str, Any]], key: str) -> int:
    return sum(int_or_none(item.get(key)) or 0 for item in items)
