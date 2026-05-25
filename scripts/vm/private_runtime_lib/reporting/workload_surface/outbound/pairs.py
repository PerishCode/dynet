from __future__ import annotations

from typing import Any


def pair_counts(
    rows: list[dict[str, Any]],
    *,
    start_kind: str,
    finish_kind: str,
    key_name: str,
    start_field: str,
    finish_field: str,
    pair_field: str,
    finish_without_field: str,
    start_without_field: str,
    order_field: str,
) -> dict[str, int]:
    starts = keyed(rows, start_kind, key_name)
    finishes = keyed(rows, finish_kind, key_name)
    return {
        start_field: row_count(starts),
        finish_field: row_count(finishes),
        pair_field: pair_count(starts, finishes),
        finish_without_field: missing_pair_count(finishes, starts),
        start_without_field: missing_pair_count(starts, finishes),
        order_field: order_violation_count(starts, finishes),
    }


def keyed(
    rows: list[dict[str, Any]],
    kind: str,
    key_name: str,
) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        if row["kind"] == kind and row.get(key_name):
            result.setdefault(row[key_name], []).append(row)
    return result


def row_count(rows: dict[str, list[dict[str, Any]]]) -> int:
    return sum(len(group) for group in rows.values())


def pair_count(
    starts: dict[str, list[dict[str, Any]]],
    finishes: dict[str, list[dict[str, Any]]],
) -> int:
    keys = starts.keys() | finishes.keys()
    return sum(min(len(starts.get(key, [])), len(finishes.get(key, []))) for key in keys)


def missing_pair_count(
    left: dict[str, list[dict[str, Any]]],
    right: dict[str, list[dict[str, Any]]],
) -> int:
    return sum(max(0, len(rows) - len(right.get(key, []))) for key, rows in left.items())


def order_violation_count(
    starts: dict[str, list[dict[str, Any]]],
    finishes: dict[str, list[dict[str, Any]]],
) -> int:
    violations = 0
    for key in starts.keys() & finishes.keys():
        for start, finish in zip(starts[key], finishes[key]):
            if finish["index"] < start["index"]:
                violations += 1
    return violations
