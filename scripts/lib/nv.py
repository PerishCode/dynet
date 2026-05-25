from __future__ import annotations

from collections import Counter
from typing import Any, Iterable


def row_key(row: Any, default: str = "") -> str:
    if isinstance(row, dict):
        value = row.get("key")
        if value is not None:
            return str(value)
    return default


def count_keys(rows: Any, *, default: str = "") -> list[str]:
    if isinstance(rows, list) and all(isinstance(row, str) for row in rows):
        return sorted({row for row in rows if row})
    return sorted({
        row_key(row, default)
        for row in rows or []
        if isinstance(row, dict) and row_key(row, default)
    })


def merge_items(sources: Iterable[dict[str, Any]], field: str) -> list[str]:
    return sorted({
        str(item)
        for source in sources
        for item in source.get(field, [])
        if item
    })


def merge_keys(sources: Iterable[dict[str, Any]], field: str) -> list[str]:
    return sorted({
        str(source[field])
        for source in sources
        if source.get(field)
    })


def count_map(values: Iterable[str | None]) -> list[dict[str, Any]]:
    counts = Counter(value for value in values if value)
    return [{"key": key, "count": counts[key]} for key in sorted(counts)]


def sum_int(sources: Iterable[dict[str, Any]], field: str) -> int:
    return sum(int(source.get(field) or 0) for source in sources)
