from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any


SUMMARY_SCHEMA = "dynet-trace-attribution-summary/v1alpha1"
BATCH_SCHEMA = "dynet-trace-attribution-batch/v1alpha1"
BATCH_MANIFEST_SCHEMA = "dynet-trace-attribution-batch-manifest/v1alpha1"
DEFAULT_OUTPUT_JSON = ".task/resources/dynet-trace-attribution-summary.json"
DEFAULT_OUTPUT_MD = ".task/resources/dynet-trace-attribution-summary.md"
DEFAULT_BATCH_OUTPUT_JSON = ".task/resources/dynet-trace-attribution-batch.json"
DEFAULT_BATCH_OUTPUT_MD = ".task/resources/dynet-trace-attribution-batch.md"
DEFAULT_MIN_REPEAT_RUNS = 2
DEFAULT_MAX_UNKNOWN_RATE = 0.1
MAX_MISSING_CORRELATION_RATE = 0.25


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())

def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True))

def event_kind(event: dict[str, Any]) -> str:
    return str(event.get("kind", "unknown"))

def event_fields(event: dict[str, Any]) -> dict[str, str]:
    fields = event.get("fields", {})
    if not isinstance(fields, dict):
        return {}
    return {str(key): str(value) for key, value in fields.items()}

def int_field(fields: dict[str, str], key: str) -> int | None:
    value = fields.get(key)
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None

def int_value(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None

def latency_summary(values: list[int]) -> dict[str, int | None]:
    if not values:
        return {"p50": None, "p95": None, "max": None}
    ordered = sorted(values)
    return {
        "p50": percentile(ordered, 50),
        "p95": percentile(ordered, 95),
        "max": ordered[-1],
    }

def percentile(ordered: list[int], target: int) -> int:
    index = round((len(ordered) - 1) * (target / 100))
    return ordered[index]

def split_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [item for item in value.split(",") if item]

def top(counter: Counter[str], limit: int = 20) -> list[dict[str, Any]]:
    return [{"key": key, "count": count} for key, count in counter.most_common(limit)]

def count_kind(events: list[dict[str, Any]], kind: str) -> int:
    return sum(1 for event in events if event_kind(event) == kind)
