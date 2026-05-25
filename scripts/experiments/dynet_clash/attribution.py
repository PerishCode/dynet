from __future__ import annotations

from collections import Counter
from typing import Any


def dynet_deficit(
    summary: dict[str, Any],
    primary_bucket: str,
    runtime: dict[str, Any] | None,
) -> dict[str, Any]:
    failures = [
        item
        for item in summary.get("items", [])
        if item.get("status") != "pass" and item.get("bucket") == primary_bucket
    ]
    runtime_class = (
        runtime.get("classification")
        if isinstance(runtime, dict)
        else "missing-runtime-evidence"
    )
    runtime_clean = bool(runtime.get("clean")) if isinstance(runtime, dict) else False
    return {
        "primaryBucket": primary_bucket,
        "failureCount": len(failures),
        "classification": classify_failures(failures, runtime_class, runtime_clean),
        "runtimeGateClean": runtime_clean,
        "runtimeGateClassification": runtime_class,
        "byStage": counter_rows(item.get("failedStage") for item in failures),
        "byOutbound": counter_rows(item.get("selectedOutbound") for item in failures),
        "byDomain": counter_rows(item.get("domain") for item in failures),
        "byReasonMarker": counter_rows(reason_marker(item.get("reason")) for item in failures),
    }


def classify_failures(
    failures: list[dict[str, Any]],
    runtime_class: str | None,
    runtime_clean: bool,
) -> str:
    if not failures:
        return "no-dynet-primary-deficit"
    if runtime_clean:
        return "runtime-clean-target-or-probe-suspect"
    if runtime_class:
        return runtime_class
    return "unknown"


def counter_rows(values: Any) -> list[dict[str, Any]]:
    counts = Counter(str(value or "unknown") for value in values)
    return [
        {"key": key, "count": count}
        for key, count in counts.most_common()
    ]


def reason_marker(reason: Any) -> str:
    text = str(reason or "").lower()
    if "unexpected end of file" in text or "eof" in text:
        return "tls-eof"
    if "timed out" in text or "timeout" in text:
        return "timeout"
    if "resource temporarily unavailable" in text or "not ready" in text:
        return "pending-read"
    if "certificate" in text:
        return "certificate"
    return "unknown"
