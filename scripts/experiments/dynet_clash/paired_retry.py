from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path
from typing import Any

from scripts.cli import dynet_probe_manifest as dynet_manifest

DIRECT_TLS_EOF = "direct-tls-eof-after-path-complete"


def run(
    args: argparse.Namespace,
    entry: dict[str, Any],
    dynet_dir: Path,
    started: float,
    actual_start_offset_ms: int,
    target_start_offset_ms: int | None,
) -> dict[str, Any]:
    del started
    return dynet_manifest.run_probe(
        args,
        entry,
        dynet_dir,
        actual_start_offset_ms=actual_start_offset_ms,
        target_start_offset_ms=target_start_offset_ms,
    )


def totals(pairs: list[dict[str, Any]], args: argparse.Namespace) -> dict[str, Any]:
    return summarize_rows(retry_rows(pairs), policy_from_args(args))


def summary_totals(summary: dict[str, Any], fallback: dict[str, Any]) -> dict[str, Any]:
    rows = retry_rows(summary.get("items", []))
    if not rows:
        return normalize(fallback)
    return summarize_rows(rows, policy_from_summary(summary, fallback))


def retry_rows(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for item in items:
        retry = item.get("dynetRetry")
        if not retry and isinstance(item.get("dynet"), dict):
            retry = item["dynet"].get("directTlsRetry")
        if retry:
            rows.append(retry)
    return rows


def summarize_rows(rows: list[dict[str, Any]], policy: dict[str, Any]) -> dict[str, Any]:
    attempts = [
        attempt
        for row in rows
        for attempt in row.get("attempts", [])
    ]
    first = [items[0] for row in rows if (items := row.get("attempts", []))]
    final = [items[-1] for row in rows if (items := row.get("attempts", []))]
    return {
        "enabled": int(policy.get("maxAttempts") or 1) > 1,
        "policy": "direct-tls-eof-only",
        "maxAttempts": max(int(policy.get("maxAttempts") or 1), 1),
        "retrySleepMs": int(policy.get("retrySleepMs") or 250),
        "rows": len(rows),
        "attempts": len(attempts),
        "attemptClassified": len(attempts),
        "finalClassified": len(final),
        "rowsWithMultipleAttempts": sum(
            1 for row in rows if int(row.get("attemptsUsed") or 0) > 1
        ),
        "firstAttemptDirectTlsEof": count_class(first, DIRECT_TLS_EOF),
        "finalDirectTlsEof": count_class(final, DIRECT_TLS_EOF),
        "recoveredAfterRetry": sum(
            1 for row in rows if row.get("recoveredAfterRetry")
        ),
        "unresolvedDirectTlsEof": sum(
            1 for row in rows if row.get("unresolvedDirectTlsEof")
        ),
        "attemptClassifications": class_counts(attempts),
        "finalClassifications": class_counts(final),
    }


def policy_from_args(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "maxAttempts": args.dynet_direct_tls_retry_attempts,
        "retrySleepMs": args.dynet_direct_tls_retry_sleep_ms,
    }


def policy_from_summary(
    summary: dict[str, Any],
    fallback: dict[str, Any],
) -> dict[str, Any]:
    retry = summary.get("dynetRetry", {})
    if not isinstance(retry, dict):
        retry = fallback
    return {
        "maxAttempts": retry.get("maxAttempts", fallback.get("maxAttempts", 1)),
        "retrySleepMs": retry.get("retrySleepMs", fallback.get("retrySleepMs", 250)),
    }


def count_class(attempts: list[dict[str, Any]], classification: str) -> int:
    return sum(1 for attempt in attempts if attempt.get("classification") == classification)


def class_counts(attempts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts = Counter(str(attempt.get("classification") or "unknown") for attempt in attempts)
    return [{"key": key, "count": count} for key, count in sorted(counts.items())]


def aggregate_reports(reports: list[dict[str, Any]]) -> dict[str, Any]:
    rows = [
        normalize(report.get("dynetRetry", {}))
        for report in reports
        if isinstance(report.get("dynetRetry"), dict)
    ]
    attempts = sum_int(rows, "attempts")
    retry_rows = sum_int(rows, "rows")
    attempt_counts = sum_counts(rows, "attemptClassifications")
    final_counts = sum_counts(rows, "finalClassifications")
    attempt_seen = count_total(attempt_counts)
    final_seen = count_total(final_counts)
    return {
        "enabled": any(row.get("enabled") for row in rows),
        "windows": len(rows),
        "windowsWithRetry": sum(1 for row in rows if row.get("enabled")),
        "rows": retry_rows,
        "attempts": attempts,
        "attemptClassified": attempt_seen,
        "finalClassified": final_seen,
        "rowsWithMultipleAttempts": sum_int(rows, "rowsWithMultipleAttempts"),
        "firstAttemptDirectTlsEof": sum_int(rows, "firstAttemptDirectTlsEof"),
        "finalDirectTlsEof": sum_int(rows, "finalDirectTlsEof"),
        "recoveredAfterRetry": sum_int(rows, "recoveredAfterRetry"),
        "unresolvedDirectTlsEof": sum_int(rows, "unresolvedDirectTlsEof"),
        "attemptClassifications": with_unknown(attempt_counts, attempts - attempt_seen),
        "finalClassifications": with_unknown(final_counts, retry_rows - final_seen),
    }


def sum_int(rows: list[dict[str, Any]], key: str) -> int:
    return sum(int(row.get(key) or 0) for row in rows)


def sum_counts(rows: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    counts: Counter[str] = Counter()
    for row in rows:
        for item in row.get(key, []):
            if isinstance(item, dict):
                counts[str(item.get("key") or "unknown")] += int(item.get("count") or 0)
    return [{"key": item, "count": count} for item, count in sorted(counts.items())]


def count_total(rows: list[dict[str, Any]]) -> int:
    return sum(int(row.get("count") or 0) for row in rows)


def normalize(row: dict[str, Any]) -> dict[str, Any]:
    output = dict(row)
    output.setdefault(
        "attemptClassified",
        count_total(list_field(output, "attemptClassifications")),
    )
    output.setdefault(
        "finalClassified",
        count_total(list_field(output, "finalClassifications")),
    )
    return output


def list_field(row: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = row.get(key)
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def with_unknown(rows: list[dict[str, Any]], unknown: int) -> list[dict[str, Any]]:
    if unknown <= 0:
        return rows
    return sorted([*rows, {"key": "unknown", "count": unknown}], key=lambda row: row["key"])
