from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from common import Lab, validate_name
from private_runtime_lib.briefs import fields


DNS_TIMING_SCHEMA = "dynet-vm-private-runtime-dns-timing-surface/v1alpha1"
REPEAT_SCHEMA = "dynet-vm-private-runtime-repeat/v1alpha1"
DNS_EVENT_KINDS = {
    "dns-query-received",
    "dns-reverse-record",
    "dns-resolve-completed",
    "dns-resolve-failed",
}


def command_dns_timing_surface(_lab: Lab, args: argparse.Namespace) -> None:
    label = validate_name(args.label or "dns-timing-surface", "label")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = build_dns_timing_summary(
        label,
        output_dir,
        [Path(item) for item in args.input],
    )
    write_dns_timing_summary(output_dir, summary)
    print(json.dumps(dns_timing_print(output_dir, summary), sort_keys=True))


def build_dns_timing_summary(
    label: str,
    output_dir: Path,
    inputs: list[Path],
) -> dict[str, Any]:
    rows = [dns_timing_surface_row(path) for path in expand_inputs(inputs)]
    totals = dns_timing_totals(rows)
    return {
        "schema": DNS_TIMING_SCHEMA,
        "label": label,
        "outputDir": str(output_dir),
        "runs": [public_row(row) for row in rows],
        "totals": totals,
        "conclusion": dns_timing_conclusion(totals),
        "policy": {
            "plannerPenaltySafe": False,
            "qualityPenaltySafe": False,
            "reason": "DNS timing is runtime shape evidence, not penalty proof.",
        },
    }


def expand_inputs(inputs: list[Path]) -> list[Path]:
    paths: list[Path] = []
    for path in inputs:
        summary = load_optional_json(path / "summary.json")
        if summary.get("schema") == REPEAT_SCHEMA:
            paths.extend(
                Path(row["path"])
                for row in summary.get("runs", [])
                if isinstance(row, dict) and row.get("path")
            )
        else:
            paths.append(path)
    return paths


def dns_timing_surface_row(run_dir: Path) -> dict[str, Any]:
    summary = load_optional_json(run_dir / "summary.json")
    report = load_optional_json(run_dir / "runtime-report.json")
    query_rows = dns_query_rows(report)
    current = dns_timing_counts(query_rows)
    clean = dns_timing_clean(current)
    return {
        "label": summary.get("label") or run_dir.name,
        "path": str(run_dir),
        "classification": "clean" if clean else dns_timing_classification(current),
        "clean": clean,
        "current": current,
        "_queries": query_rows,
    }


def public_row(row: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in row.items() if not key.startswith("_")}


def dns_query_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for event in report.get("events", []):
        if not isinstance(event, dict):
            continue
        kind = str(event.get("kind"))
        if kind not in DNS_EVENT_KINDS:
            continue
        event_fields = fields(event)
        query_id = event_fields.get("dnsQueryId") or event_fields.get("flowId")
        if not query_id:
            continue
        row = rows.setdefault(str(query_id), {"records": 0})
        observe_dns_event(row, kind, event_fields, event)
    return list(rows.values())


def observe_dns_event(
    row: dict[str, Any],
    kind: str,
    event_fields: dict[str, str],
    event: dict[str, Any],
) -> None:
    timestamp = event.get("emittedAtUnixMs")
    if kind == "dns-query-received":
        row["receivedMs"] = timestamp
    elif kind == "dns-reverse-record":
        row["records"] = int(row.get("records") or 0) + 1
    elif kind == "dns-resolve-completed":
        row["completedMs"] = timestamp
        row["reportedElapsedMs"] = optional_int(event_fields.get("elapsedMs"))
        row["routeDecision"] = event_fields.get("routeDecision") == "true"
        row["proxied"] = event_fields.get("proxied") == "true"
    elif kind == "dns-resolve-failed":
        row["failedMs"] = timestamp
        row["reportedElapsedMs"] = optional_int(event_fields.get("elapsedMs"))


def dns_timing_counts(rows: list[dict[str, Any]]) -> dict[str, Any]:
    completed = [row for row in rows if isinstance(row.get("completedMs"), int)]
    failed = [row for row in rows if isinstance(row.get("failedMs"), int)]
    completed_deltas = [delta_ms(row, "completedMs") for row in completed]
    reported_elapsed = [
        int(row["reportedElapsedMs"])
        for row in completed
        if isinstance(row.get("reportedElapsedMs"), int)
    ]
    return {
        "queries": len(rows),
        "receivedQueries": count_with(rows, "receivedMs"),
        "completedQueries": len(completed),
        "failedQueries": len(failed),
        "queriesWithRecords": sum(1 for row in rows if int(row.get("records") or 0) > 0),
        "records": sum(int(row.get("records") or 0) for row in rows),
        "orderedQueries": sum(1 for row in completed if ordered(row)),
        "completedWithElapsed": len(reported_elapsed),
        "routeDecisionQueries": sum(1 for row in completed if row.get("routeDecision")),
        "proxiedQueries": sum(1 for row in completed if row.get("proxied")),
        "resolveMs": timing_stats(completed_deltas),
        "reportedElapsedMs": timing_stats(reported_elapsed),
    }


def dns_timing_clean(counts: dict[str, Any]) -> bool:
    queries = int(counts["queries"])
    return (
        queries > 0
        and counts["receivedQueries"] == queries
        and counts["completedQueries"] == queries
        and counts["failedQueries"] == 0
        and counts["queriesWithRecords"] == queries
        and counts["orderedQueries"] == queries
        and counts["completedWithElapsed"] == queries
    )


def dns_timing_classification(counts: dict[str, Any]) -> str:
    if int(counts["failedQueries"]):
        return "dns-failure"
    if int(counts["completedQueries"]) < int(counts["queries"]):
        return "dns-completion-missing"
    if int(counts["queriesWithRecords"]) < int(counts["queries"]):
        return "dns-record-missing"
    return "dns-timing-incomplete"


def dns_timing_totals(rows: list[dict[str, Any]]) -> dict[str, Any]:
    query_rows = [query for row in rows for query in row["_queries"]]
    total = dns_timing_counts(query_rows)
    return {
        "runs": len(rows),
        "cleanRuns": sum(1 for row in rows if row["clean"]),
        "failedRuns": sum(1 for row in rows if not row["clean"]),
        "classifications": aggregate(row["classification"] for row in rows),
        **total,
    }


def dns_timing_conclusion(totals: dict[str, Any]) -> dict[str, Any]:
    clean = totals["runs"] > 0 and totals["failedRuns"] == 0
    return {
        "status": "clean" if clean else "dns-timing-surface-needs-evidence",
        "nextAction": "return-to-runtime-surface" if clean else "inspect-dns-timing",
        "plannerPenaltySafe": False,
        "qualityPenaltySafe": False,
    }


def write_dns_timing_summary(output_dir: Path, summary: dict[str, Any]) -> None:
    (output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n"
    )
    write_dns_timing_markdown(output_dir / "summary.md", summary)


def write_dns_timing_markdown(path: Path, summary: dict[str, Any]) -> None:
    totals = summary["totals"]
    lines = [
        "# VM Private Runtime DNS Timing Surface",
        "",
        f"- label: `{summary['label']}`",
        f"- status: `{summary['conclusion']['status']}`",
        f"- runs: `{totals['runs']}`",
        f"- clean runs: `{totals['cleanRuns']}`",
        f"- queries: `{totals['queries']}`",
        f"- completed: `{totals['completedQueries']}`",
        f"- failed: `{totals['failedQueries']}`",
        f"- resolve p95 ms: `{totals['resolveMs']['p95']}`",
        "",
        "## Runs",
        "",
    ]
    for row in summary["runs"]:
        lines.append(
            f"- `{row['label']}` classification=`{row['classification']}` "
            f"clean=`{row['clean']}`"
        )
    path.write_text("\n".join(lines) + "\n")


def dns_timing_print(output_dir: Path, summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "outputDir": str(output_dir),
        "runs": summary["totals"]["runs"],
        "cleanRuns": summary["totals"]["cleanRuns"],
        "status": summary["conclusion"]["status"],
    }


def ordered(row: dict[str, Any]) -> bool:
    return isinstance(row.get("receivedMs"), int) and delta_ms(row, "completedMs") >= 0


def delta_ms(row: dict[str, Any], key: str) -> int:
    left = row.get("receivedMs")
    right = row.get(key)
    if isinstance(left, int) and isinstance(right, int):
        return right - left
    return -1


def timing_stats(values: list[int]) -> dict[str, int]:
    clean_values = sorted(value for value in values if value >= 0)
    if not clean_values:
        return {"count": 0, "min": 0, "avg": 0, "p95": 0, "max": 0}
    return {
        "count": len(clean_values),
        "min": clean_values[0],
        "avg": sum(clean_values) // len(clean_values),
        "p95": percentile(clean_values, 95),
        "max": clean_values[-1],
    }


def percentile(values: list[int], percent: int) -> int:
    index = min(len(values) - 1, max(0, (len(values) * percent + 99) // 100 - 1))
    return values[index]


def count_with(rows: list[dict[str, Any]], key: str) -> int:
    return sum(1 for row in rows if isinstance(row.get(key), int))


def optional_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def aggregate(values: Any) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for value in values:
        key = str(value or "unknown")
        counts[key] = counts.get(key, 0) + 1
    return [{"key": key, "count": counts[key]} for key in sorted(counts)]


def load_optional_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open() as fh:
        value = json.load(fh)
    return value if isinstance(value, dict) else {}
