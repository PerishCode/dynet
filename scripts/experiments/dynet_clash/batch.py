from __future__ import annotations

import argparse
import datetime as dt
import json
from collections import Counter
from pathlib import Path
from typing import Any

from dynet_clash import batch_scope, limits as limit_model, objective, paired_retry


SCHEMA = "dynet-clash-proof-batch/v1alpha1"
DEFAULT_OUTPUT_JSON = ".task/resources/dynet-clash-github-proof-batch.json"
DEFAULT_OUTPUT_MD = ".task/resources/dynet-clash-github-proof-batch.md"


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True))


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def build(args: argparse.Namespace) -> dict[str, Any]:
    paths = [Path(path) for path in args.comparison]
    reports = [load_json(path) for path in paths]
    return build_from_reports(reports, args, paths)


def build_from_reports(
    reports: list[dict[str, Any]],
    args: argparse.Namespace,
    paths: list[Path] | None = None,
) -> dict[str, Any]:
    input_paths = paths or [
        Path(f"comparison-{index + 1}.json") for index in range(len(reports))
    ]
    windows = [
        window(index, path, report, args)
        for index, (path, report) in enumerate(zip(input_paths, reports), start=1)
    ]
    bucket_keys = sorted({
        str(row.get("key"))
        for report in reports
        for row in report.get("byBucket", [])
        if row.get("key") is not None
    })
    buckets = [aggregate_bucket(key, reports) for key in bucket_keys]
    gate_rows = gates(windows, buckets, args)
    return {
        "schema": SCHEMA,
        "generatedAt": utc_now(),
        "inputs": [str(path) for path in input_paths],
        "thresholds": {
            "objective": args.objective,
            "minWindows": args.min_windows,
            "minWindowWinRate": args.min_window_win_rate,
            "minCleanWindowRate": args.min_clean_window_rate,
            "minAggregatePrimaryDelta": args.min_aggregate_primary_delta,
            "minAggregateParityDelta": args.min_aggregate_parity_delta,
            "minGuardrailRate": args.min_guardrail_rate,
            "primaryBucket": args.primary_bucket,
            "guardrailBuckets": args.guardrail_bucket or [],
            "requireRuntimeGate": bool(getattr(args, "require_runtime_gate", False)),
            "cleanScope": args.clean_scope,
        },
        "totals": totals(windows),
        "verdict": verdict(gate_rows, buckets, args),
        "gates": gate_rows,
        "aggregate": {
            "totals": aggregate_totals(reports),
            "byBucket": buckets,
        },
        "runtimeGate": batch_scope.runtime_batch(windows),
        "dynetRetry": paired_retry.aggregate_reports(reports),
        "limitCategories": limit_counts(windows),
        "windows": windows,
    }


def window(
    index: int,
    path: Path,
    report: dict[str, Any],
    args: argparse.Namespace,
) -> dict[str, Any]:
    verdict_report = report.get("verdict", {})
    primary = find_row(report.get("byBucket", []), args.primary_bucket)
    guardrails = [
        row
        for key in args.guardrail_bucket or []
        for row in [find_row(report.get("byBucket", []), key)]
        if row is not None
    ]
    limit_details = batch_scope.report_limit_details(report)
    blocking_details = batch_scope.scoped_limit_details(
        limit_details,
        args.clean_scope,
    )
    limits = limit_model.messages(limit_details)
    blocking_limits = limit_model.messages(blocking_details)
    return {
        "index": index,
        "label": batch_scope.path_label(path),
        "path": str(path),
        "status": verdict_report.get("status"),
        "primaryDelta": verdict_report.get("primaryDelta"),
        "runtimeGate": batch_scope.runtime_window(report.get("dynetRuntimeGate")),
        "dynetRetry": report.get("dynetRetry", {}),
        "clean": not blocking_limits,
        "cleanScope": args.clean_scope,
        "limits": limits,
        "blockingLimits": blocking_limits,
        "limitDetails": limit_details,
        "blockingLimitDetails": blocking_details,
        "limitCategories": batch_scope.detail_categories(blocking_details),
        "allLimitCategories": batch_scope.detail_categories(limit_details),
        "primary": primary,
        "guardrails": guardrails,
        "guardrailFailures": verdict_report.get("guardrailFailures", []),
    }


def totals(windows: list[dict[str, Any]]) -> dict[str, Any]:
    statuses = Counter(str(window.get("status")) for window in windows)
    return {
        "windows": len(windows),
        "cleanWindows": sum(1 for window in windows if window.get("clean")),
        "limitedWindows": sum(1 for window in windows if not window.get("clean")),
        "runtimeGateCleanWindows": sum(
            1 for window in windows if window.get("runtimeGate", {}).get("clean")
        ),
        "runtimeGateMissingWindows": sum(
            1 for window in windows if window.get("runtimeGate", {}).get("present") is False
        ),
        "statusCounts": [
            {"key": key, "count": count}
            for key, count in statuses.most_common()
        ],
    }


def aggregate_totals(reports: list[dict[str, Any]]) -> dict[str, Any]:
    clash = sum_side(
        report.get("totals", {}).get("clash", {}) for report in reports
    )
    dynet = sum_side(
        report.get("totals", {}).get("dynet", {}) for report in reports
    )
    return compare_totals("all", clash, dynet)


def aggregate_bucket(key: str, reports: list[dict[str, Any]]) -> dict[str, Any]:
    clash = [
        row.get("clash", {})
        for report in reports
        for row in report.get("byBucket", [])
        if row.get("key") == key
    ]
    dynet = [
        row.get("dynet", {})
        for report in reports
        for row in report.get("byBucket", [])
        if row.get("key") == key
    ]
    return compare_totals(key, sum_side(clash), sum_side(dynet))


def compare_totals(
    key: str,
    clash: dict[str, Any],
    dynet: dict[str, Any],
) -> dict[str, Any]:
    row = {
        "key": key,
        "clash": rate_total(clash),
        "dynet": rate_total(dynet),
    }
    row["successRateDelta"] = round(
        row["dynet"]["successRate"] - row["clash"]["successRate"],
        4,
    )
    row["failureDelta"] = row["dynet"]["failure"] - row["clash"]["failure"]
    return row


def sum_side(items: Any) -> dict[str, int]:
    total = {"count": 0, "success": 0, "failure": 0}
    for item in items:
        if not isinstance(item, dict):
            continue
        total["count"] += int(item.get("count", 0))
        total["success"] += int(item.get("success", 0))
        total["failure"] += int(item.get("failure", 0))
    return total


def rate_total(item: dict[str, Any]) -> dict[str, Any]:
    count = int(item.get("count", 0))
    success = int(item.get("success", 0))
    failure = int(item.get("failure", max(count - success, 0)))
    return {
        "count": count,
        "success": success,
        "failure": failure,
        "successRate": round(success / count, 4) if count else 0,
    }


def gates(
    windows: list[dict[str, Any]],
    buckets: list[dict[str, Any]],
    args: argparse.Namespace,
) -> list[dict[str, Any]]:
    window_count = len(windows)
    clean_count = sum(1 for window in windows if window.get("clean"))
    clean_rate = round(clean_count / window_count, 4) if window_count else 0
    winning_count = sum(1 for item in windows if primary_meets_objective(item, args))
    win_rate = round(winning_count / clean_count, 4) if clean_count else 0
    primary = find_row(buckets, args.primary_bucket)
    primary_delta = primary.get("successRateDelta", 0) if primary else 0
    required_primary_delta = objective.required_primary_delta(args)
    guardrail_rows = [
        row
        for key in args.guardrail_bucket or []
        for row in [find_row(buckets, key)]
        if row is not None
    ]
    dirty_guardrails = [
        row["key"]
        for row in guardrail_rows
        if row["clash"]["successRate"] < args.min_guardrail_rate
        or row["dynet"]["successRate"] < args.min_guardrail_rate
    ]
    runtime_failures = (
        batch_scope.runtime_gate_failures(windows)
        if getattr(args, "require_runtime_gate", False)
        else []
    )
    return [
        {
            "name": "min-windows",
            "passed": window_count >= args.min_windows,
            "value": window_count,
            "required": args.min_windows,
        },
        {
            "name": "clean-window-rate",
            "passed": clean_rate >= args.min_clean_window_rate,
            "value": clean_rate,
            "required": args.min_clean_window_rate,
        },
        {
            "name": "primary-window-win-rate",
            "passed": win_rate >= args.min_window_win_rate,
            "value": win_rate,
            "required": args.min_window_win_rate,
        },
        {
            "name": "aggregate-primary-delta",
            "passed": primary_delta >= required_primary_delta,
            "value": primary_delta,
            "required": required_primary_delta,
        },
        {
            "name": "aggregate-guardrails-clean",
            "passed": not dirty_guardrails,
            "value": dirty_guardrails,
            "required": f"both sides >= {args.min_guardrail_rate}",
        },
        {
            "name": "runtime-workload-gate-clean",
            "passed": not runtime_failures,
            "value": runtime_failures,
            "required": "all comparison windows include a clean dynet runtime workloadFlow gate",
        },
    ]


def primary_meets_objective(window: dict[str, Any], args: argparse.Namespace) -> bool:
    return (
        window.get("clean") is True
        and window.get("status") in objective.window_statuses(args)
        and float(window.get("primaryDelta") or 0) >= objective.required_primary_delta(args)
    )


def verdict(
    gates: list[dict[str, Any]],
    buckets: list[dict[str, Any]],
    args: argparse.Namespace,
) -> dict[str, Any]:
    failed = [gate["name"] for gate in gates if not gate["passed"]]
    failed_set = set(failed)
    primary = find_row(buckets, args.primary_bucket)
    primary_delta = primary.get("successRateDelta") if primary else None
    if "min-windows" in failed_set:
        status = "insufficient-evidence"
    elif "aggregate-primary-delta" in failed_set:
        status = objective.below_status(args)
    elif (
        "primary-window-win-rate" in failed_set
        and "clean-window-rate" not in failed_set
    ):
        status = objective.below_status(args)
    elif failed:
        status = "limited-evidence"
    else:
        status = objective.success_status(args)
    return {
        "status": status,
        "primaryBucket": args.primary_bucket,
        "primaryDelta": primary_delta,
        "failedGates": failed,
    }


def limit_counts(windows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts = Counter(
        category
        for window in windows
        for category in window.get("limitCategories", [])
    )
    return [
        {"key": key, "count": count}
        for key, count in counts.most_common()
    ]


def limit_categories(limits: list[str]) -> list[str]:
    return batch_scope.limit_categories(limits)


def find_row(rows: list[dict[str, Any]], key: str) -> dict[str, Any] | None:
    return next((row for row in rows if row.get("key") == key), None)


def write_markdown(path: Path, report: dict[str, Any]) -> None:
    lines = [
        "# Dynet vs Clash Proof Batch",
        "",
        f"- Verdict: `{report['verdict']['status']}`",
        f"- Primary delta: `{report['verdict']['primaryDelta']}`",
        f"- Windows: `{report['totals']['windows']}`",
        f"- Clean windows: `{report['totals']['cleanWindows']}`",
        f"- Clean scope: `{report['thresholds']['cleanScope']}`",
        f"- Runtime gate clean windows: `{report['totals']['runtimeGateCleanWindows']}`",
        f"- Dynet retry recovered: `{report['dynetRetry']['recoveredAfterRetry']}`",
        f"- Dynet retry unresolved direct TLS EOF: `{report['dynetRetry']['unresolvedDirectTlsEof']}`",
        f"- Dynet retry first-attempt direct TLS EOF: `{report['dynetRetry'].get('firstAttemptDirectTlsEof', 0)}`",
        f"- Dynet retry final direct TLS EOF: `{report['dynetRetry'].get('finalDirectTlsEof', 0)}`",
        f"- Dynet retry classified attempts: `{report['dynetRetry'].get('attemptClassified', 0)}/{report['dynetRetry'].get('attempts', 0)}`",
        f"- Dynet retry classified finals: `{report['dynetRetry'].get('finalClassified', 0)}/{report['dynetRetry'].get('rows', 0)}`",
        "",
        "## Gates",
        "",
    ]
    for gate in report["gates"]:
        lines.append(
            f"- `{gate['name']}` passed=`{gate['passed']}` "
            f"value=`{gate['value']}` required=`{gate['required']}`"
        )
    lines.extend(["", "## Aggregate Buckets", ""])
    for row in report["aggregate"]["byBucket"]:
        lines.append(comparison_line(row))
    append_runtime_gate(lines, report.get("runtimeGate", {}))
    if report["dynetRetry"].get("attemptClassifications"):
        lines.extend(["", "## Dynet Retry Attempt Classifications", ""])
        for item in report["dynetRetry"]["attemptClassifications"]:
            lines.append(f"- `{item['key']}` count=`{item['count']}`")
    if report["dynetRetry"].get("finalClassifications"):
        lines.extend(["", "## Dynet Retry Final Classifications", ""])
        for item in report["dynetRetry"]["finalClassifications"]:
            lines.append(f"- `{item['key']}` count=`{item['count']}`")
    if report["limitCategories"]:
        lines.extend(["", "## Limit Categories", ""])
        for item in report["limitCategories"]:
            lines.append(f"- `{item['key']}` count=`{item['count']}`")
    lines.extend(["", "## Windows", ""])
    for item in report["windows"]:
        runtime = item.get("runtimeGate", {})
        lines.append(
            f"- `{item['label']}` status=`{item['status']}` "
            f"delta=`{item['primaryDelta']}` clean=`{item['clean']}` "
            f"runtimeGate=`{runtime.get('classification')}`"
        )
        for limit in item.get("blockingLimits", []):
            lines.append(f"  - blocking limit: {limit}")
        nonblocking = [
            limit for limit in item["limits"]
            if limit not in item.get("blockingLimits", [])
        ]
        for limit in nonblocking:
            lines.append(f"  - nonblocking limit: {limit}")
    path.write_text("\n".join(lines) + "\n")


def comparison_line(row: dict[str, Any]) -> str:
    return (
        f"- `{row['key']}` clash={compact(row['clash'])} "
        f"dynet={compact(row['dynet'])} delta=`{row['successRateDelta']}`"
    )


def append_runtime_gate(lines: list[str], runtime: dict[str, Any]) -> None:
    if not runtime:
        return
    lines.extend(["", "## Runtime Gate", ""])
    lines.append(
        f"- windows=`{runtime.get('windowCount')}` "
        f"present=`{runtime.get('presentWindows')}` "
        f"clean=`{runtime.get('cleanWindows')}` "
        f"missing=`{runtime.get('missingWindows')}`"
    )
    for item in runtime.get("classificationCounts", []):
        lines.append(f"- classification `{item['key']}` count=`{item['count']}`")
    for item in runtime.get("failedCheckCounts", []):
        lines.append(f"- failed check `{item['key']}` count=`{item['count']}`")
    for surface, rows in runtime.get("surfaceCounts", {}).items():
        values = ", ".join(f"{item['key']}:{item['count']}" for item in rows)
        lines.append(f"- surface `{surface}`: `{values}`")


def compact(item: dict[str, Any]) -> str:
    return f"{item['success']}/{item['count']} sr={item['successRate']}"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Aggregate repeated dynet-vs-Clash proof comparisons."
    )
    parser.add_argument("--comparison", action="append", required=True)
    parser.add_argument("--output-json", default=DEFAULT_OUTPUT_JSON)
    parser.add_argument("--output-md", default=DEFAULT_OUTPUT_MD)
    parser.add_argument("--primary-bucket", default="github-proof")
    parser.add_argument(
        "--guardrail-bucket",
        action="append",
        default=["control-global", "work-direct"],
    )
    parser.add_argument("--min-windows", type=int, default=3)
    parser.add_argument("--min-window-win-rate", type=float, default=0.67)
    parser.add_argument("--min-clean-window-rate", type=float, default=1.0)
    parser.add_argument("--min-aggregate-primary-delta", type=float, default=0.05)
    parser.add_argument("--min-aggregate-parity-delta", type=float, default=0.0)
    parser.add_argument("--min-guardrail-rate", type=float, default=0.99)
    parser.add_argument(
        "--objective",
        choices=["superior", "parity"],
        default="superior",
        help="superior requires positive primary lift; parity proves dynet >= Clash",
    )
    parser.add_argument(
        "--require-runtime-gate",
        action="store_true",
        help="require every comparison window to include a clean dynet runtime workloadFlow gate",
    )
    parser.add_argument(
        "--clean-scope",
        choices=["all", "product-effect", "attribution"],
        default="all",
        help="choose which limit scope must be clean for proof-window gates",
    )
    parser.add_argument(
        "--fail-on-gate",
        action="store_true",
        help="return non-zero when any batch gate fails",
    )
    return parser


def command(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)
    report = build(args)
    output_json = Path(args.output_json)
    output_md = Path(args.output_md)
    write_json(output_json, report)
    write_markdown(output_md, report)
    failed_gates = report["verdict"]["failedGates"]
    print(json.dumps({
        "outputJson": str(output_json),
        "outputMd": str(output_md),
        "verdict": report["verdict"]["status"],
        "failedGates": failed_gates,
    }, sort_keys=True))
    return 1 if args.fail_on_gate and failed_gates else 0
