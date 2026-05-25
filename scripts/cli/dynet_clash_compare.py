#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import importlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from scripts.lib.bootstrap import add_experiments_path
from scripts.lib.jsonio import load_json, write_json

add_experiments_path()

from dynet_clash import (
    attribution,
    comparison_limits as comparison_limit_model,
    limits as limit_model,
    objective,
    paired_retry,
    runtime_gate,
)

SCHEMA = "dynet-clash-proof-comparison/v1alpha1"
DEFAULT_OUTPUT_JSON = ".task/resources/dynet-clash-github-proof-comparison.json"
DEFAULT_OUTPUT_MD = ".task/resources/dynet-clash-github-proof-comparison.md"


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def build_comparison(args: argparse.Namespace) -> dict[str, Any]:
    clash = load_json(Path(args.clash_summary))
    dynet = load_json(Path(args.dynet_summary))
    return build_comparison_from_summaries(clash, dynet, args)

def build_comparison_from_summaries(
    clash: dict[str, Any],
    dynet: dict[str, Any],
    args: argparse.Namespace,
) -> dict[str, Any]:
    clash_buckets = clash_bucket_map(clash)
    dynet_buckets = dynet_bucket_map(dynet)
    buckets = compare_groups(clash_buckets, dynet_buckets)
    domains = compare_groups(clash_domain_map(clash), dynet_domain_map(dynet))
    runtime = runtime_gate_from_args(args)
    controller = clash_controller_summary(clash)
    limit_details = comparison_limit_model.build(
        clash,
        dynet,
        args,
        runtime,
        controller,
        clash_buckets,
        dynet_buckets,
    )
    retry = dynet_retry_summary(dynet)
    paired_path = getattr(args, "paired_summary", None)
    if paired_path:
        retry = paired_retry.summary_totals(load_json(Path(paired_path)), retry)
    return {
        "schema": SCHEMA,
        "generatedAt": utc_now(),
        "inputs": {
            "clashSummary": args.clash_summary,
            "dynetSummary": args.dynet_summary,
            "runtimeSummary": getattr(args, "runtime_summary", None),
            "pairedSummary": paired_path,
        },
        "privacy": {
            "rawResultsStored": False,
            "responseBodiesStored": False,
            "sourceAddressesStored": False,
        },
        "totals": compare_totals(clash, dynet),
        "byBucket": buckets,
        "byDomain": domains,
        "clashController": controller,
        "dynetRetry": retry,
        "dynetFailures": dynet_failures(dynet),
        "dynetRuntimeGate": runtime,
        "deficitAttribution": attribution.dynet_deficit(
            dynet,
            args.primary_bucket,
            runtime,
        ),
        "verdict": verdict(buckets, args),
        "limits": limit_model.messages(limit_details),
        "limitDetails": limit_details,
    }


def runtime_gate_from_args(args: argparse.Namespace) -> dict[str, Any] | None:
    path = getattr(args, "runtime_summary", None)
    if not path:
        return None
    raw_path = Path(path)
    return runtime_gate.build(load_json(raw_path), str(raw_path))

def dynet_retry_summary(dynet: dict[str, Any]) -> dict[str, Any]:
    replay = dynet.get("pairedReplay", {})
    if not isinstance(replay, dict):
        return {"enabled": False}
    retry = replay.get("dynetRetry", {})
    if not isinstance(retry, dict):
        return {"enabled": False}
    return paired_retry.normalize(retry)

def compare_totals(clash: dict[str, Any], dynet: dict[str, Any]) -> dict[str, Any]:
    clash_total = from_clash_total(clash["totals"])
    dynet_total = from_dynet_total(dynet["totals"])
    return compare_pair("all", clash_total, dynet_total)


def compare_groups(
    clash: dict[str, dict[str, Any]],
    dynet: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    rows = []
    for key in sorted(set(clash) | set(dynet)):
        rows.append(compare_pair(key, clash.get(key), dynet.get(key)))
    return rows


def compare_pair(
    key: str,
    clash: dict[str, Any] | None,
    dynet: dict[str, Any] | None,
) -> dict[str, Any]:
    row = {"key": key, "clash": clash, "dynet": dynet}
    if clash is not None and dynet is not None:
        row["successRateDelta"] = round(dynet["successRate"] - clash["successRate"], 4)
        row["failureDelta"] = dynet["failure"] - clash["failure"]
    return row


def clash_bucket_map(summary: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(item["key"]): from_clash_total(item)
        for item in summary.get("byBucket", [])
    }


def dynet_bucket_map(summary: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(item["key"]): from_dynet_total(item)
        for item in summary.get("byBucket", [])
    }


def clash_domain_map(summary: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(item["key"]): from_clash_total(item)
        for item in summary.get("byDomain", [])
    }


def dynet_domain_map(summary: dict[str, Any]) -> dict[str, dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in summary.get("items", []):
        grouped[str(item.get("domain", "unknown"))].append(item)
    return {key: dynet_items_total(rows) for key, rows in grouped.items()}


def from_clash_total(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "count": int(item.get("count", 0)),
        "success": int(item.get("success", 0)),
        "failure": int(item.get("failure", 0)),
        "successRate": float(item.get("successRate", 0)),
        "p95Ms": item.get("latencyMs", {}).get("p95"),
        "errors": item.get("errors", []),
    }


def from_dynet_total(item: dict[str, Any]) -> dict[str, Any]:
    attempted = int(item.get("attempted", 0))
    passed = int(item.get("passed", 0))
    failed = int(item.get("failed", attempted - passed))
    return {
        "count": attempted,
        "success": passed,
        "failure": failed,
        "successRate": round(passed / attempted, 4) if attempted else 0,
    }


def dynet_items_total(items: list[dict[str, Any]]) -> dict[str, Any]:
    attempted = len(items)
    passed = sum(1 for item in items if item.get("status") == "pass")
    failures = [
        item
        for item in items
        if item.get("status") != "pass"
    ]
    total = from_dynet_total({
        "attempted": attempted,
        "passed": passed,
        "failed": attempted - passed,
    })
    reasons = Counter(str(item.get("failedStage") or "unknown") for item in failures)
    if reasons:
        total["errors"] = [{"key": key, "count": count} for key, count in reasons.most_common()]
    return total


def dynet_failures(summary: dict[str, Any]) -> list[dict[str, Any]]:
    output = []
    for item in summary.get("items", []):
        if item.get("status") == "pass":
            continue
        output.append({
            "id": item.get("id"),
            "bucket": item.get("bucket"),
            "domain": item.get("domain"),
            "selectedOutbound": item.get("selectedOutbound"),
            "failedStage": item.get("failedStage"),
            "reason": item.get("reason"),
        })
    return output


def clash_controller_summary(clash: dict[str, Any]) -> dict[str, Any]:
    controller = clash.get("controllerAttribution", {})
    if not isinstance(controller, dict) or not controller.get("enabled"):
        return {
            "enabled": False,
            "observed": 0,
            "items": 0,
            "rawNodeNamesStored": False,
            "chainKeys": [],
        }
    return {
        "enabled": True,
        "observed": int(controller.get("observed", 0)),
        "items": int(controller.get("items", 0)),
        "missing": int(controller.get("missing", 0)),
        "rawNodeNamesStored": bool(controller.get("rawNodeNamesStored", False)),
        "chainKeys": controller.get("chainKeys", []),
        "rules": controller.get("rules", []),
        "matchSources": controller.get("matchSources", []),
        "missReasons": controller.get("missReasons", []),
        "failureGroups": controller.get("failureGroups", []),
    }


def comparison_limits(
    clash: dict[str, Any],
    dynet: dict[str, Any],
    args: argparse.Namespace,
    runtime: dict[str, Any] | None = None,
) -> list[str]:
    return limit_model.messages(comparison_limit_details(clash, dynet, args, runtime))


def comparison_limit_details(
    clash: dict[str, Any],
    dynet: dict[str, Any],
    args: argparse.Namespace,
    runtime: dict[str, Any] | None = None,
) -> list[dict[str, str]]:
    return comparison_limit_model.build(
        clash,
        dynet,
        args,
        runtime,
        clash_controller_summary(clash),
        clash_bucket_map(clash),
        dynet_bucket_map(dynet),
    )


def verdict(rows: list[dict[str, Any]], args: argparse.Namespace) -> dict[str, Any]:
    primary = find_row(rows, args.primary_bucket)
    controls = [find_row(rows, key) for key in args.guardrail_bucket or []]
    controls = [row for row in controls if row is not None]
    primary_delta = primary.get("successRateDelta", 0) if primary else None
    guardrail_failures = [
        row for row in controls
        if row.get("dynet", {}).get("successRate", 0) < args.min_guardrail_rate
    ]
    return {
        "status": objective.comparison_status(primary_delta, guardrail_failures, args),
        "primaryBucket": args.primary_bucket,
        "primaryDelta": primary_delta,
        "guardrailFailures": [row["key"] for row in guardrail_failures],
    }


def find_row(rows: list[dict[str, Any]], key: str) -> dict[str, Any] | None:
    return next((row for row in rows if row["key"] == key), None)


def write_markdown(path: Path, report: dict[str, Any]) -> None:
    lines = [
        "# Dynet vs Clash Proof Comparison",
        "",
        f"- Verdict: `{report['verdict']['status']}`",
        f"- Primary delta: `{report['verdict']['primaryDelta']}`",
        "",
        "## Totals",
        "",
        comparison_line(report["totals"]),
        "",
        "## Buckets",
        "",
    ]
    for row in report["byBucket"]:
        lines.append(comparison_line(row))
    lines.extend(["", "## Domains", ""])
    for row in sorted(report["byDomain"], key=domain_sort_key)[:16]:
        lines.append(comparison_line(row))
    if report["clashController"]["enabled"]:
        append_clash_controller(lines, report["clashController"])
    append_dynet_retry(lines, report.get("dynetRetry", {}))
    if report.get("dynetRuntimeGate"):
        lines.extend(runtime_gate.markdown_lines(report["dynetRuntimeGate"]))
    append_deficit_attribution(lines, report["deficitAttribution"])
    if report["dynetFailures"]:
        lines.extend(["", "## Dynet Failures", ""])
        for item in report["dynetFailures"]:
            lines.append(
                f"- `{item['domain']}` bucket=`{item['bucket']}` "
                f"outbound=`{item['selectedOutbound']}` stage=`{item['failedStage']}` "
                f"reason=`{item['reason']}`"
            )
    lines.extend(["", "## Limits", ""])
    for item in report["limits"]:
        lines.append(f"- {item}")
    path.write_text("\n".join(lines) + "\n")


def append_clash_controller(lines: list[str], controller: dict[str, Any]) -> None:
    lines.extend(["", "## Clash Controller", ""])
    lines.append(
        f"- observed=`{controller['observed']}/{controller['items']}` "
        f"missing=`{controller['missing']}` rawNodeNamesStored=`{controller['rawNodeNamesStored']}`"
    )
    for item in controller.get("chainKeys", [])[:8]:
        lines.append(f"- chain `{item['key']}` count=`{item['count']}`")
    for item in controller.get("matchSources", [])[:8]:
        lines.append(f"- match `{item['key']}` count=`{item['count']}`")
    for item in controller.get("missReasons", [])[:8]:
        lines.append(f"- miss `{item['key']}` count=`{item['count']}`")
    if controller.get("failureGroups"):
        append_clash_failures(lines, controller["failureGroups"])


def append_dynet_retry(lines: list[str], retry: dict[str, Any]) -> None:
    if not retry.get("enabled"):
        return
    lines.extend(["", "## Dynet Retry", ""])
    lines.append(
        f"- policy=`{retry.get('policy')}` attempts=`{retry.get('attempts')}` "
        f"recoveredAfterRetry=`{retry.get('recoveredAfterRetry')}` "
        f"unresolvedDirectTlsEof=`{retry.get('unresolvedDirectTlsEof')}`"
    )
    lines.append(
        f"- classifiedAttempts=`{retry.get('attemptClassified', 0)}/{retry.get('attempts', 0)}` "
        f"classifiedFinals=`{retry.get('finalClassified', 0)}/{retry.get('rows', 0)}`"
    )
    if retry.get("attemptClassifications"):
        for item in retry["attemptClassifications"]:
            lines.append(f"- attempt `{item['key']}` count=`{item['count']}`")
    if retry.get("finalClassifications"):
        for item in retry["finalClassifications"]:
            lines.append(f"- final `{item['key']}` count=`{item['count']}`")


def append_deficit_attribution(lines: list[str], summary: dict[str, Any]) -> None:
    lines.extend(["", "## Deficit Attribution", ""])
    lines.append(
        f"- classification=`{summary['classification']}` "
        f"runtimeGate=`{summary['runtimeGateClassification']}` "
        f"failures=`{summary['failureCount']}`"
    )
    for key in ["byStage", "byOutbound", "byReasonMarker"]:
        if summary.get(key):
            compact = ", ".join(
                f"{item['key']}:{item['count']}"
                for item in summary[key][:8]
            )
            lines.append(f"- {key}: `{compact}`")


def append_clash_failures(lines: list[str], groups: list[dict[str, Any]]) -> None:
    lines.append("- failure groups:")
    for item in groups[:10]:
        miss = item.get("missReason") or "none"
        sources = ",".join(
            source["key"] for source in item.get("matchSources", [])
        ) or "none"
        lines.append(
            f"  - chain=`{item['chainKey']}` observed=`{item['observed']}` "
            f"missReason=`{miss}` domain=`{item['domain']}` "
            f"probe=`{item['probe']}` "
            f"stage=`{item['errorStage']}` error=`{item['errorType']}` "
            f"count=`{item['count']}` matchSources=`{sources}`"
        )


def comparison_line(row: dict[str, Any]) -> str:
    clash = compact(row.get("clash"))
    dynet = compact(row.get("dynet"))
    delta = row.get("successRateDelta")
    return f"- `{row['key']}` clash={clash} dynet={dynet} delta=`{delta}`"


def compact(item: dict[str, Any] | None) -> str:
    if item is None:
        return "none"
    return f"{item['success']}/{item['count']} sr={item['successRate']}"


def domain_sort_key(row: dict[str, Any]) -> tuple[int, int, str]:
    dynet_fail = row.get("dynet", {}).get("failure", 0) if row.get("dynet") else 0
    clash_fail = row.get("clash", {}).get("failure", 0) if row.get("clash") else 0
    return (-(dynet_fail + clash_fail), -max_count(row), row["key"])


def max_count(row: dict[str, Any]) -> int:
    return max(
        row.get("clash", {}).get("count", 0) if row.get("clash") else 0,
        row.get("dynet", {}).get("count", 0) if row.get("dynet") else 0,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Compare Clash real-access baseline with dynet probe summary."
    )
    parser.add_argument("--clash-summary", required=True)
    parser.add_argument("--dynet-summary", required=True)
    parser.add_argument("--output-json", default=DEFAULT_OUTPUT_JSON)
    parser.add_argument("--output-md", default=DEFAULT_OUTPUT_MD)
    parser.add_argument("--runtime-summary")
    parser.add_argument("--paired-summary")
    parser.add_argument(
        "--require-runtime-gate",
        action="store_true",
        help="treat missing or failed dynet runtime workloadFlow evidence as a comparison limit",
    )
    parser.add_argument("--primary-bucket", default="github-proof")
    parser.add_argument("--guardrail-bucket", action="append", default=["control-global", "work-direct"])
    parser.add_argument("--min-primary-delta", type=float, default=0.05)
    parser.add_argument(
        "--min-parity-delta",
        type=float,
        default=0.0,
        help="minimum primary-bucket delta for dynet >= Clash parity",
    )
    parser.add_argument("--min-guardrail-rate", type=float, default=0.99)
    parser.add_argument("--max-pair-gap-ms", type=int, default=2000)
    return parser


def main() -> int:
    subcommands = {
        "batch": "dynet_clash.batch",
        "paired": "dynet_clash.paired",
        "paired-read-surface": "dynet_clash.paired_surface.read_surface",
        "gap": "dynet_clash.gap",
        "gap-drilldown": "dynet_clash.gap.drilldown",
        "gap-recommend": "dynet_clash.gap.recommendation",
        "gap-retry": "dynet_clash.gap.retry",
        "gap-protocol-retry": "dynet_clash.gap.protocol_retry",
        "gap-read-budget": "dynet_clash.gap.read_budget",
    }
    if len(sys.argv) > 1 and sys.argv[1] in subcommands:
        module = importlib.import_module(subcommands[sys.argv[1]])
        return module.command(sys.argv[2:])
    args = build_parser().parse_args()
    report = build_comparison(args)
    write_json(Path(args.output_json), report)
    write_markdown(Path(args.output_md), report)
    print(json.dumps({
        "outputJson": args.output_json,
        "outputMd": args.output_md,
        "verdict": report["verdict"]["status"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
