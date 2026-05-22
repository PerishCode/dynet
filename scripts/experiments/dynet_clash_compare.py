#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


SCHEMA = "dynet-clash-proof-comparison/v1alpha1"
DEFAULT_OUTPUT_JSON = ".task/resources/dynet-clash-github-proof-comparison.json"
DEFAULT_OUTPUT_MD = ".task/resources/dynet-clash-github-proof-comparison.md"


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True))


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
    buckets = compare_groups(clash_bucket_map(clash), dynet_bucket_map(dynet))
    domains = compare_groups(clash_domain_map(clash), dynet_domain_map(dynet))
    return {
        "schema": SCHEMA,
        "generatedAt": utc_now(),
        "inputs": {
            "clashSummary": args.clash_summary,
            "dynetSummary": args.dynet_summary,
        },
        "privacy": {
            "rawResultsStored": False,
            "responseBodiesStored": False,
            "sourceAddressesStored": False,
        },
        "totals": compare_totals(clash, dynet),
        "byBucket": buckets,
        "byDomain": domains,
        "dynetFailures": dynet_failures(dynet),
        "verdict": verdict(buckets, args),
        "limits": [
            "dynet probe manifest is diagnostic and does not replay the original schedule",
            "dynet probe currently runs HTTPS HEAD even when sourceProbe says tls-handshake",
            "black-box Clash summary lacks selected-node and candidate-plan evidence",
        ],
    }


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


def verdict(rows: list[dict[str, Any]], args: argparse.Namespace) -> dict[str, Any]:
    primary = find_row(rows, args.primary_bucket)
    controls = [find_row(rows, key) for key in args.guardrail_bucket or []]
    controls = [row for row in controls if row is not None]
    primary_win = bool(
        primary
        and primary.get("successRateDelta", 0) >= args.min_primary_delta
    )
    guardrail_failures = [
        row for row in controls
        if row.get("dynet", {}).get("successRate", 0) < args.min_guardrail_rate
    ]
    if primary_win and not guardrail_failures:
        status = "dynet-superior-candidate"
    elif primary_win:
        status = "github-superior-with-guardrail-regression"
    else:
        status = "not-superior"
    return {
        "status": status,
        "primaryBucket": args.primary_bucket,
        "primaryDelta": primary.get("successRateDelta") if primary else None,
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
    parser.add_argument("--primary-bucket", default="github-proof")
    parser.add_argument("--guardrail-bucket", action="append", default=["control-global", "work-direct"])
    parser.add_argument("--min-primary-delta", type=float, default=0.05)
    parser.add_argument("--min-guardrail-rate", type=float, default=0.99)
    return parser


def main() -> int:
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
