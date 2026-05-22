#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from real_access.common import (
    DEFAULT_ENVIRONMENT,
    DEFAULT_PROFILE,
    DEFAULT_RUN_ROOT,
    DEFAULT_SEED,
    load_json,
    run_output_dir,
    utc_now,
    write_json,
)
from real_access.aggregate import summarize_run
from real_access.comparison import build_comparison
from real_access.controller import add_controller_args
from real_access.manifest import build_manifest
from real_access.reports import write_comparison_report, write_report
from real_access.runner import run_manifest


def command_plan(args: argparse.Namespace) -> int:
    manifest = build_manifest(args)
    output = Path(args.output)
    write_json(output, manifest)
    print(json.dumps({"manifest": str(output), "count": len(manifest["entries"])}))
    return 0

def command_run(args: argparse.Namespace) -> int:
    output_dir = run_output_dir(
        Path(args.output_root),
        args.environment,
        args.seed,
        args.label,
    )
    output_dir.mkdir(parents=True, exist_ok=False)
    if args.manifest:
        manifest = load_json(Path(args.manifest))
    else:
        manifest = build_manifest(args)
    manifest["environment"] = args.environment
    write_json(output_dir / "manifest.json", manifest)
    summary = run_manifest(manifest, args, output_dir)
    print(
        json.dumps(
            {
                "outputDir": str(output_dir),
                "count": summary["totals"]["count"],
                "successRate": summary["totals"]["successRate"],
            },
            sort_keys=True,
        )
    )
    return 0

def command_compare(args: argparse.Namespace) -> int:
    comparison = build_comparison(args.run)
    output_json = Path(args.output_json)
    output_md = Path(args.output_md)
    write_json(output_json, comparison)
    write_comparison_report(output_md, comparison)
    print(
        json.dumps(
            {
                "outputJson": str(output_json),
                "outputMd": str(output_md),
                "runs": len(comparison["runs"]),
            },
            sort_keys=True,
        )
    )
    return 0

def command_summarize(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir)
    manifest = load_json(Path(args.manifest or run_dir / "manifest.json"))
    results = read_results_jsonl(Path(args.results_jsonl or run_dir / "results.jsonl"))
    existing_summary = Path(args.existing_summary or run_dir / "summary.json")
    previous = load_json(existing_summary) if existing_summary.exists() else {}
    started = args.started_at or previous.get("startedAt") or first_started_at(results)
    ended = args.ended_at or previous.get("endedAt") or utc_now()
    summary = summarize_run(manifest, results, str(started), str(ended))
    output_json = Path(args.output_json or run_dir / "summary.json")
    output_md = Path(args.output_md or run_dir / "report.md")
    write_json(output_json, summary)
    write_report(output_md, summary)
    print(
        json.dumps(
            {
                "outputJson": str(output_json),
                "outputMd": str(output_md),
                "count": summary["totals"]["count"],
                "successRate": summary["totals"]["successRate"],
            },
            sort_keys=True,
        )
    )
    return 0

def read_results_jsonl(path: Path) -> list[dict[str, object]]:
    return [
        json.loads(line)
        for line in path.read_text().splitlines()
        if line.strip()
    ]

def first_started_at(results: list[dict[str, object]]) -> str:
    for row in results:
        value = row.get("startedAt")
        if isinstance(value, str):
            return value
    return utc_now()

def add_sampling_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--profile", default=DEFAULT_PROFILE)
    parser.add_argument("--environment", default=DEFAULT_ENVIRONMENT)
    parser.add_argument("--seed", default=DEFAULT_SEED)
    parser.add_argument("--count", type=int, default=24)
    parser.add_argument("--buckets")
    parser.add_argument("--probe-modes")
    parser.add_argument("--behaviors")
    parser.add_argument("--duration-seconds", type=float, default=0)
    parser.add_argument("--spacing-ms", type=int, default=250)
    parser.add_argument("--jitter-ms", type=int, default=250)
    parser.add_argument("--burst-groups", type=int, default=4)
    parser.add_argument("--burst-window-ms", type=int, default=1000)
    parser.add_argument("--control-domain", action="append")
    parser.add_argument("--control-weight", type=int, default=8)
    parser.add_argument("--no-default-controls", action="store_true")
    parser.add_argument("--focus-domain", action="append")
    parser.add_argument("--focus-weight", type=int, default=25)
    parser.add_argument("--focus-bucket", default="target-focus")
    parser.add_argument("--timeout-seconds", type=float, default=5)

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run zero-identity black-box real-access baseline probes."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    plan_parser = subparsers.add_parser("plan", help="write a replay manifest")
    add_sampling_args(plan_parser)
    plan_parser.add_argument("--output", required=True)
    plan_parser.set_defaults(handler=command_plan)

    run_parser = subparsers.add_parser("run", help="run a replay manifest or sampled plan")
    add_sampling_args(run_parser)
    run_parser.add_argument("--manifest")
    run_parser.add_argument("--output-root", default=DEFAULT_RUN_ROOT)
    run_parser.add_argument("--label")
    add_controller_args(run_parser)
    run_parser.add_argument(
        "--replay-mode",
        choices=["open-loop", "sequential"],
        default="open-loop",
        help="schedule replay model when respecting scheduled offsets",
    )
    run_parser.add_argument("--max-concurrency", type=int, default=16)
    run_parser.add_argument("--lag-budget-ms", type=int, default=1000)
    run_parser.add_argument(
        "--no-respect-schedule",
        action="store_false",
        dest="respect_schedule",
        help="ignore manifest scheduled offsets and use --spacing-ms between entries",
    )
    run_parser.set_defaults(respect_schedule=True)
    run_parser.set_defaults(handler=command_run)

    compare_parser = subparsers.add_parser("compare", help="compare run summaries")
    compare_parser.add_argument(
        "--run",
        action="append",
        required=True,
        help="summary path or label=summary path; pass once per run",
    )
    compare_parser.add_argument("--output-json", required=True)
    compare_parser.add_argument("--output-md", required=True)
    compare_parser.set_defaults(handler=command_compare)

    summarize_parser = subparsers.add_parser(
        "summarize",
        help="rebuild a run summary/report from results.jsonl",
    )
    summarize_parser.add_argument("--run-dir", required=True)
    summarize_parser.add_argument("--manifest")
    summarize_parser.add_argument("--results-jsonl")
    summarize_parser.add_argument("--existing-summary")
    summarize_parser.add_argument("--started-at")
    summarize_parser.add_argument("--ended-at")
    summarize_parser.add_argument("--output-json")
    summarize_parser.add_argument("--output-md")
    summarize_parser.set_defaults(handler=command_summarize)

    return parser

def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
