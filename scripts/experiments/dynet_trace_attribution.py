#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from dynet_trace.batch import build_batch
from dynet_trace.common import (
    BATCH_MANIFEST_SCHEMA,
    DEFAULT_BATCH_OUTPUT_JSON,
    DEFAULT_BATCH_OUTPUT_MD,
    DEFAULT_MAX_UNKNOWN_RATE,
    DEFAULT_MIN_REPEAT_RUNS,
    DEFAULT_OUTPUT_JSON,
    DEFAULT_OUTPUT_MD,
    MAX_MISSING_CORRELATION_RATE,
    load_json,
    write_json,
)
from dynet_trace.reports import write_batch_report, write_report
from dynet_trace.summary import build_summary


def load_manifest(path: Path) -> dict[str, Any]:
    manifest = load_json(path)
    if manifest.get("schema") not in {BATCH_MANIFEST_SCHEMA, None}:
        raise SystemExit(
            f"unsupported batch manifest schema in {path}: {manifest.get('schema')}"
        )
    summaries = manifest.get("summaries")
    if not isinstance(summaries, list) or not summaries:
        raise SystemExit(f"batch manifest must contain a non-empty summaries list: {path}")
    if any(not isinstance(item, str) or not item for item in summaries):
        raise SystemExit(f"batch manifest summaries must be non-empty strings: {path}")
    return manifest

def manifest_input_path(raw: str, manifest_path: Path) -> Path:
    path = Path(raw)
    if path.is_absolute() or path.exists():
        return path
    return manifest_path.parent / path

def manifest_output_path(raw: str, manifest_path: Path) -> Path:
    path = Path(raw)
    if path.is_absolute():
        return path
    if path.parts and path.parts[0].startswith("."):
        return path
    return manifest_path.parent / path

def batch_paths_from_args(
    args: argparse.Namespace,
) -> tuple[list[Path], dict[str, Any] | None, Path | None]:
    manifest = None
    manifest_path = None
    paths: list[Path] = []
    if args.manifest:
        manifest_path = Path(args.manifest)
        manifest = load_manifest(manifest_path)
        paths.extend(
            manifest_input_path(path, manifest_path)
            for path in manifest.get("summaries", [])
        )
    paths.extend(Path(path) for path in args.summary or [])
    if not paths:
        raise SystemExit("batch requires at least one --summary or a --manifest")
    return paths, manifest, manifest_path

def manifest_section(manifest: dict[str, Any] | None, key: str) -> dict[str, Any]:
    if not manifest:
        return {}
    section = manifest.get(key, {})
    return section if isinstance(section, dict) else {}

def int_setting(
    cli_value: int | None,
    manifest: dict[str, Any] | None,
    key: str,
    default: int,
) -> int:
    if cli_value is not None:
        return cli_value
    value = manifest_section(manifest, "thresholds").get(key)
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        raise SystemExit(f"invalid integer threshold {key}: {value}") from None

def float_setting(
    cli_value: float | None,
    manifest: dict[str, Any] | None,
    key: str,
    default: float,
) -> float:
    if cli_value is not None:
        return cli_value
    value = manifest_section(manifest, "thresholds").get(key)
    if value is None:
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        raise SystemExit(f"invalid float threshold {key}: {value}") from None

def output_path_setting(
    cli_value: str | None,
    manifest: dict[str, Any] | None,
    manifest_path: Path | None,
    key: str,
    default: str,
) -> Path:
    if cli_value is not None:
        return Path(cli_value)
    value = manifest_section(manifest, "outputs").get(key)
    if isinstance(value, str) and value:
        if manifest_path:
            return manifest_output_path(value, manifest_path)
        return Path(value)
    return Path(default)

def failed_gate_names(batch: dict[str, Any]) -> list[str]:
    return [gate["name"] for gate in batch["gates"] if not gate["passed"]]

def command_summary(args: argparse.Namespace) -> int:
    report = load_json(Path(args.runtime_report))
    workload_probe = load_json(Path(args.workload_probe)) if args.workload_probe else None
    summary = build_summary(report, workload_probe)
    output_json = Path(args.output_json)
    output_md = Path(args.output_md)
    write_json(output_json, summary)
    write_report(output_md, summary)
    print(
        json.dumps(
            {
                "outputJson": str(output_json),
                "outputMd": str(output_md),
                "events": summary["totals"]["events"],
                "ready": summary["attributionReadiness"][
                    "canExplainPlanVsNodeForObservedPath"
                ],
            },
            sort_keys=True,
        )
    )
    return 0

def command_batch(args: argparse.Namespace) -> int:
    paths, manifest, manifest_path = batch_paths_from_args(args)
    batch = build_batch(
        paths,
        int_setting(
            args.min_repeat_runs,
            manifest,
            "minRepeatRuns",
            DEFAULT_MIN_REPEAT_RUNS,
        ),
        float_setting(
            args.max_unknown_rate,
            manifest,
            "maxUnknownRate",
            DEFAULT_MAX_UNKNOWN_RATE,
        ),
        float_setting(
            args.max_missing_correlation_rate,
            manifest,
            "maxMissingCorrelationRate",
            MAX_MISSING_CORRELATION_RATE,
        ),
    )
    output_json = output_path_setting(
        args.output_json,
        manifest,
        manifest_path,
        "json",
        DEFAULT_BATCH_OUTPUT_JSON,
    )
    output_md = output_path_setting(
        args.output_md,
        manifest,
        manifest_path,
        "md",
        DEFAULT_BATCH_OUTPUT_MD,
    )
    write_json(output_json, batch)
    write_batch_report(output_md, batch)
    failed_gates = failed_gate_names(batch)
    print(
        json.dumps(
            {
                "outputJson": str(output_json),
                "outputMd": str(output_md),
                "runs": batch["totals"]["runs"],
                "items": batch["totals"]["items"],
                "failedGates": failed_gates,
            },
            sort_keys=True,
        )
    )
    return 1 if args.fail_on_gate and failed_gates else 0

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Summarize dynet runtime events for plan-vs-node attribution."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    summary_parser = subparsers.add_parser("summary", help="summarize one runtime JSON report")
    summary_parser.add_argument("--runtime-report", required=True)
    summary_parser.add_argument("--workload-probe")
    summary_parser.add_argument("--output-json", default=DEFAULT_OUTPUT_JSON)
    summary_parser.add_argument("--output-md", default=DEFAULT_OUTPUT_MD)
    summary_parser.set_defaults(handler=command_summary)

    batch_parser = subparsers.add_parser(
        "batch",
        help="aggregate multiple attribution summaries into planner-safe evidence",
    )
    batch_parser.add_argument("--summary", action="append")
    batch_parser.add_argument(
        "--manifest",
        help="JSON manifest with summaries, thresholds, and optional outputs",
    )
    batch_parser.add_argument("--output-json")
    batch_parser.add_argument("--output-md")
    batch_parser.add_argument("--min-repeat-runs", type=int)
    batch_parser.add_argument("--max-unknown-rate", type=float)
    batch_parser.add_argument("--max-missing-correlation-rate", type=float)
    batch_parser.add_argument(
        "--fail-on-gate",
        action="store_true",
        help="return non-zero when any batch gate fails",
    )
    batch_parser.set_defaults(handler=command_batch)

    return parser

def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
