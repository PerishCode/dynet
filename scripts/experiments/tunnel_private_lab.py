#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from tunnel_private_config import (
    MERGED_CONFIG,
    PROVIDER_DIR,
    ConfigInputs,
    build_config,
    config_inputs,
    metadata,
    safe_proxy,
    write_json,
)


RUN_SCHEMA = "dynet-tunnel-private-run/v1alpha1"


def command_build(args: argparse.Namespace) -> int:
    inputs = config_inputs(args)
    config = build_config(args, inputs.candidates, inputs.private)
    meta = metadata(
        inputs.group,
        inputs.all_candidates,
        inputs.supported_candidates,
        inputs.selected_candidates,
        inputs.candidates,
        inputs.private,
        inputs.resolution,
    )
    write_json(Path(args.output_config), config, secret=True)
    write_json(Path(args.output_meta), meta)
    print(json.dumps({"config": args.output_config, "meta": args.output_meta}, sort_keys=True))
    return 0


def command_probe(args: argparse.Namespace) -> int:
    inputs = config_inputs(args)
    output_dir = Path(args.output_dir)
    report_dir = output_dir / "reports"
    output_dir.mkdir(parents=True, exist_ok=True)
    reports = []
    with tempfile.TemporaryDirectory(prefix="dynet-tunnel-private-") as temp_dir:
        for index, proxy in enumerate(inputs.candidates, start=1):
            tag = f"tunnel-{index:03d}"
            for attempt in range(1, args.attempts + 1):
                config = build_config(
                    args,
                    [proxy],
                    inputs.private,
                    tag_offset=index - 1,
                    private_path=args.probe_mode == "private",
                )
                config_path = Path(temp_dir) / f"{tag}-{attempt}.json"
                write_json(config_path, config, secret=True)
                report = run_probe(args, config_path)
                item = summarize_probe(report, proxy, tag, attempt, report_dir)
                reports.append(item)
    summary = run_summary(args, inputs, reports)
    write_json(output_dir / "summary.json", summary)
    write_markdown(output_dir / "summary.md", summary)
    print(json.dumps({"outputDir": str(output_dir), **summary["totals"]}, sort_keys=True))
    return 0 if summary["totals"]["passed"] else 1


def command_probe_plan(args: argparse.Namespace) -> int:
    inputs = config_inputs(args)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="dynet-tunnel-private-plan-") as temp_dir:
        config = build_config(
            args,
            inputs.candidates,
            inputs.private,
            private_path=args.probe_mode == "private",
        )
        config_path = Path(temp_dir) / "plan.json"
        write_json(config_path, config, secret=True)
        report = run_probe(args, config_path)
    report_path = output_dir / "report.json"
    write_json(report_path, clean_report(report))
    summary = plan_run_summary(
        args,
        inputs,
        report,
        report_path,
    )
    write_json(output_dir / "summary.json", summary)
    write_plan_markdown(output_dir / "summary.md", summary)
    print(json.dumps({"outputDir": str(output_dir), **summary["totals"]}, sort_keys=True))
    return 0 if summary["totals"]["passed"] else 1


def run_probe(args: argparse.Namespace, config_path: Path) -> dict[str, Any]:
    command = [
        args.dynet_bin,
        "probe",
        "--config",
        str(config_path),
        "--url",
        args.target_url,
        "--format",
        "json",
    ]
    if args.quality_state:
        command.extend(["--quality-state", args.quality_state])
    completed = subprocess.run(command, text=True, capture_output=True, check=False)
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        report = {
            "schema": "dynet-probe/invalid-output",
            "status": "deny",
            "reason": f"invalid dynet probe JSON: {error}; stderr={completed.stderr.strip()}",
            "events": [],
        }
    report["_exitCode"] = completed.returncode
    return report


def summarize_probe(
    report: dict[str, Any],
    proxy: dict[str, Any],
    tag: str,
    attempt: int,
    report_dir: Path,
) -> dict[str, Any]:
    report_path = report_dir / f"{tag}-{attempt}.json"
    write_json(report_path, clean_report(report))
    return {
        "tag": tag,
        "attempt": attempt,
        "candidate": safe_proxy(proxy, tag),
        "status": report.get("status"),
        "reason": report.get("reason"),
        "exitCode": report.get("_exitCode"),
        "boundSelected": final_bound_selected(report),
        "failedStage": failed_stage(report),
        "reportPath": str(report_path),
    }


def clean_report(report: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in report.items() if not key.startswith("_")}


def fields(event: dict[str, Any]) -> dict[str, str]:
    value = event.get("fields", {})
    if not isinstance(value, dict):
        return {}
    return {str(key): str(item) for key, item in value.items()}


def bound_selected(report: dict[str, Any]) -> str | None:
    for event in report.get("events", []):
        event_fields = fields(event)
        if event.get("kind") == "dialer-cascade-selected":
            return event_fields.get("boundSelected")
    return None


def final_bound_selected(report: dict[str, Any]) -> str | None:
    for event in report.get("events", []):
        event_fields = fields(event)
        if (
            event.get("kind") == "dialer-cascade-attempt-finished"
            and event_fields.get("status") == "success"
        ):
            return event_fields.get("boundSelected")
    return bound_selected(report)


def failed_stage(report: dict[str, Any]) -> str | None:
    for event in report.get("events", []):
        event_fields = fields(event)
        if event.get("kind") == "outbound-stage-finished" and event_fields.get("status") == "failed":
            outbound = event_fields.get("outbound", "<unknown>")
            stage = event_fields.get("stage", "unknown")
            return f"{outbound}:{stage}"
    return None


def run_summary(
    args: argparse.Namespace,
    inputs: ConfigInputs,
    reports: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "schema": RUN_SCHEMA,
        "targetUrl": args.target_url,
        "probeMode": args.probe_mode,
        "metadata": metadata(
            inputs.group,
            inputs.all_candidates,
            inputs.supported_candidates,
            inputs.selected_candidates,
            inputs.candidates,
            inputs.private,
            inputs.resolution,
        ),
        "totals": {
            "attempted": len(reports),
            "passed": sum(1 for item in reports if item["status"] == "pass"),
            "failed": sum(1 for item in reports if item["status"] != "pass"),
        },
        "reports": reports,
    }


def plan_run_summary(
    args: argparse.Namespace,
    inputs: ConfigInputs,
    report: dict[str, Any],
    report_path: Path,
) -> dict[str, Any]:
    passed = report.get("status") == "pass"
    return {
        "schema": RUN_SCHEMA,
        "targetUrl": args.target_url,
        "probeMode": args.probe_mode,
        "metadata": metadata(
            inputs.group,
            inputs.all_candidates,
            inputs.supported_candidates,
            inputs.selected_candidates,
            inputs.candidates,
            inputs.private,
            inputs.resolution,
        ),
        "totals": {
            "attempted": 1,
            "passed": 1 if passed else 0,
            "failed": 0 if passed else 1,
        },
        "report": {
            "status": report.get("status"),
            "reason": report.get("reason"),
            "exitCode": report.get("_exitCode"),
            "boundSelected": final_bound_selected(report),
            "failedStage": None if passed else failed_stage(report),
            "cascadeAttempts": cascade_attempts(report),
            "reportPath": str(report_path),
        },
    }


def cascade_attempts(report: dict[str, Any]) -> list[dict[str, str]]:
    attempts = []
    for event in report.get("events", []):
        if event.get("kind") != "dialer-cascade-attempt-finished":
            continue
        event_fields = fields(event)
        attempts.append(
            {
                key: value
                for key, value in {
                    "attempt": event_fields.get("attempt"),
                    "boundSelected": event_fields.get("boundSelected"),
                    "status": event_fields.get("status"),
                    "errorType": event_fields.get("errorType"),
                    "elapsedMs": event_fields.get("elapsedMs"),
                }.items()
                if value is not None
            }
        )
    return attempts


def write_markdown(path: Path, summary: dict[str, Any]) -> None:
    lines = [
        "# Tunnel Private Probe Run",
        "",
        f"- target: `{summary['targetUrl']}`",
        f"- attempted: `{summary['totals']['attempted']}`",
        f"- passed: `{summary['totals']['passed']}`",
        f"- failed: `{summary['totals']['failed']}`",
        "",
        "## Reports",
        "",
    ]
    for item in summary["reports"]:
        lines.append(
            f"- `{item['tag']}` attempt={item['attempt']} status=`{item['status']}` "
            f"bound=`{item['boundSelected']}` failedStage=`{item['failedStage']}`"
        )
    path.write_text("\n".join(lines) + "\n")


def write_plan_markdown(path: Path, summary: dict[str, Any]) -> None:
    report = summary["report"]
    lines = [
        "# Tunnel Private Plan Probe Run",
        "",
        f"- target: `{summary['targetUrl']}`",
        f"- status: `{report['status']}`",
        f"- boundSelected: `{report['boundSelected']}`",
        f"- failedStage: `{report['failedStage']}`",
        f"- reason: `{report['reason']}`",
        "",
        "## Cascade Attempts",
        "",
    ]
    for item in report["cascadeAttempts"]:
        lines.append(
            f"- attempt=`{item.get('attempt')}` bound=`{item.get('boundSelected')}` "
            f"status=`{item.get('status')}` errorType=`{item.get('errorType')}` "
            f"elapsedMs=`{item.get('elapsedMs')}`"
        )
    path.write_text("\n".join(lines) + "\n")


def add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--merged-config", default=str(MERGED_CONFIG))
    parser.add_argument("--provider-dir", default=str(PROVIDER_DIR))
    parser.add_argument("--private-provider", default=str(PROVIDER_DIR / "private.yaml"))
    parser.add_argument("--tunnel-name", default="Tunnel")
    parser.add_argument("--filter")
    parser.add_argument("--private-name")
    parser.add_argument("--private-contains", default="Private")
    parser.add_argument("--private-server-ip")
    parser.add_argument("--resolve-private-server", action="store_true")
    parser.add_argument("--resolve-tunnel-server", action="store_true")
    parser.add_argument("--supported-type", action="append", default=["vmess", "trojan"])
    parser.add_argument("--strategy-key", default="cascade-quality")
    parser.add_argument("--domain", action="append", default=[])
    parser.add_argument("--domain-suffix", action="append", default=["chatgpt.com"])
    parser.add_argument("--limit", type=int)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build and probe dynet-native Tunnel-to-Private configs."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build")
    add_common(build)
    build.add_argument("--output-config", required=True)
    build.add_argument("--output-meta", required=True)
    build.set_defaults(handler=command_build)
    probe = subparsers.add_parser("probe-candidates")
    add_common(probe)
    probe.add_argument("--output-dir", required=True)
    probe.add_argument("--dynet-bin", default="target/debug/dynet")
    probe.add_argument("--target-url", default="https://chatgpt.com/")
    probe.add_argument("--attempts", type=int, default=1)
    probe.add_argument("--probe-mode", choices=["private", "candidate"], default="private")
    probe.add_argument("--quality-state")
    probe.set_defaults(handler=command_probe)
    probe_plan = subparsers.add_parser("probe-plan")
    add_common(probe_plan)
    probe_plan.add_argument("--output-dir", required=True)
    probe_plan.add_argument("--dynet-bin", default="target/debug/dynet")
    probe_plan.add_argument("--target-url", default="https://chatgpt.com/")
    probe_plan.add_argument("--probe-mode", choices=["private", "candidate"], default="private")
    probe_plan.add_argument("--quality-state")
    probe_plan.set_defaults(handler=command_probe_plan)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
