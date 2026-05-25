#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from scripts.lib.bootstrap import add_experiments_path

add_experiments_path()

from tunnel_private_config import (
    ConfigInputs,
    build_config,
    build_private_config,
    candidate_tag_offset,
    config_inputs,
    metadata,
    safe_proxy,
    write_json,
)
from tunnel_private import owned_private, plan_quality
from tunnel_private.cli import build_tunnel_private_parser
from tunnel_private.compare import compare_matrices, write_compare_markdown
from tunnel_private.matrix import command_matrix as run_matrix_command
from tunnel_private.quality_refresh import (
    command_quality_refresh as run_quality_refresh_command,
)
from tunnel_private.quality.regression import (
    command_quality_regression as run_quality_regression_command,
)
from tunnel_private.quality import adapter_readiness, sweep as sweep_commands, transport as transport_commands, transport_evidence
from tunnel_private.quality.readiness import maturity as adapter_maturity, product_effect as adapter_product_effect, protocol_followup, protocol_followup_batch
from tunnel_private.reporting import cascade_attempts, failed_stage, failure_scope, final_bound_selected, write_markdown, write_plan_markdown
from tunnel_private.target_observer import command_observe_target as run_observe_target_command
from dynet_clash import paired as paired_compare
from dynet_mainline import (
    adapter_coverage as mainline_adapter_coverage,
    baseline as mainline_baseline,
    provider_availability as mainline_provider_availability,
)
from dynet_mainline.runtime_surface.tcp import hardening as mainline_runtime_hardening

RUN_SCHEMA = "dynet-tunnel-private-run/v1alpha1"
BACKTICK_VALUE = re.compile(r"`[^`]+`")
IP_PORT_VALUE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}:\d+\b")
SENSITIVE_EVENT_FIELDS = {"error", "reason", "target"}


def command_build(args: argparse.Namespace) -> int:
    inputs = config_inputs(args)
    config = build_config(
        args,
        inputs.candidates,
        inputs.private,
        tag_offset=candidate_tag_offset(args),
    )
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
    offset = candidate_tag_offset(args)
    output_dir = Path(args.output_dir)
    report_dir = output_dir / "reports"
    output_dir.mkdir(parents=True, exist_ok=True)
    reports = []
    with tempfile.TemporaryDirectory(prefix="dynet-tunnel-private-") as temp_dir:
        for index, proxy in enumerate(inputs.candidates, start=1):
            tag = f"tunnel-{offset + index:03d}"
            for attempt in range(1, args.attempts + 1):
                config = build_config(
                    args,
                    [proxy],
                    inputs.private,
                    tag_offset=offset + index - 1,
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
            tag_offset=candidate_tag_offset(args),
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


def command_probe_private(args: argparse.Namespace) -> int:
    inputs = config_inputs(args)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="dynet-private-direct-") as temp_dir:
        config_path = Path(temp_dir) / "private.json"
        write_json(config_path, build_private_config(inputs.private), secret=True)
        report = run_probe(args, config_path)
    report_path = output_dir / "report.json"
    write_json(report_path, clean_report(report))
    summary = private_run_summary(args, inputs, report, report_path)
    write_json(output_dir / "summary.json", summary)
    write_plan_markdown(output_dir / "summary.md", summary)
    print(json.dumps({"outputDir": str(output_dir), **summary["totals"]}, sort_keys=True))
    return 0 if summary["totals"]["passed"] else 1


def command_matrix(args: argparse.Namespace) -> int:
    return run_matrix_command(
        args,
        run_probe=run_probe,
        clean_report=clean_report,
        plan_summary=plan_run_summary,
        private_summary=private_run_summary,
        write_markdown=write_plan_markdown,
    )


def command_compare_matrices(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = compare_matrices([Path(path) for path in args.matrix])
    write_json(output_dir / "summary.json", summary)
    write_compare_markdown(output_dir / "summary.md", summary)
    print(json.dumps({"outputDir": str(output_dir), **summary["totals"]}, sort_keys=True))
    return 0


def command_observe_target(args: argparse.Namespace) -> int:
    return run_observe_target_command(
        args,
        inputs=config_inputs(args),
        run_probe=run_probe,
        clean_report=clean_report,
        plan_summary=plan_run_summary,
        private_summary=private_run_summary,
    )


def command_observe_owned_private(args: argparse.Namespace) -> int:
    return owned_private.command_observe_owned_private(
        args,
        inputs=config_inputs(args),
        run_probe=run_probe,
        clean_report=clean_report,
        plan_summary=plan_run_summary,
        private_summary=private_run_summary,
    )


def command_quality_refresh(args: argparse.Namespace) -> int:
    return run_quality_refresh_command(
        args,
        inputs=config_inputs(args),
        run_probe=run_probe,
        clean_report=clean_report,
    )


def command_quality_regression(args: argparse.Namespace) -> int:
    return run_quality_regression_command(
        args,
        inputs=config_inputs(args),
        run_probe=run_probe,
        clean_report=clean_report,
        plan_summary=plan_run_summary,
        private_summary=private_run_summary,
        write_markdown=write_plan_markdown,
    )


def command_paired(args: argparse.Namespace) -> int:
    inputs = config_inputs(args)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    write_json(output_dir / "meta.json", paired_meta(inputs))
    with tempfile.TemporaryDirectory(prefix="dynet-tunnel-private-paired-") as temp_dir:
        config_path = Path(temp_dir) / "dynet-route-plan-private.json"
        write_json(
            config_path,
            build_config(args, inputs.candidates, inputs.private),
            secret=True,
        )
        paired_args = argparse.Namespace(**vars(args))
        paired_args.config = str(config_path)
        paired_args.limit = args.pair_limit
        return paired_compare.command_run(paired_args)


def paired_meta(inputs: ConfigInputs) -> dict[str, Any]:
    return {
        "schema": "dynet-tunnel-private-paired-config/v1alpha1",
        "config": metadata(
            inputs.group,
            inputs.all_candidates,
            inputs.supported_candidates,
            inputs.selected_candidates,
            inputs.candidates,
            inputs.private,
            inputs.resolution,
        ),
        "privacy": {
            "rawSecretsStored": False,
            "identityInformationSent": False,
            "cookiesSent": False,
            "authorizationSent": False,
        },
    }


def command_transport_check(args: argparse.Namespace) -> int:
    return transport_commands.command_transport_check(args, inputs=config_inputs(args))


def command_transport_evidence(args: argparse.Namespace) -> int:
    return transport_evidence.command_transport_evidence(args)


def command_inspect_plan_quality(args: argparse.Namespace) -> int:
    return plan_quality.command_inspect_plan_quality(args, inputs=config_inputs(args))


def command_compare_plan_quality(args: argparse.Namespace) -> int:
    return plan_quality.command_compare_plan_quality(args)


def run_probe(args: argparse.Namespace, config_path: Path) -> dict[str, Any]:
    command = [
        args.dynet_bin,
        "probe",
        "--config",
        str(config_path),
        "--url",
        args.target_url,
        "--protocol",
        args.protocol,
        "--format",
        "json",
    ]
    if args.quality_state:
        command.extend(["--quality-state", args.quality_state])
    if getattr(args, "inbound", None):
        command.extend(["--inbound", args.inbound])
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
        "reason": sanitize_text(report.get("reason")),
        "exitCode": report.get("_exitCode"),
        "boundSelected": final_bound_selected(report),
        "failedStage": failed_stage(report),
        "reportPath": str(report_path),
    }


def clean_report(report: dict[str, Any]) -> dict[str, Any]:
    return {
        key: clean_value(key, value)
        for key, value in report.items()
        if not key.startswith("_")
    }


def clean_value(key: str, value: Any) -> Any:
    if key == "reason":
        return sanitize_text(value)
    if key == "events" and isinstance(value, list):
        return [clean_event(event) for event in value]
    return value


def clean_event(event: Any) -> Any:
    if not isinstance(event, dict):
        return event
    cleaned = dict(event)
    event_fields = cleaned.get("fields")
    if isinstance(event_fields, dict):
        cleaned["fields"] = {
            str(key): clean_event_field(str(key), item)
            for key, item in event_fields.items()
        }
    return cleaned


def clean_event_field(key: str, value: Any) -> Any:
    if key == "target":
        return "<redacted-target>"
    if key in SENSITIVE_EVENT_FIELDS:
        return sanitize_text(value)
    return value


def sanitize_text(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    text = BACKTICK_VALUE.sub("`<redacted>`", value)
    return IP_PORT_VALUE.sub("<redacted-ip-port>", text)


def run_summary(
    args: argparse.Namespace,
    inputs: ConfigInputs,
    reports: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "schema": RUN_SCHEMA,
        "targetUrl": args.target_url,
        "probeMode": getattr(args, "probe_mode", "private"),
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
        "probeMode": getattr(args, "probe_mode", "private"),
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
            "reason": sanitize_text(report.get("reason")),
            "exitCode": report.get("_exitCode"),
            "boundSelected": final_bound_selected(report),
            "failedStage": None if passed else failed_stage(report),
            "failureScope": failure_scope(report),
            "cascadeAttempts": cascade_attempts(report),
            "reportPath": str(report_path),
        },
    }


def private_run_summary(
    args: argparse.Namespace,
    inputs: ConfigInputs,
    report: dict[str, Any],
    report_path: Path,
) -> dict[str, Any]:
    summary = plan_run_summary(args, inputs, report, report_path)
    summary["probeMode"] = "private-direct"
    return summary


def build_parser() -> argparse.ArgumentParser:
    return build_tunnel_private_parser({
        "build": command_build,
        "probe_candidates": command_probe,
        "probe_plan": command_probe_plan,
        "probe_private": command_probe_private,
        "matrix": command_matrix,
        "compare_matrices": command_compare_matrices,
        "observe_target": command_observe_target,
        "observe_owned_private": command_observe_owned_private,
        "quality_refresh": command_quality_refresh,
        "quality_regression": command_quality_regression,
        "paired": command_paired,
        "quality_sweep": lambda args: sweep_commands.command_quality_sweep(args, run_regression=command_quality_regression),
        "quality_sweep_summary": sweep_commands.command_quality_sweep_summary,
        "transport_check": command_transport_check,
        "transport_evidence": command_transport_evidence,
        "adapter_readiness": adapter_readiness.command_adapter_readiness,
        "adapter_maturity": adapter_maturity.command_adapter_maturity,
        "adapter_product_effect": adapter_product_effect.command_adapter_product_effect,
        "mainline_baseline": mainline_baseline.command_mainline_baseline,
        "mainline_provider_availability": (
            mainline_provider_availability.command_mainline_provider_availability
        ),
        "mainline_adapter_coverage": mainline_adapter_coverage.command_mainline_adapter_coverage,
        "mainline_runtime_handoff": mainline_runtime_hardening.command_mainline_runtime_handoff,
        "protocol_followup": protocol_followup.command_protocol_followup,
        "protocol_followup_batch": protocol_followup_batch.command_protocol_followup_batch,
        "inspect_plan_quality": command_inspect_plan_quality,
        "compare_plan_quality": command_compare_plan_quality,
    })


def main() -> int:
    args = build_parser().parse_args()
    return args.handler(args)

if __name__ == "__main__":
    raise SystemExit(main())
