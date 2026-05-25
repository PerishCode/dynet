#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import time
from pathlib import Path
from typing import Any

from scripts.lib.jsonio import write_json

try:
    from probe_smoke.quality_gap_pipeline import run_local_pipeline, verify
    from probe_smoke.sinks import TcpSink
except ModuleNotFoundError:
    from quality_gap_pipeline import run_local_pipeline, verify
    from sinks import TcpSink


SUMMARY_SCHEMA = "dynet-probe-manifest-run/v1alpha1"
DEFAULT_OUTPUT_DIR = ".task/resources/quality-gap-smoke/latest"
DOMAIN = "api.gap.example"
PLAN_DOMAIN = "plan.gap.example"


def config_json(server_port: int) -> dict[str, Any]:
    return {
        "outbounds": [
            {"tag": "direct", "type": "direct"},
            ss_outbound("private-a", server_port),
            ss_outbound("private-b", server_port),
            plan_outbound("auto-static", "static"),
            plan_outbound("auto-cascade", "cascade-quality"),
        ],
        "routes": [
            {"domain": DOMAIN, "outbound": "auto-static"},
            {"domain": PLAN_DOMAIN, "outbound": "auto-cascade"},
            {"outbound": "direct"},
        ],
    }


def ss_outbound(tag: str, server_port: int) -> dict[str, Any]:
    return {
        "tag": tag,
        "type": "ss",
        "payload": {
            "server": "127.0.0.1",
            "port": server_port,
            "cipher": "aes-128-gcm",
            "password": "secret",
        },
    }


def plan_outbound(tag: str, strategy: str) -> dict[str, Any]:
    return {
        "tag": tag,
        "type": "plan",
        "capabilities": ["tcp", "ip-target", "domain-target", "probeable"],
        "payload": {
            "strategy": {
                "source": "internal",
                "key": strategy,
                "version": "",
                "options": {},
            },
            "selection": {
                "edges": [
                    {"type": "candidate", "to": "private-a"},
                    {"type": "candidate", "to": "private-b"},
                ]
            },
        },
    }


def quality_state() -> dict[str, Any]:
    return {
        "schema": "dynet-outbound-quality-state/v1alpha1",
        "generatedAtUnixMs": 1,
        "ttlSecs": 3600,
        "windowSecs": 3600,
        "expiresAtUnixMs": 4102444800000,
        "outbounds": [
            quality_entry("private-a", "unhealthy", 3, 0),
            quality_entry("private-b", "healthy", 3, 3),
        ],
    }


def quality_entry(
    outbound: str,
    verdict: str,
    attempts: int,
    successes: int,
) -> dict[str, Any]:
    failures = attempts - successes
    return {
        "outbound": outbound,
        "scope": "plan-candidate",
        "targetFamily": "gap.example",
        "transport": "tcp",
        "verdict": verdict,
        "attempts": attempts,
        "successes": successes,
        "failures": failures,
        "errorRate": round(failures / attempts, 4),
        "confidence": "medium",
        "stages": [],
    }


def run_probe(
    args: argparse.Namespace,
    run_dir: Path,
    run_id: str,
) -> dict[str, Any]:
    report_name = f"{run_id}-{DOMAIN}.json"
    report_path = run_dir / report_name
    command = [
        args.dynet_bin,
        "probe",
        "--config",
        str(args.config),
        "--quality-state",
        str(args.input_quality),
        "--host",
        DOMAIN,
        "--protocol",
        "tcp-connect",
        "--format",
        "json",
    ]
    completed = subprocess.run(command, text=True, capture_output=True, check=False)
    report = parse_report(completed.stdout)
    write_json(report_path, report)
    item = {
        "id": run_id,
        "bucket": "quality-gap-smoke",
        "behavior": "static-selected-behind",
        "groupId": "repeat-gap",
        "domain": DOMAIN,
        "sourceProbe": "tcp-connect",
        "dynetProtocol": "tcp-connect",
        "scheduledOffsetMs": None,
        "targetStartOffsetMs": None,
        "actualStartOffsetMs": None,
        "exitCode": completed.returncode,
        "status": report.get("status"),
        "reason": report.get("reason"),
        "selectedOutbound": selected_outbound(report),
        "failedStage": failed_stage(report),
        "httpStatus": None,
        "reportPath": report_name,
    }
    write_run_summary(run_dir, item)
    return item


def parse_report(stdout: str) -> dict[str, Any]:
    try:
        report = json.loads(stdout)
    except json.JSONDecodeError as error:
        return {
            "schema": "dynet-probe/invalid-output",
            "status": "deny",
            "reason": f"failed to parse dynet probe JSON: {error}",
            "events": [],
        }
    if isinstance(report, dict):
        return report
    return {
        "schema": "dynet-probe/invalid-output",
        "status": "deny",
        "reason": "dynet probe JSON root was not an object",
        "events": [],
    }


def selected_outbound(report: dict[str, Any]) -> str | None:
    for event in report.get("events", []):
        if event.get("kind") == "outbound-graph-selected":
            return fields(event).get("selected")
    for event in report.get("events", []):
        if event.get("kind") == "route-matched":
            return fields(event).get("outbound")
    return None


def failed_stage(report: dict[str, Any]) -> str | None:
    for event in report.get("events", []):
        event_fields = fields(event)
        if event.get("kind") == "outbound-stage-finished" and event_fields.get("status") == "failed":
            return event_fields.get("stage")
    return None


def fields(event: dict[str, Any]) -> dict[str, str]:
    value = event.get("fields", {})
    if not isinstance(value, dict):
        return {}
    return {str(key): str(item) for key, item in value.items()}


def write_run_summary(run_dir: Path, item: dict[str, Any]) -> None:
    summary = {
        "schema": SUMMARY_SCHEMA,
        "privacy": {
            "identityInformationSent": False,
            "cookiesSent": False,
            "authorizationSent": False,
            "responseBodiesStored": False,
            "rawPayloadStored": False,
        },
        "replay": {"schedule": False, "scheduleScale": 1.0},
        "scheduler": {"mode": "single", "maxConcurrency": 1},
        "totals": {
            "attempted": 1,
            "passed": 1 if item["status"] == "pass" else 0,
            "failed": 0 if item["status"] == "pass" else 1,
        },
        "items": [item],
    }
    write_json(run_dir / "summary.json", summary)


def write_artifact_summary(
    output_dir: Path,
    items: list[dict[str, Any]],
    server: dict[str, Any],
) -> dict[str, Any]:
    summary = {
        "schema": "dynet-quality-gap-smoke/v1alpha1",
        "runs": ["run-a", "run-b"],
        "domain": DOMAIN,
        "planDomain": PLAN_DOMAIN,
        "server": server,
        "totals": {
            "attempted": len(items),
            "passed": sum(1 for item in items if item["status"] == "pass"),
            "failed": sum(1 for item in items if item["status"] != "pass"),
        },
        "items": items,
    }
    write_json(output_dir / "summary.json", summary)
    return summary


def command_run(args: argparse.Namespace) -> int:
    if args.pipeline_only:
        return command_pipeline(args)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    with TcpSink(expected=2) as server:
        args.config = output_dir / "dynet.json"
        args.input_quality = output_dir / "input-quality.json"
        write_json(args.config, config_json(server.port))
        write_json(args.input_quality, quality_state())
        time.sleep(0.05)
        items = [
            run_probe(args, output_dir / "run-a", "0001"),
            run_probe(args, output_dir / "run-b", "0001"),
        ]
        server_summary = server.summary()
    summary = write_artifact_summary(output_dir, items, server_summary)
    if args.skip_pipeline:
        print(json.dumps(skipped_result(output_dir, summary), sort_keys=True))
        return 0 if summary["totals"]["failed"] == 0 else 1
    run_local_pipeline(output_dir, args)
    verification = verify(output_dir)
    result = {
        "outputDir": str(output_dir),
        "attempted": summary["totals"]["attempted"],
        "passed": summary["totals"]["passed"],
        "failed": summary["totals"]["failed"],
        "repeatedQualityGapKeys": verification["probeBatchTotals"]["repeatedQualityGapKeys"],
        "penaltyObservations": verification["penalizePlannerFeedback"]["penaltyObservations"],
        "status": verification["status"],
    }
    print(json.dumps(result, sort_keys=True))
    return 0 if verification["status"] == "pass" else 1


def command_pipeline(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir)
    args.config = output_dir / "dynet.json"
    args.input_quality = output_dir / "input-quality.json"
    run_local_pipeline(output_dir, args)
    verification = verify(output_dir)
    result = {
        "outputDir": str(output_dir),
        "repeatedQualityGapKeys": verification["probeBatchTotals"]["repeatedQualityGapKeys"],
        "penaltyObservations": verification["penalizePlannerFeedback"]["penaltyObservations"],
        "status": verification["status"],
    }
    print(json.dumps(result, sort_keys=True))
    return 0 if verification["status"] == "pass" else 1


def skipped_result(output_dir: Path, summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "outputDir": str(output_dir),
        "attempted": summary["totals"]["attempted"],
        "passed": summary["totals"]["passed"],
        "failed": summary["totals"]["failed"],
        "status": "pipeline-skipped",
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a repeated selected-vs-best quality-gap dynet smoke."
    )
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--dynet-bin", default="target/debug/dynet")
    parser.add_argument("--skip-pipeline", action="store_true")
    parser.add_argument("--pipeline-only", action="store_true")
    parser.set_defaults(handler=command_run)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
