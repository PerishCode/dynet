#!/usr/bin/env python3
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import subprocess
import time
from pathlib import Path
from typing import Any

from scripts.lib.bootstrap import add_experiments_path
from scripts.lib.jsonio import load_json, write_json

add_experiments_path()

from dynet_probe.quality_pipeline import build_quality_pipeline
from dynet_probe.reports import write_summary


SUMMARY_SCHEMA = "dynet-probe-manifest-run/v1alpha1"
DEFAULT_OUTPUT_DIR = ".task/resources/dynet-probe-runs/latest"
DEFAULT_PROBES = {"tcp-connect", "tls-handshake", "https-head", "https-get"}
SOURCE_PROTOCOL = "source"
READ_POLICY_FLAGS = [
    ("read_poll_ms", "pollTimeoutMs", "--probe-read-poll-timeout-ms"),
    ("read_budget_ms", "pendingBudgetMs", "--probe-read-pending-budget-ms"),
    ("read_sleep_ms", "pendingSleepMs", "--probe-read-pending-sleep-ms"),
]


def manifest_entries(manifest: Any) -> list[dict[str, Any]]:
    if isinstance(manifest, dict):
        entries = manifest.get("entries", [])
    else:
        entries = manifest
    return [entry for entry in entries if isinstance(entry, dict)]


def selected_entries(args: argparse.Namespace) -> list[dict[str, Any]]:
    entries = manifest_entries(load_json(Path(args.manifest)))
    probes = set(args.probe_type or DEFAULT_PROBES)
    rows = []
    for entry in entries:
        if entry.get("probe") not in probes:
            continue
        if args.bucket and entry.get("bucket") not in args.bucket:
            continue
        if args.domain and entry.get("domain") not in args.domain:
            continue
        if int(entry.get("port") or 443) != 443:
            continue
        rows.append(entry)
        if args.limit and len(rows) >= args.limit:
            break
    return rows


def run_probe(
    args: argparse.Namespace,
    entry: dict[str, Any],
    output_dir: Path,
    actual_start_offset_ms: int | None = None,
    target_start_offset_ms: int | None = None,
) -> dict[str, Any]:
    entry_id = str(entry.get("id") or len(list(output_dir.glob("*.json"))) + 1)
    domain = str(entry["domain"])
    command = dynet_probe_command(args, entry)
    completed = subprocess.run(command, text=True, capture_output=True, check=False)
    report = parse_report(completed.stdout)
    item = {
        "id": entry_id,
        "bucket": entry.get("bucket"),
        "behavior": entry.get("behavior"),
        "groupId": entry.get("groupId"),
        "domain": domain,
        "sourceProbe": entry.get("probe"),
        "dynetProtocol": dynet_protocol(args, entry),
        "scheduledOffsetMs": entry.get("scheduledOffsetMs"),
        "targetStartOffsetMs": target_start_offset_ms,
        "actualStartOffsetMs": actual_start_offset_ms,
        "exitCode": completed.returncode,
        "status": report.get("status"),
        "reason": report.get("reason"),
        "failureScope": report.get("failureScope"),
        "selectedOutbound": selected_outbound(report),
        "failedStage": failed_stage(report),
        "httpStatus": http_status(report),
        "reportPath": str(output_dir / f"{entry_id}-{safe_name(domain)}.json"),
    }
    retry = retry_report(report)
    if retry:
        item["directTlsRetry"] = retry
    read_policy = report_read_policy(report)
    if read_policy:
        item["readPolicy"] = read_policy
    write_json(Path(item["reportPath"]), report)
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


def dynet_command(args: argparse.Namespace) -> list[str]:
    if args.sudo:
        return ["sudo", args.dynet_bin]
    return [args.dynet_bin]


def dynet_probe_command(args: argparse.Namespace, entry: dict[str, Any]) -> list[str]:
    domain = str(entry["domain"])
    command = dynet_command(args) + [
        "probe",
        "--config",
        args.config,
        "--url",
        f"https://{domain}/",
        "--protocol",
        dynet_protocol(args, entry),
        "--format",
        "json",
    ]
    if args.inbound:
        command.extend(["--inbound", args.inbound])
    if args.quality_state:
        command.extend(["--quality-state", args.quality_state])
    append_read_policy(command, args)
    attempts = retry_attempts(args)
    if attempts > 1:
        command.extend(["--retry-direct-tls-eof-attempts", str(attempts)])
        command.extend(["--retry-direct-tls-eof-sleep-ms", str(retry_sleep_ms(args))])
    return command


def append_read_policy(command: list[str], args: argparse.Namespace) -> None:
    for attr, _key, flag in READ_POLICY_FLAGS:
        value = getattr(args, attr, None)
        if value is not None:
            command.extend([flag, str(int(value))])


def report_read_policy(report: dict[str, Any]) -> dict[str, Any] | None:
    policy = report.get("readPolicy")
    if isinstance(policy, dict):
        return policy
    return None


def retry_report(report: dict[str, Any]) -> dict[str, Any] | None:
    retry = report.get("retry")
    if isinstance(retry, dict) and retry.get("enabled"):
        return retry
    return None


def retry_attempts(args: argparse.Namespace) -> int:
    return int(
        getattr(
            args,
            "retry_direct_tls_eof_attempts",
            getattr(args, "dynet_direct_tls_retry_attempts", 1),
        )
    )


def retry_sleep_ms(args: argparse.Namespace) -> int:
    return int(
        getattr(
            args,
            "retry_direct_tls_eof_sleep_ms",
            getattr(args, "dynet_direct_tls_retry_sleep_ms", 250),
        )
    )


def dynet_protocol(args: argparse.Namespace, entry: dict[str, Any]) -> str:
    if args.dynet_protocol != SOURCE_PROTOCOL:
        return args.dynet_protocol
    if entry.get("probe") == "tcp-connect":
        return "tcp-connect"
    if entry.get("probe") == "tls-handshake":
        return "tls-handshake"
    return "https-head"


def schedule_base_offset(entries: list[dict[str, Any]]) -> int:
    if not entries:
        return 0
    return scheduled_offset_ms(entries[0])


def scheduled_offset_ms(entry: dict[str, Any]) -> int:
    return int(entry.get("scheduledOffsetMs") or 0)


def replay_target_ms(args: argparse.Namespace, entry: dict[str, Any], base_offset_ms: int) -> int:
    delta = max(0, scheduled_offset_ms(entry) - base_offset_ms)
    return round(delta * args.schedule_scale)


def sleep_until(target_ms: int, started_monotonic: float) -> None:
    elapsed_ms = round((time.monotonic() - started_monotonic) * 1000)
    sleep_ms = target_ms - elapsed_ms
    if sleep_ms > 0:
        time.sleep(sleep_ms / 1000)


def non_negative_float(value: str) -> float:
    number = float(value)
    if number < 0:
        raise argparse.ArgumentTypeError("must be non-negative")
    return number


def non_negative_int(value: str) -> int:
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError("must be non-negative")
    return number


def positive_int(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return number


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


def http_status(report: dict[str, Any]) -> int | None:
    for event in report.get("events", []):
        if event.get("kind") != "outbound-attempt-finished":
            continue
        value = fields(event).get("httpStatus")
        if value is None:
            continue
        try:
            return int(value)
        except ValueError:
            return None
    return None


def fields(event: dict[str, Any]) -> dict[str, str]:
    value = event.get("fields", {})
    if not isinstance(value, dict):
        return {}
    return {str(key): str(item) for key, item in value.items()}


def safe_name(value: str) -> str:
    return "".join(char if char.isalnum() or char in ".-" else "_" for char in value)[:80]


def command_run(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    entries = selected_entries(args)
    if args.replay_schedule:
        entries = sorted(entries, key=scheduled_offset_ms)
    started = time.monotonic()
    base_offset_ms = schedule_base_offset(entries)
    if args.replay_schedule and args.replay_mode == "open-loop":
        items = run_open_loop(args, entries, output_dir, started, base_offset_ms)
    else:
        items = run_sequential(args, entries, output_dir, started, base_offset_ms)
    items = sorted(items, key=lambda item: str(item.get("id")))
    summary = write_summary(output_dir, items, args)
    quality_pipeline = None
    if args.build_quality_state:
        quality_pipeline = build_quality_pipeline(output_dir, args)
        summary = write_summary(output_dir, items, args, quality_pipeline)
    print(
        json.dumps(
            {
                "outputDir": str(output_dir),
                "attempted": summary["totals"]["attempted"],
                "passed": summary["totals"]["passed"],
                "failed": summary["totals"]["failed"],
                "qualityState": quality_pipeline.get("qualityState")
                if quality_pipeline
                else None,
            },
            sort_keys=True,
        )
    )
    return 0 if summary["totals"]["failed"] == 0 else 1


def run_open_loop(
    args: argparse.Namespace,
    entries: list[dict[str, Any]],
    output_dir: Path,
    started: float,
    base_offset_ms: int,
) -> list[dict[str, Any]]:
    items = []
    with ThreadPoolExecutor(max_workers=max(args.max_concurrency, 1)) as executor:
        futures = []
        for entry in entries:
            target_ms = replay_target_ms(args, entry, base_offset_ms)
            sleep_until(target_ms, started)
            futures.append(
                executor.submit(
                    run_probe_with_clock,
                    args,
                    entry,
                    output_dir,
                    started,
                    target_ms,
                )
            )
        for future in as_completed(futures):
            items.append(future.result())
    return items


def run_probe_with_clock(
    args: argparse.Namespace,
    entry: dict[str, Any],
    output_dir: Path,
    started: float,
    target_ms: int,
) -> dict[str, Any]:
    actual_ms = monotonic_offset_ms(started)
    return run_probe(args, entry, output_dir, actual_ms, target_ms)


def run_sequential(
    args: argparse.Namespace,
    entries: list[dict[str, Any]],
    output_dir: Path,
    started: float,
    base_offset_ms: int,
) -> list[dict[str, Any]]:
    items = []
    for entry in entries:
        if args.replay_schedule:
            target_ms = replay_target_ms(args, entry, base_offset_ms)
            sleep_until(target_ms, started)
        else:
            target_ms = None
        actual_start_offset_ms = monotonic_offset_ms(started)
        items.append(run_probe(args, entry, output_dir, actual_start_offset_ms, target_ms))
    return items


def monotonic_offset_ms(started: float) -> int:
    return round((time.monotonic() - started) * 1000)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Replay real-access manifest HTTPS targets through dynet probe."
    )
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--dynet-bin", default="dynet")
    parser.add_argument("--sudo", action="store_true")
    parser.add_argument("--inbound")
    parser.add_argument("--quality-state")
    parser.add_argument("--probe-read-poll-timeout-ms", dest="read_poll_ms", type=positive_int)
    parser.add_argument("--probe-read-pending-budget-ms", dest="read_budget_ms", type=non_negative_int)
    parser.add_argument("--probe-read-pending-sleep-ms", dest="read_sleep_ms", type=non_negative_int)
    parser.add_argument("--retry-direct-tls-eof-attempts", type=int, default=1)
    parser.add_argument("--retry-direct-tls-eof-sleep-ms", type=int, default=250)
    parser.add_argument(
        "--build-quality-state",
        action="store_true",
        help="post-process this run into attribution, probe-batch, and quality state",
    )
    parser.add_argument(
        "--previous-quality-state",
        action="append",
        help="fresh quality-state JSON to retain while building the output state",
    )
    parser.add_argument(
        "--previous-attribution",
        action="append",
        help="prior probe-manifest attribution JSON for repeat-gap batching",
    )
    parser.add_argument("--attribution-output-json")
    parser.add_argument("--attribution-output-md")
    parser.add_argument("--probe-batch-output-json")
    parser.add_argument("--probe-batch-output-md")
    parser.add_argument("--quality-output-json")
    parser.add_argument("--quality-output-md")
    parser.add_argument("--quality-ttl-seconds", type=int, default=300)
    parser.add_argument("--quality-window-seconds", type=int, default=1800)
    parser.add_argument("--quality-now-unix-ms", type=int)
    parser.add_argument("--min-repeat-runs", type=int, default=2)
    parser.add_argument(
        "--quality-gap-mode",
        choices=["observe", "penalize", "auto"],
        default="observe",
        help="observe, penalize, or auto-promote repeated quality gaps with proof",
    )
    parser.add_argument(
        "--quality-gap-promotion-proof",
        action="append",
        help="VM private-runtime repeat summary proving penalty promotion safety",
    )
    parser.add_argument(
        "--quality-gap-promotion-context",
        action="append",
        help="maturity/product-effect summary carrying observe-only policy context",
    )
    parser.add_argument("--limit", type=int)
    parser.add_argument("--bucket", action="append")
    parser.add_argument("--domain", action="append")
    parser.add_argument("--probe-type", action="append")
    parser.add_argument("--replay-schedule", action="store_true")
    parser.add_argument("--schedule-scale", type=non_negative_float, default=1.0)
    parser.add_argument(
        "--replay-mode",
        choices=["open-loop", "sequential"],
        default="open-loop",
    )
    parser.add_argument("--max-concurrency", type=int, default=16)
    parser.add_argument("--lag-budget-ms", type=int, default=1000)
    parser.add_argument(
        "--dynet-protocol",
        choices=[SOURCE_PROTOCOL, "tcp-connect", "https-head", "tls-handshake"],
        default=SOURCE_PROTOCOL,
        help="dynet probe protocol to run; source preserves tcp-connect and maps manifest tls-handshake entries to TLS-only probes.",
    )
    parser.set_defaults(handler=command_run)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
