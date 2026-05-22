#!/usr/bin/env python3
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import subprocess
import time
from pathlib import Path
from typing import Any


SUMMARY_SCHEMA = "dynet-probe-manifest-run/v1alpha1"
DEFAULT_OUTPUT_DIR = ".task/resources/dynet-probe-runs/latest"
DEFAULT_PROBES = {"tls-handshake", "https-head", "https-get"}
SOURCE_PROTOCOL = "source"


def load_json(path: Path) -> Any:
    return json.loads(path.read_text())


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True))


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
        "selectedOutbound": selected_outbound(report),
        "failedStage": failed_stage(report),
        "httpStatus": http_status(report),
        "reportPath": str(output_dir / f"{entry_id}-{safe_name(domain)}.json"),
    }
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


def dynet_protocol(args: argparse.Namespace, entry: dict[str, Any]) -> str:
    if args.dynet_protocol != SOURCE_PROTOCOL:
        return args.dynet_protocol
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


def write_summary(
    output_dir: Path,
    items: list[dict[str, Any]],
    args: argparse.Namespace,
) -> dict[str, Any]:
    summary = {
        "schema": SUMMARY_SCHEMA,
        "privacy": {
            "identityInformationSent": False,
            "cookiesSent": False,
            "authorizationSent": False,
            "responseBodiesStored": False,
        },
        "replay": {
            "schedule": bool(args.replay_schedule),
            "scheduleScale": args.schedule_scale,
        },
        "scheduler": scheduler_summary(items, args),
        "totals": {
            "attempted": len(items),
            "passed": sum(1 for item in items if item["status"] == "pass"),
            "failed": sum(1 for item in items if item["status"] != "pass"),
        },
        "byBucket": aggregate(items, "bucket"),
        "byBehavior": aggregate(items, "behavior"),
        "bySourceProbe": aggregate(items, "sourceProbe"),
        "bySelectedOutbound": aggregate(items, "selectedOutbound"),
        "items": items,
    }
    write_json(output_dir / "summary.json", summary)
    write_markdown(output_dir / "summary.md", summary)
    return summary


def aggregate(items: list[dict[str, Any]], field: str) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for item in items:
        key = str(item.get(field) or "unknown")
        grouped.setdefault(key, []).append(item)
    output = []
    for key, rows in sorted(grouped.items()):
        attempted = len(rows)
        passed = sum(1 for row in rows if row["status"] == "pass")
        output.append(
            {
                "key": key,
                "attempted": attempted,
                "passed": passed,
                "failed": attempted - passed,
                "successRate": round(passed / attempted, 4) if attempted else 0,
            }
        )
    return output


def write_markdown(path: Path, summary: dict[str, Any]) -> None:
    scheduler = summary.get("scheduler", {})
    lag = scheduler.get("lagMs", {})
    lines = [
        "# Dynet Probe Manifest Run",
        "",
        f"- attempted: `{summary['totals']['attempted']}`",
        f"- passed: `{summary['totals']['passed']}`",
        f"- failed: `{summary['totals']['failed']}`",
        f"- replay mode: `{scheduler.get('mode')}`",
        f"- max concurrency: `{scheduler.get('maxConcurrency')}`",
        f"- lag budget: `{scheduler.get('lagBudgetMs')}` ms",
        f"- lag exceeded: `{scheduler.get('lagExceeded')}`",
        f"- schedule lag p95: `{lag.get('p95')}` ms",
        "",
        "## By Behavior",
        "",
    ]
    for item in summary["byBehavior"]:
        lines.append(
            f"- `{item['key']}` passed={item['passed']}/{item['attempted']} "
            f"rate={item['successRate']}"
        )
    lines.extend(
        [
            "",
            "## By Source Probe",
            "",
        ]
    )
    for item in summary["bySourceProbe"]:
        lines.append(
            f"- `{item['key']}` passed={item['passed']}/{item['attempted']} "
            f"rate={item['successRate']}"
        )
    lines.extend(
        [
            "",
            "## By Selected Outbound",
            "",
        ]
    )
    for item in summary["bySelectedOutbound"]:
        lines.append(
            f"- `{item['key']}` passed={item['passed']}/{item['attempted']} "
            f"rate={item['successRate']}"
        )
    lines.extend(
        [
            "",
            "## Items",
            "",
        ]
    )
    for item in summary["items"]:
        lines.append(
            f"- `{item['id']}` {item['domain']} status=`{item['status']}` "
            f"behavior=`{item['behavior']}` sourceProbe=`{item['sourceProbe']}` "
            f"dynetProtocol=`{item['dynetProtocol']}` outbound=`{item['selectedOutbound']}` "
            f"scheduledOffsetMs=`{item['scheduledOffsetMs']}` "
            f"targetStartOffsetMs=`{item['targetStartOffsetMs']}` "
            f"actualStartOffsetMs=`{item['actualStartOffsetMs']}` failedStage=`{item['failedStage']}`"
        )
    path.write_text("\n".join(lines) + "\n")


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
    print(
        json.dumps(
            {
                "outputDir": str(output_dir),
                "attempted": summary["totals"]["attempted"],
                "passed": summary["totals"]["passed"],
                "failed": summary["totals"]["failed"],
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


def scheduler_summary(items: list[dict[str, Any]], args: argparse.Namespace) -> dict[str, Any]:
    lags = []
    for item in items:
        scheduled = item.get("targetStartOffsetMs")
        actual = item.get("actualStartOffsetMs")
        if isinstance(scheduled, int) and isinstance(actual, int):
            lags.append(max(0, actual - scheduled))
    p95 = percentile(lags, 95)
    return {
        "mode": args.replay_mode if args.replay_schedule else "sequential",
        "maxConcurrency": args.max_concurrency if args.replay_schedule else 1,
        "lagBudgetMs": args.lag_budget_ms,
        "lagExceeded": bool(p95 is not None and p95 > args.lag_budget_ms),
        "lagMs": {
            "p50": percentile(lags, 50),
            "p95": p95,
            "max": max(lags) if lags else None,
        },
    }


def percentile(values: list[int], target: int) -> int | None:
    if not values:
        return None
    ordered = sorted(values)
    index = round((len(ordered) - 1) * (target / 100))
    return ordered[index]


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
        choices=[SOURCE_PROTOCOL, "https-head", "tls-handshake"],
        default=SOURCE_PROTOCOL,
        help="dynet probe protocol to run; source maps manifest tls-handshake entries to TLS-only probes.",
    )
    parser.set_defaults(handler=command_run)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
