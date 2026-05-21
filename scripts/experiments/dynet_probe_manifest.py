#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any


SUMMARY_SCHEMA = "dynet-probe-manifest-run/v1alpha1"
DEFAULT_OUTPUT_DIR = ".task/resources/dynet-probe-runs/latest"
DEFAULT_PROBES = {"tls-handshake", "https-head", "https-get"}


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


def run_probe(args: argparse.Namespace, entry: dict[str, Any], output_dir: Path) -> dict[str, Any]:
    entry_id = str(entry.get("id") or len(list(output_dir.glob("*.json"))) + 1)
    domain = str(entry["domain"])
    command = dynet_command(args) + [
        "probe",
        "--config",
        args.config,
        "--url",
        f"https://{domain}/",
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
        "scheduledOffsetMs": entry.get("scheduledOffsetMs"),
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


def write_summary(output_dir: Path, items: list[dict[str, Any]]) -> dict[str, Any]:
    summary = {
        "schema": SUMMARY_SCHEMA,
        "privacy": {
            "identityInformationSent": False,
            "cookiesSent": False,
            "authorizationSent": False,
            "responseBodiesStored": False,
        },
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
    lines = [
        "# Dynet Probe Manifest Run",
        "",
        f"- attempted: `{summary['totals']['attempted']}`",
        f"- passed: `{summary['totals']['passed']}`",
        f"- failed: `{summary['totals']['failed']}`",
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
            f"outbound=`{item['selectedOutbound']}` failedStage=`{item['failedStage']}`"
        )
    path.write_text("\n".join(lines) + "\n")


def command_run(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    items = [run_probe(args, entry, output_dir) for entry in selected_entries(args)]
    summary = write_summary(output_dir, items)
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
    parser.set_defaults(handler=command_run)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
