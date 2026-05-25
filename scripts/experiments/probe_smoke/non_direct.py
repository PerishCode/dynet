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
    from probe_smoke.sinks import TcpSink, TlsSink, combined_server_summary
except ModuleNotFoundError:
    from sinks import TcpSink, TlsSink, combined_server_summary


SUMMARY_SCHEMA = "dynet-probe-manifest-run/v1alpha1"
DEFAULT_OUTPUT_DIR = ".task/resources/non-direct-smoke/latest"


def config_json(server_port: int, tls_port: int | None = None) -> dict[str, Any]:
    tls_port = server_port if tls_port is None else tls_port
    return {
        "outbounds": [
            {"tag": "direct", "type": "direct"},
            plan_outbound("bound-plan", "direct"),
            ss_outbound(server_port),
            plan_outbound("auto-ss", "private-ss"),
            vmess_outbound(server_port),
            plan_outbound("auto-vmess", "private-vmess"),
            trojan_outbound(tls_port),
            plan_outbound("auto-trojan", "private-trojan"),
            dialer_outbound("private-ss-via-bound", "private-ss"),
            dialer_outbound("private-vmess-via-bound", "private-vmess"),
            dialer_outbound("private-trojan-via-bound", "private-trojan"),
        ],
        "rules": [
            {
                "tag": "identity-ss-private",
                "domain": "dialer.example",
                "outbound": "private-ss-via-bound",
            },
            {
                "tag": "identity-vmess-private",
                "domain": "dialer-vmess.example",
                "outbound": "private-vmess-via-bound",
            },
            {
                "tag": "identity-trojan-private",
                "domain": "dialer-trojan.example",
                "outbound": "private-trojan-via-bound",
            },
        ],
        "routes": [
            {"domain": "candidate.example", "outbound": "auto-ss"},
            {"domain": "candidate-vmess.example", "outbound": "auto-vmess"},
            {"domain": "candidate-trojan.example", "outbound": "auto-trojan"},
            {"outbound": "direct"},
        ],
    }


def plan_outbound(tag: str, candidate: str) -> dict[str, Any]:
    return {
        "tag": tag,
        "type": "plan",
        "capabilities": ["tcp", "ip-target", "domain-target", "probeable"],
        "payload": {
            "strategy": {
                "source": "internal",
                "key": "cascade-quality",
                "version": "",
                "options": {},
            },
            "selection": {"edges": [{"type": "candidate", "to": candidate}]},
        },
    }


def ss_outbound(server_port: int) -> dict[str, Any]:
    return {
        "tag": "private-ss",
        "type": "ss",
        "payload": {
            "server": "127.0.0.1",
            "port": server_port,
            "cipher": "aes-128-gcm",
            "password": "secret",
        },
    }


def vmess_outbound(server_port: int) -> dict[str, Any]:
    return {
        "tag": "private-vmess",
        "type": "vmess",
        "payload": {
            "server": "127.0.0.1",
            "port": server_port,
            "uuid": "00000000-0000-0000-0000-000000000001",
            "cipher": "aes-128-gcm",
        },
    }


def trojan_outbound(server_port: int) -> dict[str, Any]:
    return {
        "tag": "private-trojan",
        "type": "trojan",
        "payload": {
            "server": "localhost",
            "serverIp": "127.0.0.1",
            "port": server_port,
            "password": "secret",
            "sni": "localhost",
            "skipCertVerify": True,
        },
    }


def dialer_outbound(tag: str, target: str) -> dict[str, Any]:
    return {
        "tag": tag,
        "type": "dialer",
        "payload": {"bound": "bound-plan", "target": target},
    }


def smoke_entries() -> list[dict[str, Any]]:
    return [
        {
            "id": "0001",
            "bucket": "non-direct-smoke",
            "behavior": "plan-candidate-ss",
            "domain": "candidate.example",
            "probe": "tcp-connect",
        },
        {
            "id": "0002",
            "bucket": "non-direct-smoke",
            "behavior": "dialer-bound-ss",
            "domain": "dialer.example",
            "probe": "tcp-connect",
        },
        {
            "id": "0003",
            "bucket": "non-direct-smoke",
            "behavior": "plan-candidate-vmess",
            "domain": "candidate-vmess.example",
            "probe": "tcp-connect",
        },
        {
            "id": "0004",
            "bucket": "non-direct-smoke",
            "behavior": "dialer-bound-vmess",
            "domain": "dialer-vmess.example",
            "probe": "tcp-connect",
        },
        {
            "id": "0005",
            "bucket": "non-direct-smoke",
            "behavior": "plan-candidate-trojan",
            "domain": "candidate-trojan.example",
            "probe": "tcp-connect",
        },
        {
            "id": "0006",
            "bucket": "non-direct-smoke",
            "behavior": "dialer-bound-trojan",
            "domain": "dialer-trojan.example",
            "probe": "tcp-connect",
        },
    ]


def run_probe(args: argparse.Namespace, entry: dict[str, Any], output_dir: Path) -> dict[str, Any]:
    report_path = output_dir / f"{entry['id']}-{entry['domain']}.json"
    command = [
        args.dynet_bin,
        "probe",
        "--config",
        args.config,
        "--host",
        entry["domain"],
        "--protocol",
        "tcp-connect",
        "--format",
        "json",
    ]
    completed = subprocess.run(command, text=True, capture_output=True, check=False)
    report = parse_report(completed.stdout)
    write_json(report_path, report)
    return {
        "id": entry["id"],
        "bucket": entry["bucket"],
        "behavior": entry["behavior"],
        "groupId": None,
        "domain": entry["domain"],
        "sourceProbe": entry["probe"],
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
        "reportPath": str(report_path),
    }


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


def write_summary(
    output_dir: Path,
    items: list[dict[str, Any]],
    server: dict[str, Any],
) -> dict[str, Any]:
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
        "scheduler": {"mode": "sequential", "maxConcurrency": 1},
        "server": server,
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
        grouped.setdefault(str(item.get(field) or "unknown"), []).append(item)
    rows = []
    for key, group in sorted(grouped.items()):
        passed = sum(1 for item in group if item["status"] == "pass")
        rows.append({
            "key": key,
            "attempted": len(group),
            "passed": passed,
            "failed": len(group) - passed,
            "successRate": round(passed / len(group), 4) if group else 0,
        })
    return rows


def write_markdown(path: Path, summary: dict[str, Any]) -> None:
    lines = [
        "# Dynet Non-Direct Smoke",
        "",
        f"- attempted: `{summary['totals']['attempted']}`",
        f"- passed: `{summary['totals']['passed']}`",
        f"- failed: `{summary['totals']['failed']}`",
        f"- server connections: `{summary['server']['connections']}`",
        f"- server bytes: `{summary['server']['totalBytes']}`",
        "",
        "## Items",
        "",
    ]
    for item in summary["items"]:
        lines.append(
            f"- `{item['id']}` {item['domain']} behavior=`{item['behavior']}` "
            f"status=`{item['status']}` outbound=`{item['selectedOutbound']}` "
            f"reason=`{item['reason']}`"
        )
    path.write_text("\n".join(lines) + "\n")


def command_run(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    entries = smoke_entries()
    raw_expected = sum(1 for entry in entries if "trojan" not in entry["behavior"])
    tls_expected = len(entries) - raw_expected
    with TcpSink(expected=raw_expected) as raw_server, TlsSink(expected=tls_expected) as tls_server:
        config_path = output_dir / "dynet.json"
        write_json(config_path, config_json(raw_server.port, tls_server.port))
        args.config = str(config_path)
        time.sleep(0.05)
        items = [run_probe(args, entry, output_dir) for entry in entries]
        server_summary = combined_server_summary(raw_server.summary(), tls_server.summary())
    summary = write_summary(output_dir, items, server_summary)
    result = {
        "outputDir": str(output_dir),
        "summary": str(output_dir / "summary.json"),
        "attempted": summary["totals"]["attempted"],
        "passed": summary["totals"]["passed"],
        "failed": summary["totals"]["failed"],
        "serverConnections": server_summary["connections"],
        "serverBytes": server_summary["totalBytes"],
    }
    print(json.dumps(result, sort_keys=True))
    expected_connections = len(entries)
    ok = (
        summary["totals"]["failed"] == 0
        and server_summary["connections"] == expected_connections
        and server_summary["totalBytes"] > 0
    )
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a local non-direct dynet tcp-connect smoke."
    )
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--dynet-bin", default="target/debug/dynet")
    parser.set_defaults(handler=command_run)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
