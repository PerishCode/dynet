from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from dynet_clash.gap import read_budget


class DynetClashGapReadBudgetTest(unittest.TestCase):
    def test_selects_read_rows(self) -> None:
        rows = read_budget.selected_rows(drilldown_report(), sample_args(limit=1))

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["domain"], "api.github.com")

    def test_budget_pass(self) -> None:
        with tempfile.TemporaryDirectory() as raw_dir:
            root = Path(raw_dir)
            args = sample_args(
                drilldown=write_drilldown(root),
                output_dir=str(root / "out"),
            )
            with patch(
                "dynet_clash.gap.read_budget.subprocess.run",
                return_value=completed(probe_report("pass")),
            ):
                report = read_budget.run(args)

        self.assertEqual(report["totals"]["rows"], 1)
        self.assertEqual(report["totals"]["passed"], 1)
        self.assertEqual(report["totals"]["stillProtocolRead"], 0)
        self.assertEqual(report["policy"]["readPolicy"]["pendingBudgetMs"], 16000)
        self.assertEqual(report["rows"][0]["readPolicy"]["pendingBudgetMs"], 16000)

    def test_outbound_drift(self) -> None:
        with tempfile.TemporaryDirectory() as raw_dir:
            root = Path(raw_dir)
            args = sample_args(
                drilldown=write_drilldown(root, selected="private-via-tunnel"),
                output_dir=str(root / "out"),
            )
            with patch(
                "dynet_clash.gap.read_budget.subprocess.run",
                return_value=completed(probe_report("pass", selected="direct")),
            ):
                report = read_budget.run(args)

        self.assertEqual(report["totals"]["passed"], 0)
        self.assertEqual(report["totals"]["selectedOutboundDriftRows"], 1)
        self.assertEqual(
            report["lastClassifications"],
            [{"key": "selected-outbound-drift", "count": 1}],
        )

    def test_command_flags(self) -> None:
        command = read_budget.dynet_command(
            sample_args(read_poll_ms=100, read_sleep_ms=1),
            "api.github.com",
            "https-head",
        )

        self.assertIn("--probe-read-pending-budget-ms", command)
        self.assertIn("16000", command)
        self.assertIn("--probe-read-poll-timeout-ms", command)
        self.assertIn("100", command)
        self.assertIn("--probe-read-pending-sleep-ms", command)
        self.assertIn("1", command)


def drilldown_report() -> dict[str, object]:
    return {
        "rows": [
            row("api.github.com", "https-head", protocol_read_key()),
            row("github.com", "https-head", "direct-tls-eof-after-path-complete"),
        ]
    }


def row(domain: str, probe: str, classification: str) -> dict[str, object]:
    return {
        "id": "0001",
        "window": 1,
        "domain": domain,
        "probe": probe,
        "outcome": "dynet-only-failure",
        "classification": classification,
        "evidence": read_evidence(),
    }


def protocol_read_key() -> str:
    return "protocol-read-vmess-response-header-length-pending-budget-exhausted"


def read_evidence() -> dict[str, object]:
    return {
        "streamFirstRead": {
            "protocolReadMarker": "vmess-response-header-length-pending",
            "protocolReadDisposition": "pending-budget-exhausted",
        }
    }


def write_drilldown(root: Path, selected: str | None = None) -> str:
    path = root / "drilldown.json"
    item = row("api.github.com", "https-head", protocol_read_key())
    if selected:
        item["dynetSummary"] = {"selectedOutbound": selected}
    path.write_text(json.dumps({"rows": [item]}))
    return str(path)


def completed(report: dict[str, object]) -> subprocess.CompletedProcess[str]:
    status = 0 if report["status"] == "pass" else 1
    return subprocess.CompletedProcess(
        args=["dynet", "probe"],
        returncode=status,
        stdout=json.dumps(report),
        stderr="",
    )


def probe_report(status: str, selected: str = "tunnel-001") -> dict[str, object]:
    report = {
        "schema": "dynet-probe/v1alpha1",
        "status": status,
        "target": {"host": "api.github.com", "port": 443},
        "readPolicy": {
            "pollTimeoutMs": 250,
            "pendingBudgetMs": 16000,
            "pendingSleepMs": 10,
        },
        "events": [
            event("route-matched", outbound="tunnel", status="Accept"),
            event("outbound-graph-selected", selected=selected),
            stage("tcp-connect", "success", elapsedMs="3"),
            stage("stream-first-write", "success", bytes="242"),
        ],
    }
    if status != "pass":
        report["failureScope"] = "direct"
        report["reason"] = "VMess response header length is not ready"
        report["events"].append(
            stage(
                "stream-first-read",
                "failed",
                error="VMess response header length is not ready",
                protocolReadMarker="vmess-response-header-length-pending",
                protocolReadDisposition="pending-budget-exhausted",
            )
        )
    return report


def event(kind: str, **fields: str) -> dict[str, object]:
    return {"kind": kind, "fields": fields}


def stage(stage_name: str, status: str, **fields: str) -> dict[str, object]:
    return {
        "kind": "outbound-stage-finished",
        "fields": {"stage": stage_name, "status": status, **fields},
    }


def sample_args(
    *,
    drilldown: str = "drilldown.json",
    output_dir: str = "out",
    limit: int | None = None,
    read_poll_ms: int | None = None,
    read_sleep_ms: int | None = None,
) -> argparse.Namespace:
    return argparse.Namespace(
        drilldown=drilldown,
        config="dynet.json",
        output_dir=output_dir,
        dynet_bin="dynet",
        sudo=False,
        inbound=None,
        quality_state=None,
        read_poll_ms=read_poll_ms,
        read_budget_ms=16000,
        read_sleep_ms=read_sleep_ms,
        limit=limit,
        domain=None,
        probe_type=None,
    )


if __name__ == "__main__":
    unittest.main()
