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
from dynet_clash.gap import protocol_retry


class DynetClashGapProtocolRetryTest(unittest.TestCase):
    def test_selects_read_rows(self) -> None:
        rows = protocol_retry.selected_rows(drilldown_report(), sample_args(limit=1))

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["domain"], "api.github.com")

    def test_retry_recovers(self) -> None:
        with tempfile.TemporaryDirectory() as raw_dir:
            root = Path(raw_dir)
            args = sample_args(
                drilldown=write_drilldown(root),
                output_dir=str(root / "out"),
            )
            with patch(
                "dynet_clash.gap.protocol_retry.subprocess.run",
                side_effect=[
                    completed(probe_report("deny")),
                    completed(probe_report("pass")),
                ],
            ):
                report = protocol_retry.run(args)

        self.assertEqual(report["totals"]["rows"], 1)
        self.assertEqual(report["totals"]["recovered"], 1)
        self.assertEqual(report["totals"]["recoveredAfterRetry"], 1)
        self.assertEqual(report["totals"]["attempts"], 2)

    def test_unresolved_read(self) -> None:
        with tempfile.TemporaryDirectory() as raw_dir:
            root = Path(raw_dir)
            args = sample_args(
                drilldown=write_drilldown(root),
                output_dir=str(root / "out"),
            )
            with patch(
                "dynet_clash.gap.protocol_retry.subprocess.run",
                side_effect=[
                    completed(probe_report("deny")),
                    completed(probe_report("deny")),
                    completed(probe_report("deny")),
                ],
            ):
                report = protocol_retry.run(args)

        self.assertEqual(report["totals"]["recovered"], 0)
        self.assertEqual(report["totals"]["unresolvedProtocolRead"], 1)
        self.assertEqual(report["totals"]["changedSurface"], 0)
        self.assertEqual(
            report["lastFailureClassifications"],
            [{"key": protocol_read_key(), "count": 1}],
        )
        self.assertEqual(report["rows"][0]["lastProtocolRead"]["context"], read_context())
        self.assertEqual(
            report["rows"][0]["attempts"][0]["probeAttemptClassification"],
            protocol_read_key(),
        )

    def test_outbound_drift(self) -> None:
        with tempfile.TemporaryDirectory() as raw_dir:
            root = Path(raw_dir)
            args = sample_args(
                drilldown=write_drilldown(root, selected="private-via-tunnel"),
                output_dir=str(root / "out"),
            )
            with patch(
                "dynet_clash.gap.protocol_retry.subprocess.run",
                side_effect=[
                    completed(probe_report("pass", selected="direct")),
                    completed(probe_report("pass", selected="direct")),
                    completed(probe_report("pass", selected="direct")),
                ],
            ):
                report = protocol_retry.run(args)

        self.assertEqual(report["totals"]["recovered"], 0)
        self.assertEqual(report["totals"]["selectedOutboundDriftRows"], 1)
        self.assertEqual(report["totals"]["changedSurface"], 1)
        self.assertEqual(
            report["lastFailureClassifications"],
            [{"key": "selected-outbound-drift", "count": 1}],
        )

    def test_command_flags(self) -> None:
        base = protocol_retry.dynet_command(sample_args(), "api.github.com", "https-head")
        command = protocol_retry.dynet_command(
            sample_args(
                inbound="tun0",
                quality_state="quality.json",
                read_poll_ms=100,
                read_budget_ms=16000,
                read_sleep_ms=1,
            ),
            "api.github.com",
            "https-head",
        )

        self.assertNotIn("--probe-read-pending-budget-ms", base)
        self.assertIn("--probe-read-pending-budget-ms", command)
        self.assertIn("16000", command)
        self.assertIn("--probe-read-poll-timeout-ms", command)
        self.assertIn("100", command)
        self.assertIn("--probe-read-pending-sleep-ms", command)
        self.assertIn("1", command)
        self.assertIn("--inbound", command)
        self.assertIn("tun0", command)
        self.assertIn("--quality-state", command)
        self.assertIn("quality.json", command)


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


def read_context() -> str:
    return "shadowsocks-response-salt"


def read_evidence() -> dict[str, object]:
    return {
        "streamFirstRead": {
            "protocolReadMarker": "vmess-response-header-length-pending",
            "protocolReadContext": read_context(),
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
        "events": [
            event("route-matched", outbound="tunnel", status="Accept"),
            event("outbound-graph-selected", selected=selected),
            stage("tcp-connect", "success", elapsedMs="3"),
            stage("stream-first-write", "success", bytes="242"),
        ],
    }
    if status != "pass":
        report["failureScope"] = "proxy"
        report["reason"] = "VMess response header length is not ready"
        report["events"].extend([read_failure(), attempt_finished()])
    return report


def read_failure() -> dict[str, object]:
    return stage(
        "stream-first-read",
        "failed",
        error="VMess response header length is not ready",
        protocolReadMarker="vmess-response-header-length-pending",
        protocolReadStage="vmess-response-header-length",
        protocolReadContext=read_context(),
        protocolReadDisposition="pending-budget-exhausted",
    )


def attempt_finished() -> dict[str, object]:
    return event(
        "probe-attempt-finished",
        classification=protocol_read_key(),
        protocolReadMarker="vmess-response-header-length-pending",
        protocolReadStage="vmess-response-header-length",
        protocolReadContext=read_context(),
        protocolReadDisposition="pending-budget-exhausted",
    )


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
    inbound: str | None = None,
    quality_state: str | None = None,
    read_poll_ms: int | None = None,
    read_budget_ms: int | None = None,
    read_sleep_ms: int | None = None,
    limit: int | None = None,
) -> argparse.Namespace:
    return argparse.Namespace(
        drilldown=drilldown,
        config="dynet.json",
        output_dir=output_dir,
        dynet_bin="dynet",
        sudo=False,
        inbound=inbound,
        quality_state=quality_state,
        attempts=3,
        retry_sleep_ms=0,
        read_poll_ms=read_poll_ms,
        read_budget_ms=read_budget_ms,
        read_sleep_ms=read_sleep_ms,
        limit=limit,
        domain=None,
        probe_type=None,
    )


if __name__ == "__main__":
    unittest.main()
