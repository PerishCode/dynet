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
from dynet_clash.gap import retry


class DynetClashGapRetryTest(unittest.TestCase):
    def test_selects_direct_tls(self) -> None:
        args = sample_args(limit=1, domain=["api.github.com"], probe_type=None)
        rows = retry.selected_rows(drilldown_report(), args)

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["domain"], "api.github.com")

    def test_recovered_after_retry(self) -> None:
        with tempfile.TemporaryDirectory() as raw_dir:
            root = Path(raw_dir)
            args = sample_args(
                drilldown=write_drilldown(root),
                output_dir=str(root / "out"),
            )
            with patch(
                "dynet_clash.gap.retry.subprocess.run",
                side_effect=[
                    completed(probe_report("deny")),
                    completed(probe_report("pass")),
                ],
            ):
                report = retry.run(args)

        self.assertEqual(report["totals"]["rows"], 1)
        self.assertEqual(report["totals"]["recovered"], 1)
        self.assertEqual(report["totals"]["recoveredAfterRetry"], 1)
        self.assertEqual(report["totals"]["attempts"], 2)

    def test_unresolved_is_result(self) -> None:
        with tempfile.TemporaryDirectory() as raw_dir:
            root = Path(raw_dir)
            args = sample_args(
                drilldown=write_drilldown(root),
                output_dir=str(root / "out"),
            )
            with patch(
                "dynet_clash.gap.retry.subprocess.run",
                side_effect=[
                    completed(probe_report("deny")),
                    completed(probe_report("deny")),
                    completed(probe_report("deny")),
                ],
            ):
                report = retry.run(args)

        self.assertEqual(report["totals"]["recovered"], 0)
        self.assertEqual(report["totals"]["unresolved"], 1)
        self.assertEqual(
            report["lastFailureClassifications"],
            [{"key": "direct-tls-eof-after-path-complete", "count": 1}],
        )


def drilldown_report() -> dict[str, object]:
    return {
        "rows": [
            row("api.github.com", "https-head", retry.DIRECT_TLS_EOF),
            row("github.com", "https-head", "not-dynet-failure"),
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
    }


def write_drilldown(root: Path) -> str:
    path = root / "drilldown.json"
    path.write_text(json.dumps({"rows": [row("api.github.com", "https-head", retry.DIRECT_TLS_EOF)]}))
    return str(path)


def completed(report: dict[str, object]) -> subprocess.CompletedProcess[str]:
    status = 0 if report["status"] == "pass" else 1
    return subprocess.CompletedProcess(
        args=["dynet", "probe"],
        returncode=status,
        stdout=json.dumps(report),
        stderr="",
    )


def probe_report(status: str) -> dict[str, object]:
    report = {
        "schema": "dynet-probe/v1alpha1",
        "status": status,
        "failureScope": None,
        "target": {"host": "api.github.com", "port": 443},
        "events": [
            event("route-matched", outbound="direct", status="Accept"),
            event("outbound-graph-selected", selected="direct"),
            stage("tcp-connect", "success", elapsedMs="3"),
            stage("stream-first-write", "success", bytes="242"),
            stage(
                "stream-first-read",
                "success",
                bytes="0",
                pendingBudgetMs="8000",
                pendingRetries="18",
            ),
        ],
    }
    if status != "pass":
        report["failureScope"] = "direct"
        report["reason"] = "unexpected end of file"
        report["events"].append(
            stage(
                "tls-handshake",
                "failed",
                error="unexpected end of file",
                errorType="tls",
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
    domain: list[str] | None = None,
    probe_type: list[str] | None = None,
) -> argparse.Namespace:
    return argparse.Namespace(
        drilldown=drilldown,
        config="dynet.json",
        output_dir=output_dir,
        dynet_bin="dynet",
        sudo=False,
        inbound=None,
        quality_state=None,
        attempts=3,
        retry_sleep_ms=0,
        limit=limit,
        domain=domain,
        probe_type=probe_type,
    )


if __name__ == "__main__":
    unittest.main()
