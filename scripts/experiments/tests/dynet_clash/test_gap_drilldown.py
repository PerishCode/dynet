from __future__ import annotations

import argparse
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from dynet_clash.gap import drilldown as gap_drilldown


class DynetClashGapDrilldownTest(unittest.TestCase):
    def test_direct_tls_eof(self) -> None:
        with tempfile.TemporaryDirectory() as raw_dir:
            comparison = fixture(Path(raw_dir), include_report=True)
            report = gap_drilldown.build_from_reports([comparison], sample_args())

        self.assertEqual(report["totals"]["rows"], 1)
        self.assertEqual(
            report["classificationCounts"],
            [{"key": "direct-tls-eof-after-path-complete", "count": 1}],
        )
        row = report["rows"][0]
        self.assertEqual(row["missingEvidence"], [])
        self.assertEqual(row["evidence"]["tcpConnect"]["status"], "success")
        self.assertEqual(row["evidence"]["streamFirstRead"]["bytes"], 0)

    def test_missing_report(self) -> None:
        with tempfile.TemporaryDirectory() as raw_dir:
            comparison = fixture(Path(raw_dir), include_report=False)
            report = gap_drilldown.build_from_reports([comparison], sample_args())

        self.assertEqual(
            report["classificationCounts"],
            [{"key": "missing-dynet-report", "count": 1}],
        )
        self.assertEqual(
            report["missingEvidenceCounts"],
            [{"key": "dynet-report-present", "count": 1}],
        )

    def test_protocol_read_surface(self) -> None:
        with tempfile.TemporaryDirectory() as raw_dir:
            comparison = fixture(
                Path(raw_dir),
                include_report=True,
                report=protocol_read_report(),
                failed_stage="stream-first-read",
                failure_scope="direct",
                selected="tunnel-001",
                reason="VMess response header length is not ready",
            )
            report = gap_drilldown.build_from_reports([comparison], sample_args())

        self.assertEqual(
            report["classificationCounts"],
            [
                {
                    "key": (
                        "protocol-read-"
                        "vmess-response-header-length-pending-budget-exhausted"
                    ),
                    "count": 1,
                }
            ],
        )
        self.assertEqual(
            report["protocolReadSurfaceCounts"],
            [
                {
                    "count": 1,
                    "domain": "api.github.com",
                    "failureScope": "direct",
                    "probe": "https-head",
                    "protocolReadDisposition": "pending-budget-exhausted",
                    "protocolReadContext": "vmess-response-header-length",
                    "protocolReadMarker": "vmess-response-header-length-pending",
                    "selectedOutbound": "tunnel-001",
                }
            ],
        )
        self.assertEqual(report["rows"][0]["missingEvidence"], [])

    def test_protocol_context_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as raw_dir:
            comparison = fixture(
                Path(raw_dir),
                include_report=True,
                report=protocol_read_report(include_context=False),
                failed_stage="stream-first-read",
                failure_scope="direct",
                selected="tunnel-001",
                reason="Shadowsocks response salt is not ready",
            )
            report = gap_drilldown.build_from_reports([comparison], sample_args())

        self.assertEqual(
            report["protocolReadSurfaceCounts"][0]["protocolReadContext"],
            "shadowsocks-response-salt",
        )


def fixture(
    root: Path,
    *,
    include_report: bool,
    report: dict[str, object] | None = None,
    failed_stage: str = "tls-handshake",
    failure_scope: str = "direct",
    selected: str = "direct",
    reason: str = "unexpected end of file",
) -> dict[str, object]:
    run = root / "run"
    dynet_dir = run / "dynet"
    dynet_dir.mkdir(parents=True)
    report_path = dynet_dir / "0001-api.github.com.json"
    if include_report:
        write_json(report_path, report or probe_report())
    write_json(dynet_dir / "summary.json", {
        "items": [
            {
                "id": "0001",
                "bucket": "github-proof",
                "domain": "api.github.com",
                "sourceProbe": "https-head",
                "status": "deny",
                "failedStage": failed_stage,
                "failureScope": failure_scope,
                "selectedOutbound": selected,
                "reason": reason,
                "reportPath": str(report_path),
            }
        ]
    })
    write_json(run / "pairs.json", {
        "items": [
            {
                "id": "0001",
                "bucket": "github-proof",
                "domain": "api.github.com",
                "probe": "https-head",
                "clashOk": True,
                "dynetStatus": "deny",
            }
        ]
    })
    return {
        "inputs": {"dynetSummary": str(dynet_dir / "summary.json")},
        "byBucket": [],
    }


def probe_report() -> dict[str, object]:
    return {
        "schema": "dynet-probe/v1alpha1",
        "status": "deny",
        "failureScope": "direct",
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
            stage(
                "tls-handshake",
                "failed",
                error="unexpected end of file",
                errorType="tls",
            ),
        ],
    }


def protocol_read_report(include_context: bool = True) -> dict[str, object]:
    fields = {
        "error": (
            "Shadowsocks response salt is not ready: "
            "VMess response header length is not ready"
        ),
        "errorType": "vmess",
        "pendingBudgetMs": "8000",
        "pendingRetries": "30",
        "protocolReadDisposition": "pending-budget-exhausted",
        "protocolReadMarker": "vmess-response-header-length-pending",
        "protocolReadStage": "vmess-response-header-length",
    }
    if include_context:
        fields["protocolReadContext"] = "vmess-response-header-length"
    return {
        "schema": "dynet-probe/v1alpha1",
        "status": "deny",
        "failureScope": "direct",
        "target": {"host": "api.github.com", "port": 443},
        "events": [
            event("route-matched", outbound="tunnel", status="Accept"),
            event("outbound-graph-selected", selected="tunnel-001"),
            stage("tcp-connect", "success", elapsedMs="3"),
            stage("stream-first-write", "success", bytes="242"),
            stage("stream-first-read", "failed", **fields),
        ],
    }


def event(kind: str, **fields: str) -> dict[str, object]:
    return {"kind": kind, "fields": fields}


def stage(stage_name: str, status: str, **fields: str) -> dict[str, object]:
    return {
        "kind": "outbound-stage-finished",
        "fields": {"stage": stage_name, "status": status, **fields},
    }


def write_json(path: Path, data: dict[str, object]) -> None:
    path.write_text(json.dumps(data))


def sample_args() -> argparse.Namespace:
    return argparse.Namespace(primary_bucket="github-proof")


if __name__ == "__main__":
    unittest.main()
