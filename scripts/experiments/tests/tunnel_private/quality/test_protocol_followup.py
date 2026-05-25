from __future__ import annotations

import argparse
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[5]
EXPERIMENTS = ROOT / "scripts" / "experiments"
sys.path.insert(0, str(EXPERIMENTS))

from scripts.cli import tunnel_private_lab as lab
from tunnel_private.quality.readiness import protocol_followup, protocol_followup_batch


class ProtocolFollowupTest(unittest.TestCase):
    def test_parser(self) -> None:
        args = lab.build_parser().parse_args([
            "protocol-followup",
            "--output-dir",
            "/tmp/out",
            "--readiness",
            "/tmp/readiness.json",
            "--compare",
            "/tmp/compare.json",
            "--report-dir",
            "/tmp/reports",
        ])

        self.assertEqual(args.command, "protocol-followup")
        self.assertEqual(args.readiness, "/tmp/readiness.json")
        self.assertEqual(args.compare, ["/tmp/compare.json"])
        self.assertEqual(args.report_dir, ["/tmp/reports"])

        batch = lab.build_parser().parse_args([
            "protocol-followup-batch",
            "--output-dir",
            "/tmp/out",
            "--summary",
            "/tmp/one.json",
        ])

        self.assertEqual(batch.command, "protocol-followup-batch")
        self.assertEqual(batch.summary, ["/tmp/one.json"])

    def test_marker_current_clean(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            readiness = root / "readiness.json"
            compare = root / "compare.json"
            attribution = root / "attribution.json"
            report = root / "report.json"
            write_json(readiness, readiness_summary())
            write_json(compare, compare_summary())
            write_json(attribution, attribution_summary())
            write_json(report, report_summary("success"))

            summary = protocol_followup.protocol_followup_summary(
                readiness,
                [compare],
                [attribution],
                [report],
            )

        self.assertEqual(summary["conclusion"]["status"], "historical-marker-current-artifacts-clean")
        self.assertTrue(summary["conclusion"]["currentReadClean"])
        self.assertTrue(summary["conclusion"]["readFailureClassificationClean"])
        self.assertEqual(summary["compareEvidence"]["readMarkerCount"], 2)
        self.assertEqual(summary["attributionEvidence"]["readStageFailures"], 0)
        self.assertEqual(summary["reportEvidence"]["pendingRetriesMax"], 4)

    def test_current_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report = root / "report.json"
            write_json(report, report_summary("failed"))

            summary = protocol_followup.protocol_followup_summary(
                None,
                [],
                [],
                [report],
            )

        self.assertEqual(summary["conclusion"]["status"], "current-read-failure")
        self.assertFalse(summary["conclusion"]["currentReadClean"])
        self.assertEqual(summary["reportEvidence"]["readFailureCount"], 1)
        self.assertEqual(summary["reportEvidence"]["readFailureUnclassifiedCount"], 1)
        self.assertFalse(summary["conclusion"]["readFailureClassificationClean"])

    def test_pending_budget_classification(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report = root / "report.json"
            write_json(report, pending_budget_report())

            summary = protocol_followup.protocol_followup_summary(
                None,
                [],
                [],
                [report],
            )

        self.assertEqual(
            summary["reportEvidence"]["readFailureMarkers"],
            [{"count": 1, "key": "vmess-response-header-length-pending"}],
        )
        self.assertEqual(
            summary["reportEvidence"]["readFailureDispositions"],
            [{"count": 1, "key": "pending-budget-exhausted"}],
        )
        self.assertEqual(summary["reportEvidence"]["readFailureUnclassifiedCount"], 0)
        self.assertTrue(summary["conclusion"]["readFailureClassificationClean"])

    def test_command(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            readiness = root / "readiness.json"
            output = root / "out"
            write_json(readiness, readiness_summary())

            with contextlib.redirect_stdout(io.StringIO()):
                status = protocol_followup.command_protocol_followup(
                    argparse.Namespace(
                        output_dir=str(output),
                        readiness=str(readiness),
                        compare=[],
                        attribution=[],
                        report=[],
                    )
                )

            self.assertEqual(status, 0)
            self.assertTrue((output / "summary.json").exists())
            self.assertTrue((output / "summary.md").exists())

    def test_missing_input_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            missing = Path(temp_dir) / "missing.json"

            with self.assertRaises(SystemExit):
                protocol_followup.protocol_followup_summary(
                    None,
                    [],
                    [],
                    [missing],
                )

    def test_collect_report_dir(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report = root / "report.json"
            summary = root / "summary.json"
            write_json(report, report_summary("success"))
            write_json(summary, {"schema": "dynet-tunnel-private-summary/v1alpha1"})

            reports = protocol_followup.collect_report_paths([], [root])

        self.assertEqual(reports, [report])

    def test_batch_surface_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            one = root / "one.json"
            two = root / "two.json"
            write_json(one, followup_summary("vmess-response-header-length-eof", "remote-eof"))
            write_json(two, followup_summary(
                "vmess-response-header-length-pending",
                "pending-budget-exhausted",
            ))

            summary = protocol_followup_batch.protocol_followup_batch([one, two])

        self.assertEqual(summary["conclusion"]["status"], "read-surface-repeated-drift")
        self.assertEqual(summary["totals"]["readFailureCount"], 2)
        self.assertEqual(summary["conclusion"]["surfaceKinds"], 2)
        self.assertTrue(summary["conclusion"]["classificationClean"])


def readiness_summary() -> dict:
    return {
        "schema": "dynet-tunnel-private-adapter-readiness/v1alpha1",
        "status": "ready",
        "conclusion": {"readyForMainlineAdapterWork": True},
        "protocolFollowup": {
            "open": True,
            "readMarkerCount": 2,
            "readMarkers": [
                {"key": "vmess-response-header-length-eof", "count": 1},
                {"key": "vmess-response-header-length-read", "count": 1},
            ],
            "nextProof": "collect-runtime-stage-repeat-for-read-marker-before-adapter-claim",
        },
    }


def compare_summary() -> dict:
    return {
        "schema": "dynet-tunnel-private-matrix-compare/v1alpha1",
        "totals": {"failures": 1},
        "markerSummary": {
            "vmess-response-header-length-eof": 1,
            "vmess-response-header-length-read": 1,
        },
        "failureSignatures": [
            {
                "label": "candidate-direct",
                "protocol": "https-head",
                "failureScope": "direct",
                "failedStage": "tunnel-001:stream-first-read",
                "markers": [
                    "vmess-response-header-length-read",
                    "vmess-response-header-length-eof",
                ],
                "matrixPaths": ["/tmp/old-matrix.json"],
                "targets": ["https://api.github.com/"],
            }
        ],
    }


def attribution_summary() -> dict:
    return {
        "schema": "dynet-probe-attribution-summary/v1alpha1",
        "stageLatencyMs": [
            {
                "key": "stream-first-read",
                "count": 6,
                "failures": 0,
                "latencyMs": {"p95": 1103},
            }
        ],
    }


def report_summary(status: str) -> dict:
    return {
        "schema": "dynet-probe/v1alpha1",
        "status": "deny" if status == "failed" else "pass",
        "events": [
            {
                "kind": "outbound-stage-finished",
                "fields": {
                    "outbound": "tunnel-001",
                    "stage": "stream-first-read",
                    "status": status,
                    "pendingRetries": "4",
                },
            }
        ],
    }


def pending_budget_report() -> dict:
    return {
        "schema": "dynet-probe/v1alpha1",
        "status": "deny",
        "events": [
            {
                "kind": "outbound-stage-finished",
                "fields": {
                    "error": (
                        "VMess response header length is not ready: "
                        "failed to read VMess response header length"
                    ),
                    "errorType": "vmess",
                    "outbound": "tunnel-002",
                    "pendingBudgetMs": "8000",
                    "pendingRetries": "30",
                    "stage": "stream-first-read",
                    "status": "failed",
                },
            }
        ],
    }


def followup_summary(marker: str, disposition: str) -> dict:
    return {
        "schema": "dynet-tunnel-private-protocol-followup/v1alpha1",
        "conclusion": {
            "status": "current-read-failure",
            "currentReadStageFailures": 1,
        },
        "reportEvidence": {
            "readFailureCount": 1,
            "readFailureUnclassifiedCount": 0,
            "sources": [
                {
                    "path": f"/tmp/{marker}.json",
                    "readFailure": {
                        "marker": marker,
                        "disposition": disposition,
                        "protocolStage": "vmess-response-header-length",
                        "stage": "stream-first-read",
                        "outbound": "private-via-tunnel",
                        "pendingBudgetMs": 30000,
                    },
                }
            ],
        },
    }


def write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data))


if __name__ == "__main__":
    unittest.main()
