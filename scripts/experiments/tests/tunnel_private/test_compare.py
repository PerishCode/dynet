from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
EXPERIMENTS = ROOT / "scripts" / "experiments"
sys.path.insert(0, str(EXPERIMENTS))

from tunnel_private import compare


class CompareTest(unittest.TestCase):
    def test_trojan_eof_marker(self) -> None:
        markers = compare.reason_markers(
            "dialer `<redacted>` failed all 4 bound candidates: "
            "tunnel-001: failed Trojan TLS handshake with `<redacted>`: "
            "unexpected end of file"
        )

        self.assertIn("trojan-tls-handshake", markers)
        self.assertIn("trojan-tls-handshake-eof", markers)
        self.assertIn("tls-unexpected-eof", markers)

    def test_groups_trojan_eof(self) -> None:
        summary = compare.compare_matrices_from_data([
            {
                "_path": "/tmp/trojan-matrix.json",
                "targetUrl": "https://www.cloudflare.com/",
                "metadata": {"counts": {"usable": 4}},
                "totals": {"attempted": 5, "passed": 1, "failed": 1},
                "cases": [
                    {
                        "label": "tunnel-private-tcp",
                        "protocol": "tcp-connect",
                        "status": "deny",
                        "failureScope": "bound",
                        "failedStage": "tunnel-001:tcp-connect",
                        "reason": (
                            "dialer `<redacted>` failed all 4 bound candidates: "
                            "tunnel-001: failed Trojan TLS handshake with `<redacted>`: "
                            "unexpected end of file"
                        ),
                    }
                ],
            }
        ])

        signature = summary["failureSignatures"][0]
        self.assertEqual(signature["failureScope"], "bound")
        self.assertEqual(signature["failedStage"], "tunnel-001:tcp-connect")
        self.assertIn("trojan-tls-handshake-eof", signature["markers"])
        self.assertEqual(summary["markerSummary"]["trojan-tls-handshake-eof"], 1)

    def test_structured_marker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "report.json"
            write_marker_report(report_path, "vmess-response-header-length-eof", "remote-eof")
            summary = compare.compare_matrices_from_data([vmess_marker_matrix(report_path)])

        signature = summary["failureSignatures"][0]
        self.assertEqual(signature["markers"], ["vmess-response-header-length-eof"])
        self.assertEqual(summary["markerSummary"]["vmess-response-header-length-eof"], 1)

    def test_pending_budget_marker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "report.json"
            write_marker_report(
                report_path,
                "vmess-response-header-length-pending",
                "pending-budget-exhausted",
            )
            summary = compare.compare_matrices_from_data([vmess_marker_matrix(report_path)])

        self.assertEqual(summary["markerSummary"]["vmess-response-header-length-pending"], 1)
        self.assertEqual(
            summary["markerSummary"]["vmess-response-header-length-pending-budget-exhausted"],
            1,
        )


def write_marker_report(path: Path, marker: str, disposition: str) -> None:
    path.write_text(json.dumps({
        "events": [
            {
                "kind": "outbound-stage-finished",
                "fields": {
                    "pendingBudgetMs": "8000",
                    "pendingRetries": "30",
                    "stage": "stream-first-read",
                    "status": "failed",
                    "protocolReadDisposition": disposition,
                    "protocolReadMarker": marker,
                    "protocolReadStage": "vmess-response-header-length",
                },
            }
        ]
    }))


def vmess_marker_matrix(report_path: Path) -> dict:
    return {
        "_path": "/tmp/vmess-matrix.json",
        "targetUrl": "https://api.github.com/",
        "metadata": {"counts": {"usable": 1}},
        "totals": {"attempted": 1, "passed": 0, "failed": 1},
        "cases": [
            {
                "label": "candidate-direct",
                "protocol": "https-head",
                "status": "deny",
                "failureScope": "direct",
                "failedStage": "tunnel-001:stream-first-read",
                "reason": "failed TLS handshake",
                "reportPath": str(report_path),
            }
        ],
    }


if __name__ == "__main__":
    unittest.main()
