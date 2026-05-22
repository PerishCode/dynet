from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dynet_trace import probe as attribution


class DynetProbeAttributionTest(unittest.TestCase):
    def test_github_failure_class(self) -> None:
        row = {
            "status": "deny",
            "bucket": "github-proof",
            "selectedOutbound": "direct",
            "planDecisionCount": 0,
            "candidateSets": [],
            "graphSelected": "direct",
            "missingEvidence": [],
        }

        self.assertEqual(
            attribution.classify(row, guardrails_clean=True),
            "target-or-probe-suspect",
        )

    def test_control_direct_failure(self) -> None:
        row = {
            "status": "deny",
            "bucket": "work-direct",
            "selectedOutbound": "direct",
            "missingEvidence": [],
        }

        self.assertEqual(
            attribution.classify(row, guardrails_clean=True),
            "dynet-infra-suspect",
        )

    def test_build_from_reports(self) -> None:
        with tempfile.TemporaryDirectory() as raw_dir:
            workdir = Path(raw_dir)
            summary_path = write_fixture(workdir)

            report = attribution.build_probe_attribution(summary_path)

        self.assertEqual(report["totals"]["items"], 2)
        self.assertEqual(report["totals"]["failed"], 1)
        self.assertEqual(report["failures"][0]["classification"], "target-or-probe-suspect")


def json_report() -> str:
    return """
{
  "events": [
    {"kind": "route-matched", "fields": {"status": "Accept", "outbound": "direct", "reason": "rule"}},
    {"kind": "outbound-graph-selected", "fields": {"selected": "direct", "hopTags": "direct", "hopKinds": "direct", "decisions": "0"}},
    {"kind": "outbound-attempt-finished", "fields": {"outbound": "direct", "protocol": "tcp-connect", "status": "success", "elapsedMs": "5"}},
    {"kind": "outbound-stage-finished", "fields": {"outbound": "direct", "stage": "tls-handshake", "status": "failed", "elapsedMs": "5000", "errorType": "tls"}}
  ]
}
"""


def write_fixture(workdir: Path) -> Path:
    report_path = workdir / "0001-api.github.com.json"
    report_path.write_text(json_report())
    summary_path = workdir / "summary.json"
    summary_path.write_text(summary_json())
    return summary_path


def summary_json() -> str:
    return """
{
  "items": [
    {
      "id": "0001",
      "bucket": "github-proof",
      "domain": "api.github.com",
      "sourceProbe": "tls-handshake",
      "dynetProtocol": "tls-handshake",
      "status": "deny",
      "selectedOutbound": "direct",
      "failedStage": "tls-handshake",
      "reason": "failed TLS handshake",
      "reportPath": "0001-api.github.com.json"
    },
    {
      "id": "0002",
      "bucket": "control-global",
      "domain": "example.com",
      "sourceProbe": "https-head",
      "dynetProtocol": "https-head",
      "status": "pass",
      "selectedOutbound": "direct",
      "reportPath": "missing.json"
    }
  ]
}
"""


if __name__ == "__main__":
    unittest.main()
