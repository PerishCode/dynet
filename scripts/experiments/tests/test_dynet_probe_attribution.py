from __future__ import annotations

import json
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
        self.assertEqual(report["failures"][0]["failureScope"], "direct")
        self.assertEqual(report["candidateQuality"]["candidateSets"], 0)

    def test_rule_decision(self) -> None:
        with tempfile.TemporaryDirectory() as raw_dir:
            workdir = Path(raw_dir)
            report_path = workdir / "0001-dialer.example.json"
            report_path.write_text(rule_report_json())
            summary_path = workdir / "summary.json"
            summary_path.write_text(rule_summary_json())

            report = attribution.build_probe_attribution(summary_path)

        self.assertEqual(report["totals"]["withMissingEvidence"], 0)
        self.assertEqual(
            report["evidenceCompleteness"]["route-or-rule-matched"]["missing"],
            0,
        )

    def test_candidate_details(self) -> None:
        rows = attribution.candidate_sets([
            {
                "kind": "outbound-candidate-set",
                "fields": {
                    "plan": "auto",
                    "selected": "b",
                    "candidateCount": "2",
                    "candidates": "a,b",
                    "candidatesJson": (
                        '[{"to":"a","quality":{"score":-4960}},'
                        '{"to":"b","quality":{"score":4240}}]'
                    ),
                    "selectedEdgeType": "candidate",
                },
            }
        ])

        self.assertEqual(rows[0]["candidates"], ["a", "b"])
        self.assertEqual(rows[0]["scope"], "plan-candidate")
        self.assertEqual(rows[0]["candidateDetails"][1]["quality"]["score"], 4240)
        self.assertEqual(rows[0]["quality"]["selectedScore"], 4240)
        self.assertEqual(rows[0]["quality"]["scoreGap"], 0)

    def test_quality_gap_plan(self) -> None:
        row = {
            "status": "deny",
            "bucket": "github-proof",
            "selectedOutbound": "a",
            "planDecisionCount": 1,
            "candidateSets": [
                {
                    "quality": {
                        "selectedScore": -4960,
                        "bestScore": 4240,
                        "selectedStale": False,
                        "scoreGap": 9200,
                    }
                }
            ],
            "graphSelected": "a",
            "missingEvidence": [],
        }

        self.assertEqual(
            attribution.classify(row, guardrails_clean=True),
            "plan-suspect",
        )

    def test_quality_totals(self) -> None:
        rows = [
            {
                "id": "0001",
                "bucket": "github-proof",
                "domain": "api.github.com",
                "status": "deny",
                "classification": "plan-suspect",
                "candidateSets": [
                    {
                        "plan": "auto",
                        "selected": "a",
                        "quality": {
                            "selectedScore": -10,
                            "bestScore": 20,
                            "selectedStale": False,
                            "scoreGap": 30,
                            "bestCandidates": ["b"],
                            "selectedReason": "exact-quality",
                        },
                    }
                ],
            },
            {
                "id": "0002",
                "status": "pass",
                "classification": "healthy",
                "candidateSets": [
                    {
                        "selected": "b",
                        "quality": {
                            "selectedScore": 20,
                            "bestScore": 20,
                            "selectedStale": False,
                            "scoreGap": 0,
                            "selectedReason": "exact-quality",
                        },
                    }
                ],
            },
        ]

        quality = attribution.candidate_quality_totals(rows)

        self.assertEqual(quality["withQuality"], 2)
        self.assertEqual(quality["selectedBest"], 1)
        self.assertEqual(quality["selectedBehind"], 1)
        self.assertEqual(quality["maxScoreGap"], 30)
        self.assertEqual(quality["gaps"][0]["bestCandidates"], ["b"])
        self.assertEqual(quality["gaps"][0]["scope"], "plan-candidate")


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
      "failureScope": "direct",
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


def rule_report_json() -> str:
    return """
{
  "events": [
    {"kind": "rule-matched", "fields": {"rule": "identity", "outbound": "dialer", "bypassesPlan": "true", "reason": "rule"}},
    {"kind": "outbound-graph-selected", "fields": {"selected": "dialer", "hopTags": "dialer", "hopKinds": "dialer", "decisions": "0"}},
    {"kind": "outbound-attempt-finished", "fields": {"outbound": "dialer", "protocol": "tcp-connect", "status": "success", "elapsedMs": "5"}},
    {"kind": "outbound-stage-finished", "fields": {"outbound": "dialer", "stage": "stream-flush", "status": "success", "elapsedMs": "1"}}
  ]
}
"""


def rule_summary_json() -> str:
    return """
{
  "items": [
    {
      "id": "0001",
      "bucket": "non-direct-smoke",
      "domain": "dialer.example",
      "sourceProbe": "tcp-connect",
      "dynetProtocol": "tcp-connect",
      "status": "pass",
      "selectedOutbound": "dialer",
      "reason": "TCP connect completed",
      "reportPath": "0001-dialer.example.json"
    }
  ]
}
"""


if __name__ == "__main__":
    unittest.main()
