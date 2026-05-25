from __future__ import annotations

import argparse
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
EXPERIMENTS = ROOT / "scripts" / "experiments"
sys.path.insert(0, str(EXPERIMENTS))

from scripts.cli import tunnel_private_lab as lab
from tunnel_private.quality import sweep


class QualitySweepTest(unittest.TestCase):
    def test_parser(self) -> None:
        parser = lab.build_parser()

        args = parser.parse_args([
            "quality-sweep",
            "--output-dir",
            "/tmp/out",
            "--target-url",
            "https://api.github.com/",
            "--target-url",
            "https://www.cloudflare.com/",
            "--sweep-offset",
            "2",
            "--sweep-offset",
            "4",
        ])

        self.assertEqual(args.command, "quality-sweep")
        self.assertEqual(
            args.target_url,
            ["https://api.github.com/", "https://www.cloudflare.com/"],
        )
        self.assertEqual(args.sweep_offset, [2, 4])
        self.assertIsNone(args.initial_quality_state)
        self.assertEqual(args.quality_ttl_seconds, 3600)
        self.assertFalse(args.require_candidate_direct)

    def test_phase_args(self) -> None:
        args = argparse.Namespace(
            output_dir="/tmp/out",
            target_url=["https://api.github.com/"],
            candidate_offset=0,
        )

        phase = sweep.phase_args(args, Path("/tmp/out"), "https://api.github.com/", 2)

        self.assertEqual(phase.target_url, "https://api.github.com/")
        self.assertEqual(phase.candidate_offset, 2)
        self.assertEqual(phase.output_dir, "/tmp/out/offset-002-https-api-github-com")

    def test_summary(self) -> None:
        summary = sweep.sweep_summary(
            argparse.Namespace(
                gate_mode="product",
                refresh_probe_mode="auto",
                protocol="https-head",
                supported_type=["vmess"],
                limit=2,
                sweep_offset=[2, 4],
                target_url=["https://api.github.com/"],
            ),
            [
                {
                    "status": "pass",
                    "strictStatus": "pass",
                    "compare": {"markerSummary": {}},
                },
                {
                    "status": "fail",
                    "strictStatus": "fail",
                    "compare": {"markerSummary": {"trojan-tls-handshake-eof": 4}},
                },
            ],
        )

        self.assertEqual(summary["schema"], sweep.SWEEP_SCHEMA)
        self.assertEqual(summary["status"], "fail")
        self.assertEqual(summary["totals"]["runs"], 2)
        self.assertEqual(summary["markerSummary"], {"trojan-tls-handshake-eof": 4})

    def test_null_compare(self) -> None:
        summary = sweep.sweep_summary(
            argparse.Namespace(
                gate_mode="product",
                refresh_probe_mode="auto",
                protocol="https-head",
                supported_type=["vmess"],
                limit=2,
                sweep_offset=[18],
                target_url=["https://api.github.com/"],
            ),
            [
                {
                    "status": "pass",
                    "strictStatus": "pass",
                    "compare": None,
                },
            ],
        )

        self.assertEqual(summary["status"], "pass")
        self.assertEqual(summary["markerSummary"], {})

    def test_run_row(self) -> None:
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        path = Path(temp_dir.name) / "offset-002-https-api-github-com"
        path.mkdir(parents=True)
        (path / "summary.json").write_text(
            """{
              "status": "pass",
              "strictStatus": "pass",
              "plan": {
                "selected": "tunnel-001",
                "quality": {"selectedBehind": 0}
              },
              "matrix": {"totals": {"passed": 5, "failed": 0}},
              "compare": null
            }"""
        )

        row = sweep.run_row(
            argparse.Namespace(
                output_dir=str(path),
                target_url="https://api.github.com/",
                candidate_offset=2,
            ),
            0,
        )

        self.assertEqual(row["label"], "offset-002-https-api-github-com")
        self.assertEqual(row["selected"], "tunnel-001")
        self.assertEqual(row["selectedBehind"], 0)
        self.assertEqual(row["compare"], {})

    def test_combined_summary(self) -> None:
        summary = sweep.combined_summary(
            [
                {
                    "runs": [
                        {
                            "candidateOffset": 2,
                            "targetUrl": "https://a/",
                            "outputDir": "offset-002-https-a",
                            "status": "pass",
                            "strictStatus": "pass",
                            "selectedBehind": 0,
                            "matrix": {"failed": 0},
                        },
                    ],
                },
                {
                    "runs": [
                        {
                            "candidateOffset": 4,
                            "targetUrl": "https://b/",
                            "status": "pass",
                            "strictStatus": "pass",
                            "selectedBehind": 1,
                            "matrix": {"failed": 0},
                        },
                    ],
                },
            ],
            ["/tmp/a/summary.json", "/tmp/b/summary.json"],
        )

        self.assertEqual(summary["schema"], sweep.SWEEP_SUMMARY_SCHEMA)
        self.assertEqual(summary["status"], "pass")
        self.assertEqual(summary["totals"]["runs"], 2)
        self.assertEqual(summary["totals"]["selectedBehindMax"], 1)
        self.assertEqual(summary["limits"]["candidateOffsets"], [2, 4])
        self.assertEqual(summary["sources"], ["/tmp/a/summary.json", "/tmp/b/summary.json"])
        self.assertEqual(summary["sourceSummaries"][0]["path"], "/tmp/a/summary.json")
        self.assertEqual(summary["runs"][0]["label"], "offset-002-https-a")
        self.assertEqual(summary["runs"][0]["source"], "/tmp/a/summary.json")
        self.assertEqual(summary["runs"][0]["runPath"], "/tmp/a/offset-002-https-a")


if __name__ == "__main__":
    unittest.main()
