from __future__ import annotations

import argparse
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
EXPERIMENTS = ROOT / "scripts" / "experiments"
sys.path.insert(0, str(EXPERIMENTS))

import tunnel_private_config as config
from scripts.cli import tunnel_private_lab as lab
from tunnel_private.quality import regression


class QualityRegressionTest(unittest.TestCase):
    def test_parser(self) -> None:
        parser = lab.build_parser()

        args = parser.parse_args([
            "quality-regression",
            "--output-dir",
            "/tmp/out",
            "--target-url",
            "https://chatgpt.com/",
            "--protocol",
            "https-head",
            "--window-size",
            "3",
            "--baseline-matrix",
            "/tmp/baseline/matrix.json",
        ])

        self.assertEqual(args.command, "quality-regression")
        self.assertEqual(args.window_size, 3)
        self.assertEqual(args.gate_mode, "product")
        self.assertEqual(args.refresh_probe_mode, "auto")
        self.assertEqual(args.baseline_matrix, ["/tmp/baseline/matrix.json"])
        self.assertFalse(args.refresh_require_pass)
        self.assertFalse(args.require_candidate_direct)

    def test_refresh_defaults(self) -> None:
        args = argparse.Namespace(
            output_dir="/tmp/root",
            refresh_require_pass=False,
            refresh_probe_mode="auto",
            gate_mode="product",
            quality_state="/tmp/old.json",
            domain=[],
            target_url="https://www.cloudflare.com/",
        )

        phase = regression.refresh_phase_args(args, Path("/tmp/root/refresh"))

        self.assertEqual(phase.output_dir, "/tmp/root/refresh")
        self.assertEqual(phase.probe_mode, "private")
        self.assertEqual(phase.domain, ["www.cloudflare.com"])
        self.assertTrue(phase.allow_failures)
        self.assertIsNone(phase.quality_state)

    def test_refresh_requires_clean(self) -> None:
        args = argparse.Namespace(
            output_dir="/tmp/root",
            refresh_require_pass=True,
            refresh_probe_mode="auto",
            gate_mode="direct",
            domain=["api.github.com"],
            target_url="https://api.github.com/",
        )

        phase = regression.refresh_phase_args(args, Path("/tmp/root/refresh"))

        self.assertEqual(phase.probe_mode, "candidate")
        self.assertEqual(phase.domain, ["api.github.com"])
        self.assertFalse(phase.allow_failures)

    def test_plan_scope(self) -> None:
        args = argparse.Namespace(
            refresh_probe_mode="auto",
            gate_mode="direct",
            domain=[],
            target_url="https://chatgpt.com/",
        )

        phase = regression.quality_state_phase_args(
            args,
            Path("/tmp/root/plan"),
            Path("/tmp/root/quality.json"),
        )

        self.assertEqual(phase.plan_quality_scope, "plan-candidate")
        self.assertEqual(phase.domain, ["chatgpt.com"])

    def test_summary_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            write_regression_fixture(root, matrix_failed=False, selected_behind=0)
            summary = regression.regression_summary(
                argparse.Namespace(target_url="https://chatgpt.com/", protocol="https-head"),
                root,
                {"qualityRefresh": 0, "planQuality": 0, "matrix": 0},
            )

        self.assertEqual(summary["schema"], regression.REGRESSION_SCHEMA)
        self.assertEqual(summary["status"], "pass")
        self.assertEqual(summary["strictStatus"], "pass")
        self.assertTrue(all(item["passed"] for item in summary["gates"]))
        self.assertEqual(summary["plan"]["selected"], "tunnel-002")

    def test_selected_behind(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            write_regression_fixture(root, matrix_failed=False, selected_behind=1)
            summary = regression.regression_summary(
                argparse.Namespace(target_url="https://chatgpt.com/", protocol="https-head"),
                root,
                {"qualityRefresh": 0, "planQuality": 1, "matrix": 0},
            )

        failed = [item["name"] for item in summary["gates"] if not item["passed"]]
        self.assertEqual(summary["status"], "fail")
        self.assertIn("plan-quality-command", failed)
        self.assertIn("plan-selected-best", failed)

    def test_direct_control(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            write_regression_fixture(root, matrix_failed=True, selected_behind=0)
            summary = regression.regression_summary(
                argparse.Namespace(target_url="https://chatgpt.com/", protocol="https-head"),
                root,
                {"qualityRefresh": 0, "planQuality": 0, "matrix": 0},
            )

        failed = [item["name"] for item in summary["gates"] if not item["passed"]]
        self.assertEqual(summary["status"], "pass")
        self.assertEqual(summary["strictStatus"], "fail")
        self.assertIn("matrix-all-pass", failed)
        self.assertIn("matrix-candidate-direct-pass", failed)

    def test_direct_required(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            write_regression_fixture(root, matrix_failed=True, selected_behind=0)
            summary = regression.regression_summary(
                argparse.Namespace(
                    target_url="https://chatgpt.com/",
                    protocol="https-head",
                    require_candidate_direct=True,
                ),
                root,
                {"qualityRefresh": 0, "planQuality": 0, "matrix": 0},
            )

        failed_required = [
            item["name"]
            for item in summary["gates"]
            if item["required"] and not item["passed"]
        ]
        self.assertEqual(summary["status"], "fail")
        self.assertIn("matrix-candidate-direct-pass", failed_required)


def write_regression_fixture(
    root: Path,
    *,
    matrix_failed: bool,
    selected_behind: int,
) -> None:
    write_refresh_fixture(root / "quality-refresh")
    write_plan_fixture(root / "plan-quality", selected_behind)
    write_matrix_fixture(root / "matrix", matrix_failed)


def write_refresh_fixture(root: Path) -> None:
    config.write_json(
        root / "verification.json",
        {
            "status": "pass",
            "errors": [],
            "firstWindow": {"attempted": 6, "passed": 6, "failed": 0},
            "secondWindow": {"attempted": 6, "passed": 6, "failed": 0},
            "failureScopes": {"windowA": [], "windowB": []},
            "qualityState": {
                "planCandidate": [{"outbound": "tunnel-002", "scope": "plan-candidate"}],
                "dialerBound": [],
            },
        },
    )


def write_plan_fixture(root: Path, selected_behind: int) -> None:
    selected_best = selected_behind == 0
    config.write_json(
        root / "summary.json",
        {
            "status": "pass" if selected_best else "fail",
            "inspectionScope": "dialer-bound",
            "qualityState": str(root.parent / "quality-refresh" / "window-b" / "quality-state.json"),
            "inspectedPath": {"selected": "tunnel-002"},
            "dialerBoundPath": {"selected": "tunnel-002"},
            "candidateQuality": {
                "selectedBest": selected_best,
                "selectedBehind": selected_behind,
                "selectedHasMatches": True,
                "selectedScore": 5545,
                "bestScore": 5545 if selected_best else 5600,
                "selected": {"to": "tunnel-002"},
                "best": {"to": "tunnel-002" if selected_best else "tunnel-001"},
            },
        },
    )


def write_matrix_fixture(root: Path, failed: bool) -> None:
    cases = []
    for label in [
        "private-direct",
        "candidate-direct",
        "tunnel-private-tcp",
        "tunnel-private-tls",
        "tunnel-private-https",
    ]:
        status = "deny" if failed and label == "candidate-direct" else "pass"
        cases.append(
            {
                "label": label,
                "protocol": "https-head",
                "status": status,
                "reason": "failed" if status != "pass" else "ok",
                "boundSelected": "tunnel-002",
                "failedStage": "tunnel-001:stream-first-read" if status != "pass" else None,
                "failureScope": "direct" if status != "pass" else "none",
                "reportPath": str(root / label / "report.json"),
            }
        )
    config.write_json(
        root / "matrix.json",
        {
            "targetUrl": "https://chatgpt.com/",
            "totals": {
                "attempted": len(cases),
                "passed": sum(1 for item in cases if item["status"] == "pass"),
                "failed": sum(1 for item in cases if item["status"] != "pass"),
            },
            "cases": cases,
        },
    )


if __name__ == "__main__":
    unittest.main()
