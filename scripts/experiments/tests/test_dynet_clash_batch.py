from __future__ import annotations

import argparse
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dynet_clash import batch


class DynetClashBatchTest(unittest.TestCase):
    def test_repeated_candidate(self) -> None:
        report = batch.build_from_reports(
            [
                comparison(8, 9, status="dynet-superior-candidate"),
                comparison(8, 9, status="dynet-superior-candidate"),
                comparison(8, 9, status="dynet-superior-candidate"),
            ],
            sample_args(),
        )

        self.assertEqual(
            report["verdict"]["status"],
            "dynet-superior-repeated-candidate",
        )
        self.assertEqual(report["verdict"]["failedGates"], [])
        self.assertEqual(report["aggregate"]["totals"]["clash"]["count"], 60)

    def test_single_insufficient(self) -> None:
        report = batch.build_from_reports(
            [comparison(8, 9, status="dynet-superior-candidate")],
            sample_args(),
        )

        self.assertEqual(report["verdict"]["status"], "insufficient-evidence")
        self.assertIn("min-windows", report["verdict"]["failedGates"])

    def test_limit_blocks_proof(self) -> None:
        report = batch.build_from_reports(
            [
                comparison(8, 9, status="dynet-superior-candidate"),
                comparison(
                    8,
                    9,
                    status="dynet-superior-candidate",
                    limits=["some Clash probes lack controller selected-chain observations"],
                ),
                comparison(8, 9, status="dynet-superior-candidate"),
            ],
            sample_args(),
        )

        self.assertEqual(report["verdict"]["status"], "limited-evidence")
        self.assertIn("clean-window-rate", report["verdict"]["failedGates"])
        self.assertEqual(report["limitCategories"], [{"key": "controller", "count": 1}])

    def test_negative_delta(self) -> None:
        report = batch.build_from_reports(
            [
                comparison(9, 8, status="not-superior"),
                comparison(9, 8, status="not-superior"),
                comparison(9, 8, status="not-superior"),
            ],
            sample_args(),
        )

        self.assertEqual(report["verdict"]["status"], "not-superior")
        self.assertIn("aggregate-primary-delta", report["verdict"]["failedGates"])

    def test_dirty_guardrail(self) -> None:
        report = batch.build_from_reports(
            [
                comparison(8, 9, status="dynet-superior-candidate", dynet_control=4),
                comparison(8, 9, status="dynet-superior-candidate"),
                comparison(8, 9, status="dynet-superior-candidate"),
            ],
            sample_args(),
        )

        self.assertEqual(report["verdict"]["status"], "limited-evidence")
        self.assertIn("aggregate-guardrails-clean", report["verdict"]["failedGates"])


def sample_args() -> argparse.Namespace:
    return argparse.Namespace(
        primary_bucket="github-proof",
        guardrail_bucket=["control-global", "work-direct"],
        min_windows=3,
        min_window_win_rate=0.67,
        min_clean_window_rate=1.0,
        min_aggregate_primary_delta=0.05,
        min_guardrail_rate=0.99,
    )


def comparison(
    clash_github_success: int,
    dynet_github_success: int,
    *,
    status: str,
    limits: list[str] | None = None,
    dynet_control: int = 5,
) -> dict[str, object]:
    github = bucket("github-proof", clash_github_success, 10, dynet_github_success, 10)
    control = bucket("control-global", 5, 5, dynet_control, 5)
    work = bucket("work-direct", 5, 5, 5, 5)
    by_bucket = [github, control, work]
    clash_success = clash_github_success + 10
    dynet_success = dynet_github_success + dynet_control + 5
    total_count = 20
    primary_delta = github["successRateDelta"]
    return {
        "totals": {
            "key": "all",
            "clash": side(clash_success, total_count),
            "dynet": side(dynet_success, total_count),
            "successRateDelta": round(
                side(dynet_success, total_count)["successRate"]
                - side(clash_success, total_count)["successRate"],
                4,
            ),
        },
        "byBucket": by_bucket,
        "verdict": {
            "status": status,
            "primaryBucket": "github-proof",
            "primaryDelta": primary_delta,
            "guardrailFailures": [],
        },
        "limits": limits or [],
    }


def bucket(
    key: str,
    clash_success: int,
    clash_count: int,
    dynet_success: int,
    dynet_count: int,
) -> dict[str, object]:
    clash = side(clash_success, clash_count)
    dynet = side(dynet_success, dynet_count)
    return {
        "key": key,
        "clash": clash,
        "dynet": dynet,
        "successRateDelta": round(dynet["successRate"] - clash["successRate"], 4),
        "failureDelta": dynet["failure"] - clash["failure"],
    }


def side(success: int, count: int) -> dict[str, object]:
    return {
        "count": count,
        "success": success,
        "failure": count - success,
        "successRate": round(success / count, 4),
    }


if __name__ == "__main__":
    unittest.main()
