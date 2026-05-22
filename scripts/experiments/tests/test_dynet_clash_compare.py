from __future__ import annotations

import argparse
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import dynet_clash_compare as compare


class DynetClashCompareTest(unittest.TestCase):
    def test_guardrail_verdict(self) -> None:
        report = compare.build_comparison_from_summaries(
            sample_clash(),
            sample_dynet(),
            sample_args(),
        )

        self.assertEqual(
            report["verdict"]["status"],
            "github-superior-with-guardrail-regression",
        )
        self.assertEqual(report["verdict"]["guardrailFailures"], ["work-direct"])


def sample_args() -> argparse.Namespace:
    return argparse.Namespace(
        clash_summary="clash.json",
        dynet_summary="dynet.json",
        primary_bucket="github-proof",
        guardrail_bucket=["control-global", "work-direct"],
        min_primary_delta=0.05,
        min_guardrail_rate=0.99,
    )


def sample_clash() -> dict[str, object]:
    return {
        "totals": {"count": 10, "success": 8, "failure": 2, "successRate": 0.8},
        "byBucket": [
            {"key": "github-proof", "count": 5, "success": 2, "failure": 3, "successRate": 0.4},
            {"key": "work-direct", "count": 5, "success": 5, "failure": 0, "successRate": 1.0},
        ],
        "byDomain": [],
    }


def sample_dynet() -> dict[str, object]:
    return {
        "totals": {"attempted": 10, "passed": 8, "failed": 2},
        "byBucket": [
            {"key": "github-proof", "attempted": 5, "passed": 5, "failed": 0},
            {"key": "work-direct", "attempted": 5, "passed": 3, "failed": 2},
        ],
        "items": [],
    }


if __name__ == "__main__":
    unittest.main()
