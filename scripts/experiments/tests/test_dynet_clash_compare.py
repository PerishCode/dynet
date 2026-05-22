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

    def test_limit_protocol_mismatch(self) -> None:
        limits = compare.comparison_limits(
            sample_clash(),
            {
                "items": [
                    {"sourceProbe": "tls-handshake", "dynetProtocol": "https-head"},
                    {"sourceProbe": "https-head", "dynetProtocol": "https-head"},
                ]
            },
            sample_args(),
        )

        self.assertIn(
            "some dynet tls-handshake source probes were not replayed as TLS-only probes",
            limits,
        )

    def test_limit_protocol_alignment(self) -> None:
        limits = compare.comparison_limits(
            sample_clash(),
            {
                "replay": {"schedule": False},
                "items": [
                    {"sourceProbe": "tls-handshake", "dynetProtocol": "tls-handshake"},
                    {"sourceProbe": "https-head", "dynetProtocol": "https-head"},
                ],
            },
            sample_args(),
        )

        self.assertNotIn(
            "some dynet tls-handshake source probes were not replayed as TLS-only probes",
            limits,
        )

    def test_limit_schedule_replay(self) -> None:
        limits = compare.comparison_limits(
            sample_clash(),
            {
                "replay": {"schedule": True},
                "items": [],
            },
            sample_args(),
        )

        self.assertNotIn(
            "dynet probe manifest is diagnostic and does not replay the original schedule",
            limits,
        )

    def test_controller_clean_limit(self) -> None:
        limits = compare.comparison_limits(
            sample_clash_controller(),
            {
                "replay": {"schedule": True},
                "items": [],
            },
            sample_args(),
        )

        self.assertNotIn(
            "black-box Clash summary lacks selected-node and candidate-plan evidence",
            limits,
        )
        self.assertNotIn(
            "some Clash probes lack controller selected-chain observations",
            limits,
        )

    def test_controller_missing_limit(self) -> None:
        clash = sample_clash_controller()
        clash["controllerAttribution"]["missing"] = 2

        limits = compare.comparison_limits(
            clash,
            {
                "replay": {"schedule": True},
                "items": [],
            },
            sample_args(),
        )

        self.assertIn(
            "some Clash probes lack controller selected-chain observations",
            limits,
        )

    def test_clash_guardrail_limit(self) -> None:
        clash = sample_clash_controller()
        clash["byBucket"].append(
            {
                "key": "control-global",
                "count": 15,
                "success": 14,
                "failure": 1,
                "successRate": 0.9333,
            }
        )

        limits = compare.comparison_limits(
            clash,
            {
                "replay": {"schedule": True},
                "items": [],
            },
            sample_args(),
        )

        self.assertIn(
            "Clash guardrail bucket `control-global` is below clean baseline threshold",
            limits,
        )

    def test_dynet_guardrail_limit(self) -> None:
        dynet = sample_dynet()
        dynet["replay"] = {"schedule": True}

        limits = compare.comparison_limits(
            sample_clash_controller(),
            dynet,
            sample_args(),
        )

        self.assertIn(
            "dynet guardrail bucket `work-direct` is below clean baseline threshold",
            limits,
        )


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


def sample_clash_controller() -> dict[str, object]:
    data = sample_clash()
    data["controllerAttribution"] = {
        "enabled": True,
        "observed": 10,
        "items": 10,
        "missing": 0,
        "rawNodeNamesStored": False,
        "chainKeys": [{"key": "abcd1234", "count": 7}],
        "rules": [{"key": "RuleSet", "count": 10}],
    }
    return data


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
