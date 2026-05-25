from __future__ import annotations

import argparse
import json
import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.cli import dynet_clash_compare as compare


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

    def test_parity_verdict(self) -> None:
        report = compare.build_comparison_from_summaries(
            sample_clash_controller(),
            sample_dynet_parity(),
            sample_args(),
        )

        self.assertEqual(report["verdict"]["status"], "dynet-parity-candidate")
        self.assertEqual(report["verdict"]["primaryDelta"], 0.0)

    def test_dynet_retry_report(self) -> None:
        dynet = sample_dynet_parity()
        dynet["pairedReplay"] = {
            "dynetRetry": {
                "enabled": True,
                "attempts": 12,
                "recoveredAfterRetry": 2,
                "unresolvedDirectTlsEof": 1,
            }
        }

        report = compare.build_comparison_from_summaries(
            sample_clash_controller(),
            dynet,
            sample_args(),
        )

        self.assertEqual(report["dynetRetry"]["recoveredAfterRetry"], 2)
        self.assertEqual(report["dynetRetry"]["unresolvedDirectTlsEof"], 1)

    def test_retry_from_pairs(self) -> None:
        with tempfile.TemporaryDirectory() as raw_dir:
            pairs = Path(raw_dir) / "pairs.json"
            pairs.write_text(json.dumps(retry_pair_summary()))
            args = sample_args(paired_summary=str(pairs))
            dynet = sample_dynet_parity()
            dynet["pairedReplay"] = {"dynetRetry": {"enabled": True, "attempts": 1, "rows": 1}}
            report = compare.build_comparison_from_summaries(sample_clash_controller(), dynet, args)

        self.assertEqual(report["dynetRetry"]["attemptClassified"], 1)
        self.assertEqual(
            report["dynetRetry"]["attemptClassifications"],
            [{"key": "not-dynet-failure", "count": 1}],
        )

    def test_paired_replay_limits(self) -> None:
        clash = sample_clash_controller()
        clash["pairedReplay"] = {
            "controllerAttribution": {"overlapRisk": True},
            "pairGapMs": {"p95": 2501},
        }

        limits = compare.comparison_limits(
            clash,
            {
                "replay": {"schedule": True},
                "scheduler": {"mode": "paired-interleaved", "lagExceeded": False},
                "items": [],
            },
            sample_args(),
        )

        self.assertIn(
            "paired replay used overlapping controller captures; selected-chain attribution is observe-only",
            limits,
        )
        self.assertIn("paired replay pair gap exceeded configured budget", limits)

        details = compare.comparison_limit_details(
            clash,
            {
                "replay": {"schedule": True},
                "scheduler": {"mode": "paired-interleaved", "lagExceeded": False},
                "items": [],
            },
            sample_args(),
        )

        self.assertIn(
            {
                "scope": "attribution",
                "category": "controller",
                "message": "paired replay used overlapping controller captures; selected-chain attribution is observe-only",
            },
            details,
        )
        self.assertIn(
            {
                "scope": "product-effect",
                "category": "scheduler",
                "message": "paired replay pair gap exceeded configured budget",
            },
            details,
        )

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

    def test_schedule_lag_limit(self) -> None:
        dynet = sample_dynet()
        dynet["replay"] = {"schedule": True}
        dynet["scheduler"] = {
            "mode": "open-loop",
            "lagExceeded": True,
        }

        limits = compare.comparison_limits(
            sample_clash_controller(),
            dynet,
            sample_args(),
        )

        self.assertIn("dynet schedule lag exceeded configured budget", limits)

    def test_paired_scheduler_alignment(self) -> None:
        dynet = sample_dynet()
        dynet["replay"] = {"schedule": True}
        dynet["scheduler"] = {
            "mode": "paired-interleaved",
            "lagExceeded": False,
        }

        limits = compare.comparison_limits(
            sample_clash_controller(),
            dynet,
            sample_args(),
        )

        self.assertNotIn(
            "dynet replay did not use open-loop or paired scheduler",
            limits,
        )

    def test_scheduler_metadata_limit(self) -> None:
        limits = compare.comparison_limits(
            sample_clash_controller(),
            {
                "replay": {"schedule": True},
                "items": [],
            },
            sample_args(),
        )

        self.assertIn("dynet summary lacks replay scheduler metadata", limits)

    def test_runtime_gate_report(self) -> None:
        with tempfile.TemporaryDirectory() as raw_dir:
            runtime_path = Path(raw_dir) / "runtime.json"
            runtime_path.write_text(json.dumps(clean_runtime_repeat()))
            args = sample_args(runtime_summary=str(runtime_path))

            report = compare.build_comparison_from_summaries(
                sample_clash_controller(),
                sample_dynet_scheduled(),
                args,
            )

        self.assertTrue(report["dynetRuntimeGate"]["clean"])
        self.assertEqual(
            report["dynetRuntimeGate"]["classification"],
            "runtime-workload-clean",
        )
        self.assertEqual(
            report["deficitAttribution"]["classification"],
            "runtime-clean-target-or-probe-suspect",
        )
        self.assertEqual(
            report["deficitAttribution"]["byStage"],
            [{"key": "tls-handshake", "count": 1}],
        )
        self.assertEqual(report["limitDetails"], [])
        self.assertNotIn(
            "dynet runtime workloadFlow gate failed",
            "\n".join(report["limits"]),
        )

    def test_runtime_gate_required(self) -> None:
        args = sample_args(require_runtime_gate=True)

        limits = compare.comparison_limits(
            sample_clash_controller(),
            sample_dynet_scheduled(),
            args,
        )

        self.assertIn(
            "dynet runtime workloadFlow gate is required but no runtime summary was supplied",
            limits,
        )

    def test_runtime_gate_limit(self) -> None:
        gate = compare.runtime_gate.build(dirty_runtime_repeat(), "runtime.json")

        limits = compare.comparison_limits(
            sample_clash_controller(),
            sample_dynet_scheduled(),
            sample_args(),
            gate,
        )

        self.assertTrue(any("dynet runtime workloadFlow gate failed" in item for item in limits))


def sample_args(
    *,
    runtime_summary: str | None = None,
    require_runtime_gate: bool = False,
    paired_summary: str | None = None,
) -> argparse.Namespace:
    return argparse.Namespace(
        clash_summary="clash.json",
        dynet_summary="dynet.json",
        runtime_summary=runtime_summary,
        paired_summary=paired_summary,
        require_runtime_gate=require_runtime_gate,
        primary_bucket="github-proof",
        guardrail_bucket=["control-global", "work-direct"],
        min_primary_delta=0.05,
        min_parity_delta=0.0,
        min_guardrail_rate=0.99,
        max_pair_gap_ms=2000,
    )


def retry_pair_summary() -> dict[str, object]:
    return {
        "dynetRetry": {"enabled": True, "maxAttempts": 3, "retrySleepMs": 250},
        "items": [
            {
                "dynetRetry": {
                    "attemptsUsed": 1,
                    "attempts": [{"classification": "not-dynet-failure"}],
                }
            }
        ],
    }


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


def sample_dynet_scheduled() -> dict[str, object]:
    data = sample_dynet()
    data["replay"] = {"schedule": True}
    data["scheduler"] = {"mode": "open-loop", "lagExceeded": False}
    data["byBucket"][1]["passed"] = 5
    data["byBucket"][1]["failed"] = 0
    data["items"] = [
        {
            "status": "fail",
            "bucket": "github-proof",
            "domain": "api.github.com",
            "selectedOutbound": "direct",
            "failedStage": "tls-handshake",
            "reason": "failed TLS handshake with api.github.com: unexpected end of file",
        }
    ]
    return data


def sample_dynet_parity() -> dict[str, object]:
    return {
        "totals": {"attempted": 10, "passed": 8, "failed": 2},
        "byBucket": [
            {"key": "github-proof", "attempted": 5, "passed": 2, "failed": 3},
            {"key": "work-direct", "attempted": 5, "passed": 5, "failed": 0},
        ],
        "items": [],
    }


def clean_runtime_repeat() -> dict[str, object]:
    return {
        "totals": {
            "runs": 2,
            "failedRuns": 0,
            "workloadAttempted": 36,
            "workloadSuccess": 36,
            "workloadFailure": 0,
            "workloadErrors": [],
            "workloadStrictFailedRuns": 0,
            "workloadFlowEntries": 36,
            "workloadFlowTcpAttemptedEntries": 36,
            "workloadFlowTcpAttemptedCoveredEntries": 36,
            "workloadFlowRuntimePreflowMatchedEntries": 36,
            "workloadFlowRuntimePacketHandshakeEntries": 36,
            "workloadFlowTunCaptureMatchedEntries": 36,
            "workloadFlowUnmatchedEntries": 0,
            "workloadFlowRuntimePacketTerminalEntries": 0,
            "tcpFlowFailed": 0,
            "tcpFlowFailedAfterPathComplete": 0,
            "tcpFlowFailedAfterUpstreamOnly": 0,
            "tcpSlotPressureEvents": 0,
        }
    }


def dirty_runtime_repeat() -> dict[str, object]:
    data = clean_runtime_repeat()
    data["totals"]["workloadFailure"] = 1
    data["totals"]["workloadSuccess"] = 35
    data["totals"]["workloadErrors"] = [{"key": "timeout", "count": 1}]
    data["totals"]["workloadFlowFailureSurfaces"] = [
        {"key": "https-head:tls-handshake:timeout:route-dynet:tun-witnessed", "count": 1}
    ]
    return data


if __name__ == "__main__":
    unittest.main()
