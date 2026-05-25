from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from private_runtime_lib.reporting.workload_surface.tcp import stage_pressure_profile


class StagePressureProfileTest(unittest.TestCase):
    def test_focused_profile_clean(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "round-gap.json"
            source.write_text(json.dumps(round_gap_summary(), sort_keys=True))
            report = stage_pressure_profile.build_stage_pressure_summary(
                "stage-pressure",
                root / "out",
                [source],
            )

        self.assertEqual(report["schema"], stage_pressure_profile.SCHEMA)
        self.assertEqual(report["conclusion"]["status"], "stage-pressure-profile-clean")
        self.assertEqual(report["totals"]["stageFailureEvents"], 8)
        self.assertEqual(report["totals"]["profileCount"], 1)
        self.assertEqual(report["totals"]["stageSurfaces"], ["trojan-tls-handshake:trojan"])
        self.assertEqual(report["totals"]["stageDispositions"], ["pending-timeout"])
        self.assertEqual(report["totals"]["cascadeScopes"], ["bound"])
        self.assertEqual(report["totals"]["pendingRetryEvents"], 8)
        self.assertEqual(report["totals"]["pendingRetries"], 0)
        self.assertEqual(report["totals"]["pendingElapsedMs"], 88873)
        self.assertEqual(report["totals"]["pendingElapsedMaxMs"], 12479)
        self.assertEqual(report["totals"]["pendingWaitClasses"], ["socket-read-timeout"])
        encoded = json.dumps(report, sort_keys=True)
        for value in ("tunnel-001", "tcp-session-8", "chatgpt.com"):
            self.assertNotIn(value, encoded)

    def test_selected_behind_blocks(self) -> None:
        summary = round_gap_summary()
        summary["totals"]["selectedBehind"] = 1
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "round-gap.json"
            source.write_text(json.dumps(summary, sort_keys=True))
            report = stage_pressure_profile.build_stage_pressure_summary(
                "stage-pressure",
                root / "out",
                [source],
            )

        self.assertEqual(
            report["conclusion"]["status"],
            "stage-pressure-profile-needs-evidence",
        )
        self.assertEqual(report["totals"]["selectedBehind"], 1)

    def test_product_clean(self) -> None:
        summary = round_gap_summary()
        summary["totals"].update({
            "cleanRuns": 2,
            "failedRuns": 0,
            "classifications": [{"key": "clean", "count": 2}],
            "failedByFailureStage": [],
            "failedByReplaySafe": [],
            "workloadFailure": 0,
            "cascadeStoppedFailures": 0,
            "cascadeStoppedBoundExhaustedFlows": 0,
            "tcpSlotPressureEvents": 45,
        })
        summary["conclusion"]["status"] = "clean"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "round-gap.json"
            source.write_text(json.dumps(summary, sort_keys=True))
            report = stage_pressure_profile.build_stage_pressure_summary(
                "stage-pressure",
                root / "out",
                [source],
            )

        self.assertEqual(report["conclusion"]["status"], "stage-pressure-product-clean")
        self.assertEqual(report["totals"]["tcpSlotPressureEvents"], 45)
        self.assertFalse(report["conclusion"]["plannerPenaltySafe"])


def round_gap_summary() -> dict[str, object]:
    return {
        "schema": stage_pressure_profile.ROUND_GAP_SCHEMA,
        "label": "round-gap",
        "totals": {
            "runs": 2,
            "cleanRuns": 1,
            "failedRuns": 1,
            "classifications": [
                {"key": "clean", "count": 1},
                {"key": "outbound-stage-pressure", "count": 1},
            ],
            "stageFailureBySurface": [
                {"key": "trojan-tls-handshake:trojan", "count": 8},
            ],
            "stageFailureByDisposition": [{"key": "pending-timeout", "count": 8}],
            "failedByFailureStage": [{"key": "trojan-tls-handshake", "count": 1}],
            "failedByReplaySafe": [{"key": "pre-payload", "count": 1}],
            "cascadeFailedByScope": [{"key": "bound", "count": 11}],
            "cascadeFailedByStopReason": [
                {"key": "retry-bound-failure-before-replay", "count": 10},
                {"key": "bound-candidates-exhausted", "count": 1},
            ],
            "recoveredFlowMechanisms": [
                {"key": "recovered-runtime-stage-failure-before-success", "count": 7},
            ],
            "workloadFailure": 1,
            "cascadeFailedAttempts": 11,
            "cascadeRetryableFailures": 10,
            "cascadeStoppedFailures": 1,
            "cascadeStoppedBoundExhaustedFlows": 1,
            "selectedBehind": 0,
            "tcpSlotPressureEvents": 0,
            "scheduleLagMaxMs": 5196,
            "slowStageEvents": 8,
            "slowStageMaxMs": 12480,
            "pendingRetryEvents": 8,
            "pendingRetries": 0,
            "pendingRetriesMax": 0,
            "pendingElapsedMs": 88873,
            "pendingElapsedMaxMs": 12479,
            "pendingBudgetMs": 250,
            "pendingSleepMs": 10,
            "pendingWaitClasses": [{"key": "socket-read-timeout", "count": 8}],
        },
        "conclusion": {
            "status": "mixed-with-clean-controls",
            "nextAction": "compare-mechanism-deltas-with-clean-controls",
            "plannerPenaltySafe": False,
            "qualityPenaltySafe": False,
        },
        "policy": {"plannerPenaltySafe": False, "qualityPenaltySafe": False},
    }


if __name__ == "__main__":
    unittest.main()
