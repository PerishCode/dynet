from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
from dynet_mainline import baseline as mainline_baseline
from tests.tunnel_private.quality.support.mainline_baseline import write_json
from tests.tunnel_private.quality.support.mainline_helpers import baseline_paths
from tests.tunnel_private.quality.support.mainline_surfaces.cascade_stop import (
    write_cascade_stop,
)
from tests.tunnel_private.quality.support.mainline_surfaces.stage_pressure import (
    write_stage_pressure,
)


class MainlinePostHardeningTest(unittest.TestCase):
    def test_product_clean(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = baseline_paths(root)
            paths["runtime_stage_pressure_paths"] = [
                write_stage_pressure(root, product_clean=True),
            ]
            paths["runtime_cascade_stop_paths"] = [
                write_cascade_stop(root, no_stop=True),
            ]
            paths["runtime_round_gap_paths"] = [write_round_gap(root)]
            paths["runtime_round_gap_compare_paths"] = [write_compare(root)]
            summary = mainline_baseline.mainline_baseline_summary(**paths)

        self.assertEqual(summary["status"], "mainline-baseline-current-clean")
        self.assertEqual(
            summary["runtimeStagePressure"]["statuses"],
            ["stage-pressure-product-clean"],
        )
        self.assertEqual(
            summary["runtimeCascadeStop"]["statuses"],
            ["no-cascade-stop-evidence"],
        )
        self.assertTrue(all(gate["passed"] for gate in summary["gates"]))


def write_round_gap(root: Path) -> Path:
    return write_json(root / "round-gap-product.json", {
        "schema": "dynet-vm-private-runtime-round-gap-batch/v1alpha1",
        "label": "round-gap-product",
        "totals": {
            "runs": 2, "cleanRuns": 2, "failedRuns": 0,
            "classifications": [{"key": "clean", "count": 2}],
            "failedWorkloadMechanisms": [],
            "recoveredFlowMechanisms": [
                {"key": "recovered-runtime-stage-failure-before-success", "count": 2},
            ],
            "cascadeFailedAttempts": 5, "cascadeRetryableFailures": 5,
            "cascadeStoppedFailures": 0, "cascadeRecoveredFlows": 3,
            "cascadeStoppedBoundExhaustedFlows": 0,
        },
        "conclusion": {
            "status": "clean",
            "nextAction": "observe-cascade-recovery-and-return-to-product-effect",
        },
        "policy": {"plannerPenaltySafe": False, "qualityPenaltySafe": False},
    })


def write_compare(root: Path) -> Path:
    return write_json(root / "round-gap-compare-product.json", {
        "schema": "dynet-vm-private-runtime-round-gap-compare/v1alpha1",
        "label": "round-gap-compare-product",
        "baseline": {"status": "mixed-with-clean-controls", "runs": 2},
        "candidate": {"status": "clean", "runs": 2},
        "conclusion": {
            "status": "candidate-clean",
            "nextAction": "return-to-mainline-product-effect",
            "improvements": [
                {"key": "workloadSuccess", "delta": 1},
                {"key": "stageFailureCount", "delta": -5},
            ],
            "remainingMechanisms": [
                {"key": "runtime-stage-failure", "count": 3},
                {"key": "recovered-runtime-stage-pressure", "count": 2},
            ],
            "plannerPenaltySafe": False,
            "qualityPenaltySafe": False,
        },
        "policy": {"plannerPenaltySafe": False, "qualityPenaltySafe": False},
    })


if __name__ == "__main__":
    unittest.main()
