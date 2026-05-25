from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[5]
EXPERIMENTS = ROOT / "scripts" / "experiments"
sys.path.insert(0, str(EXPERIMENTS))

from dynet_mainline import baseline as mainline_baseline
from tunnel_private.quality.readiness import product_effect
from tests.tunnel_private.quality.support.mainline_baseline import (
    runtime_pressure,
    write_json,
)
from tests.tunnel_private.quality.support.mainline_helpers import baseline_paths
from tests.tunnel_private.quality.test_adapter_product_effect import (
    clash_transport_summary,
    dynet_vm_product_summary,
    gate,
    maturity_summary,
    paired_comparison_summary,
    runtime_summary,
    write_fixture,
)


class RuntimePressureTest(unittest.TestCase):
    def test_clean_status(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = baseline_paths(root)
            pressure = runtime_pressure()
            pressure["status"] = "clean"
            pressure["conclusion"]["pressureShape"] = "no-residual-pressure"
            pressure["totals"].update({
                "stageFailures": 0,
                "stageUnrecoveredFailures": 0,
                "slotPressureEvents": 0,
                "slowStageEvents": 0,
                "slowFailedStageEvents": 0,
                "runsAtPortSlotLimit": 0,
            })
            paths["runtime_pressure_paths"] = [
                write_json(root / "pressure-clean.json", pressure),
            ]
            summary = mainline_baseline.mainline_baseline_summary(**paths)

        self.assertEqual(summary["status"], "mainline-baseline-current-clean")
        self.assertTrue(summary["runtimePressure"]["clean"])
        self.assertEqual(summary["runtimePressure"]["pressureShapes"], ["no-residual-pressure"])

    def test_pressure_clean(self) -> None:
        summary = runtime_product_effect(pressure=4)

        self.assertEqual(summary["status"], "product-effect-parity-candidate")
        self.assertTrue(gate(summary, "dynet-run-tun-runtime-clean")["passed"])

    def test_pressure_terminal(self) -> None:
        summary = runtime_product_effect(
            pressure=4,
            workload_success=7,
            workload_failure=1,
        )

        self.assertFalse(gate(summary, "dynet-run-tun-runtime-clean")["passed"])


def runtime_product_effect(
    *,
    pressure: int,
    workload_success: int = 8,
    workload_failure: int = 0,
) -> dict[str, object]:
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        maturity = write_fixture(root / "maturity.json", maturity_summary())
        dynet = write_fixture(root / "dynet.json", dynet_vm_product_summary())
        clash = write_fixture(root / "clash.json", clash_transport_summary())
        paired = write_fixture(root / "paired.json", paired_comparison_summary())
        runtime = runtime_summary()
        runtime["totals"].update({
            "tcpSlotPressureEvents": pressure,
            "workloadSuccess": workload_success,
            "workloadFailure": workload_failure,
        })
        runtime_path = write_fixture(root / "runtime.json", runtime)

        return product_effect.adapter_product_effect_summary(
            adapter_type="trojan",
            maturity_path=maturity,
            dynet_product_paths=[dynet],
            clash_transport_paths=[clash],
            runtime_paths=[runtime_path],
            paired_paths=[paired],
            minimums={"dynetProductTargets": 4, "runtimeWorkloadEntries": 8},
        )


if __name__ == "__main__":
    unittest.main()
