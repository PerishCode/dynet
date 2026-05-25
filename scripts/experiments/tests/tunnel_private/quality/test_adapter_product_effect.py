from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[5]
EXPERIMENTS = ROOT / "scripts" / "experiments"
sys.path.insert(0, str(EXPERIMENTS))

from scripts.cli import tunnel_private_lab as lab
from tunnel_private.quality.readiness import product_effect


class AdapterProductEffectTest(unittest.TestCase):
    def test_parser(self) -> None:
        parser = lab.build_parser()

        args = parser.parse_args([
            "adapter-product-effect",
            "--output-dir",
            "/tmp/out",
            "--adapter-type",
            "trojan",
            "--maturity",
            "/tmp/maturity.json",
            "--dynet-product-evidence",
            "/tmp/dynet.json",
            "--clash-transport-evidence",
            "/tmp/clash.json",
            "--runtime-evidence",
            "/tmp/runtime.json",
            "--paired-evidence",
            "/tmp/paired.json",
            "--min-dynet-product-targets",
            "3",
            "--min-paired-windows",
            "2",
            "--min-paired-entries",
            "8",
            "--min-runtime-workload-entries",
            "16",
        ])

        self.assertEqual(args.command, "adapter-product-effect")
        self.assertEqual(args.adapter_type, "trojan")
        self.assertEqual(args.maturity, "/tmp/maturity.json")
        self.assertEqual(args.dynet_product_evidence, ["/tmp/dynet.json"])
        self.assertEqual(args.clash_transport_evidence, ["/tmp/clash.json"])
        self.assertEqual(args.runtime_evidence, ["/tmp/runtime.json"])
        self.assertEqual(args.paired_evidence, ["/tmp/paired.json"])
        self.assertEqual(args.min_dynet_product_targets, 3)
        self.assertEqual(args.min_paired_windows, 2)
        self.assertEqual(args.min_paired_entries, 8)
        self.assertEqual(args.min_runtime_workload_entries, 16)

    def test_needs_vm_paired(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            maturity = write_fixture(root / "maturity.json", maturity_summary())
            dynet = write_fixture(root / "dynet.json", dynet_vm_product_summary())
            clash = write_fixture(root / "clash.json", clash_transport_summary())

            summary = product_effect.adapter_product_effect_summary(
                adapter_type="trojan",
                maturity_path=maturity,
                dynet_product_paths=[dynet],
                clash_transport_paths=[clash],
                runtime_paths=[],
                paired_paths=[],
                minimums={"dynetProductTargets": 4},
            )

        self.assertEqual(summary["status"], "needs-vm-side-paired-product-effect")
        self.assertEqual(
            summary["recommendedUse"],
            "build-vm-side-paired-product-effect-runner",
        )
        self.assertFalse(summary["conclusion"]["productEffectParityClaimSafe"])
        self.assertTrue(gate(summary, "adapter-candidate-mature")["passed"])
        self.assertTrue(gate(summary, "dynet-linux-product-clean")["passed"])
        self.assertTrue(gate(summary, "clash-product-surface-present")["passed"])
        self.assertFalse(gate(summary, "linux-interface-bound-paired-window")["passed"])
        self.assertIn(
            "build-vm-side-paired-product-effect-runner",
            [item["id"] for item in summary["conclusion"]["nextActions"]],
        )

    def test_blocks_before_maturity(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            maturity = write_fixture(
                root / "maturity.json",
                maturity_summary(status="observe-more"),
            )
            dynet = write_fixture(root / "dynet.json", dynet_vm_product_summary())
            clash = write_fixture(root / "clash.json", clash_transport_summary())

            summary = product_effect.adapter_product_effect_summary(
                adapter_type="trojan",
                maturity_path=maturity,
                dynet_product_paths=[dynet],
                clash_transport_paths=[clash],
                runtime_paths=[],
                paired_paths=[],
                minimums={"dynetProductTargets": 4},
            )

        self.assertEqual(summary["status"], "blocked")
        self.assertIn(
            "adapter-candidate-mature",
            summary["conclusion"]["notReadyReasons"],
        )

    def test_linux_parity_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            maturity = write_fixture(root / "maturity.json", maturity_summary())
            dynet = write_fixture(root / "dynet.json", dynet_vm_product_summary())
            clash = write_fixture(root / "clash.json", clash_transport_summary())
            paired = write_fixture(root / "paired.json", paired_comparison_summary())

            summary = product_effect.adapter_product_effect_summary(
                adapter_type="trojan",
                maturity_path=maturity,
                dynet_product_paths=[dynet],
                clash_transport_paths=[clash],
                runtime_paths=[],
                paired_paths=[paired],
                minimums={"dynetProductTargets": 4},
            )

        self.assertEqual(summary["status"], "product-effect-parity-candidate")
        self.assertTrue(summary["conclusion"]["productEffectParityClaimSafe"])
        self.assertTrue(summary["maturity"]["recoveredStagePressureObserved"])
        self.assertTrue(summary["maturity"]["cascadeStagePressureObserved"])
        self.assertEqual(summary["maturity"]["flowRefreshChangedRuns"], 1)
        self.assertEqual(summary["maturity"]["cascadeStageFailedAttempts"], 2)
        self.assertEqual(summary["maturity"]["cascadeStageRecoveredFlows"], 1)
        self.assertTrue(summary["maturity"]["cascadeStageNonBoundStopObserved"])
        self.assertEqual(summary["maturity"]["cascadeStageFailedByStopReason"], [
            {"key": "non-bound-failure", "count": 1},
            {"key": "retry-bound-failure-before-replay", "count": 1},
        ])
        self.assertIn(
            "retain-recovered-stage-pressure-observe-only",
            [item["id"] for item in summary["conclusion"]["nextActions"]],
        )
        self.assertIn(
            "retain-cascade-stage-pressure-observe-only",
            [item["id"] for item in summary["conclusion"]["nextActions"]],
        )
        self.assertTrue(gate(summary, "linux-interface-bound-paired-window")["passed"])
        self.assertTrue(gate(summary, "paired-product-effect-parity")["passed"])
        self.assertTrue(gate(summary, "paired-entry-depth")["passed"])
        self.assertTrue(gate(summary, "target-family-overlap-known")["passed"])

    def test_repeat_depth_required(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            maturity = write_fixture(root / "maturity.json", maturity_summary())
            dynet = write_fixture(root / "dynet.json", dynet_vm_product_summary())
            clash = write_fixture(root / "clash.json", clash_transport_summary())
            paired = write_fixture(root / "paired.json", paired_comparison_summary())

            summary = product_effect.adapter_product_effect_summary(
                adapter_type="trojan",
                maturity_path=maturity,
                dynet_product_paths=[dynet],
                clash_transport_paths=[clash],
                runtime_paths=[],
                paired_paths=[paired],
                minimums={"dynetProductTargets": 4, "pairedWindows": 2},
            )

        self.assertEqual(summary["status"], "needs-repeat-paired-product-effect")
        self.assertFalse(summary["conclusion"]["productEffectParityClaimSafe"])
        self.assertFalse(gate(summary, "paired-window-depth")["passed"])
        self.assertIn(
            "collect-repeat-paired-product-effect-window",
            [item["id"] for item in summary["conclusion"]["nextActions"]],
        )

    def test_entry_depth_required(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            maturity = write_fixture(root / "maturity.json", maturity_summary())
            dynet = write_fixture(root / "dynet.json", dynet_vm_product_summary())
            clash = write_fixture(root / "clash.json", clash_transport_summary())
            paired = write_fixture(root / "paired.json", paired_comparison_summary())

            summary = product_effect.adapter_product_effect_summary(
                adapter_type="trojan",
                maturity_path=maturity,
                dynet_product_paths=[dynet],
                clash_transport_paths=[clash],
                runtime_paths=[],
                paired_paths=[paired],
                minimums={"dynetProductTargets": 4, "pairedEntries": 8},
            )

        self.assertEqual(summary["status"], "needs-broader-paired-product-effect")
        self.assertFalse(gate(summary, "paired-entry-depth")["passed"])
        self.assertIn(
            "collect-broader-paired-product-effect-window",
            [item["id"] for item in summary["conclusion"]["nextActions"]],
        )

    def test_runtime_backed_gate(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            maturity = write_fixture(root / "maturity.json", maturity_summary())
            dynet = write_fixture(root / "dynet.json", dynet_vm_product_summary())
            clash = write_fixture(root / "clash.json", clash_transport_summary())
            paired = write_fixture(root / "paired.json", paired_comparison_summary())
            runtime = write_fixture(root / "runtime.json", runtime_summary())

            summary = product_effect.adapter_product_effect_summary(
                adapter_type="trojan",
                maturity_path=maturity,
                dynet_product_paths=[dynet],
                clash_transport_paths=[clash],
                runtime_paths=[runtime],
                paired_paths=[paired],
                minimums={"dynetProductTargets": 4, "runtimeWorkloadEntries": 8},
            )

        self.assertEqual(summary["status"], "product-effect-parity-candidate")
        self.assertTrue(gate(summary, "dynet-run-tun-runtime-clean")["passed"])
        self.assertTrue(gate(summary, "runtime-workload-depth")["passed"])
        self.assertTrue(gate(summary, "runtime-target-overlap-known")["passed"])

    def test_failure_surfaces(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            maturity = write_fixture(root / "maturity.json", maturity_summary())
            dynet = write_fixture(root / "dynet.json", dynet_vm_product_summary())
            clash = write_fixture(root / "clash.json", clash_transport_summary())
            paired = write_fixture(root / "paired.json", paired_comparison_summary())
            runtime = write_fixture(root / "runtime.json", failed_runtime_summary())

            summary = product_effect.adapter_product_effect_summary(
                adapter_type="trojan",
                maturity_path=maturity,
                dynet_product_paths=[dynet],
                clash_transport_paths=[clash],
                runtime_paths=[runtime],
                paired_paths=[paired],
                minimums={"dynetProductTargets": 4, "runtimeWorkloadEntries": 4},
            )

        self.assertFalse(gate(summary, "dynet-run-tun-runtime-clean")["passed"])
        self.assertEqual(summary["dynetRuntimeProduct"]["workloadFailedBySurface"], [
            {
                "key": "https-head:tls-handshake:tls:route-dynet:tun-witnessed",
                "count": 1,
            },
        ])
        self.assertEqual(summary["dynetRuntimeProduct"]["workloadErrors"], [
            {"key": "tls", "count": 1},
        ])

    def test_command_writes_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            maturity = write_fixture(root / "maturity.json", maturity_summary())
            dynet = write_fixture(root / "dynet.json", dynet_vm_product_summary())
            clash = write_fixture(root / "clash.json", clash_transport_summary())
            output = root / "out"

            with contextlib.redirect_stdout(io.StringIO()):
                status = product_effect.command_adapter_product_effect(command_args(
                    output=output,
                    maturity=maturity,
                    dynet=dynet,
                    clash=clash,
                ))

            self.assertEqual(status, 0)
            self.assertTrue((output / "summary.json").exists())
            self.assertTrue((output / "summary.md").exists())


def maturity_summary(status: str = "candidate-mature") -> dict[str, object]:
    hosts = ["api.github.com", "chatgpt.com", "www.cloudflare.com", "www.gstatic.com"]
    return {
        "schema": "dynet-tunnel-private-adapter-maturity/v1alpha1",
        "status": status,
        "recommendedUse": "eligible-for-broader-adapter-runtime-promotion-evaluation",
        "plannerPenaltySafe": False,
        "readiness": {"productTargetHosts": hosts},
        "runtime": {
            "runtimeTargetHosts": hosts,
            "flowRefreshChangedRuns": 1,
            "flowRefreshSourceCount": 1,
            "tcpFlowStageFailed": 2,
            "cascadeStageSourceCount": 1,
            "cascadeStageFailedAttempts": 2,
            "cascadeStageRetryableFailures": 1,
            "cascadeStageStoppedFailures": 1,
            "cascadeStageRecoveredFlows": 1,
            "cascadeStageNonBoundStopObserved": True,
            "cascadeStageFailedByScope": [
                {"key": "bound", "count": 1},
                {"key": "downstream", "count": 1},
            ],
            "cascadeStageFailedByStageSurface": [
                {"key": "private-trojan-connect:trojan", "count": 1},
                {"key": "trojan-tls-handshake:trojan", "count": 1},
            ],
            "cascadeStageFailedByStageDisposition": [
                {"key": "protocol-invalid", "count": 1},
                {"key": "reset", "count": 1},
            ],
            "cascadeStageFailedByStopReason": [
                {"key": "non-bound-failure", "count": 1},
                {"key": "retry-bound-failure-before-replay", "count": 1},
            ],
        },
        "conclusion": {
            "recoveredFallbackObserved": True,
            "recoveredStagePressureObserved": True,
            "cascadeStagePressureObserved": True,
            "nextActions": [
                {"id": "retain-recovered-stage-pressure-observe-only"},
                {"id": "retain-cascade-stage-pressure-observe-only"},
            ],
        },
    }


def dynet_vm_product_summary() -> dict[str, object]:
    targets = [
        "https://www.cloudflare.com/cdn-cgi/trace",
        "https://api.github.com/",
        "https://www.gstatic.com/generate_204",
        "https://chatgpt.com/",
    ]
    return {
        "schema": "dynet-vm-private-cascade-run/v1alpha1",
        "totals": {"attempted": 4, "passed": 4, "failed": 0},
        "reports": [{"targetUrl": target, "status": "pass"} for target in targets],
    }


def clash_transport_summary() -> dict[str, object]:
    return {
        "schema": "dynet-tunnel-private-transport-evidence/v1alpha1",
        "sourceCount": 1,
        "surfaces": [
            {
                "surface": "product-e2e",
                "candidateCount": 3,
                "passCount": 2,
                "failCount": 1,
                "configFeatureCounts": {"interface-name:true": 2},
            }
        ],
        "privacy": {"unsafeFlags": []},
    }


def paired_comparison_summary() -> dict[str, object]:
    return {
        "schema": "dynet-clash-proof-comparison/v1alpha1",
        "runtimeCarrier": "linux-interface-bound",
        "targetHosts": ["api.github.com"],
        "totals": {
            "clash": {"count": 4, "success": 4, "failure": 0},
            "dynet": {"count": 4, "success": 4, "failure": 0},
        },
    }


def runtime_summary() -> dict[str, object]:
    return {
        "schema": "dynet-vm-private-runtime-repeat/v1alpha1",
        "totals": {
            "runs": 1,
            "passedRuns": 1,
            "failedRuns": 0,
            "workloadFailedRuns": 0,
            "workloadAttempted": 8,
            "workloadSuccess": 8,
            "workloadFailure": 0,
            "workloadFlowEntries": 8,
            "workloadFlowMatchedEntries": 8,
            "workloadFlowCoveredEntries": 8,
            "qualityBoundCandidateSets": 8,
            "qualityBoundSelectedWithQuality": 8,
            "qualityBoundSelectedBehind": 0,
            "tcpFlowRouteGraphSelected": 8,
            "tcpFlowPathComplete": 8,
            "tcpFlowPayloadBidirectional": 8,
            "tcpFlowFailed": 0,
        },
        "runs": [
            {
                "tcpClosedSessions": 8,
                "tcpSessionFailures": 0,
                "targetIdentity": {"domainTargets": ["api.github.com:443"]},
                "workloadFlow": {"rows": [{"domain": "api.github.com"}]},
                "boundSelection": {"rows": []},
            }
        ],
    }


def failed_runtime_summary() -> dict[str, object]:
    payload = runtime_summary()
    payload["totals"].update({
        "failedRuns": 1,
        "workloadFailedRuns": 1,
        "workloadSuccess": 3,
        "workloadFailure": 1,
        "workloadFlowMatchedEntries": 3,
        "workloadFlowCoveredEntries": 3,
        "workloadFailedBySurface": [
            {
                "key": "https-head:tls-handshake:tls:route-dynet:tun-witnessed",
                "count": 1,
            },
        ],
        "workloadErrors": [{"key": "tls", "count": 1}],
    })
    return payload


def gate(summary: dict[str, object], gate_id: str) -> dict[str, object]:
    for item in summary["gates"]:
        if item["id"] == gate_id:
            return item
    raise AssertionError(f"missing gate {gate_id}")


def write_fixture(path: Path, payload: dict[str, object]) -> Path:
    path.write_text(json.dumps(payload))
    return path


def command_args(output: Path, maturity: Path, dynet: Path, clash: Path) -> object:
    return lab.argparse.Namespace(
        output_dir=str(output),
        adapter_type="trojan",
        maturity=str(maturity),
        dynet_product_evidence=[str(dynet)],
        clash_transport_evidence=[str(clash)],
        paired_evidence=[],
        min_dynet_product_targets=4,
        min_paired_windows=1,
        min_paired_entries=0,
        runtime_evidence=[],
        min_runtime_workload_entries=0,
    )


if __name__ == "__main__":
    unittest.main()
