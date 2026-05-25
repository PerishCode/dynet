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
from tunnel_private.quality.readiness import maturity


class AdapterMaturityTest(unittest.TestCase):
    def test_parser(self) -> None:
        parser = lab.build_parser()

        args = parser.parse_args([
            "adapter-maturity",
            "--output-dir",
            "/tmp/out",
            "--adapter-type",
            "trojan",
            "--readiness",
            "/tmp/readiness.json",
            "--runtime-evidence",
            "/tmp/runtime.json",
            "--flow-refresh-evidence",
            "/tmp/refresh.json",
            "--cascade-stage-evidence",
            "/tmp/cascade.json",
            "--min-runtime-runs",
            "8",
        ])

        self.assertEqual(args.command, "adapter-maturity")
        self.assertEqual(args.adapter_type, "trojan")
        self.assertEqual(args.readiness, "/tmp/readiness.json")
        self.assertEqual(args.runtime_evidence, ["/tmp/runtime.json"])
        self.assertEqual(args.flow_refresh_evidence, ["/tmp/refresh.json"])
        self.assertEqual(args.cascade_stage_evidence, ["/tmp/cascade.json"])
        self.assertEqual(args.min_runtime_runs, 8)

    def test_observe_more_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            readiness = write_fixture(root / "readiness.json", readiness_summary())
            runtime = write_fixture(root / "runtime.json", runtime_summary())

            summary = maturity.adapter_maturity_summary(
                adapter_type="trojan",
                readiness_path=readiness,
                runtime_paths=[runtime],
                minimums=minimums(),
            )

        self.assertEqual(summary["status"], "observe-more")
        self.assertEqual(summary["recommendedUse"], "continue-mainline-runtime-observe")
        self.assertFalse(summary["plannerPenaltySafe"])
        self.assertIn("runtime-repeat-depth", summary["conclusion"]["notMatureReasons"])
        self.assertIn("runtime-workload-depth", summary["conclusion"]["notMatureReasons"])
        self.assertNotIn("runtime-target-diversity", summary["conclusion"]["notMatureReasons"])
        self.assertNotIn("primary-candidate-diversity", summary["conclusion"]["notMatureReasons"])
        self.assertEqual(summary["runtime"]["uniquePrimarySelectedCandidates"], 2)
        self.assertEqual(summary["runtime"]["runtimeTargetHostCount"], 4)
        self.assertTrue(summary["conclusion"]["recoveredFallbackObserved"])
        self.assertTrue(summary["conclusion"]["recoveredStagePressureObserved"])
        self.assertEqual(summary["runtime"]["tcpFlowStageFailed"], 2)
        self.assertEqual(summary["runtime"]["workloadFlowMatchedRecoveredFailureEntries"], 2)
        self.assertIn(
            "retain-fallback-recovery-observe-only",
            [item["id"] for item in summary["conclusion"]["nextActions"]],
        )
        self.assertIn(
            "retain-recovered-stage-pressure-observe-only",
            [item["id"] for item in summary["conclusion"]["nextActions"]],
        )

    def test_candidate_mature(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            readiness = write_fixture(root / "readiness.json", readiness_summary())
            runtime = write_fixture(root / "runtime.json", runtime_summary())

            summary = maturity.adapter_maturity_summary(
                adapter_type="trojan",
                readiness_path=readiness,
                runtime_paths=[runtime],
                minimums=minimums(runtime_runs=4, runtime_workload=8),
            )

        self.assertEqual(summary["status"], "candidate-mature")
        self.assertTrue(summary["conclusion"]["promotionEvaluationEligible"])
        self.assertFalse(summary["conclusion"]["plannerPenaltySafe"])
        self.assertEqual(summary["conclusion"]["notMatureReasons"], [])
        self.assertTrue(summary["conclusion"]["recoveredStagePressureObserved"])
        self.assertEqual(summary["runtime"]["primarySelectedCandidates"], [
            {"key": "tunnel-001", "count": 1},
            {"key": "tunnel-004", "count": 3},
        ])

    def test_failure_surfaces(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            readiness = write_fixture(root / "readiness.json", readiness_summary())
            runtime = write_fixture(root / "runtime.json", failed_runtime_summary())

            summary = maturity.adapter_maturity_summary(
                adapter_type="trojan",
                readiness_path=readiness,
                runtime_paths=[runtime],
                minimums=minimums(runtime_runs=4, runtime_workload=8),
            )

        self.assertIn("runtime-clean", summary["conclusion"]["notMatureReasons"])
        self.assertEqual(summary["runtime"]["workloadFailedBySurface"], [
            {
                "key": "https-head:dns:timeout:route-unknown:tun-witnessed",
                "count": 1,
            },
            {
                "key": "https-head:tls-handshake:tls:route-dynet:tun-witnessed",
                "count": 1,
            },
        ])
        self.assertEqual(summary["runtime"]["workloadErrors"], [
            {"key": "timeout", "count": 1},
            {"key": "tls", "count": 1},
        ])

    def test_flow_refresh_observe(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            readiness = write_fixture(root / "readiness.json", readiness_summary())
            runtime = write_fixture(
                root / "runtime.json",
                runtime_summary(stage_pressure=False),
            )
            refresh = write_fixture(root / "refresh.json", flow_refresh_summary())

            summary = maturity.adapter_maturity_summary(
                adapter_type="trojan",
                readiness_path=readiness,
                runtime_paths=[runtime],
                flow_refresh_paths=[refresh],
                minimums=minimums(runtime_runs=4, runtime_workload=8),
            )

        self.assertEqual(summary["status"], "candidate-mature")
        self.assertTrue(summary["conclusion"]["recoveredStagePressureObserved"])
        self.assertEqual(summary["runtime"]["flowRefreshSourceCount"], 1)
        self.assertEqual(summary["runtime"]["flowRefreshChangedRuns"], 1)
        self.assertEqual(summary["runtime"]["tcpFlowStageFailed"], 2)
        self.assertEqual(
            summary["runtime"]["workloadFlowMatchedRecoveredFailureEntries"],
            2,
        )
        self.assertIn(
            "retain-recovered-stage-pressure-observe-only",
            [item["id"] for item in summary["conclusion"]["nextActions"]],
        )

    def test_cascade_stage_observe(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            readiness = write_fixture(root / "readiness.json", readiness_summary())
            runtime = write_fixture(
                root / "runtime.json",
                runtime_summary(stage_pressure=False),
            )
            cascade = write_fixture(root / "cascade.json", cascade_stage_summary())

            summary = maturity.adapter_maturity_summary(
                adapter_type="trojan",
                readiness_path=readiness,
                runtime_paths=[runtime],
                cascade_stage_paths=[cascade],
                minimums=minimums(runtime_runs=4, runtime_workload=8),
            )

        self.assertEqual(summary["status"], "candidate-mature")
        self.assertFalse(summary["conclusion"]["recoveredStagePressureObserved"])
        self.assertTrue(summary["conclusion"]["cascadeStagePressureObserved"])
        self.assertEqual(summary["runtime"]["cascadeStageSourceCount"], 1)
        self.assertEqual(summary["runtime"]["cascadeStageFailedAttempts"], 2)
        self.assertEqual(summary["runtime"]["cascadeStageRetryableFailures"], 1)
        self.assertEqual(summary["runtime"]["cascadeStageStoppedFailures"], 1)
        self.assertTrue(summary["runtime"]["cascadeStageNonBoundStopObserved"])
        self.assertEqual(summary["runtime"]["cascadeStageFailedByStageSurface"], [
            {"key": "private-trojan-connect:trojan", "count": 1},
            {"key": "trojan-tls-handshake:trojan", "count": 1},
        ])
        self.assertIn(
            "retain-cascade-stage-pressure-observe-only",
            [item["id"] for item in summary["conclusion"]["nextActions"]],
        )

    def test_single_runtime_cascade(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            readiness = write_fixture(root / "readiness.json", readiness_summary())
            runtime = write_fixture(
                root / "runtime.json",
                runtime_summary(stage_pressure=False),
            )
            cascade = write_fixture(
                root / "cascade.json",
                single_runtime_cascade_summary(),
            )

            summary = maturity.adapter_maturity_summary(
                adapter_type="trojan",
                readiness_path=readiness,
                runtime_paths=[runtime],
                cascade_stage_paths=[cascade],
                minimums=minimums(runtime_runs=4, runtime_workload=8),
            )

        self.assertEqual(summary["status"], "candidate-mature")
        self.assertTrue(summary["conclusion"]["cascadeStagePressureObserved"])
        self.assertEqual(summary["runtime"]["cascadeStageSourceCount"], 1)
        self.assertEqual(summary["runtime"]["cascadeStageFailedAttempts"], 4)
        self.assertEqual(summary["runtime"]["cascadeStageRetryableFailures"], 4)
        self.assertEqual(summary["runtime"]["cascadeStageStoppedFailures"], 0)
        self.assertEqual(summary["runtime"]["cascadeStageRecoveredFlows"], 3)
        self.assertFalse(summary["runtime"]["cascadeStageNonBoundStopObserved"])
        self.assertEqual(summary["runtime"]["cascadeStageFailedByStageSurface"], [
            {"key": "trojan-tls-handshake:trojan", "count": 4},
        ])
        self.assertEqual(summary["runtime"]["cascadeStageFailedByStageDisposition"], [
            {"key": "pending-timeout", "count": 4},
        ])

    def test_command_writes_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            readiness = write_fixture(root / "readiness.json", readiness_summary())
            runtime = write_fixture(root / "runtime.json", runtime_summary())
            output = root / "out"

            with contextlib.redirect_stdout(io.StringIO()):
                status = maturity.command_adapter_maturity(lab.argparse.Namespace(
                    output_dir=str(output),
                    adapter_type="trojan",
                    readiness=str(readiness),
                    runtime_evidence=[str(runtime)],
                    min_product_targets=4,
                    min_runtime_runs=6,
                    min_workload_attempted=12,
                    min_runtime_targets=4,
                    min_primary_candidates=2,
                ))

            self.assertEqual(status, 0)
            self.assertTrue((output / "summary.json").exists())
            self.assertTrue((output / "summary.md").exists())


def readiness_summary() -> dict[str, object]:
    targets = [
        "https://www.cloudflare.com/cdn-cgi/trace",
        "https://api.github.com/",
        "https://www.gstatic.com/generate_204",
        "https://chatgpt.com/",
    ]
    return {
        "schema": "dynet-tunnel-private-adapter-readiness/v1alpha1",
        "status": "ready",
        "recommendedUse": "use-as-mainline-adapter-runtime-work-slice",
        "productEvidence": {"product-e2e": {"runs": 6, "failed": 0, "targets": targets}},
        "runtimeEvidence": {"clean": True, "runs": 4, "failedRuns": 0},
        "conclusion": {"readyForMainlineAdapterWork": True},
    }


def runtime_summary(*, stage_pressure: bool = True) -> dict[str, object]:
    totals = {
        "runs": 4,
        "passedRuns": 4,
        "failedRuns": 0,
        "workloadFailedRuns": 0,
        "workloadAttempted": 8,
        "workloadSuccess": 8,
        "workloadFailure": 0,
        "workloadFlowEntries": 8,
        "workloadFlowMatchedEntries": 8,
        "workloadFlowCoveredEntries": 8,
        "qualityBoundCandidateSets": 10,
        "qualityBoundSelectedWithQuality": 10,
        "qualityBoundSelectedBehind": 0,
        "tcpFlowRouteGraphSelected": 10,
        "tcpFlowPathComplete": 10,
        "tcpFlowPayloadBidirectional": 10,
        "tcpFlowFailed": 0,
    }
    if stage_pressure:
        totals.update({
            "tcpFlowStageFailed": 2,
            "workloadFlowMatchedRecoveredFailureEntries": 2,
            "workloadFlowMatchedFlowStageFailedAttempts": 2,
        })
    return {
        "schema": "dynet-vm-private-runtime-repeat/v1alpha1",
        "totals": totals,
        "runs": [runtime_run()],
    }


def failed_runtime_summary() -> dict[str, object]:
    payload = runtime_summary()
    payload["totals"].update({
        "failedRuns": 1,
        "workloadFailedRuns": 1,
        "workloadSuccess": 6,
        "workloadFailure": 2,
        "workloadFlowMatchedEntries": 6,
        "workloadFlowCoveredEntries": 6,
        "workloadFailedBySurface": [
            {"key": "https-head:dns:timeout:route-unknown:tun-witnessed", "count": 1},
            {
                "key": "https-head:tls-handshake:tls:route-dynet:tun-witnessed",
                "count": 1,
            },
        ],
        "workloadFailedByStage": [
            {"key": "dns", "count": 1},
            {"key": "tls-handshake", "count": 1},
        ],
        "workloadErrors": [
            {"key": "timeout", "count": 1},
            {"key": "tls", "count": 1},
        ],
        "workloadFlowUnmatchedFailureSurfaces": [
            {"key": "https-head:dns:timeout:route-unknown:tun-witnessed", "count": 1},
        ],
    })
    return payload


def flow_refresh_summary() -> dict[str, object]:
    return {
        "schema": "dynet-vm-private-runtime-flow-refresh/v1alpha1",
        "totals": {
            "runs": 1,
            "changedRuns": 1,
            "recoveredStageSeparatedRuns": 1,
            "classifications": [
                {"key": "recovered-stage-separated", "count": 1},
            ],
        },
        "runs": [{
            "classification": "recovered-stage-separated",
            "current": {
                "tcpFlow": {"stageFailedFlows": 2},
                "workloadFlow": {
                    "matchedRecoveredFailureEntries": 2,
                    "matchedFlowStageFailedAttempts": 2,
                },
            },
        }],
    }


def cascade_stage_summary() -> dict[str, object]:
    return {
        "schema": "dynet-vm-private-runtime-round-gap-batch/v1alpha1",
        "totals": {
            "cascadeFailedAttempts": 2,
            "cascadeRetryableFailures": 1,
            "cascadeStoppedFailures": 1,
            "cascadeRecoveredFlows": 0,
            "cascadeFailedByStageSurface": [
                {"key": "private-trojan-connect:trojan", "count": 1},
                {"key": "trojan-tls-handshake:trojan", "count": 1},
            ],
            "cascadeFailedByStageDisposition": [
                {"key": "protocol-invalid", "count": 1},
                {"key": "reset", "count": 1},
            ],
            "cascadeFailedByStopReason": [
                {"key": "non-bound-failure", "count": 1},
                {"key": "retry-bound-failure-before-replay", "count": 1},
            ],
        },
        "conclusion": {
            "cascade": {
                "status": "non-bound-stop-observed",
            },
        },
    }


def single_runtime_cascade_summary() -> dict[str, object]:
    return {
        "schema": "dynet-vm-private-runtime-run/v1alpha1",
        "selection": {
            "cascadeAttempts": {
                "failedAttempts": 4,
                "retryableFailures": 4,
                "stoppedFailures": 0,
                "recoveredFlows": 3,
                "failedByScope": [{"key": "bound", "count": 4}],
                "failedByStageSurface": [
                    {"key": "trojan-tls-handshake:trojan", "count": 4},
                ],
                "failedByStageDisposition": [
                    {"key": "pending-timeout", "count": 4},
                ],
                "failedByStopReason": [
                    {"key": "retry-bound-failure-before-replay", "count": 4},
                ],
            },
        },
    }


def runtime_run() -> dict[str, object]:
    return {
        "tcpClosedSessions": 10,
        "tcpSessionFailures": 0,
        "tcpUpstreamBytes": 2048,
        "tcpDownstreamBytes": 8192,
        "targetIdentity": {"domainTargets": [
            "www.cloudflare.com:443",
            "api.github.com:443",
            "www.gstatic.com:443",
            "chatgpt.com:443",
        ]},
        "workloadFlow": {"rows": [
            {"domain": "www.cloudflare.com"},
            {"domain": "api.github.com"},
            {"domain": "www.gstatic.com"},
            {"domain": "chatgpt.com"},
        ]},
        "boundSelection": {
            "fallbackCandidateSets": 3,
            "fallbackSelectedWithQuality": 2,
            "fallbackSelectedBehind": 3,
            "rows": [
                primary_row("tunnel-001"),
                primary_row("tunnel-004"),
                primary_row("tunnel-004"),
                primary_row("tunnel-004"),
                {"selected": "tunnel-002", "selectionRole": "fallback", "candidateCount": 4},
            ],
        },
    }


def primary_row(selected: str) -> dict[str, object]:
    return {"selected": selected, "selectionRole": "primary", "candidateCount": 4}


def minimums(runtime_runs: int = 6, runtime_workload: int = 12) -> dict[str, int]:
    return {
        "productTargets": 4,
        "runtimeRuns": runtime_runs,
        "runtimeWorkload": runtime_workload,
        "runtimeTargets": 4,
        "primaryCandidates": 2,
    }


def write_fixture(path: Path, payload: dict[str, object]) -> Path:
    path.write_text(json.dumps(payload))
    return path


if __name__ == "__main__":
    unittest.main()
