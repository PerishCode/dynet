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

    def test_runtime_gate_required(self) -> None:
        args = sample_args(require_runtime_gate=True)
        report = batch.build_from_reports(
            [
                comparison(8, 9, status="dynet-superior-candidate", runtime_clean=True),
                comparison(8, 9, status="dynet-superior-candidate", runtime_clean=True),
                comparison(8, 9, status="dynet-superior-candidate", runtime_clean=True),
            ],
            args,
        )

        self.assertEqual(
            report["verdict"]["status"],
            "dynet-superior-repeated-candidate",
        )
        self.assertEqual(report["totals"]["runtimeGateCleanWindows"], 3)
        self.assertEqual(
            report["runtimeGate"]["classificationCounts"],
            [{"key": "runtime-workload-clean", "count": 3}],
        )
        self.assertEqual(report["runtimeGate"]["failedCheckCounts"], [])

    def test_runtime_gate_missing(self) -> None:
        args = sample_args(require_runtime_gate=True)
        report = batch.build_from_reports(
            [
                comparison(8, 9, status="dynet-superior-candidate", runtime_clean=True),
                comparison(8, 9, status="dynet-superior-candidate"),
                comparison(8, 9, status="dynet-superior-candidate", runtime_clean=True),
            ],
            args,
        )

        self.assertEqual(report["verdict"]["status"], "limited-evidence")
        self.assertIn("runtime-workload-gate-clean", report["verdict"]["failedGates"])
        self.assertEqual(report["totals"]["runtimeGateMissingWindows"], 1)
        self.assertEqual(report["runtimeGate"]["missingWindows"], 1)
        self.assertEqual(
            report["runtimeGate"]["classificationCounts"],
            [
                {"key": "runtime-workload-clean", "count": 2},
                {"key": "missing-runtime-evidence", "count": 1},
            ],
        )

    def test_runtime_surface_summary(self) -> None:
        args = sample_args(require_runtime_gate=True)
        report = batch.build_from_reports(
            [
                comparison(8, 9, status="dynet-superior-candidate", runtime_clean=True),
                comparison(8, 9, status="dynet-superior-candidate", runtime_clean=False),
                comparison(8, 9, status="dynet-superior-candidate", runtime_clean=False),
            ],
            args,
        )

        self.assertEqual(report["verdict"]["status"], "limited-evidence")
        self.assertEqual(
            report["runtimeGate"]["failedCheckCounts"],
            [{"key": "workload-all-success", "count": 2}],
        )
        self.assertEqual(
            report["runtimeGate"]["surfaceCounts"]["workloadFailedBySurface"],
            [{"key": "https-head:tls-handshake:timeout", "count": 2}],
        )
        self.assertEqual(len(report["runtimeGate"]["failedWindows"]), 2)

    def test_runtime_quality_totals(self) -> None:
        args = sample_args(require_runtime_gate=True, min_windows=1)
        window = comparison(8, 8, status="dynet-parity-candidate")
        window["dynetRuntimeGate"] = quality_route_runtime_gate()

        report = batch.build_from_reports([window], args)

        self.assertEqual(
            report["runtimeGate"]["classificationCounts"],
            [{"key": "runtime-route-plan-quality-clean", "count": 1}],
        )
        totals = report["windows"][0]["runtimeGate"]["totals"]
        self.assertTrue(totals["qualityStateUsed"])
        self.assertEqual(totals["qualityBoundSelectedWithQuality"], 8)
        self.assertEqual(totals["tcpFlowRouteGraphSelected"], 8)

    def test_parity_objective(self) -> None:
        args = sample_args(require_runtime_gate=True, objective="parity")
        report = batch.build_from_reports(
            [
                comparison(8, 8, status="dynet-parity-candidate", runtime_clean=True),
                comparison(8, 8, status="dynet-parity-candidate", runtime_clean=True),
                comparison(8, 8, status="dynet-parity-candidate", runtime_clean=True),
            ],
            args,
        )

        self.assertEqual(
            report["verdict"]["status"],
            "dynet-parity-repeated-candidate",
        )
        self.assertEqual(report["thresholds"]["objective"], "parity")

    def test_retry_aggregate(self) -> None:
        report = batch.build_from_reports(
            [
                comparison(
                    8,
                    9,
                    status="dynet-superior-candidate",
                    dynet_retry=retry(10, 2, 0),
                ),
                comparison(
                    8,
                    9,
                    status="dynet-superior-candidate",
                    dynet_retry=retry(12, 3, 1),
                ),
                comparison(
                    8,
                    9,
                    status="dynet-superior-candidate",
                    dynet_retry=retry(9, 0, 0),
                ),
            ],
            sample_args(),
        )

        self.assertTrue(report["dynetRetry"]["enabled"])
        self.assertEqual(report["dynetRetry"]["attempts"], 31)
        self.assertEqual(report["dynetRetry"]["attemptClassified"], 31)
        self.assertEqual(report["dynetRetry"]["finalClassified"], 30)
        self.assertEqual(report["dynetRetry"]["rowsWithMultipleAttempts"], 6)
        self.assertEqual(report["dynetRetry"]["firstAttemptDirectTlsEof"], 6)
        self.assertEqual(report["dynetRetry"]["finalDirectTlsEof"], 1)
        self.assertEqual(report["dynetRetry"]["recoveredAfterRetry"], 5)
        self.assertEqual(report["dynetRetry"]["unresolvedDirectTlsEof"], 1)
        self.assertEqual(
            report["dynetRetry"]["attemptClassifications"],
            [
                {"key": "direct-tls-eof-after-path-complete", "count": 6},
                {"key": "not-dynet-failure", "count": 25},
            ],
        )
        self.assertEqual(
            report["dynetRetry"]["finalClassifications"],
            [
                {"key": "direct-tls-eof-after-path-complete", "count": 1},
                {"key": "not-dynet-failure", "count": 29},
            ],
        )

    def test_scope_ignores_attribution(self) -> None:
        args = sample_args(
            objective="parity",
            clean_scope="product-effect",
            min_windows=1,
            min_window_win_rate=1.0,
        )
        report = batch.build_from_reports(
            [
                comparison(
                    8,
                    8,
                    status="dynet-parity-candidate",
                    limit_details=[
                        {
                            "scope": "attribution",
                            "category": "controller",
                            "message": "some Clash probes lack controller selected-chain observations",
                        }
                    ],
                )
            ],
            args,
        )

        self.assertEqual(
            report["verdict"]["status"],
            "dynet-parity-window-candidate",
        )
        self.assertEqual(report["totals"]["cleanWindows"], 1)
        self.assertEqual(report["limitCategories"], [])
        self.assertEqual(
            report["windows"][0]["allLimitCategories"],
            ["controller"],
        )

    def test_scope_blocks_product(self) -> None:
        args = sample_args(
            objective="parity",
            clean_scope="product-effect",
            min_windows=1,
            min_window_win_rate=1.0,
        )
        report = batch.build_from_reports(
            [
                comparison(
                    8,
                    8,
                    status="dynet-parity-candidate",
                    limit_details=[
                        {
                            "scope": "product-effect",
                            "category": "scheduler",
                            "message": "paired replay pair gap exceeded configured budget",
                        }
                    ],
                )
            ],
            args,
        )

        self.assertEqual(report["verdict"]["status"], "limited-evidence")
        self.assertIn("clean-window-rate", report["verdict"]["failedGates"])
        self.assertEqual(report["limitCategories"], [{"key": "scheduler", "count": 1}])


def sample_args(
    *,
    require_runtime_gate: bool = False,
    objective: str = "superior",
    clean_scope: str = "all",
    min_windows: int = 3,
    min_window_win_rate: float = 0.67,
) -> argparse.Namespace:
    return argparse.Namespace(
        primary_bucket="github-proof",
        guardrail_bucket=["control-global", "work-direct"],
        min_windows=min_windows,
        min_window_win_rate=min_window_win_rate,
        min_clean_window_rate=1.0,
        min_aggregate_primary_delta=0.05,
        min_aggregate_parity_delta=0.0,
        min_guardrail_rate=0.99,
        require_runtime_gate=require_runtime_gate,
        objective=objective,
        clean_scope=clean_scope,
    )


def comparison(
    clash_github_success: int,
    dynet_github_success: int,
    *,
    status: str,
    limits: list[str] | None = None,
    limit_details: list[dict[str, str]] | None = None,
    dynet_control: int = 5,
    runtime_clean: bool | None = None,
    dynet_retry: dict[str, object] | None = None,
) -> dict[str, object]:
    github = bucket("github-proof", clash_github_success, 10, dynet_github_success, 10)
    control = bucket("control-global", 5, 5, dynet_control, 5)
    work = bucket("work-direct", 5, 5, 5, 5)
    by_bucket = [github, control, work]
    clash_success = clash_github_success + 10
    dynet_success = dynet_github_success + dynet_control + 5
    total_count = 20
    primary_delta = github["successRateDelta"]
    report_limits = limits
    if report_limits is None and limit_details is not None:
        report_limits = [item["message"] for item in limit_details]
    report = {
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
        "limits": report_limits or [],
    }
    if limit_details is not None:
        report["limitDetails"] = limit_details
    if runtime_clean is not None:
        report["dynetRuntimeGate"] = runtime_gate(runtime_clean)
    if dynet_retry is not None:
        report["dynetRetry"] = dynet_retry
    return report


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


def runtime_gate(clean: bool) -> dict[str, object]:
    failed = [] if clean else ["workload-all-success"]
    return {
        "present": True,
        "clean": clean,
        "classification": "runtime-workload-clean" if clean else "target-or-probe-suspect",
        "failedChecks": failed,
        "totals": {
            "workloadAttempted": 18,
            "workloadSuccess": 18 if clean else 17,
            "workloadFailure": 0 if clean else 1,
            "tcpAttemptedEntries": 18,
            "tcpAttemptedCoveredEntries": 18,
            "unmatchedEntries": 0,
            "runtimePacketTerminalEntries": 0,
            "tcpFlowFailed": 0,
            "tcpSlotPressureEvents": 0,
        },
        "surfaces": {} if clean else {
            "workloadFailedBySurface": [
                {"key": "https-head:tls-handshake:timeout", "count": 1}
            ]
        },
    }


def quality_route_runtime_gate() -> dict[str, object]:
    return {
        "present": True,
        "clean": True,
        "classification": "runtime-route-plan-quality-clean",
        "failedChecks": [],
        "totals": {
            "workloadAttempted": 8,
            "workloadSuccess": 8,
            "workloadFailure": 0,
            "tcpAttemptedEntries": 8,
            "tcpAttemptedCoveredEntries": 8,
            "unmatchedEntries": 0,
            "runtimePacketTerminalEntries": 0,
            "tcpFlowFailed": 0,
            "tcpSlotPressureEvents": 0,
            "qualityStateUsed": True,
            "qualityBoundCandidateSets": 8,
            "qualityBoundSelectedWithQuality": 8,
            "qualityBoundSelectedBehind": 0,
            "tcpFlowRouteMatched": 8,
            "tcpFlowRouteGraphSelected": 8,
            "tcpFlowRuleMatched": 0,
            "tcpFlowPlanBypassed": 0,
        },
        "surfaces": {},
    }


def retry(
    attempts: int,
    recovered: int,
    unresolved: int,
) -> dict[str, object]:
    first_eof = recovered + unresolved
    return {
        "enabled": True,
        "rows": 10,
        "attempts": attempts,
        "rowsWithMultipleAttempts": first_eof,
        "firstAttemptDirectTlsEof": first_eof,
        "finalDirectTlsEof": unresolved,
        "recoveredAfterRetry": recovered,
        "unresolvedDirectTlsEof": unresolved,
        "attemptClassifications": [
            {"key": "direct-tls-eof-after-path-complete", "count": first_eof},
            {"key": "not-dynet-failure", "count": attempts - first_eof},
        ],
        "finalClassifications": [
            {"key": "direct-tls-eof-after-path-complete", "count": unresolved},
            {"key": "not-dynet-failure", "count": 10 - unresolved},
        ],
    }


if __name__ == "__main__":
    unittest.main()
