from __future__ import annotations

import argparse
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from dynet_clash.gap import recommendation


class DynetClashGapRecommendationTest(unittest.TestCase):
    def test_observe_direct_tls(self) -> None:
        report = recommendation.build_from_reports(
            gap_report(),
            drilldown_report(),
            sample_args(),
        )

        self.assertEqual(
            report["recommendation"]["status"],
            "observe-direct-tls-target-probe",
        )
        self.assertEqual(report["recommendation"]["plannerFeedback"], "none")
        self.assertEqual(report["recommendation"]["qualityFeedback"], "none")
        self.assertEqual(report["recommendation"]["followUp"]["subcommand"], "gap-retry")
        self.assertTrue(all(gate["passed"] for gate in report["gates"]))

    def test_runtime_gate_blocks(self) -> None:
        gap = gap_report()
        gap["runtimeGate"]["cleanWindows"] = 0
        gap["runtimeGate"]["failedCheckCounts"] = [
            {"key": "workload-flow-covered", "count": 1}
        ]

        report = recommendation.build_from_reports(
            gap,
            drilldown_report(),
            sample_args(),
        )

        self.assertEqual(report["recommendation"]["status"], "needs-runtime-attribution")
        failed = [gate["name"] for gate in report["gates"] if not gate["passed"]]
        self.assertEqual(failed, ["runtime-gate-clean"])

    def test_missing_evidence_blocks(self) -> None:
        drilldown = drilldown_report()
        drilldown["totals"]["rowsWithMissingEvidence"] = 1

        report = recommendation.build_from_reports(
            gap_report(),
            drilldown,
            sample_args(),
        )

        self.assertEqual(report["recommendation"]["status"], "insufficient-evidence")
        failed = [gate["name"] for gate in report["gates"] if not gate["passed"]]
        self.assertEqual(failed, ["retained-evidence-complete"])

    def test_no_cross_side(self) -> None:
        drilldown = drilldown_report()
        drilldown["totals"]["bothFailure"] = 0

        report = recommendation.build_from_reports(
            gap_report(),
            drilldown,
            sample_args(),
        )

        self.assertEqual(report["recommendation"]["status"], "needs-investigation")
        failed = [gate["name"] for gate in report["gates"] if not gate["passed"]]
        self.assertEqual(failed, ["cross-side-volatility-visible"])

    def test_protocol_read_budget(self) -> None:
        report = recommendation.build_from_reports(
            gap_report(),
            protocol_read_drilldown(),
            sample_args(),
        )

        self.assertEqual(
            report["recommendation"]["status"],
            "observe-protocol-read-probe-budget",
        )
        self.assertEqual(
            report["recommendation"]["action"],
            "run-scoped-read-budget-experiment",
        )
        self.assertEqual(report["recommendation"]["plannerFeedback"], "none")
        self.assertEqual(report["recommendation"]["qualityFeedback"], "none")
        self.assertEqual(
            report["recommendation"]["followUp"]["subcommand"],
            "gap-read-budget",
        )
        self.assertIn(
            "probe-read-pending-budget-ms",
            report["recommendation"]["followUp"]["requiredInputs"],
        )
        self.assertEqual(
            report["evidence"]["protocolReadSurfaceCounts"][0]["protocolReadMarker"],
            "vmess-response-header-length-pending",
        )
        self.assertTrue(all(gate["passed"] for gate in report["gates"]))

    def test_protocol_retry_shape(self) -> None:
        gap = gap_report()
        gap["conclusion"]["status"] = "below-parity"
        gap["conclusion"]["aggregatePrimaryDelta"] = -0.125

        report = recommendation.build_from_reports(
            gap,
            protocol_read_drilldown(),
            sample_args(protocol_retry_summary="retry.json"),
            protocol_retry_summary(),
        )

        self.assertEqual(
            report["recommendation"]["status"],
            "observe-protocol-read-paired-shape",
        )
        self.assertEqual(
            report["recommendation"]["action"],
            "isolate-paired-parallel-pressure",
        )
        self.assertEqual(report["recommendation"]["plannerFeedback"], "none")
        self.assertEqual(report["recommendation"]["qualityFeedback"], "none")
        self.assertEqual(
            report["recommendation"]["protocolRetry"]["recovered"],
            2,
        )
        self.assertEqual(
            report["recommendation"]["followUp"]["subcommand"],
            "paired",
        )
        self.assertIn(
            "protocol-retry-same-path-recovered",
            [gate["name"] for gate in report["gates"]],
        )

    def test_pressure_boundary(self) -> None:
        gap = gap_report()
        gap["conclusion"]["status"] = "below-parity"
        gap["conclusion"]["aggregatePrimaryDelta"] = -0.125

        report = recommendation.build_from_reports(
            gap,
            protocol_read_drilldown(),
            sample_args(
                protocol_retry_summary="retry.json",
                paired_read_surface_summary="surface.json",
            ),
            protocol_retry_summary(),
            paired_surface_summary(),
        )

        pressure = report["recommendation"]["pairedPressure"]
        self.assertEqual(pressure["status"], "bracketed-clean-above-failure")
        self.assertEqual(pressure["suggestedNextStaggerMs"], 1031)
        self.assertEqual(
            report["recommendation"]["followUp"]["suggestedInputs"],
            {"side-order": "clash,dynet", "parallel-side-stagger-ms": 1031},
        )
        self.assertEqual(report["evidence"]["pairedPressure"], pressure)

    def test_current_isolated_blocks(self) -> None:
        gap = gap_report()
        gap["conclusion"]["status"] = "below-parity"
        gap["conclusion"]["aggregatePrimaryDelta"] = -0.125

        report = recommendation.build_from_reports(
            gap,
            protocol_read_drilldown(),
            sample_args(
                protocol_retry_summary="retry.json",
                paired_read_surface_summary="surface.json",
                isolated_protocol_followup="isolated.json",
            ),
            protocol_retry_summary(),
            paired_surface_summary(),
            isolated_followup_summary(),
        )

        self.assertEqual(
            report["recommendation"]["status"],
            "observe-protocol-read-current-isolated",
        )
        self.assertEqual(
            report["recommendation"]["action"],
            "refresh-current-quality-and-repeat-isolated",
        )
        self.assertEqual(report["recommendation"]["qualityFeedback"], "observe-only")
        self.assertEqual(report["evidence"]["isolatedCurrent"]["readFailureCount"], 2)

    def test_isolated_refresh_classifies(self) -> None:
        gap = gap_report()
        gap["conclusion"]["status"] = "below-parity"
        gap["conclusion"]["aggregatePrimaryDelta"] = -0.125

        report = recommendation.build_from_reports(
            gap,
            protocol_read_drilldown(),
            sample_args(
                protocol_retry_summary="retry.json",
                paired_read_surface_summary="surface.json",
                isolated_protocol_followup="isolated.json",
                isolated_quality_refresh="quality.json",
            ),
            protocol_retry_summary(),
            paired_surface_summary(),
            isolated_followup_summary(),
            isolated_quality_summary(),
        )

        self.assertEqual(
            report["recommendation"]["status"],
            "observe-protocol-read-current-isolated-repeat",
        )
        self.assertEqual(
            report["recommendation"]["action"],
            "classify-current-isolated-protocol-read-degradation",
        )
        self.assertEqual(
            report["recommendation"]["followUp"]["subcommand"],
            "protocol-followup",
        )
        self.assertTrue(report["evidence"]["isolatedQuality"]["clean"])

    def test_fresh_config_shape(self) -> None:
        gap = gap_report()
        gap["conclusion"]["status"] = "below-parity"
        gap["conclusion"]["aggregatePrimaryDelta"] = -0.125
        surface = paired_surface_summary()
        surface["sources"] = [
            {
                "label": "clash-first-1031ms-saved-config-drift",
                "count": 8,
                "dynetPassed": 0,
                "clashPassed": 8,
                "readFailureCount": 8,
            },
            {
                "label": "clash-first-1000ms-fresh-config",
                "count": 8,
                "dynetPassed": 8,
                "clashPassed": 8,
                "readFailureCount": 0,
            },
        ]

        report = recommendation.build_from_reports(
            gap,
            protocol_read_drilldown(),
            sample_args(
                protocol_retry_summary="retry.json",
                paired_read_surface_summary="surface.json",
                isolated_protocol_followup="isolated.json",
                isolated_quality_refresh="quality.json",
                fresh_config_summary="fresh-summary.json",
                fresh_config_followup="fresh-followup.json",
            ),
            protocol_retry_summary(),
            surface,
            isolated_followup_summary(),
            isolated_quality_summary(),
            fresh_config_summary(),
            fresh_config_followup(),
        )

        self.assertEqual(
            report["recommendation"]["status"],
            "observe-saved-config-drift-repeat-clean",
        )
        self.assertEqual(
            report["recommendation"]["action"],
            "exclude-stale-config-controls-from-pressure-bisection",
        )
        self.assertEqual(report["recommendation"]["qualityFeedback"], "none")
        self.assertTrue(report["evidence"]["freshConfig"]["clean"])
        self.assertTrue(report["recommendation"]["pairedPressure"]["freshConfig"]["clean"])


def gap_report() -> dict[str, object]:
    return {
        "conclusion": {
            "status": "parity-supported-superior-gap",
            "aggregatePrimaryDelta": 0.0339,
            "superiorDeltaGap": 0.0161,
            "additionalNetSuccessesForSuperior": 3,
        },
        "primary": {
            "clash": {"count": 177, "success": 148},
            "dynet": {"count": 177, "success": 154},
        },
        "runtimeGate": {
            "windowCount": 3,
            "presentWindows": 3,
            "cleanWindows": 3,
            "missingWindows": 0,
            "classificationCounts": [{"key": "runtime-workload-clean", "count": 3}],
            "failedCheckCounts": [],
        },
        "outcomeBalance": {},
    }


def drilldown_report() -> dict[str, object]:
    return {
        "totals": {
            "rows": 23,
            "dynetOnlyFailure": 9,
            "bothFailure": 14,
            "rowsWithMissingEvidence": 0,
        },
        "classificationCounts": [
            {"key": "direct-tls-eof-after-path-complete", "count": 23}
        ],
        "surfaceCounts": [],
    }


def protocol_read_drilldown() -> dict[str, object]:
    return {
        "totals": {
            "rows": 2,
            "dynetOnlyFailure": 2,
            "bothFailure": 0,
            "rowsWithMissingEvidence": 0,
        },
        "classificationCounts": [
            {
                "key": "protocol-read-vmess-response-header-length-pending-budget-exhausted",
                "count": 2,
            }
        ],
        "surfaceCounts": [],
        "protocolReadSurfaceCounts": [
            {
                "count": 2,
                "domain": "api.github.com",
                "failureScope": "direct",
                "probe": "https-head",
                "protocolReadDisposition": "pending-budget-exhausted",
                "protocolReadMarker": "vmess-response-header-length-pending",
                "selectedOutbound": "tunnel-001",
            }
        ],
    }


def protocol_retry_summary() -> dict[str, object]:
    return {
        "schema": "dynet-clash-protocol-read-retry-experiment/v1alpha1",
        "policy": {
            "readPolicy": {
                "pollTimeoutMs": 250,
                "pendingBudgetMs": 30000,
                "pendingSleepMs": 10,
            }
        },
        "totals": {
            "rows": 2,
            "recovered": 2,
            "recoveredOnFirstAttempt": 2,
            "recoveredAfterRetry": 0,
            "attempts": 2,
            "unresolvedProtocolRead": 0,
            "selectedOutboundDriftRows": 0,
        },
    }


def paired_surface_summary() -> dict[str, object]:
    return {
        "schema": "dynet-clash-paired-read-surface-batch/v1alpha1",
        "conclusion": {"status": "dynet-later-read-surface-repeat-drift"},
        "pressureBoundary": {
            "scope": "parallel-clash-first-dynet-second",
            "status": "bracketed-clean-above-failure",
            "maxFailingStaggerMs": 1000,
            "minCleanStaggerAboveFailureMs": 1062,
            "boundaryGapMs": 62,
            "failingStaggerMs": [0, 250, 1000],
            "cleanStaggerMs": [1062, 1125, 1250],
            "cleanAboveFailureWindowCount": 3,
        },
    }


def isolated_followup_summary() -> dict[str, object]:
    return {
        "schema": "dynet-tunnel-private-protocol-followup/v1alpha1",
        "sourceCount": 2,
        "conclusion": {
            "status": "current-read-failure",
            "readFailureClassificationClean": True,
        },
        "reportEvidence": {
            "readFailureCount": 2,
            "readFailureUnclassifiedCount": 0,
            "sources": [
                {
                    "readFailure": {
                        "marker": "vmess-response-header-length-pending",
                        "disposition": "pending-budget-exhausted",
                        "context": "shadowsocks-response-salt",
                        "outbound": "private-via-tunnel",
                    }
                },
                {
                    "readFailure": {
                        "marker": "vmess-response-header-length-pending",
                        "disposition": "pending-budget-exhausted",
                        "context": "shadowsocks-response-salt",
                        "outbound": "private-via-tunnel",
                    }
                },
            ],
        },
    }


def isolated_quality_summary() -> dict[str, object]:
    return {
        "schema": "dynet-tunnel-private-quality-refresh-verification/v1alpha1",
        "status": "pass",
        "firstWindow": {"attempted": 3, "failed": 0, "passed": 3},
        "secondWindow": {"attempted": 3, "failed": 0, "passed": 3},
        "qualityState": {
            "dialerBound": [
                {
                    "scope": "dialer-bound",
                    "outbound": "tunnel-002",
                    "successes": 6,
                    "failures": 0,
                }
            ]
        },
        "boundSelection": {
            "windowB": {
                "attempted": 3,
                "selectedWithQuality": 3,
                "selectedBest": 3,
                "bySelected": [{"key": "tunnel-002", "count": 3}],
            }
        },
    }


def fresh_config_summary() -> dict[str, object]:
    return {
        "schema": "dynet-probe-manifest-run/v1alpha1",
        "totals": {"attempted": 8, "passed": 8, "failed": 0},
    }


def fresh_config_followup() -> dict[str, object]:
    return {
        "schema": "dynet-tunnel-private-protocol-followup/v1alpha1",
        "conclusion": {
            "status": "no-followup",
            "currentReadStageFailures": 0,
            "readFailureCount": 0,
        },
        "reportEvidence": {"readFailureCount": 0},
    }


def sample_args(
    protocol_retry_summary: str | None = None,
    paired_read_surface_summary: str | None = None,
    isolated_protocol_followup: str | None = None,
    isolated_quality_refresh: str | None = None,
    fresh_config_summary: str | None = None,
    fresh_config_followup: str | None = None,
) -> argparse.Namespace:
    return argparse.Namespace(
        gap_report="gap.json",
        drilldown="drilldown.json",
        protocol_retry_summary=protocol_retry_summary,
        paired_read_surface_summary=paired_read_surface_summary,
        isolated_protocol_followup=isolated_protocol_followup,
        isolated_quality_refresh=isolated_quality_refresh,
        fresh_config_summary=fresh_config_summary,
        fresh_config_followup=fresh_config_followup,
    )


if __name__ == "__main__":
    unittest.main()
