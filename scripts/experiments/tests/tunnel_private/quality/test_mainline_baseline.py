from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from dynet_mainline import baseline as mainline_baseline
from dynet_mainline.runtime_surface.tcp import hardening as runtime_hardening
from tests.tunnel_private.quality.support.mainline_baseline import (
    paired_read_surface,
    runtime_guardrail_without,
    write_json,
)
from tests.tunnel_private.quality.support.mainline_helpers import (
    HandlerMap,
    baseline_paths,
    clean_sections,
    parser_args,
    parser_expected,
    status_clean_sections,
)


class MainlineBaselineTest(unittest.TestCase):
    def test_clean_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            summary = mainline_baseline.mainline_baseline_summary(
                **baseline_paths(Path(temp_dir)),
            )

        self.assertEqual(summary["status"], "mainline-baseline-current-clean")
        self.assertEqual(
            summary["recommendedUse"],
            "use-as-mainline-baseline-for-next-runtime-slice",
        )
        self.assertFalse(summary["plannerPenaltySafe"])
        self.assertFalse(summary["qualityPenaltySafe"])
        for section in clean_sections():
            self.assertTrue(summary[section]["clean"], section)
        self.assertEqual(summary["runtimeFallback"]["modes"], ["direct", "non-direct"])
        self.assertEqual(summary["runtimeDnsProduct"]["adapterTypes"], ["trojan"])
        self.assertEqual(summary["runtimeRoundGap"]["statuses"], ["mixed-with-clean-controls"])
        self.assertEqual(summary["runtimeRoundGap"]["rawDetailKeys"], [])
        self.assertEqual(summary["runtimeCascadeStop"]["statuses"], ["cascade-stop-shape-clean"])
        self.assertEqual(summary["runtimeCascadeStop"]["rawDetailKeys"], [])
        self.assertEqual(summary["runtimeStagePressure"]["statuses"], ["stage-pressure-profile-clean"])
        self.assertEqual(summary["runtimeStagePressure"]["stageSurfaces"], ["trojan-tls-handshake:trojan"])
        self.assertEqual(
            summary["runtimeRoundGapCompare"]["statuses"],
            ["schedule-lag-separated-outbound-stage-remains"],
        )
        self.assertEqual(summary["runtimeRoundGapCompare"]["rawDetailKeys"], [])
        self.assertEqual(summary["runtimeQualityPlan"]["adapterTypes"], ["trojan"])
        self.assertEqual(summary["runtimeRouteRefresh"]["classifications"], ["unchanged"])
        self.assertEqual(summary["runtimeSelectionRefresh"]["classifications"], ["unchanged"])
        self.assertEqual(summary["runtimeWorkloadFlow"]["classifications"], ["runtime-workload-clean"])
        self.assertEqual(summary["runtimeQualityWorkload"]["adapterTypes"], ["trojan"])
        self.assertEqual(summary["runtimeWorkloadSurface"]["statuses"], ["clean"])
        self.assertEqual(summary["runtimeCloseSurface"]["statuses"], ["clean"])
        self.assertEqual(summary["runtimePayloadSurface"]["statuses"], ["clean"])
        self.assertEqual(summary["runtimeStageSurface"]["statuses"], ["clean"])
        self.assertEqual(summary["runtimeTimingSurface"]["statuses"], ["clean"])
        for section in status_clean_sections():
            self.assertEqual(summary[section]["statuses"], ["clean"])
        self.assertEqual(summary["runtimeFlowRefresh"]["classifications"], ["unchanged"])
        self.assertEqual(summary["runtimeDnsRefresh"]["classifications"], ["unchanged"])
        self.assertEqual(summary["runtimeCascadeRefresh"]["classifications"], ["unchanged"])
        self.assertEqual(summary["runtimeTargetIdentity"]["classifications"], ["unchanged"])
        self.assertEqual(
            summary["qualityFeedbackBoundary"]["categories"],
            [
                "auto-no-proof-observe-only",
                "auto-runtime-proof",
                "observe-repeated-gap",
                "penalize-repeated-gap",
            ],
        )
        self.assertEqual(summary["planQualityStateBridge"]["adapterTypes"], ["trojan", "vmess"])
        self.assertEqual(summary["planQualityStateBridge"]["feedbackModes"], ["observe", "penalize"])
        self.assertTrue(summary["pairedReadSurface"]["clean"])
        self.assertTrue(summary["recommendations"]["clean"])
        self.assertEqual(summary["runtimePressure"]["stageUnrecoveredFailures"], 0)
        self.assertEqual(
            summary["runtimePressure"]["pressureShapes"],
            ["separated-handshake-wait-and-slot-admission-pressure"],
        )
        self.assertEqual(summary["runtimePressure"]["slowFailedStageEvents"], 5)
        self.assertEqual(summary["runtimePressure"]["runsWithStageAndSlotPressure"], 0)
        self.assertEqual(summary["runtimePressure"]["runsAtPortSlotLimit"], 1)
        self.assertEqual(summary["pairedReadSurface"]["excludedReadFailureCount"], 3)
        self.assertTrue(all(gate["passed"] for gate in summary["gates"]))

    def test_hardening_ready(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            summary = hardening_summary(Path(temp_dir))

        self.assertEqual(summary["status"], "runtime-hardening-handoff-ready")
        self.assertEqual(summary["target"]["action"], "harden-trojan-tls-handshake-pending-timeout-path")
        self.assertEqual(summary["target"]["adapterType"], "trojan")
        self.assertEqual(summary["target"]["replayScope"], "pre-payload")
        self.assertEqual(summary["target"]["pendingWaitClasses"], ["socket-read-timeout"])
        self.assertTrue(summary["target"]["waitClassFocused"])
        self.assertEqual(summary["evidence"]["pendingWaitClasses"], ["socket-read-timeout"])
        self.assertEqual(summary["evidence"]["failureStagePendingWaitClasses"], ["socket-read-timeout"])
        self.assertEqual(summary["evidence"]["rawDetailKeys"], [])
        self.assertFalse(summary["conclusion"]["policyChangeSafe"])
        self.assertTrue(all(gate["passed"] for gate in summary["gates"]))

    def test_hardening_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            summary = hardening_summary(
                Path(temp_dir),
                stage_pressure_failed=True,
            )

        self.assertEqual(summary["status"], "runtime-hardening-handoff-needs-evidence")
        self.assertIn("stage-pressure-focused", summary["conclusion"]["notReadyReasons"])
        self.assertIn("mainline-baseline-clean", summary["conclusion"]["notReadyReasons"])

    def test_read_surface_blocks(self) -> None:
        read = paired_read_surface()
        read["actionableConclusion"]["readFailureCount"] = 1
        with tempfile.TemporaryDirectory() as temp_dir:
            summary = mainline_baseline.mainline_baseline_summary(
                **baseline_paths(Path(temp_dir), read_surface_data=read),
            )

        self.assertEqual(summary["status"], "mainline-baseline-needs-evidence")
        self.assertEqual(
            summary["conclusion"]["notReadyReasons"],
            ["paired-read-surface-actionable-clean"],
        )
        self.assertFalse(summary["pairedReadSurface"]["clean"])
        self.assertFalse(
            next(
                gate
                for gate in summary["gates"]
                if gate["id"] == "paired-read-surface-actionable-clean"
            )["passed"]
        )

    def test_fallback_coverage_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            summary = mainline_baseline.mainline_baseline_summary(
                **baseline_paths(Path(temp_dir), fallback_shape="direct-only"),
            )

        self.assertEqual(summary["status"], "mainline-baseline-needs-evidence")
        self.assertIn("runtime-fallback-mode-coverage", summary["conclusion"]["notReadyReasons"])

    def test_repeat_fallback_clean(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            summary = mainline_baseline.mainline_baseline_summary(
                **baseline_paths(Path(temp_dir), fallback_shape="repeat-non-direct"),
            )

        self.assertEqual(summary["status"], "mainline-baseline-current-clean")
        self.assertTrue(summary["runtimeFallback"]["clean"])
        self.assertEqual(summary["runtimeFallback"]["modes"], ["direct", "non-direct"])
        self.assertEqual(summary["runtimeFallback"]["workloadAttempted"], 9)
        self.assertEqual(summary["runtimeFallback"]["routeFallbackUsed"], 13)
        self.assertEqual(summary["runtimeFallback"]["stageFailedFlows"], 13)

    def test_guardrail_blocks(self) -> None:
        guardrail_data = runtime_guardrail_without("cascade-no-second-attempt")
        with tempfile.TemporaryDirectory() as temp_dir:
            summary = mainline_baseline.mainline_baseline_summary(
                **baseline_paths(Path(temp_dir), guardrail_data=guardrail_data),
            )

        self.assertEqual(summary["status"], "mainline-baseline-needs-evidence")
        self.assertFalse(summary["runtimeGuardrail"]["clean"])
        self.assertIn("runtime-non-bound-stop-clean", summary["conclusion"]["notReadyReasons"])

    def test_runtime_dns_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            summary = mainline_baseline.mainline_baseline_summary(
                **baseline_paths(Path(temp_dir), dns_mode="udp-diagnostic-override"),
            )

        self.assertEqual(summary["status"], "mainline-baseline-needs-evidence")
        self.assertFalse(summary["runtimeDnsProduct"]["clean"])
        self.assertIn(
            "runtime-dns-product-chain-clean",
            summary["conclusion"]["notReadyReasons"],
        )

    def test_dns_refresh_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            summary = mainline_baseline.mainline_baseline_summary(
                **baseline_paths(Path(temp_dir), dns_refresh_inconsistent=1),
            )

        self.assertEqual(summary["status"], "mainline-baseline-needs-evidence")
        self.assertFalse(summary["runtimeDnsRefresh"]["clean"])
        self.assertIn(
            "runtime-dns-refresh-consistent",
            summary["conclusion"]["notReadyReasons"],
        )

    def test_dns_refresh_failures(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            summary = mainline_baseline.mainline_baseline_summary(
                **baseline_paths(Path(temp_dir), dns_refresh_failed_queries=2),
            )

        self.assertEqual(summary["status"], "mainline-baseline-current-clean")
        self.assertTrue(summary["runtimeDnsRefresh"]["clean"])
        self.assertEqual(summary["runtimeDnsRefresh"]["resolveFailedEvents"], 2)

    def test_quality_plan_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            summary = mainline_baseline.mainline_baseline_summary(
                **baseline_paths(Path(temp_dir), quality_selected_behind=1),
            )

        self.assertEqual(summary["status"], "mainline-baseline-needs-evidence")
        self.assertFalse(summary["runtimeQualityPlan"]["clean"])
        self.assertIn(
            "runtime-quality-plan-clean",
            summary["conclusion"]["notReadyReasons"],
        )

    def test_workload_flow_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            summary = mainline_baseline.mainline_baseline_summary(
                **baseline_paths(Path(temp_dir), workload_unmatched=1),
            )

        self.assertEqual(summary["status"], "mainline-baseline-needs-evidence")
        self.assertFalse(summary["runtimeWorkloadFlow"]["clean"])
        self.assertIn(
            "runtime-workload-flow-clean",
            summary["conclusion"]["notReadyReasons"],
        )
        self.assertIn(
            "runtime-workload-flow-correlation",
            summary["conclusion"]["notReadyReasons"],
        )

    def test_quality_workload_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            summary = mainline_baseline.mainline_baseline_summary(
                **baseline_paths(Path(temp_dir), quality_workload_unmatched=1),
            )

        self.assertEqual(summary["status"], "mainline-baseline-needs-evidence")
        self.assertFalse(summary["runtimeQualityWorkload"]["clean"])
        self.assertIn(
            "runtime-quality-workload-clean",
            summary["conclusion"]["notReadyReasons"],
        )

    def test_workload_surface_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            summary = mainline_baseline.mainline_baseline_summary(
                **baseline_paths(Path(temp_dir), workload_surface_failed_rows=1),
            )

        self.assertEqual(summary["status"], "mainline-baseline-needs-evidence")
        self.assertFalse(summary["runtimeWorkloadSurface"]["clean"])
        self.assertIn(
            "runtime-workload-surface-clean",
            summary["conclusion"]["notReadyReasons"],
        )

    def test_target_identity_gap(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            summary = mainline_baseline.mainline_baseline_summary(
                **baseline_paths(Path(temp_dir), target_identity_missing_adapter=1),
            )

        self.assertEqual(summary["status"], "mainline-baseline-current-clean")
        self.assertTrue(summary["runtimeTargetIdentity"]["clean"])
        self.assertEqual(summary["runtimeTargetIdentity"]["targetChainMissingAdapter"], 1)

    def test_route_direct_refresh(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            summary = mainline_baseline.mainline_baseline_summary(
                **baseline_paths(Path(temp_dir), route_private_connect=7),
            )

        self.assertEqual(summary["status"], "mainline-baseline-current-clean")
        self.assertTrue(summary["runtimeRouteRefresh"]["clean"])
        self.assertEqual(summary["runtimeRouteRefresh"]["routeEntryFlows"], 8)
        self.assertEqual(summary["runtimeRouteRefresh"]["privateConnectFlows"], 7)

    def test_selection_mixed_quality(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            summary = mainline_baseline.mainline_baseline_summary(
                **baseline_paths(
                    Path(temp_dir),
                    selection_selected_with_quality=4,
                    selection_fallback_quality=0,
                    selection_fallback_selected_behind=1,
                ),
            )

        self.assertEqual(summary["status"], "mainline-baseline-current-clean")
        self.assertTrue(summary["runtimeSelectionRefresh"]["clean"])
        self.assertEqual(summary["runtimeSelectionRefresh"]["candidateSets"], 8)
        self.assertEqual(summary["runtimeSelectionRefresh"]["selectedWithQuality"], 4)

    def test_cascade_controlled_refresh(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = baseline_paths(root)
            paths["runtime_cascade_refresh_paths"] = [
                write_json(root / "cascade-controlled.json", controlled_cascade()),
            ]
            summary = mainline_baseline.mainline_baseline_summary(**paths)

        cascade = summary["runtimeCascadeRefresh"]
        self.assertEqual(summary["status"], "mainline-baseline-current-clean")
        self.assertTrue(cascade["clean"])
        self.assertEqual(cascade["stoppedFailures"], 15)
        self.assertEqual(cascade["unaccountedFailedAttempts"], 0)
        self.assertEqual(cascade["unaccountedRetryableFailures"], 0)
        self.assertEqual(cascade["unaccountedStoppedFailures"], 0)

    def test_refresh_blocks(self) -> None:
        cases = [
            ({"flow_refresh_changed_runs": 1}, "runtimeFlowRefresh", "runtime-flow-refresh-unchanged"),
            ({"route_refresh_changed_runs": 1}, "runtimeRouteRefresh", "runtime-route-refresh-unchanged"),
            ({"route_private_connect": 9}, "runtimeRouteRefresh", "runtime-route-refresh-unchanged"),
            ({"selection_refresh_changed_runs": 1}, "runtimeSelectionRefresh", "runtime-selection-refresh-unchanged"),
            ({"selection_selected_behind": 1}, "runtimeSelectionRefresh", "runtime-selection-refresh-unchanged"),
            ({"close_surface_failed_runs": 1}, "runtimeCloseSurface", "runtime-close-surface-clean"),
            ({"payload_surface_failed_runs": 1}, "runtimePayloadSurface", "runtime-payload-surface-clean"),
            ({"event_stream_failed_runs": 1}, "runtimeEventStream", "runtime-event-stream-clean"),
            ({"event_correlation_failed_runs": 1}, "runtimeEventCorrelation", "runtime-event-correlation-clean"),
            ({"event_causality_failed_runs": 1}, "runtimeEventCausality", "runtime-event-causality-clean"),
            ({"failure_attribution_unknown": 1}, "runtimeFailureAttribution", "runtime-failure-attribution-clean"),
            ({"failure_impact_unsafe": 1}, "runtimeFailureImpact", "runtime-failure-impact-clean"),
            ({"stage_surface_unrecovered": 1}, "runtimeStageSurface", "runtime-stage-surface-clean"),
            ({"timing_surface_failed_runs": 1}, "runtimeTimingSurface", "runtime-timing-surface-clean"),
            ({"dns_timing_failed_runs": 1}, "runtimeDnsTiming", "runtime-dns-timing-clean"),
            ({"dns_forward_failed_runs": 1}, "runtimeDnsForward", "runtime-dns-forward-clean"),
            ({"outbound_timing_failed_runs": 1}, "runtimeOutboundTiming", "runtime-outbound-timing-clean"),
            ({"outbound_attempt_failed_runs": 1}, "runtimeOutboundAttempt", "runtime-outbound-attempt-clean"),
            ({"candidate_set_failed_runs": 1}, "runtimeCandidateSet", "runtime-candidate-set-clean"),
            ({"candidate_quality_failed_runs": 1}, "runtimeCandidateQuality", "runtime-candidate-quality-clean"),
            ({"failure_propagation_failed_runs": 1}, "runtimeFailurePropagation", "runtime-failure-propagation-clean"),
            ({"stage_chain_failed_runs": 1}, "runtimeStageChain", "runtime-stage-chain-clean"),
            ({"stage_order_failed_runs": 1}, "runtimeStageOrder", "runtime-stage-order-clean"),
            ({"route_decision_failed_runs": 1}, "runtimeRouteDecision", "runtime-route-decision-clean"),
            ({"outbound_gate_failed_runs": 1}, "runtimeOutboundGate", "runtime-outbound-gate-clean"),
            ({"outbound_retry_failed_runs": 1}, "runtimeOutboundRetry", "runtime-outbound-retry-clean"),
            ({"packet_surface_failed_runs": 1}, "runtimePacketSurface", "runtime-packet-surface-clean"),
            ({"tcp_pressure_failed_runs": 1}, "runtimeTcpPressure", "runtime-tcp-pressure-clean"),
            ({"tcp_target_failed_runs": 1}, "runtimeTcpTarget", "runtime-tcp-target-clean"),
            ({"stage_pressure_failed": True}, "runtimeStagePressure", "runtime-stage-pressure-observe-only"),
            ({"udp_session_failed_runs": 1}, "runtimeUdpSession", "runtime-udp-session-clean"),
            ({"ipv6_denial_failed_runs": 1}, "runtimeIpv6Denial", "runtime-ipv6-denial-clean"),
            ({"takeover_lifecycle_failed_runs": 1}, "runtimeTakeoverLifecycle", "runtime-takeover-lifecycle-clean"),
            ({"retained_artifact_failed_runs": 1}, "runtimeRetainedArtifact", "runtime-retained-artifact-clean"),
            ({"exit_limit_failed_runs": 1}, "runtimeExitLimit", "runtime-exit-limit-clean"),
            ({"collection_stage_failed_runs": 1}, "runtimeCollectionStage", "runtime-collection-stage-clean"),
            ({"cascade_stop_failed": True}, "runtimeCascadeStop", "runtime-cascade-stop-clean"),
            ({"round_gap_raw_key": True}, "runtimeRoundGap", "runtime-round-gap-observe-only"),
            ({"compare_raw_key": True}, "runtimeRoundGapCompare", "runtime-round-gap-compare-observe-only"),
            ({"cascade_refresh_changed_runs": 1}, "runtimeCascadeRefresh", "runtime-cascade-refresh-unchanged"),
            ({"target_identity_mismatched": 1}, "runtimeTargetIdentity", "runtime-target-identity-clean"),
        ]
        for kwargs, section, gate_id in cases:
            with tempfile.TemporaryDirectory() as temp_dir:
                summary = mainline_baseline.mainline_baseline_summary(
                    **baseline_paths(Path(temp_dir), **kwargs),
                )
            self.assertEqual(summary["status"], "mainline-baseline-needs-evidence")
            self.assertFalse(summary[section]["clean"])
            self.assertIn(gate_id, summary["conclusion"]["notReadyReasons"])

    def test_parser(self) -> None:
        from tunnel_private.cli import build_tunnel_private_parser

        args = build_tunnel_private_parser(HandlerMap()).parse_args(parser_args())
        self.assertEqual(args.command, "mainline-baseline")
        for item in parser_expected():
            key, value = item.split("=", 1)
            self.assertEqual(getattr(args, key), [value])

    def test_quality_feedback_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            summary = mainline_baseline.mainline_baseline_summary(
                **baseline_paths(
                    Path(temp_dir),
                    include_quality_auto_proof=False,
                ),
            )

        self.assertEqual(summary["status"], "mainline-baseline-needs-evidence")
        self.assertTrue(summary["qualityFeedbackBoundary"]["clean"])
        self.assertIn(
            "quality-feedback-auto-runtime-proof",
            summary["conclusion"]["notReadyReasons"],
        )

    def test_plan_bridge_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            summary = mainline_baseline.mainline_baseline_summary(
                **baseline_paths(
                    Path(temp_dir),
                    include_plan_bridge_auto=False,
                ),
            )

        self.assertEqual(summary["status"], "mainline-baseline-needs-evidence")
        self.assertFalse(summary["planQualityStateBridge"]["clean"])
        self.assertIn(
            "plan-quality-state-bridge-clean",
            summary["conclusion"]["notReadyReasons"],
        )
        self.assertIn(
            "plan-quality-state-bridge-feedback-modes",
            summary["conclusion"]["notReadyReasons"],
        )

    def test_transport_blocks(self) -> None:
        cases = [
            ({"ipv6_mode": "udp-diagnostic-override"}, "runtimeIpv6NoLeak", "runtime-ipv6-no-leak-clean"),
            ({"udp_mode": "udp-diagnostic-override"}, "runtimeUdpDirect", "runtime-udp-direct-clean"),
        ]
        for kwargs, section, gate_id in cases:
            with tempfile.TemporaryDirectory() as temp_dir:
                summary = mainline_baseline.mainline_baseline_summary(
                    **baseline_paths(Path(temp_dir), **kwargs),
                )
            self.assertEqual(summary["status"], "mainline-baseline-needs-evidence")
            self.assertFalse(summary[section]["clean"])
            self.assertIn(gate_id, summary["conclusion"]["notReadyReasons"])


def hardening_summary(root: Path, **kwargs: object) -> dict[str, object]:
    paths = baseline_paths(root, **kwargs)
    baseline = write_json(
        root / "baseline.json",
        mainline_baseline.mainline_baseline_summary(**paths),
    )
    coverage = write_json(root / "coverage.json", coverage_fixture())
    return runtime_hardening.runtime_hardening_summary(
        mainline_baseline_paths=[baseline],
        adapter_coverage_paths=[coverage],
        runtime_stage_pressure_paths=paths["runtime_stage_pressure_paths"],
        runtime_cascade_stop_paths=paths["runtime_cascade_stop_paths"],
        runtime_round_gap_paths=paths["runtime_round_gap_paths"],
        round_gap_compare_paths=paths["runtime_round_gap_compare_paths"],
    )


def coverage_fixture() -> dict[str, object]:
    return {
        "schema": "dynet-mainline-adapter-coverage/v1alpha1",
        "status": "adapter-coverage-gaps-open",
        "plannerPenaltySafe": False,
        "qualityPenaltySafe": False,
        "adapters": [
            {"adapterType": "trojan", "coverageLevel": "product-effect-baseline"},
            {"adapterType": "vmess", "coverageLevel": "product-effect-baseline"},
            {"adapterType": "ss", "coverageLevel": "no-provider"},
        ],
        "conclusion": {
            "coverageComplete": False,
            "runtimeWorkUnblocked": True,
            "gaps": [
                {
                    "adapterType": "ss",
                    "gaps": ["provider-acquisition-required"],
                },
            ],
            "plannerPenaltySafe": False,
            "qualityPenaltySafe": False,
        },
    }


def controlled_cascade() -> dict[str, object]:
    return {
        "schema": "dynet-vm-private-runtime-cascade-refresh/v1alpha1",
        "label": "cascade-controlled",
        "totals": {
            "runs": 14,
            "changedRuns": 0,
            "failedAttempts": 21,
            "retryableFailures": 6,
            "stoppedFailures": 15,
            "stoppedBoundExhaustedFlows": 13,
            "stoppedNonBoundFlows": 2,
            "stoppedRetryableFailures": 3,
            "recoveredFlows": 3,
            "stoppedFlowByStopReason": [
                {"key": "bound-candidates-exhausted", "count": 13},
                {"key": "non-bound-failure", "count": 2},
            ],
            "classifications": [{"key": "unchanged", "count": 14}],
        },
    }
