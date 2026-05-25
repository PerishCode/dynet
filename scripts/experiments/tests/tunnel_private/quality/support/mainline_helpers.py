from __future__ import annotations

from pathlib import Path

from tests.tunnel_private.quality.support.mainline_baseline import (
    noop,
    paired_read_surface,
    product_effect,
    recommendation,
    runtime_fallback,
    runtime_guardrail,
    runtime_pressure,
    write_dns_repeat,
    write_fallback_repeat,
    write_ipv6_repeat,
    write_json,
)
from tests.tunnel_private.quality.support.runtime_surface import (
    write_cascade_refresh,
    write_close_surface,
    write_dns_refresh,
    write_dns_timing,
    write_flow_refresh,
    write_outbound_gate,
    write_outbound_timing,
    write_packet_surface,
    write_payload_surface,
    write_route_refresh,
    write_selection_refresh,
    write_stage_surface,
    write_target_identity_refresh,
    write_timing_surface,
    write_workload_surface,
)
from tests.tunnel_private.quality.support.mainline_surfaces.cascade_stop import write_cascade_stop
from tests.tunnel_private.quality.support.mainline_surfaces.stage_pressure import write_stage_pressure
from tests.tunnel_private.quality.support.runtime_quality_plan import write_quality_plan_repeat
from tests.tunnel_private.quality.support.quality_feedback import write_quality_feedback_sources
from tests.tunnel_private.quality.support.plan_bridge import write_plan_bridges
from tests.tunnel_private.quality.support import runtime_event as rev, runtime_udp as ru
from tests.tunnel_private.quality.support.runtime_workload_flow import write_workload_flow_repeat


def clean_sections() -> list[str]:
    sections = "adapterProductEffect runtimePressure runtimeFallback runtimeDnsProduct runtimeDnsRefresh runtimeDnsForward runtimeQualityPlan runtimeRouteRefresh runtimeSelectionRefresh runtimeWorkloadFlow runtimeQualityWorkload runtimeWorkloadSurface runtimeCloseSurface runtimePayloadSurface runtimeEventStream runtimeEventCorrelation runtimeEventCausality runtimeFailureAttribution runtimeFailureImpact runtimeStageSurface runtimeTimingSurface runtimeDnsTiming runtimeOutboundTiming runtimeOutboundAttempt runtimeCandidateSet runtimeCandidateQuality runtimeFailurePropagation runtimeStageChain runtimeStageOrder runtimeRouteDecision runtimeOutboundGate runtimeOutboundRetry runtimePacketSurface runtimeTcpPressure runtimeTcpTarget runtimeStagePressure runtimeUdpSession runtimeIpv6Denial runtimeTakeoverLifecycle runtimeRetainedArtifact runtimeExitLimit runtimeCollectionStage runtimeCascadeStop runtimeRoundGap runtimeRoundGapCompare runtimeFlowRefresh runtimeCascadeRefresh runtimeTargetIdentity qualityFeedbackBoundary planQualityStateBridge runtimeUdpDirect runtimeIpv6NoLeak runtimeGuardrail"
    return sections.split()


def status_clean_sections() -> list[str]:
    return "runtimeEventStream runtimeEventCorrelation runtimeEventCausality runtimeFailureAttribution runtimeFailureImpact runtimeDnsForward runtimeDnsTiming runtimeOutboundTiming runtimeOutboundAttempt runtimeCandidateSet runtimeCandidateQuality runtimeFailurePropagation runtimeStageChain runtimeStageOrder runtimeRouteDecision runtimeOutboundGate runtimeOutboundRetry runtimePacketSurface runtimeTcpPressure runtimeTcpTarget runtimeUdpSession runtimeIpv6Denial runtimeTakeoverLifecycle runtimeRetainedArtifact runtimeExitLimit runtimeCollectionStage".split()


def parser_args() -> list[str]:
    return """
mainline-baseline --output-dir out --adapter-product-effect product.json --runtime-pressure pressure.json --runtime-fallback fallback.json --runtime-dns-product dns.json --runtime-dns-refresh dns-refresh.json --runtime-dns-forward dns-forward.json --runtime-quality-plan quality-plan.json --runtime-route-refresh route-refresh.json --runtime-selection-refresh selection-refresh.json --runtime-workload-flow workload-flow.json --runtime-quality-workload quality-workload.json --runtime-workload-surface workload-surface.json --runtime-close-surface close-surface.json --runtime-payload-surface payload-surface.json --runtime-event-stream event-stream.json --runtime-event-correlation event-correlation.json --runtime-event-causality event-causality.json --runtime-failure-attribution failure-attribution.json --runtime-failure-impact failure-impact.json --runtime-stage-surface stage-surface.json --runtime-timing-surface timing-surface.json --runtime-dns-timing dns-timing.json --runtime-outbound-timing outbound-timing.json --runtime-outbound-attempt outbound-attempt.json --runtime-candidate-set candidate-set.json --runtime-candidate-quality candidate-quality.json --runtime-failure-propagation failure-propagation.json --runtime-stage-chain stage-chain.json --runtime-stage-order stage-order.json --runtime-route-decision route-decision.json --runtime-flow-refresh flow-refresh.json --runtime-outbound-gate outbound-gate.json --runtime-outbound-retry outbound-retry.json --runtime-packet-surface packet-surface.json --runtime-tcp-pressure tcp-pressure.json --runtime-tcp-target tcp-target.json --runtime-stage-pressure stage-pressure.json --runtime-udp-session udp-session.json --runtime-ipv6-denial ipv6-denial.json --runtime-takeover-lifecycle takeover-lifecycle.json --runtime-retained-artifact retained-artifact.json --runtime-exit-limit exit-limit.json --runtime-collection-stage collection-stage.json --runtime-cascade-stop cascade-stop.json --runtime-round-gap round-gap.json --runtime-round-gap-compare round-gap-compare.json --runtime-cascade-refresh cascade-refresh.json --runtime-target-identity target-identity-refresh.json --quality-feedback feedback.json --plan-quality-bridge plan-quality.json --runtime-udp udp.json --runtime-ipv6 ipv6.json --runtime-guardrail guardrail.json --paired-read-surface surface.json --recommendation recommendation.json
""".split()


def parser_expected() -> list[str]:
    return """
adapter_product_effect=product.json runtime_pressure=pressure.json runtime_fallback=fallback.json runtime_dns_product=dns.json runtime_dns_refresh=dns-refresh.json runtime_dns_forward=dns-forward.json runtime_quality_plan=quality-plan.json runtime_route_refresh=route-refresh.json runtime_selection_refresh=selection-refresh.json runtime_workload_flow=workload-flow.json runtime_quality_workload=quality-workload.json runtime_workload_surface=workload-surface.json runtime_close_surface=close-surface.json runtime_payload_surface=payload-surface.json runtime_event_stream=event-stream.json runtime_event_correlation=event-correlation.json runtime_event_causality=event-causality.json runtime_failure_attribution=failure-attribution.json runtime_failure_impact=failure-impact.json runtime_stage_surface=stage-surface.json runtime_timing_surface=timing-surface.json runtime_dns_timing=dns-timing.json runtime_outbound_timing=outbound-timing.json runtime_outbound_attempt=outbound-attempt.json runtime_candidate_set=candidate-set.json runtime_candidate_quality=candidate-quality.json runtime_failure_propagation=failure-propagation.json runtime_stage_chain=stage-chain.json runtime_stage_order=stage-order.json runtime_route_decision=route-decision.json runtime_flow_refresh=flow-refresh.json runtime_outbound_gate=outbound-gate.json runtime_outbound_retry=outbound-retry.json runtime_packet_surface=packet-surface.json runtime_tcp_pressure=tcp-pressure.json runtime_tcp_target=tcp-target.json runtime_stage_pressure=stage-pressure.json runtime_udp_session=udp-session.json runtime_ipv6_denial=ipv6-denial.json runtime_takeover_lifecycle=takeover-lifecycle.json runtime_retained_artifact=retained-artifact.json runtime_exit_limit=exit-limit.json runtime_collection_stage=collection-stage.json runtime_cascade_stop=cascade-stop.json runtime_round_gap=round-gap.json runtime_round_gap_compare=round-gap-compare.json runtime_cascade_refresh=cascade-refresh.json runtime_target_identity=target-identity-refresh.json quality_feedback=feedback.json plan_quality_bridge=plan-quality.json runtime_udp=udp.json runtime_ipv6=ipv6.json runtime_guardrail=guardrail.json paired_read_surface=surface.json recommendation=recommendation.json
""".split()


class HandlerMap(dict[str, object]):
    def __missing__(self, _: str) -> object:
        return noop


def baseline_paths(
    root: Path,
    *,
    fallback_shape: str = "both",
    dns_mode: str = "config-chain",
    dns_refresh_inconsistent: int = 0,
    dns_refresh_failed_queries: int = 0,
    quality_selected_behind: int = 0,
    route_refresh_changed_runs: int = 0,
    route_private_connect: int = 8,
    selection_refresh_changed_runs: int = 0,
    selection_selected_behind: int = 0,
    selection_selected_with_quality: int = 8,
    selection_fallback_quality: int = 1,
    selection_fallback_selected_behind: int = 1,
    workload_unmatched: int = 0,
    quality_workload_unmatched: int = 0,
    workload_surface_failed_rows: int = 0,
    close_surface_failed_runs: int = 0,
    payload_surface_failed_runs: int = 0,
    event_stream_failed_runs: int = 0,
    event_correlation_failed_runs: int = 0,
    event_causality_failed_runs: int = 0,
    failure_attribution_unknown: int = 0,
    failure_impact_unsafe: int = 0,
    stage_surface_failed_runs: int = 0,
    stage_surface_unrecovered: int = 0,
    timing_surface_failed_runs: int = 0,
    dns_timing_failed_runs: int = 0,
    dns_forward_failed_runs: int = 0,
    outbound_timing_failed_runs: int = 0,
    outbound_attempt_failed_runs: int = 0,
    candidate_set_failed_runs: int = 0,
    candidate_quality_failed_runs: int = 0,
    failure_propagation_failed_runs: int = 0,
    stage_chain_failed_runs: int = 0,
    stage_order_failed_runs: int = 0,
    route_decision_failed_runs: int = 0,
    outbound_gate_failed_runs: int = 0,
    outbound_retry_failed_runs: int = 0,
    packet_surface_failed_runs: int = 0,
    tcp_pressure_failed_runs: int = 0,
    tcp_target_failed_runs: int = 0,
    stage_pressure_failed: bool = False,
    udp_session_failed_runs: int = 0,
    ipv6_denial_failed_runs: int = 0,
    takeover_lifecycle_failed_runs: int = 0,
    retained_artifact_failed_runs: int = 0,
    exit_limit_failed_runs: int = 0,
    collection_stage_failed_runs: int = 0,
    cascade_stop_failed: bool = False,
    round_gap_raw_key: bool = False,
    compare_raw_key: bool = False,
    flow_refresh_changed_runs: int = 0,
    cascade_refresh_changed_runs: int = 0,
    target_identity_mismatched: int = 0,
    target_identity_missing_adapter: int = 0,
    udp_mode: str = "config-chain",
    ipv6_mode: str = "config-chain",
    include_quality_auto_proof: bool = True,
    include_plan_bridge_auto: bool = True,
    guardrail_data: dict[str, object] | None = None,
    read_surface_data: dict[str, object] | None = None,
) -> dict[str, list[Path]]:
    direct = write_json(root / "fallback-direct.json", runtime_fallback("direct"))
    fallback_paths = [direct]
    if fallback_shape == "both":
        fallback_paths.append(
            write_json(root / "fallback-private.json", runtime_fallback("non-direct"))
        )
    if fallback_shape == "repeat-non-direct":
        fallback_paths.append(write_fallback_repeat(root, "non-direct"))
    quality_plan = write_quality_plan_repeat(
        root,
        "trojan",
        selected_behind=quality_selected_behind,
    )
    return {
        "adapter_product_effect_paths": [write_json(root / "product.json", product_effect())],
        "runtime_pressure_paths": [write_json(root / "pressure.json", runtime_pressure())],
        "runtime_fallback_paths": fallback_paths,
        "runtime_dns_product_paths": [write_dns_repeat(root, "trojan", dns_mode)],
        "runtime_dns_refresh_paths": [
            write_dns_refresh(root, dns_refresh_inconsistent, dns_refresh_failed_queries),
        ],
        "runtime_dns_forward_paths": [rev.write_dns_forward_surface(root, dns_forward_failed_runs)],
        "runtime_quality_plan_paths": [quality_plan],
        "runtime_route_refresh_paths": [
            write_route_refresh(
                root,
                route_refresh_changed_runs,
                route_private_connect,
            ),
        ],
        "runtime_selection_refresh_paths": [
            write_selection_refresh(
                root,
                selection_refresh_changed_runs,
                selection_selected_behind,
                selection_selected_with_quality,
                selection_fallback_quality,
                selection_fallback_selected_behind,
            ),
        ],
        "runtime_workload_flow_paths": [write_workload_flow_repeat(root, unmatched=workload_unmatched)],
        "runtime_quality_workload_paths": [ru.write_quality_workload(quality_plan, quality_workload_unmatched)],
        "runtime_workload_surface_paths": [write_workload_surface(root, workload_surface_failed_rows)],
        "runtime_close_surface_paths": [write_close_surface(root, close_surface_failed_runs)],
        "runtime_payload_surface_paths": [write_payload_surface(root, payload_surface_failed_runs)],
        "runtime_event_stream_paths": [rev.write_event_stream_surface(root, event_stream_failed_runs)],
        "runtime_event_correlation_paths": [rev.write_event_correlation_surface(root, event_correlation_failed_runs)],
        "runtime_event_causality_paths": [rev.write_event_causality_surface(root, event_causality_failed_runs)],
        "runtime_failure_attribution_paths": [write_failure_attribution(root, failure_attribution_unknown)],
        "runtime_failure_impact_paths": [write_failure_impact(root, failure_impact_unsafe)],
        "runtime_stage_surface_paths": [write_stage_surface(root, stage_surface_failed_runs, stage_surface_unrecovered)],
        "runtime_timing_surface_paths": [write_timing_surface(root, timing_surface_failed_runs)],
        "runtime_dns_timing_paths": [write_dns_timing(root, dns_timing_failed_runs)],
        "runtime_outbound_timing_paths": [write_outbound_timing(root, outbound_timing_failed_runs)],
        "runtime_outbound_attempt_paths": [rev.write_outbound_attempt_surface(root, outbound_attempt_failed_runs)],
        "runtime_candidate_set_paths": [write_candidate_set(root, candidate_set_failed_runs)],
        "runtime_candidate_quality_paths": [write_candidate_quality(root, candidate_quality_failed_runs)],
        "runtime_failure_propagation_paths": [write_failure_propagation(root, failure_propagation_failed_runs)],
        "runtime_stage_chain_paths": [rev.write_stage_chain_surface(root, stage_chain_failed_runs)],
        "runtime_stage_order_paths": [write_stage_order(root, stage_order_failed_runs)],
        "runtime_route_decision_paths": [rev.write_route_decision_surface(root, route_decision_failed_runs)],
        "runtime_outbound_gate_paths": [write_outbound_gate(root, outbound_gate_failed_runs)],
        "runtime_outbound_retry_paths": [rev.write_outbound_retry_surface(root, outbound_retry_failed_runs)],
        "runtime_packet_surface_paths": [write_packet_surface(root, packet_surface_failed_runs)],
        "runtime_tcp_pressure_paths": [rev.write_tcp_pressure_surface(root, tcp_pressure_failed_runs)],
        "runtime_tcp_target_paths": [write_tcp_target(root, tcp_target_failed_runs)],
        "runtime_stage_pressure_paths": [
            write_stage_pressure(root, stage_pressure_failed),
        ],
        "runtime_udp_session_paths": [ru.write_udp_session_surface(root, udp_session_failed_runs)],
        "runtime_ipv6_denial_paths": [ru.write_ipv6_denial_surface(root, ipv6_denial_failed_runs)],
        "runtime_takeover_lifecycle_paths": [ru.write_takeover_lifecycle_surface(root, takeover_lifecycle_failed_runs)],
        "runtime_retained_artifact_paths": [ru.write_retained_artifact_surface(root, retained_artifact_failed_runs)],
        "runtime_exit_limit_paths": [ru.write_exit_limit_surface(root, exit_limit_failed_runs)],
        "runtime_collection_stage_paths": [ru.write_collection_stage_surface(root, collection_stage_failed_runs)],
        "runtime_cascade_stop_paths": [
            write_cascade_stop(root, cascade_stop_failed),
        ],
        "runtime_round_gap_paths": [write_round_gap(root, round_gap_raw_key)],
        "runtime_round_gap_compare_paths": [
            write_round_gap_compare(root, compare_raw_key),
        ],
        "runtime_flow_refresh_paths": [write_flow_refresh(root, flow_refresh_changed_runs)],
        "runtime_cascade_refresh_paths": [write_cascade_refresh(root, cascade_refresh_changed_runs)],
        "runtime_target_identity_paths": [
            write_target_identity_refresh(
                root,
                target_identity_mismatched,
                target_identity_missing_adapter,
            ),
        ],
        "quality_feedback_paths": write_quality_feedback_sources(root, include_auto_proof=include_quality_auto_proof),
        "plan_quality_bridge_paths": write_plan_bridges(root, include_auto=include_plan_bridge_auto),
        "runtime_udp_paths": [ru.write_udp_repeat(root, runtime_dns_mode=udp_mode)],
        "runtime_ipv6_paths": [write_ipv6_repeat(root, runtime_dns_mode=ipv6_mode)],
        "runtime_guardrail_paths": [write_json(root / "guardrail.json", guardrail_data or runtime_guardrail())],
        "paired_read_surface_paths": [write_json(root / "read-surface.json", read_surface_data or paired_read_surface())],
        "recommendation_paths": [write_json(root / "recommendation.json", recommendation())],
    }


def write_failure_attribution(root: Path, unknown: int = 0) -> Path:
    clean = not unknown
    return write_json(root / "failure-attribution.json", {
        "schema": "dynet-vm-private-runtime-failure-attribution-surface/v1alpha1",
        "label": "failure-attribution",
        "conclusion": {"status": "clean" if clean else "failure-attribution-needs-evidence"},
        "totals": {
            "runs": 2, "cleanRuns": 2 - unknown, "failedRuns": unknown,
            "classifications": [{"key": "clean" if clean else "unknown-failure-attribution", "count": 2}],
            "eventReports": 2, "runtimePass": 2, "events": 120,
            "failureSignals": 6, "classifiedSignals": 6 - unknown,
            "unknownSignals": unknown, "missingEvidenceSignals": 0,
            "stageFailures": 2, "attemptFailures": 2, "cascadeFailures": 2,
            "dnsFailures": 0, "ipDenials": 0, "tcpFailures": 0, "udpFailures": 0,
            "nodeSuspect": 6 - unknown, "dynetInfraSuspect": 0, "planSuspect": 0,
            "targetOrProbeSuspect": 0, "experimentShapeSuspect": 0, "unknown": unknown,
            "categories": [{"key": "node-suspect", "count": 6 - unknown}],
            "surfaces": [{"key": "stage", "count": 2}, {"key": "attempt", "count": 2}, {"key": "cascade", "count": 2}],
            "profiles": [{"key": "stage:trojan:trojan-tls-handshake:pending-timeout", "count": 2}],
            "missingEvidence": [],
        },
    })


def write_round_gap(root: Path, raw_key: bool = False) -> Path:
    summary = {
        "schema": "dynet-vm-private-runtime-round-gap-batch/v1alpha1",
        "label": "round-gap",
        "totals": {
            "runs": 2, "cleanRuns": 1, "failedRuns": 1,
            "classifications": [{"key": "clean", "count": 1}, {"key": "outbound-stage-pressure", "count": 1}],
            "failedWorkloadMechanisms": [{"key": "failed-workload-with-runtime-stage-failure", "count": 1}],
            "recoveredFlowMechanisms": [{"key": "recovered-runtime-stage-failure-before-success", "count": 2}],
            "pendingWaitClasses": [{"key": "socket-read-timeout", "count": 1}],
            "cascadeFailedAttempts": 3, "cascadeRetryableFailures": 2,
            "cascadeStoppedFailures": 1, "cascadeRecoveredFlows": 2,
            "cascadeStoppedBoundExhaustedFlows": 1,
        },
        "conclusion": {"status": "mixed-with-clean-controls", "nextAction": "compare-mechanism-deltas-with-clean-controls"},
        "policy": {"plannerPenaltySafe": False, "qualityPenaltySafe": False},
    }
    if raw_key:
        summary["runs"] = [{"flowId": "tcp-session-1"}]
    return write_json(root / "round-gap.json", summary)


def write_round_gap_compare(root: Path, raw_key: bool = False) -> Path:
    summary = {
        "schema": "dynet-vm-private-runtime-round-gap-compare/v1alpha1",
        "label": "round-gap-compare",
        "inputs": {"baseline": "baseline.json", "candidate": "candidate.json"},
        "baseline": {
            "label": "baseline",
            "status": "stage-pressure-with-schedule-lag",
            "nextAction": "compare-mechanism-deltas-with-clean-controls",
            "runs": 2,
            "workloadAttempted": 8,
            "workloadSuccess": 7,
            "workloadFailure": 1,
        },
        "candidate": {
            "label": "candidate",
            "status": "outbound-stage-pressure",
            "nextAction": "compare-mechanism-deltas-with-clean-controls",
            "runs": 2,
            "workloadAttempted": 8,
            "workloadSuccess": 7,
            "workloadFailure": 1,
        },
        "deltas": {"scheduleLagMaxMs": {"baseline": 8000, "candidate": 0, "delta": -8000}},
        "conclusion": {
            "status": "schedule-lag-separated-outbound-stage-remains",
            "nextAction": "harden-outbound-stage-failure-path",
            "reason": "compare fixture",
            "improvements": [{"key": "scheduleLagMaxMs", "delta": -8000}],
            "remainingMechanisms": [{"key": "runtime-stage-failure", "count": 1}],
            "plannerPenaltySafe": False,
            "qualityPenaltySafe": False,
        },
        "policy": {"plannerPenaltySafe": False, "qualityPenaltySafe": False},
    }
    if raw_key:
        summary["candidate"]["flowId"] = "tcp-session-1"
    return write_json(root / "round-gap-compare.json", summary)


def write_failure_impact(root: Path, unsafe: int = 0) -> Path:
    clean = not unsafe
    return write_json(root / "failure-impact.json", {
        "schema": "dynet-vm-private-runtime-failure-impact-surface/v1alpha1",
        "label": "failure-impact",
        "conclusion": {"status": "clean" if clean else "failure-impact-needs-evidence"},
        "totals": {
            "runs": 2, "cleanRuns": 2 - unsafe, "failedRuns": unsafe,
            "classifications": [{"key": "clean" if clean else "unsafe-penalty-impact", "count": 2}],
            "eventReports": 2, "runtimePass": 2, "events": 120,
            "failureSignals": 6, "classifiedSignals": 6,
            "unknownSignals": 0, "missingEvidenceSignals": 0,
            "recoveredSignals": 4 - unsafe, "controlledSignals": 2,
            "unboundedSignals": unsafe, "nodeSuspectSignals": 4,
            "recoveredNodeSuspectSignals": 4 - unsafe,
            "maskedNodeSuspectSignals": 0,
            "unboundedNodeSuspectSignals": unsafe,
            "experimentShapeSignals": 2, "unboundedExperimentShapeSignals": 0,
            "targetOrProbeSignals": 0, "dynetInfraSignals": 0,
            "planSuspectSignals": 0, "unsafePenaltySignals": unsafe,
            "terminalFailureSignals": 0,
            "categories": [{"key": "node-suspect", "count": 4}, {"key": "experiment-shape-suspect", "count": 2}],
            "surfaces": [{"key": "stage", "count": 2}, {"key": "attempt", "count": 2}, {"key": "cascade", "count": 2}],
            "impacts": [{"key": "recovered", "count": 4 - unsafe}, {"key": "controlled-experiment", "count": 2}],
            "missingEvidence": [],
        },
    })


def write_candidate_set(root: Path, failed_runs: int = 0) -> Path:
    clean = not failed_runs
    return write_json(root / "candidate-set.json", {
        "schema": "dynet-vm-private-runtime-outbound-candidate-set-surface/v1alpha1",
        "label": "candidate-set",
        "conclusion": {"status": "clean" if clean else "candidate-set-surface-needs-evidence"},
        "totals": {
            "runs": 2, "cleanRuns": 2 - failed_runs, "failedRuns": failed_runs,
            "classifications": [{"key": "clean" if clean else "candidate-graph-missing", "count": 2}],
            "eventReports": 2, "runtimePass": 2, "events": 120,
            "candidateSets": 8, "tcpRouteCandidateSets": 2, "dialerBoundCandidateSets": 6,
            "missingScope": 0, "missingSelected": 0, "missingCandidateCount": 0,
            "candidateCountMismatches": 0, "selectedMissingFromList": 0,
            "selectedMissingFromJson": 0, "jsonCandidateCountMismatches": 0,
            "missingStrategyFields": 0, "missingPlan": 0, "missingGraph": failed_runs,
            "missingEgress": 0, "routeCandidateMissingRoute": 0,
            "dialerCandidateMissingCascadeSelected": 0,
            "dialerCandidateMissingCascadeAttempt": 0,
            "jsonParseFailures": 0, "candidatesWithQuality": 8,
            "selectedWithQuality": 8,
            "scopes": [{"key": "tcp-route", "count": 2}, {"key": "dialer-bound", "count": 6}],
            "candidateCounts": [{"key": "2", "count": 8}],
            "candidateTypes": [{"key": "trojan", "count": 8}],
            "strategyKeys": [{"key": "cascade-quality", "count": 8}],
            "selectors": [{"key": "CascadeQuality", "count": 8}],
        },
    })


def write_candidate_quality(root: Path, failed_runs: int = 0) -> Path:
    clean = not failed_runs
    return write_json(root / "candidate-quality.json", {
        "schema": "dynet-vm-private-runtime-outbound-candidate-quality-surface/v1alpha1",
        "label": "candidate-quality",
        "conclusion": {"status": "clean" if clean else "candidate-quality-needs-evidence"},
        "totals": {
            "runs": 2, "cleanRuns": 2 - failed_runs, "failedRuns": failed_runs,
            "classifications": [{"key": "clean" if clean else "primary-selected-behind", "count": 2}],
            "eventReports": 2, "runtimePass": 2, "events": 120,
            "candidateSets": 8, "qualityCandidateSets": 6, "staticCandidateSets": 2,
            "candidateRows": 12, "qualityRows": 12, "candidatesWithQuality": 12,
            "selectedWithQuality": 6, "selectedBest": 6 - failed_runs,
            "selectedBehind": failed_runs, "primaryQualityCandidateSets": 6,
            "primarySelectedBest": 6 - failed_runs, "primarySelectedBehind": failed_runs,
            "fallbackQualityCandidateSets": 0, "fallbackSelectedBest": 0,
            "fallbackSelectedBehind": 0, "recoveredSelectedBehind": 0,
            "unrecoveredSelectedBehind": failed_runs, "jsonParseFailures": 0,
            "missingQuality": 0, "missingScore": 0, "missingReason": 0,
            "staleQuality": 0, "missingMatchScope": 0, "selectedMissingQuality": 0,
            "qualityReasons": [{"key": "exact-and-overall-quality", "count": 12}],
            "qualityVerdicts": [{"key": "healthy", "count": 12}],
            "qualityConfidences": [{"key": "low", "count": 12}],
            "qualityMatchScopes": [{"key": "dialer-bound", "count": 12}],
            "candidateTypes": [{"key": "trojan", "count": 12}],
        },
    })


def write_failure_propagation(root: Path, failed_runs: int = 0) -> Path:
    clean = not failed_runs
    return write_json(root / "failure-propagation.json", {
        "schema": "dynet-vm-private-runtime-outbound-failure-propagation-surface/v1alpha1",
        "label": "failure-propagation",
        "conclusion": {"status": "clean" if clean else "failure-propagation-needs-evidence"},
        "totals": {
            "runs": 2, "cleanRuns": 2 - failed_runs, "failedRuns": failed_runs,
            "classifications": [{"key": "clean" if clean else "cascade-error-mismatch", "count": 2}],
            "eventReports": 2, "runtimePass": 2, "events": 120,
            "failedStages": 4, "failedAttempts": 4, "failedCascades": 4,
            "failedAttemptsWithStage": 4, "failedCascadesWithEvidence": 4 - failed_runs,
            "failedAttemptMissingStage": 0, "failedCascadeMissingEvidence": 0,
            "failedStageErrorTypeMissing": 0, "failedStageDispositionMissing": 0,
            "failedAttemptErrorTypeMissing": 0, "failedAttemptDispositionMissing": 0,
            "failedCascadeErrorTypeMissing": 0, "failedCascadeDispositionMissing": 0,
            "stageAttemptErrorTypeMismatches": 0, "stageAttemptDispositionMismatches": 0,
            "cascadeErrorTypeMismatches": failed_runs, "cascadeDispositionMismatches": 0,
            "cascadeFailureScopeMissing": 0, "cascadeRetryAllowedMissing": 0,
            "cascadeRetryStopReasonMissing": 0,
            "stageFailureProfiles": [{"key": "stage:tcp-connect:refused:connection-refused:none", "count": 4}],
            "attemptFailureProfiles": [{"key": "attempt:tcp-connect:refused:connection-refused:none", "count": 4}],
            "cascadeFailureProfiles": [{"key": "cascade:unknown:refused:connection-refused:bound", "count": 4}],
        },
    })


def write_tcp_target(root: Path, failed_runs: int = 0) -> Path:
    clean = not failed_runs
    return write_json(root / "tcp-target.json", {
        "schema": "dynet-vm-private-runtime-tcp-target-surface/v1alpha1",
        "label": "tcp-target",
        "conclusion": {"status": "clean" if clean else "tcp-target-surface-needs-evidence"},
        "totals": {
            "runs": 2, "cleanRuns": 2 - failed_runs, "failedRuns": failed_runs,
            "classifications": [{"key": "clean" if clean else "adapter-target-mismatch", "count": 2}],
            "eventReports": 2, "runtimePass": 2, "events": 120,
            "connectingEvents": 8, "directConnectEvents": 1,
            "dialerConnectEvents": 7, "unknownKindConnectEvents": 0,
            "withConnectTarget": 8, "withIdentityDomain": 8,
            "withTargetAddressSource": 8, "domainConnectTargets": 7,
            "socketConnectTargets": 1, "adapterConnectEvents": 7,
            "adapterMatchedConnects": 7 - failed_runs,
            "socketPreservedDirectConnects": 1,
            "controlledMissingAdapterConnects": 0,
            "uncontrolledMissingAdapterConnects": 0,
            "adapterMismatchedConnects": failed_runs,
            "adapterDuplicateFlows": 0, "directMissingSocketPreserved": 0,
            "dialerMissingDnsReverse": 0, "coveredConnects": 8 - failed_runs,
            "connectSourceProfiles": [{"key": "dialer:dns-reverse-rule-domain:domain", "count": 7}],
            "adapterStageProfiles": [{"key": "trojan:private-trojan-connect:success", "count": 7}],
            "missingAdapterProfiles": [],
        },
    })


def write_stage_order(root: Path, failed_runs: int = 0) -> Path:
    clean = not failed_runs
    return write_json(root / "stage-order.json", {
        "schema": "dynet-vm-private-runtime-outbound-stage-order-surface/v1alpha1",
        "label": "stage-order",
        "conclusion": {"status": "clean" if clean else "stage-order-surface-needs-evidence"},
        "totals": {
            "runs": 2, "cleanRuns": 2 - failed_runs, "failedRuns": failed_runs,
            "classifications": [{"key": "clean" if clean else "stage-order-violation", "count": 2}],
            "eventReports": 2, "runtimePass": 2, "events": 120,
            "attempts": 8, "knownProfileAttempts": 8,
            "unknownProfileAttempts": 0, "successfulAttempts": 8,
            "failedAttempts": 0, "stageEvents": 16,
            "orderedAttempts": 8 - failed_runs, "attemptStageMissing": 0,
            "unexpectedStageEvents": 0, "duplicateStageEvents": 0,
            "stageOrderViolations": failed_runs, "stageAfterFailure": 0,
            "failedStageEvents": 0,
            "attemptProfiles": [{"key": "tcp-connect:trojan:success", "count": 8}],
            "stageSequences": [{"key": "tcp-connect:trojan:success:payload-decode>tcp-connect", "count": 8}],
        },
    })
