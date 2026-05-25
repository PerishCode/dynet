from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from tunnel_private_config import write_json
from dynet_mainline.baseline_support.inputs import (
    adapter_product_effect_source,
    adapter_product_effect_summary,
    paired_read_surface_source,
    paired_read_surface_summary,
    recommendation_source,
    recommendation_summary,
    runtime_pressure_source,
    runtime_pressure_summary,
    print_summary,
    privacy_summary,
)
from dynet_mainline.baseline_support.gates import baseline_conclusion, baseline_gates
from dynet_mainline.baseline_support.runtime_ipv6 import (
    runtime_ipv6_source,
    runtime_ipv6_summary,
)
from dynet_mainline.baseline_support.runtime_udp import (
    runtime_udp_source,
    runtime_udp_summary,
)
from dynet_mainline.baseline_support.runtime_quality_plan import (
    runtime_quality_plan_source,
    runtime_quality_plan_summary,
    runtime_route_refresh_source,
    runtime_route_refresh_summary,
    runtime_selection_refresh_source,
    runtime_selection_refresh_summary,
)
from dynet_mainline.baseline_support.runtime_workload_flow import (
    runtime_workload_flow_source,
    runtime_workload_flow_summary,
)
from dynet_mainline.baseline_support.runtime_quality_workload import (
    runtime_quality_workload_source,
    runtime_quality_workload_summary,
)
from dynet_mainline.baseline_support.runtime_workload_surface import (
    runtime_cascade_refresh_source,
    runtime_cascade_refresh_summary,
    runtime_flow_refresh_source,
    runtime_flow_refresh_summary,
    runtime_payload_surface_source,
    runtime_payload_surface_summary,
    runtime_target_identity_source,
    runtime_target_identity_summary,
    runtime_workload_surface_source,
    runtime_workload_surface_summary,
)
from dynet_mainline.runtime_surface.round_gap import runtime_round_gap_source, runtime_round_gap_summary
from dynet_mainline.runtime_surface.cascade_stop import (
    runtime_cascade_stop_source,
    runtime_cascade_stop_summary,
)
from dynet_mainline.runtime_surface.round_gap_compare import (
    round_gap_compare_source,
    round_gap_compare_summary,
)
from dynet_mainline.baseline_support.quality_feedback import (
    quality_feedback_source,
    quality_feedback_summary,
)
from dynet_mainline.baseline_support.plan_quality_bridge import (
    plan_quality_bridge_source,
    plan_quality_bridge_summary,
)
from dynet_mainline.markdown import write_markdown
from dynet_mainline.runtime_fallback import (
    runtime_fallback_source,
    runtime_fallback_summary,
)
from dynet_mainline.runtime_dns import (
    runtime_dns_refresh_source,
    runtime_dns_refresh_summary,
    runtime_dns_product_source,
    runtime_dns_product_summary,
)
from dynet_mainline.runtime_guardrail import (
    runtime_guardrail_source,
    runtime_guardrail_summary,
)
from dynet_mainline.runtime_surface.stage import runtime_stage_surface_source, runtime_stage_surface_summary
from dynet_mainline.runtime_surface.close import runtime_close_surface_source, runtime_close_surface_summary
from dynet_mainline.runtime_surface.event.stream import runtime_event_stream_source, runtime_event_stream_summary
from dynet_mainline.runtime_surface.event.correlation import runtime_event_correlation_source, runtime_event_correlation_summary
from dynet_mainline.runtime_surface.event.causality import runtime_event_causality_source, runtime_event_causality_summary
from dynet_mainline.runtime_surface.event.failure import runtime_failure_attribution_source, runtime_failure_attribution_summary
from dynet_mainline.runtime_surface.event.impact import runtime_failure_impact_source, runtime_failure_impact_summary
from dynet_mainline.runtime_surface.timing import runtime_timing_surface_source, runtime_timing_surface_summary
from dynet_mainline.runtime_surface.dns.forward import runtime_dns_forward_source, runtime_dns_forward_summary
from dynet_mainline.runtime_surface.dns_timing import runtime_dns_timing_source, runtime_dns_timing_summary
from dynet_mainline.runtime_surface.outbound.timing import runtime_outbound_timing_source, runtime_outbound_timing_summary
from dynet_mainline.runtime_surface.outbound.attempt import runtime_outbound_attempt_source, runtime_outbound_attempt_summary
from dynet_mainline.runtime_surface.outbound.candidate import runtime_candidate_set_source, runtime_candidate_set_summary
from dynet_mainline.runtime_surface.outbound.failure_propagation import runtime_failure_propagation_source, runtime_failure_propagation_summary
from dynet_mainline.runtime_surface.outbound.quality import runtime_candidate_quality_source, runtime_candidate_quality_summary
from dynet_mainline.runtime_surface.outbound.stage_chain import runtime_stage_chain_source, runtime_stage_chain_summary
from dynet_mainline.runtime_surface.outbound.stage_order import runtime_stage_order_source, runtime_stage_order_summary
from dynet_mainline.runtime_surface.route.decision import runtime_route_decision_source, runtime_route_decision_summary
from dynet_mainline.runtime_surface.outbound.gate import runtime_outbound_gate_source, runtime_outbound_gate_summary
from dynet_mainline.runtime_surface.outbound.retry import runtime_outbound_retry_source, runtime_outbound_retry_summary
from dynet_mainline.runtime_surface.packet import runtime_packet_surface_source, runtime_packet_surface_summary
from dynet_mainline.runtime_surface.tcp.pressure import runtime_tcp_pressure_source, runtime_tcp_pressure_summary
from dynet_mainline.runtime_surface.tcp.target import runtime_tcp_target_source, runtime_tcp_target_summary
from dynet_mainline.runtime_surface.tcp.stage_pressure import (
    runtime_stage_pressure_source,
    runtime_stage_pressure_summary,
)
from dynet_mainline.runtime_surface.udp_session import runtime_udp_session_source, runtime_udp_session_summary
from dynet_mainline.runtime_surface.platform.ipv6_denial import (
    runtime_ipv6_denial_source,
    runtime_ipv6_denial_summary,
)
from dynet_mainline.runtime_surface.platform.takeover_lifecycle import (
    runtime_takeover_lifecycle_source,
    runtime_takeover_lifecycle_summary,
)
from dynet_mainline.runtime_surface.platform.retained_artifact import (
    runtime_retained_artifact_source,
    runtime_retained_artifact_summary,
)
from dynet_mainline.runtime_surface.platform.exit_limit import (
    runtime_exit_limit_source,
    runtime_exit_limit_summary,
)
from dynet_mainline.runtime_surface.platform.collection_stage import (
    runtime_collection_stage_source,
    runtime_collection_stage_summary,
)

SCHEMA = "dynet-mainline-baseline-gate/v1alpha1"

SECTION_SPECS = [
    ("adapterProductEffect", "adapter_product_effect_paths", adapter_product_effect_source, adapter_product_effect_summary),
    ("runtimePressure", "runtime_pressure_paths", runtime_pressure_source, runtime_pressure_summary),
    ("runtimeFallback", "runtime_fallback_paths", runtime_fallback_source, runtime_fallback_summary),
    ("runtimeDnsProduct", "runtime_dns_product_paths", runtime_dns_product_source, runtime_dns_product_summary),
    ("runtimeDnsRefresh", "runtime_dns_refresh_paths", runtime_dns_refresh_source, runtime_dns_refresh_summary),
    ("runtimeDnsForward", "runtime_dns_forward_paths", runtime_dns_forward_source, runtime_dns_forward_summary),
    ("runtimeQualityPlan", "runtime_quality_plan_paths", runtime_quality_plan_source, runtime_quality_plan_summary),
    ("runtimeRouteRefresh", "runtime_route_refresh_paths", runtime_route_refresh_source, runtime_route_refresh_summary),
    ("runtimeSelectionRefresh", "runtime_selection_refresh_paths", runtime_selection_refresh_source, runtime_selection_refresh_summary),
    ("runtimeWorkloadFlow", "runtime_workload_flow_paths", runtime_workload_flow_source, runtime_workload_flow_summary),
    ("runtimeQualityWorkload", "runtime_quality_workload_paths", runtime_quality_workload_source, runtime_quality_workload_summary),
    ("runtimeWorkloadSurface", "runtime_workload_surface_paths", runtime_workload_surface_source, runtime_workload_surface_summary),
    ("runtimeCloseSurface", "runtime_close_surface_paths", runtime_close_surface_source, runtime_close_surface_summary),
    ("runtimePayloadSurface", "runtime_payload_surface_paths", runtime_payload_surface_source, runtime_payload_surface_summary),
    ("runtimeEventStream", "runtime_event_stream_paths", runtime_event_stream_source, runtime_event_stream_summary),
    ("runtimeEventCorrelation", "runtime_event_correlation_paths", runtime_event_correlation_source, runtime_event_correlation_summary),
    ("runtimeEventCausality", "runtime_event_causality_paths", runtime_event_causality_source, runtime_event_causality_summary),
    ("runtimeFailureAttribution", "runtime_failure_attribution_paths", runtime_failure_attribution_source, runtime_failure_attribution_summary),
    ("runtimeFailureImpact", "runtime_failure_impact_paths", runtime_failure_impact_source, runtime_failure_impact_summary),
    ("runtimeStageSurface", "runtime_stage_surface_paths", runtime_stage_surface_source, runtime_stage_surface_summary),
    ("runtimeTimingSurface", "runtime_timing_surface_paths", runtime_timing_surface_source, runtime_timing_surface_summary),
    ("runtimeDnsTiming", "runtime_dns_timing_paths", runtime_dns_timing_source, runtime_dns_timing_summary),
    ("runtimeOutboundTiming", "runtime_outbound_timing_paths", runtime_outbound_timing_source, runtime_outbound_timing_summary),
    ("runtimeOutboundAttempt", "runtime_outbound_attempt_paths", runtime_outbound_attempt_source, runtime_outbound_attempt_summary),
    ("runtimeCandidateSet", "runtime_candidate_set_paths", runtime_candidate_set_source, runtime_candidate_set_summary),
    ("runtimeCandidateQuality", "runtime_candidate_quality_paths", runtime_candidate_quality_source, runtime_candidate_quality_summary),
    ("runtimeFailurePropagation", "runtime_failure_propagation_paths", runtime_failure_propagation_source, runtime_failure_propagation_summary),
    ("runtimeStageChain", "runtime_stage_chain_paths", runtime_stage_chain_source, runtime_stage_chain_summary),
    ("runtimeStageOrder", "runtime_stage_order_paths", runtime_stage_order_source, runtime_stage_order_summary),
    ("runtimeRouteDecision", "runtime_route_decision_paths", runtime_route_decision_source, runtime_route_decision_summary),
    ("runtimeOutboundGate", "runtime_outbound_gate_paths", runtime_outbound_gate_source, runtime_outbound_gate_summary),
    ("runtimeOutboundRetry", "runtime_outbound_retry_paths", runtime_outbound_retry_source, runtime_outbound_retry_summary),
    ("runtimePacketSurface", "runtime_packet_surface_paths", runtime_packet_surface_source, runtime_packet_surface_summary),
    ("runtimeTcpPressure", "runtime_tcp_pressure_paths", runtime_tcp_pressure_source, runtime_tcp_pressure_summary),
    ("runtimeTcpTarget", "runtime_tcp_target_paths", runtime_tcp_target_source, runtime_tcp_target_summary),
    ("runtimeStagePressure", "runtime_stage_pressure_paths", runtime_stage_pressure_source, runtime_stage_pressure_summary),
    ("runtimeUdpSession", "runtime_udp_session_paths", runtime_udp_session_source, runtime_udp_session_summary),
    ("runtimeIpv6Denial", "runtime_ipv6_denial_paths", runtime_ipv6_denial_source, runtime_ipv6_denial_summary),
    ("runtimeTakeoverLifecycle", "runtime_takeover_lifecycle_paths", runtime_takeover_lifecycle_source, runtime_takeover_lifecycle_summary),
    ("runtimeRetainedArtifact", "runtime_retained_artifact_paths", runtime_retained_artifact_source, runtime_retained_artifact_summary),
    ("runtimeExitLimit", "runtime_exit_limit_paths", runtime_exit_limit_source, runtime_exit_limit_summary),
    ("runtimeCollectionStage", "runtime_collection_stage_paths", runtime_collection_stage_source, runtime_collection_stage_summary),
    ("runtimeCascadeStop", "runtime_cascade_stop_paths", runtime_cascade_stop_source, runtime_cascade_stop_summary),
    ("runtimeRoundGap", "runtime_round_gap_paths", runtime_round_gap_source, runtime_round_gap_summary),
    ("runtimeRoundGapCompare", "runtime_round_gap_compare_paths", round_gap_compare_source, round_gap_compare_summary),
    ("runtimeFlowRefresh", "runtime_flow_refresh_paths", runtime_flow_refresh_source, runtime_flow_refresh_summary),
    ("runtimeCascadeRefresh", "runtime_cascade_refresh_paths", runtime_cascade_refresh_source, runtime_cascade_refresh_summary),
    ("runtimeTargetIdentity", "runtime_target_identity_paths", runtime_target_identity_source, runtime_target_identity_summary),
    ("qualityFeedbackBoundary", "quality_feedback_paths", quality_feedback_source, quality_feedback_summary),
    ("planQualityStateBridge", "plan_quality_bridge_paths", plan_quality_bridge_source, plan_quality_bridge_summary),
    ("runtimeUdpDirect", "runtime_udp_paths", runtime_udp_source, runtime_udp_summary),
    ("runtimeIpv6NoLeak", "runtime_ipv6_paths", runtime_ipv6_source, runtime_ipv6_summary),
    ("runtimeGuardrail", "runtime_guardrail_paths", runtime_guardrail_source, runtime_guardrail_summary),
    ("pairedReadSurface", "paired_read_surface_paths", paired_read_surface_source, paired_read_surface_summary),
    ("recommendations", "recommendation_paths", recommendation_source, recommendation_summary),
]


def command_mainline_baseline(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = mainline_baseline_summary(**command_path_groups(args))
    write_json(output_dir / "summary.json", summary)
    write_markdown(output_dir / "summary.md", summary)
    print(json.dumps(print_summary(output_dir, summary), sort_keys=True))
    return 0 if summary["sourceCount"] else 1


def arg_paths(args: argparse.Namespace, name: str) -> list[Path]:
    return [Path(path) for path in getattr(args, name, []) or []]


def summarize(paths: list[Path], source_fn: Any, summary_fn: Any) -> dict[str, Any]:
    return summary_fn([source_fn(path) for path in paths])


def command_path_groups(args: argparse.Namespace) -> dict[str, list[Path]]:
    return {
        path_key: arg_paths(args, arg_name(path_key))
        for _, path_key, _, _ in SECTION_SPECS
    }


def arg_name(path_key: str) -> str:
    return path_key[:-6] if path_key.endswith("_paths") else path_key


def mainline_baseline_summary(**path_groups: list[Path]) -> dict[str, Any]:
    section_values = section_summaries(path_groups)
    ordered_sections = [
        section_values[name] for name, _, _, _ in SECTION_SPECS
    ]
    gates = baseline_gates(*ordered_sections)
    conclusion = baseline_conclusion(gates, *ordered_sections)
    return {
        "schema": SCHEMA,
        "sourceCount": sum(section["sourceCount"] for section in ordered_sections),
        "status": conclusion["status"],
        "recommendedUse": conclusion["recommendedUse"],
        "plannerPenaltySafe": False,
        "qualityPenaltySafe": False,
        "runtimePolicy": "do-not-change-from-this-baseline-alone",
        **section_values,
        "gates": gates,
        "conclusion": conclusion,
        "privacy": privacy_summary(*ordered_sections),
    }


def section_summaries(path_groups: dict[str, list[Path]]) -> dict[str, dict[str, Any]]:
    return {
        name: summarize(path_groups.get(path_key, []), source_fn, summary_fn)
        for name, path_key, source_fn, summary_fn in SECTION_SPECS
    }
