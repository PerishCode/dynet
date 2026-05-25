from __future__ import annotations

import argparse
from typing import Callable

from private_runtime_lib.reporting.cascade_refresh import (
    command_cascade_refresh,
    command_route_refresh,
    command_selection_refresh,
)
from private_runtime_lib.reporting.workload_surface.tcp.cascade_stop_surface import (
    command_cascade_stop_surface,
)
from private_runtime_lib.reporting.workload_surface.tcp.stage_pressure_profile import (
    command_stage_pressure_profile,
)
from private_runtime_lib.reporting.flow_refresh import (
    command_dns_refresh,
    command_flow_refresh,
    command_target_identity_refresh,
)
from private_runtime_lib.reporting.pressure import command_pressure
from private_runtime_lib.reporting.round_gap import command_round_gap
from private_runtime_lib.reporting.round_gap_compare import command_round_gap_compare
from private_runtime_lib.reporting.workload_surface import command_workload_surface
from private_runtime_lib.reporting.workload_surface.artifact.retention import (
    command_retained_artifact_surface,
)
from private_runtime_lib.reporting.workload_surface.close import command_close_surface
from private_runtime_lib.reporting.workload_surface.dns.forward import (
    command_dns_forward_surface,
)
from private_runtime_lib.reporting.workload_surface.dns_timing import command_dns_timing_surface
from private_runtime_lib.reporting.workload_surface.event.causality import (
    command_event_causality_surface,
)
from private_runtime_lib.reporting.workload_surface.event.correlation import (
    command_event_correlation_surface,
)
from private_runtime_lib.reporting.workload_surface.event.failure import (
    command_failure_attribution_surface,
)
from private_runtime_lib.reporting.workload_surface.event.impact import (
    command_failure_impact_surface,
)
from private_runtime_lib.reporting.workload_surface.event.stream import (
    command_event_stream_surface,
)
from private_runtime_lib.reporting.workload_surface.ip.ipv6 import (
    command_ipv6_denial_surface,
)
from private_runtime_lib.reporting.workload_surface.lifecycle.collection import (
    command_collection_stage_surface,
)
from private_runtime_lib.reporting.workload_surface.lifecycle.exit_limit import (
    command_exit_limit_surface,
)
from private_runtime_lib.reporting.workload_surface.lifecycle.takeover import (
    command_takeover_lifecycle_surface,
)
from private_runtime_lib.reporting.workload_surface.outbound.gate import (
    command_outbound_gate_surface,
)
from private_runtime_lib.reporting.workload_surface.outbound.attempt import (
    command_outbound_attempt_surface,
)
from private_runtime_lib.reporting.workload_surface.outbound.candidate import (
    command_candidate_set_surface,
)
from private_runtime_lib.reporting.workload_surface.outbound.failure.propagation import (
    command_failure_propagation_surface,
)
from private_runtime_lib.reporting.workload_surface.outbound.quality import (
    command_candidate_quality_surface,
)
from private_runtime_lib.reporting.workload_surface.outbound.retry import (
    command_outbound_retry_surface,
)
from private_runtime_lib.reporting.workload_surface.outbound.route_decision import (
    command_route_decision_surface,
)
from private_runtime_lib.reporting.workload_surface.outbound.stage_chain import (
    command_stage_chain_surface,
)
from private_runtime_lib.reporting.workload_surface.outbound.stage_order import (
    command_stage_order_surface,
)
from private_runtime_lib.reporting.workload_surface.outbound_timing import (
    command_outbound_timing_surface,
)
from private_runtime_lib.reporting.workload_surface.packet import command_packet_surface
from private_runtime_lib.reporting.workload_surface.payload import command_payload_surface
from private_runtime_lib.reporting.workload_surface.stage import command_stage_surface
from private_runtime_lib.reporting.workload_surface.tcp.pressure import (
    command_tcp_pressure_surface,
)
from private_runtime_lib.reporting.workload_surface.tcp.target import (
    command_tcp_target_surface,
)
from private_runtime_lib.reporting.workload_surface.timing import command_timing_surface
from private_runtime_lib.reporting.workload_surface.udp.session import (
    command_udp_session_surface,
)


Handler = Callable[[object, argparse.Namespace], None]


RUN_DIR_COMMANDS: list[tuple[str, str, Handler]] = [
    ("flow-refresh", "flow-refresh", command_flow_refresh),
    ("dns-refresh", "dns-refresh", command_dns_refresh),
    ("target-identity-refresh", "target-identity-refresh", command_target_identity_refresh),
    ("cascade-refresh", "cascade-refresh", command_cascade_refresh),
    ("route-refresh", "route-refresh", command_route_refresh),
    ("selection-refresh", "selection-refresh", command_selection_refresh),
]

INPUT_COMMANDS: list[tuple[str, str, Handler]] = [
    ("close-surface", "close-surface", command_close_surface),
    ("payload-surface", "payload-surface", command_payload_surface),
    ("event-stream-surface", "event-stream-surface", command_event_stream_surface),
    ("event-correlation-surface", "event-correlation-surface", command_event_correlation_surface),
    ("event-causality-surface", "event-causality-surface", command_event_causality_surface),
    ("failure-attribution-surface", "failure-attribution-surface", command_failure_attribution_surface),
    ("failure-impact-surface", "failure-impact-surface", command_failure_impact_surface),
    ("stage-surface", "stage-surface", command_stage_surface),
    ("timing-surface", "timing-surface", command_timing_surface),
    ("dns-forward-surface", "dns-forward-surface", command_dns_forward_surface),
    ("dns-timing-surface", "dns-timing-surface", command_dns_timing_surface),
    ("route-decision-surface", "route-decision-surface", command_route_decision_surface),
    ("stage-chain-surface", "stage-chain-surface", command_stage_chain_surface),
    ("outbound-timing-surface", "outbound-timing-surface", command_outbound_timing_surface),
    ("outbound-attempt-surface", "outbound-attempt-surface", command_outbound_attempt_surface),
    ("candidate-set-surface", "candidate-set-surface", command_candidate_set_surface),
    ("candidate-quality-surface", "candidate-quality-surface", command_candidate_quality_surface),
    ("failure-propagation-surface", "failure-propagation-surface", command_failure_propagation_surface),
    ("outbound-gate-surface", "outbound-gate-surface", command_outbound_gate_surface),
    ("outbound-retry-surface", "outbound-retry-surface", command_outbound_retry_surface),
    ("packet-surface", "packet-surface", command_packet_surface),
    ("stage-order-surface", "stage-order-surface", command_stage_order_surface),
    ("tcp-pressure-surface", "tcp-pressure-surface", command_tcp_pressure_surface),
    ("tcp-target-surface", "tcp-target-surface", command_tcp_target_surface),
    ("udp-session-surface", "udp-session-surface", command_udp_session_surface),
    ("ipv6-denial-surface", "ipv6-denial-surface", command_ipv6_denial_surface),
    ("takeover-lifecycle-surface", "takeover-lifecycle-surface", command_takeover_lifecycle_surface),
    ("retained-artifact-surface", "retained-artifact-surface", command_retained_artifact_surface),
    ("exit-limit-surface", "exit-limit-surface", command_exit_limit_surface),
    ("collection-stage-surface", "collection-stage-surface", command_collection_stage_surface),
    ("cascade-stop-surface", "cascade-stop-surface", command_cascade_stop_surface),
    ("stage-pressure-profile", "stage-pressure-profile", command_stage_pressure_profile),
    ("pressure", "pressure", command_pressure),
    ("workload-surface", "workload-surface", command_workload_surface),
]


def add_reporting_commands(subparsers: argparse._SubParsersAction) -> None:
    for name, label, handler in RUN_DIR_COMMANDS:
        add_repeat_command(subparsers, name, label, "run_dir", handler)
    for name, label, handler in INPUT_COMMANDS:
        add_repeat_command(subparsers, name, label, "input", handler)
    add_round_gap_commands(subparsers)


def add_repeat_command(
    subparsers: argparse._SubParsersAction,
    name: str,
    label: str,
    path_arg: str,
    handler: Handler,
) -> None:
    command = subparsers.add_parser(name)
    command.add_argument("--label", default=label)
    command.add_argument("--output-dir", required=True)
    command.add_argument(path_arg, nargs="+")
    command.set_defaults(handler=handler)


def add_round_gap_commands(subparsers: argparse._SubParsersAction) -> None:
    round_gap = subparsers.add_parser("round-gap")
    round_gap.add_argument("--label", default="round-gap")
    round_gap.add_argument("--output-dir", required=True)
    round_gap.add_argument("run_dir", nargs="+")
    round_gap.set_defaults(handler=command_round_gap)

    compare = subparsers.add_parser("round-gap-compare")
    compare.add_argument("--label", default="round-gap-compare")
    compare.add_argument("--output-dir", required=True)
    compare.add_argument("--baseline", required=True)
    compare.add_argument("--candidate", required=True)
    compare.add_argument("--baseline-label")
    compare.add_argument("--candidate-label")
    compare.set_defaults(handler=command_round_gap_compare)
