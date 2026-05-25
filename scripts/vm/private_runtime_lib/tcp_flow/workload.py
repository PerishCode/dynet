from __future__ import annotations

from private_runtime_lib.tcp_flow.packet import (
    packet_terminal_fields,
    preflow_candidate_fields,
    preflow_missed_fields,
    tcp_packet_ports,
    tcp_packet_terminal_ports,
    tcp_preflow_candidate_ports,
    tcp_preflow_missed_ports,
    tcp_preflow_ports,
)
from private_runtime_lib.tcp_flow.session import (
    aggregate_field,
    flow_lifecycle_complete,
    flow_path_complete,
    flow_payload_bidirectional,
    int_value,
    optional_int,
    tcp_flow_rows,
)


def workload_flow_brief(report: dict, workload_report: dict) -> dict:
    rows = workload_flow_rows(report, workload_report)
    groups = workload_flow_groups(rows)
    return {
        **workload_entry_counts(rows, groups),
        **workload_match_counts(groups),
        **workload_runtime_counts(rows, groups),
        **workload_failure_counts(groups),
        "rows": rows,
    }


def workload_flow_rows(report: dict, workload_report: dict) -> list[dict]:
    preflows_by_port = tcp_preflow_ports(report)
    preflow_candidate_by_port = tcp_preflow_candidate_ports(report)
    preflow_missed_by_port = tcp_preflow_missed_ports(report)
    packets_by_port = tcp_packet_ports(report)
    terminals_by_port = tcp_packet_terminal_ports(report)
    capture_by_port = tun_capture_ports(workload_report)
    flows_by_port = tcp_flows_by_port(report)
    entries = [
        item
        for item in workload_report.get("results", [])
        if isinstance(item, dict) and item.get("probe") != "dns"
    ] if isinstance(workload_report, dict) else []
    return [
        workload_flow_row(item, flows_by_port, preflows_by_port, packets_by_port, capture_by_port)
        | packet_terminal_fields(optional_int(item.get("localPort")), terminals_by_port)
        | preflow_candidate_fields(optional_int(item.get("localPort")), preflow_candidate_by_port)
        | preflow_missed_fields(optional_int(item.get("localPort")), preflow_missed_by_port)
        for item in entries
    ]


def workload_flow_groups(rows: list[dict]) -> dict[str, list[dict]]:
    tcp_attempted = [row for row in rows if row["workloadTcpAttempted"]]
    matched = [row for row in rows if row["flowMatched"]]
    unmatched = [row for row in rows if not row["flowMatched"]]
    failed = [row for row in rows if row["workloadOk"] is False]
    return {
        "tcpAttempted": tcp_attempted,
        "matched": matched,
        "unmatched": unmatched,
        "failed": failed,
        "failedMatched": [row for row in failed if row["flowMatched"]],
        "failedUnmatched": [row for row in failed if not row["flowMatched"]],
    }


def workload_entry_counts(rows: list[dict], groups: dict[str, list[dict]]) -> dict:
    tcp_attempted = groups["tcpAttempted"]
    matched = groups["matched"]
    unmatched = groups["unmatched"]
    return {
        "entries": len(rows),
        "entriesWithLocalPort": sum(1 for row in rows if row["localPort"] is not None),
        "tcpAttemptedEntries": len(tcp_attempted),
        "preTcpEntries": len(rows) - len(tcp_attempted),
        "tcpAttemptedEntriesWithLocalPort": sum(1 for row in tcp_attempted if row["localPort"] is not None),
        "tcpAttemptedCoveredEntries": sum(
            1 for row in tcp_attempted if row["flowMatched"] or row["packetTerminalOnly"]
        ),
        "tcpAttemptedUnmatchedEntries": sum(1 for row in tcp_attempted if not row["flowMatched"]),
        "matchedEntries": len(matched),
        "unmatchedEntries": len(unmatched),
        "coveredEntries": sum(1 for row in rows if row["flowMatched"] or row["packetTerminalOnly"]),
        "packetTerminalEntries": sum(1 for row in rows if row["packetTerminalOnly"]),
        "unmatchedPacketTerminalEntries": sum(1 for row in unmatched if row["packetTerminalOnly"]),
        "unmatchedNonTerminalEntries": sum(1 for row in unmatched if not row["packetTerminalOnly"]),
    }


def workload_match_counts(groups: dict[str, list[dict]]) -> dict:
    matched = groups["matched"]
    failed_matched = groups["failedMatched"]
    return {
        "matchedFailures": len(failed_matched),
        "unmatchedFailures": len(groups["failedUnmatched"]),
        "matchedFlowAttempts": sum(row["flowMatchedCount"] for row in matched),
        "matchedDuplicateFlowEntries": sum(1 for row in matched if row["flowMatchedCount"] > 1),
        "matchedRecoveredFailureEntries": sum(1 for row in matched if row["flowRecoveredFailure"]),
        "matchedFlowFailedAttempts": sum(row["flowFailedCount"] for row in matched),
        "matchedFlowStageFailedAttempts": sum(row["flowStageFailedCount"] for row in matched),
        "matchedPathComplete": sum(1 for row in matched if row["flowPathComplete"]),
        "matchedLifecycleComplete": sum(1 for row in matched if row["flowLifecycleComplete"]),
        "matchedPayloadStarted": sum(1 for row in matched if row["flowPayloadStarted"]),
        "matchedPayloadBidirectional": sum(1 for row in matched if row["flowPayloadBidirectional"]),
        "matchedClosed": sum(1 for row in matched if row["flowClosed"]),
        "matchedFlowFailed": sum(1 for row in matched if row["flowFailed"]),
    }


def workload_runtime_counts(rows: list[dict], groups: dict[str, list[dict]]) -> dict:
    tcp_attempted = groups["tcpAttempted"]
    unmatched = groups["unmatched"]
    failed_unmatched = groups["failedUnmatched"]
    terminal_rows = [row for row in rows if row["runtimePacketTerminalMatched"]]
    unmatched_terminal_rows = [row for row in unmatched if row["runtimePacketTerminalMatched"]]
    failed_unmatched_terminal_rows = [
        row for row in failed_unmatched if row["runtimePacketTerminalMatched"]
    ]
    return {
        "runtimePreflowMatchedEntries": sum(1 for row in rows if row["runtimePreflowMatched"]),
        "unmatchedRuntimePreflowMatched": sum(1 for row in unmatched if row["runtimePreflowMatched"]),
        "unmatchedRuntimePreflowMatchedFailures": sum(
            1 for row in failed_unmatched if row["runtimePreflowMatched"]
        ),
        "runtimePacketMatchedEntries": sum(1 for row in rows if row["runtimePacketMatched"]),
        "tcpAttemptedRuntimePacketMatchedEntries": sum(
            1 for row in tcp_attempted if row["runtimePacketMatched"]
        ),
        "runtimePacketHandshakeEntries": sum(1 for row in rows if row["runtimePacketHandshakeComplete"]),
        "runtimePacketTerminalEntries": sum(1 for row in rows if row["runtimePacketTerminalMatched"]),
        "runtimePacketTerminalByReason": aggregate_field(
            terminal_rows,
            "runtimePacketTerminalReason",
        ),
        **preflow_observation_counts(rows, groups),
        "runtimeIngressSynMatchedEntries": sum(
            1 for row in rows if row["runtimeIngressSynPackets"] > 0
        ),
        "tcpAttemptedRuntimeIngressSynMatchedEntries": sum(
            1 for row in tcp_attempted if row["runtimeIngressSynPackets"] > 0
        ),
        "runtimeEgressSynAckMatchedEntries": sum(
            1 for row in rows if row["runtimeEgressSynAckPackets"] > 0
        ),
        "unmatchedRuntimePacketMatched": sum(1 for row in unmatched if row["runtimePacketMatched"]),
        "unmatchedRuntimePacketMatchedFailures": sum(
            1 for row in failed_unmatched if row["runtimePacketMatched"]
        ),
        "unmatchedRuntimePacketTerminalMatched": sum(
            1 for row in unmatched if row["runtimePacketTerminalMatched"]
        ),
        "unmatchedRuntimePacketTerminalFailures": sum(
            1 for row in failed_unmatched if row["runtimePacketTerminalMatched"]
        ),
        "unmatchedRuntimePacketTerminalByReason": aggregate_field(
            unmatched_terminal_rows,
            "runtimePacketTerminalReason",
        ),
        "unmatchedRuntimePacketTerminalFailureByReason": aggregate_field(
            failed_unmatched_terminal_rows,
            "runtimePacketTerminalReason",
        ),
        "unmatchedTcpConnectedRuntimePacketMissing": sum(
            1 for row in failed_unmatched if row["workloadTcpConnectOk"] and not row["runtimePacketMatched"]
        ),
        "tunCaptureMatchedEntries": sum(1 for row in rows if row["tunCaptureMatched"]),
        "tcpAttemptedTunCaptureMatchedEntries": sum(1 for row in tcp_attempted if row["tunCaptureMatched"]),
        "unmatchedTunCaptureMatched": sum(1 for row in unmatched if row["tunCaptureMatched"]),
        "unmatchedTunCaptureMatchedFailures": sum(1 for row in failed_unmatched if row["tunCaptureMatched"]),
        "unmatchedTcpConnectedTunCaptureMissing": sum(
            1 for row in failed_unmatched if row["workloadTcpConnectOk"] and not row["tunCaptureMatched"]
        ),
    }


def preflow_observation_counts(rows: list[dict], groups: dict[str, list[dict]]) -> dict:
    unmatched = groups["unmatched"]
    failed_unmatched = groups["failedUnmatched"]
    candidate_rows = [row for row in rows if row["runtimePreflowCandidateMatched"]]
    missed_rows = [row for row in rows if row["runtimePreflowMissedMatched"]]
    return {
        "runtimePreflowCandidateEntries": len(candidate_rows),
        "runtimePreflowCandidateByReason": aggregate_field(
            candidate_rows,
            "runtimePreflowCandidateReason",
        ),
        "unmatchedRuntimePreflowCandidate": sum(
            1 for row in unmatched if row["runtimePreflowCandidateMatched"]
        ),
        "unmatchedRuntimePreflowCandidateFailures": sum(
            1 for row in failed_unmatched if row["runtimePreflowCandidateMatched"]
        ),
        "runtimePreflowMissedEntries": len(missed_rows),
        "runtimePreflowMissedByReason": aggregate_field(missed_rows, "runtimePreflowMissedReason"),
        "runtimePreflowMissedBySocketState": aggregate_field(missed_rows, "runtimePreflowMissedSocketState"),
        "unmatchedRuntimePreflowMissed": sum(1 for row in unmatched if row["runtimePreflowMissedMatched"]),
        "unmatchedRuntimePreflowMissedFailures": sum(
            1 for row in failed_unmatched if row["runtimePreflowMissedMatched"]
        ),
    }


def workload_failure_counts(groups: dict[str, list[dict]]) -> dict:
    unmatched = groups["unmatched"]
    failed_matched = groups["failedMatched"]
    failed_unmatched = groups["failedUnmatched"]
    return {
        "unmatchedByProbe": aggregate_field(unmatched, "probe"),
        "failureSurfaces": aggregate_field(failed_matched, "failureSurface"),
        "unmatchedFailureSurfaces": aggregate_field(failed_unmatched, "failureSurface"),
        "unmatchedTcpConnectedFailures": sum(1 for row in failed_unmatched if row["workloadTcpConnectOk"]),
        "unmatchedRouteViaDynetFailures": sum(1 for row in failed_unmatched if row["workloadRouteViaDynet"]),
        "unmatchedTunWitnessedFailures": sum(1 for row in failed_unmatched if row["workloadTunWitnessed"]),
    }


def tcp_flows_by_port(report: dict) -> dict[int, list[dict]]:
    ports: dict[int, list[dict]] = {}
    for row in tcp_flow_rows(report):
        port = row.get("clientPort")
        if port is not None:
            ports.setdefault(int(port), []).append(row)
    return ports


def tun_capture_ports(workload_report: dict) -> dict[int, dict]:
    capture = workload_report.get("tunCapture", {}) if isinstance(workload_report, dict) else {}
    ports = {}
    for item in capture.get("ports", []) if isinstance(capture, dict) else []:
        port = optional_int(item.get("localPort"))
        if port is not None:
            ports[port] = item
    return ports


def workload_flow_row(
    item: dict,
    flows_by_port: dict[int, list[dict]],
    preflows_by_port: set[int],
    packets_by_port: dict[int, dict],
    capture_by_port: dict[int, dict],
) -> dict:
    local_port = optional_int(item.get("localPort"))
    flows = flows_by_port.get(local_port or -1, [])
    flow = primary_flow(flows)
    packet = packets_by_port.get(local_port or -1, {})
    capture = capture_by_port.get(local_port or -1, {})
    return {
        "workloadId": item.get("id"),
        "probe": item.get("probe"),
        "domain": item.get("domain"),
        "workloadOk": item.get("ok"),
        "localPort": local_port,
        "workloadTcpConnectOk": workload_stage_ok(item, "tcp-connect"),
        "workloadTcpAttempted": workload_tcp_attempted(item, local_port),
        "workloadRouteViaDynet": workload_route_via_dynet(item),
        "workloadTunWitnessed": workload_tun_witnessed(item),
        "runtimePreflowMatched": local_port in preflows_by_port,
        "runtimePacketMatched": bool(packet),
        "runtimeIngressControlPackets": int_value(packet.get("ingressControlPackets")),
        "runtimeIngressSynPackets": int_value(packet.get("ingressSynPackets")),
        "runtimeEgressControlPackets": int_value(packet.get("egressControlPackets")),
        "runtimeEgressSynAckPackets": int_value(packet.get("egressSynAckPackets")),
        "runtimeFinPackets": int_value(packet.get("finPackets")),
        "runtimeRstPackets": int_value(packet.get("rstPackets")),
        "runtimePacketHandshakeComplete": runtime_packet_handshake(packet),
        "packetTerminalOnly": packet_terminal_only(item, flow, packet),
        "tunCaptureMatched": bool(capture),
        "tunCaptureToTargetPackets": int_value(capture.get("toTargetPackets")),
        "tunCaptureFromTargetPackets": int_value(capture.get("fromTargetPackets")),
        "tunCaptureSynPackets": int_value(capture.get("synPackets")),
        "tunCaptureSynAckPackets": int_value(capture.get("synAckPackets")),
        "flowMatched": bool(flows),
        "flowMatchedCount": len(flows),
        "flowIds": [row["flowId"] for row in flows if row.get("flowId")],
        "flowFailedCount": sum(1 for row in flows if row.get("failed")),
        "flowStageFailedCount": sum(1 for row in flows if row.get("stageFailed")),
        "flowRecoveredFailure": flow_recovered_failure(flows, flow),
        "flowId": flow.get("flowId"),
        "flowDomain": flow.get("domain"),
        "flowPathComplete": flow_path_complete(flow) if flow else False,
        "flowLifecycleComplete": flow_lifecycle_complete(flow) if flow else False,
        "flowPayloadStarted": bool(flow and flow["firstWriteEvents"] > 0),
        "flowPayloadBidirectional": flow_payload_bidirectional(flow) if flow else False,
        "flowClosed": bool(flow and flow["closed"]),
        "flowFailed": bool(flow and flow["failed"]),
        "flowCloseReason": flow.get("closeReason"),
        "failureSurface": workload_failure_surface(item) if item.get("ok") is False else None,
    }


def primary_flow(flows: list[dict]) -> dict:
    for row in reversed(flows):
        if not flow_failed(row):
            return row
    return flows[-1] if flows else {}


def flow_recovered_failure(flows: list[dict], primary: dict) -> bool:
    return bool(
        primary
        and not flow_failed(primary)
        and (
            primary.get("stageFailed")
            or any(row is not primary and flow_failed(row) for row in flows)
        )
    )


def flow_failed(row: dict) -> bool:
    return bool(row.get("failed") or (row.get("stageFailed") and not flow_lifecycle_complete(row)))


def workload_stage_ok(item: dict, stage_name: str) -> bool:
    stages = item.get("stages")
    if not isinstance(stages, list):
        return False
    return any(isinstance(row, dict) and row.get("name") == stage_name and row.get("ok") is True for row in stages)


def workload_stage_seen(item: dict, stage_name: str) -> bool:
    stages = item.get("stages")
    if not isinstance(stages, list):
        return False
    return any(isinstance(row, dict) and row.get("name") == stage_name for row in stages)


def workload_tcp_attempted(item: dict, local_port: int | None) -> bool:
    return local_port is not None or workload_stage_seen(item, "tcp-connect")


def runtime_packet_handshake(packet: dict) -> bool:
    return (
        int_value(packet.get("ingressSynPackets")) > 0
        and int_value(packet.get("egressSynAckPackets")) > 0
    )


def packet_terminal_only(item: dict, flow: dict, packet: dict) -> bool:
    return (
        not flow
        and item.get("probe") == "tcp-connect"
        and item.get("ok") is True
        and runtime_packet_handshake(packet)
    )


def workload_route_via_dynet(item: dict) -> bool:
    if item.get("routeViaDynet") is True:
        return True
    route_after = item.get("routeAfter")
    return isinstance(route_after, dict) and route_after.get("routeViaDynet") is True


def workload_tun_witnessed(item: dict) -> bool:
    witness = item.get("tunWitness")
    return isinstance(witness, dict) and witness.get("observed") is True


def workload_failure_surface(item: dict) -> str:
    probe = str(item.get("probe") or "unknown")
    stage = str(item.get("errorStage") or "unknown")
    error_type = str(item.get("errorType") or "unknown")
    route = "route-dynet" if item.get("routeViaDynet") is True else "route-unknown"
    witness = "tun-witnessed"
    witness_value = item.get("tunWitness")
    if not isinstance(witness_value, dict) or witness_value.get("observed") is not True:
        witness = "tun-unwitnessed"
    return f"{probe}:{stage}:{error_type}:{route}:{witness}"
