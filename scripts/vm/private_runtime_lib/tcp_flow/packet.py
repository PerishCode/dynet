from __future__ import annotations

from private_runtime_lib.briefs import fields
from private_runtime_lib.tcp_flow.session import int_value, optional_int


def tcp_preflow_ports(report: dict) -> set[int]:
    ports: set[int] = set()
    for event in report.get("events", []):
        if not isinstance(event, dict) or event.get("kind") != "tcp-forwarder-preflow":
            continue
        port = optional_int(fields(event).get("clientPort"))
        if port is not None:
            ports.add(port)
    return ports


def tcp_packet_ports(report: dict) -> dict[int, dict]:
    ports: dict[int, dict] = {}
    for event in report.get("events", []):
        if not isinstance(event, dict) or event.get("kind") != "tcp-forwarder-packet":
            continue
        event_fields = fields(event)
        port = optional_int(event_fields.get("clientPort"))
        if port is None:
            continue
        row = ports.setdefault(port, new_tcp_packet_counts())
        observe_tcp_packet(row, event_fields)
    return ports


def tcp_packet_terminal_ports(report: dict) -> dict[int, dict]:
    return tcp_event_ports(report, "tcp-forwarder-packet-terminal", tcp_terminal_row)


def tcp_preflow_candidate_ports(report: dict) -> dict[int, dict]:
    return tcp_event_ports(report, "tcp-forwarder-preflow-candidate", tcp_preflow_candidate_row)


def tcp_preflow_missed_ports(report: dict) -> dict[int, dict]:
    return tcp_event_ports(report, "tcp-forwarder-preflow-missed", tcp_preflow_missed_row)


def tcp_event_ports(report: dict, kind: str, build_row) -> dict[int, dict]:
    ports: dict[int, dict] = {}
    for event in report.get("events", []):
        if not isinstance(event, dict) or event.get("kind") != kind:
            continue
        event_fields = fields(event)
        port = optional_int(event_fields.get("clientPort"))
        if port is not None:
            ports[port] = build_row(event_fields)
    return ports


def tcp_terminal_row(event_fields: dict[str, str]) -> dict:
    return {
        "reason": event_fields.get("reason") or "unknown",
        "packetHandshakeComplete": bool_value(event_fields.get("packetHandshakeComplete")),
        "promotedToRuntimeSession": bool_value(event_fields.get("promotedToRuntimeSession")),
        "ingressControlPackets": int_value(event_fields.get("ingressControlPackets")),
        "ingressSynPackets": int_value(event_fields.get("ingressSynPackets")),
        "egressControlPackets": int_value(event_fields.get("egressControlPackets")),
        "egressSynAckPackets": int_value(event_fields.get("egressSynAckPackets")),
        "ingressPayloadPackets": int_value(event_fields.get("ingressPayloadPackets")),
        "ingressPayloadBytes": int_value(event_fields.get("ingressPayloadBytes")),
        "egressPayloadPackets": int_value(event_fields.get("egressPayloadPackets")),
        "egressPayloadBytes": int_value(event_fields.get("egressPayloadBytes")),
        "finPackets": int_value(event_fields.get("finPackets")),
        "rstPackets": int_value(event_fields.get("rstPackets")),
    }


def tcp_preflow_candidate_row(event_fields: dict[str, str]) -> dict:
    return tcp_terminal_row(event_fields)


def tcp_preflow_missed_row(event_fields: dict[str, str]) -> dict:
    return {
        **tcp_terminal_row({**event_fields, "reason": event_fields.get("terminalReason")}),
        "reason": event_fields.get("reason") or "unknown",
        "socketState": event_fields.get("socketState") or "unknown",
        "terminalReason": event_fields.get("terminalReason") or "unknown",
    }


def packet_terminal_fields(local_port: int | None, terminals_by_port: dict[int, dict]) -> dict:
    terminal = terminals_by_port.get(local_port or -1, {})
    return {
        "runtimePacketTerminalMatched": bool(terminal),
        "runtimePacketTerminalReason": terminal.get("reason"),
        "runtimePacketTerminalHandshakeComplete": bool(terminal.get("packetHandshakeComplete")),
        "runtimePacketTerminalPromotedToSession": bool(terminal.get("promotedToRuntimeSession")),
        "runtimePacketTerminalIngressControlPackets": int_value(terminal.get("ingressControlPackets")),
        "runtimePacketTerminalEgressControlPackets": int_value(terminal.get("egressControlPackets")),
        "runtimePacketTerminalIngressPayloadPackets": int_value(terminal.get("ingressPayloadPackets")),
        "runtimePacketTerminalIngressPayloadBytes": int_value(terminal.get("ingressPayloadBytes")),
        "runtimePacketTerminalEgressPayloadPackets": int_value(terminal.get("egressPayloadPackets")),
        "runtimePacketTerminalEgressPayloadBytes": int_value(terminal.get("egressPayloadBytes")),
        "runtimePacketTerminalFinPackets": int_value(terminal.get("finPackets")),
        "runtimePacketTerminalRstPackets": int_value(terminal.get("rstPackets")),
    }


def preflow_candidate_fields(local_port: int | None, candidate_by_port: dict[int, dict]) -> dict:
    candidate = candidate_by_port.get(local_port or -1, {})
    return {
        "runtimePreflowCandidateMatched": bool(candidate),
        "runtimePreflowCandidateReason": candidate.get("reason"),
        "runtimePreflowCandidateIngressPayloadBytes": int_value(candidate.get("ingressPayloadBytes")),
        "runtimePreflowCandidateEgressPayloadBytes": int_value(candidate.get("egressPayloadBytes")),
        "runtimePreflowCandidateFinPackets": int_value(candidate.get("finPackets")),
        "runtimePreflowCandidateRstPackets": int_value(candidate.get("rstPackets")),
    }


def preflow_missed_fields(local_port: int | None, missed_by_port: dict[int, dict]) -> dict:
    missed = missed_by_port.get(local_port or -1, {})
    return {
        "runtimePreflowMissedMatched": bool(missed),
        "runtimePreflowMissedReason": missed.get("reason"),
        "runtimePreflowMissedSocketState": missed.get("socketState"),
        "runtimePreflowMissedTerminalReason": missed.get("terminalReason"),
        "runtimePreflowMissedIngressPayloadBytes": int_value(missed.get("ingressPayloadBytes")),
        "runtimePreflowMissedEgressPayloadBytes": int_value(missed.get("egressPayloadBytes")),
        "runtimePreflowMissedFinPackets": int_value(missed.get("finPackets")),
        "runtimePreflowMissedRstPackets": int_value(missed.get("rstPackets")),
    }


def observe_tcp_packet(row: dict, event_fields: dict[str, str]) -> None:
    direction = event_fields.get("direction")
    syn = event_fields.get("syn") == "true"
    ack = event_fields.get("ack") == "true"
    payload_bytes = int_value(event_fields.get("payloadBytes"))
    if direction == "ingress":
        row["ingressControlPackets"] += 1
        if syn:
            row["ingressSynPackets"] += 1
        if payload_bytes > 0:
            row["ingressPayloadPackets"] += 1
            row["ingressPayloadBytes"] += payload_bytes
    elif direction == "egress":
        row["egressControlPackets"] += 1
        if syn and ack:
            row["egressSynAckPackets"] += 1
        if payload_bytes > 0:
            row["egressPayloadPackets"] += 1
            row["egressPayloadBytes"] += payload_bytes
    if event_fields.get("fin") == "true":
        row["finPackets"] += 1
    if event_fields.get("rst") == "true":
        row["rstPackets"] += 1


def new_tcp_packet_counts() -> dict[str, int]:
    return {
        "ingressControlPackets": 0,
        "ingressSynPackets": 0,
        "egressControlPackets": 0,
        "egressSynAckPackets": 0,
        "ingressPayloadPackets": 0,
        "ingressPayloadBytes": 0,
        "egressPayloadPackets": 0,
        "egressPayloadBytes": 0,
        "finPackets": 0,
        "rstPackets": 0,
    }


def bool_value(value: object) -> bool:
    return str(value).lower() == "true"
