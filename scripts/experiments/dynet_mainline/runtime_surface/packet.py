from __future__ import annotations

from pathlib import Path
from typing import Any

from scripts.lib.jsonio import load_summary
from scripts.lib.nv import count_keys, merge_items
from scripts.lib.privacy import (
    empty_surface_privacy_flags as empty_privacy_flags,
)


PACKET_SURFACE_SCHEMA = "dynet-vm-private-runtime-packet-surface/v1alpha1"
COUNT_FIELDS = [
    "runs",
    "cleanRuns",
    "failedRuns",
    "flows",
    "startedFlows",
    "closedFlows",
    "failedFlows",
    "lifecycleCompleteFlows",
    "pathCompleteFlows",
    "packetPorts",
    "packetHandshakePorts",
    "preflowPorts",
    "packetTerminalPorts",
    "preflowCandidatePorts",
    "preflowMissedPorts",
    "capacityEvents",
    "pressureEvents",
    "ingressControlPackets",
    "ingressSynPackets",
    "egressControlPackets",
    "egressSynAckPackets",
    "ingressPayloadPackets",
    "ingressPayloadBytes",
    "egressPayloadPackets",
    "egressPayloadBytes",
    "finPackets",
    "rstPackets",
]


def runtime_packet_surface_source(path: Path) -> dict[str, Any]:
    summary = load_summary(path)
    totals = summary.get("totals") or {}
    conclusion = summary.get("conclusion") or {}
    source = {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "label": str(summary.get("label") or ""),
        "status": str(conclusion.get("status") or ""),
        **{field: int(totals.get(field) or 0) for field in COUNT_FIELDS},
        "classifications": count_keys(totals.get("classifications")),
        "packetTerminalByReason": count_keys(totals.get("packetTerminalByReason")),
        "preflowCandidateByReason": count_keys(totals.get("preflowCandidateByReason")),
        "preflowMissedByReason": count_keys(totals.get("preflowMissedByReason")),
        "preflowMissedBySocketState": count_keys(
            totals.get("preflowMissedBySocketState")
        ),
        "privacy": empty_privacy_flags(),
    }
    source["clean"] = runtime_packet_surface_clean(source)
    return source


def runtime_packet_surface_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "clean": bool(sources) and all(source["clean"] for source in sources),
        "statuses": sorted({source["status"] for source in sources if source["status"]}),
        **{field: sum(source[field] for source in sources) for field in COUNT_FIELDS},
        "classifications": merge_items(sources, "classifications"),
        "packetTerminalByReason": merge_items(sources, "packetTerminalByReason"),
        "preflowCandidateByReason": merge_items(sources, "preflowCandidateByReason"),
        "preflowMissedByReason": merge_items(sources, "preflowMissedByReason"),
        "preflowMissedBySocketState": merge_items(
            sources,
            "preflowMissedBySocketState",
        ),
        "sources": sources,
    }


def runtime_packet_surface_clean(source: dict[str, Any]) -> bool:
    flows = source["flows"]
    return (
        source["schema"] == PACKET_SURFACE_SCHEMA
        and source["status"] == "clean"
        and source["runs"] > 0
        and source["cleanRuns"] == source["runs"]
        and source["failedRuns"] == 0
        and source["classifications"] == ["clean"]
        and flows > 0
        and source["startedFlows"] == flows
        and source["closedFlows"] == flows
        and source["failedFlows"] == 0
        and source["lifecycleCompleteFlows"] == flows
        and source["pathCompleteFlows"] == flows
        and source["packetPorts"] == flows
        and source["packetHandshakePorts"] == flows
        and source["preflowPorts"] == flows
        and source["packetTerminalPorts"] == 0
        and source["preflowMissedPorts"] == 0
        and source["capacityEvents"] > 0
        and not any(source["privacy"].values())
    )
