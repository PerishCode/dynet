from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from common import Lab, validate_name
from private_runtime_lib.tcp_flow import tcp_flow_brief
from private_runtime_lib.tcp_flow.packet import (
    tcp_packet_ports,
    tcp_packet_terminal_ports,
    tcp_preflow_candidate_ports,
    tcp_preflow_missed_ports,
    tcp_preflow_ports,
)


PACKET_SURFACE_SCHEMA = "dynet-vm-private-runtime-packet-surface/v1alpha1"
REPEAT_SCHEMA = "dynet-vm-private-runtime-repeat/v1alpha1"
PACKET_COUNT_KEYS = [
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


def command_packet_surface(_lab: Lab, args: argparse.Namespace) -> None:
    label = validate_name(args.label or "packet-surface", "label")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = build_packet_surface_summary(
        label,
        output_dir,
        [Path(item) for item in args.input],
    )
    write_packet_surface_summary(output_dir, summary)
    print(json.dumps(packet_print(output_dir, summary), sort_keys=True))


def build_packet_surface_summary(
    label: str,
    output_dir: Path,
    inputs: list[Path],
) -> dict[str, Any]:
    rows = [packet_surface_row(path) for path in expand_inputs(inputs)]
    totals = packet_surface_totals(rows)
    return {
        "schema": PACKET_SURFACE_SCHEMA,
        "label": label,
        "outputDir": str(output_dir),
        "runs": rows,
        "totals": totals,
        "conclusion": packet_surface_conclusion(totals),
        "policy": {
            "plannerPenaltySafe": False,
            "qualityPenaltySafe": False,
            "reason": "Packet/preflow evidence is runtime-shape evidence, not penalty proof.",
        },
    }


def expand_inputs(inputs: list[Path]) -> list[Path]:
    paths: list[Path] = []
    for path in inputs:
        summary = load_optional_json(path / "summary.json")
        if summary.get("schema") == REPEAT_SCHEMA:
            paths.extend(
                Path(row["path"])
                for row in summary.get("runs", [])
                if isinstance(row, dict) and row.get("path")
            )
        else:
            paths.append(path)
    return paths


def packet_surface_row(run_dir: Path) -> dict[str, Any]:
    summary = load_optional_json(run_dir / "summary.json")
    current = packet_counts(load_optional_json(run_dir / "runtime-report.json"))
    clean = packet_counts_clean(current)
    return {
        "label": summary.get("label") or run_dir.name,
        "path": str(run_dir),
        "classification": "clean" if clean else packet_classification(current),
        "clean": clean,
        "current": current,
    }


def packet_counts(report: dict[str, Any]) -> dict[str, Any]:
    flow = tcp_flow_brief(report)
    packets = tcp_packet_ports(report)
    preflows = tcp_preflow_ports(report)
    terminals = tcp_packet_terminal_ports(report)
    candidates = tcp_preflow_candidate_ports(report)
    missed = tcp_preflow_missed_ports(report)
    return {
        "flows": int(flow.get("flows") or 0),
        "startedFlows": int(flow.get("startedFlows") or 0),
        "closedFlows": int(flow.get("closedFlows") or 0),
        "failedFlows": int(flow.get("failedFlows") or 0),
        "lifecycleCompleteFlows": int(flow.get("lifecycleCompleteFlows") or 0),
        "pathCompleteFlows": int(flow.get("pathCompleteFlows") or 0),
        "packetPorts": len(packets),
        "packetHandshakePorts": packet_handshake_ports(packets),
        "preflowPorts": len(preflows),
        "packetTerminalPorts": len(terminals),
        "preflowCandidatePorts": len(candidates),
        "preflowMissedPorts": len(missed),
        "capacityEvents": count_events(report, "tcp-forwarder-capacity"),
        "pressureEvents": count_events(report, "tcp-forwarder-pressure"),
        **packet_totals(packets),
        "packetTerminalByReason": aggregate_rows(terminals.values(), "reason"),
        "preflowCandidateByReason": aggregate_rows(candidates.values(), "reason"),
        "preflowMissedByReason": aggregate_rows(missed.values(), "reason"),
        "preflowMissedBySocketState": aggregate_rows(missed.values(), "socketState"),
    }


def packet_totals(packets: dict[int, dict[str, Any]]) -> dict[str, int]:
    keys = [
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
    return {
        key: sum(int(row.get(key) or 0) for row in packets.values())
        for key in keys
    }


def packet_counts_clean(counts: dict[str, Any]) -> bool:
    flows = int(counts["flows"])
    return (
        flows > 0
        and counts["startedFlows"] == flows
        and counts["closedFlows"] == flows
        and counts["failedFlows"] == 0
        and counts["lifecycleCompleteFlows"] == flows
        and counts["pathCompleteFlows"] == flows
        and counts["packetPorts"] == flows
        and counts["packetHandshakePorts"] == flows
        and counts["preflowPorts"] == flows
        and counts["packetTerminalPorts"] == 0
        and counts["preflowMissedPorts"] == 0
        and counts["capacityEvents"] > 0
    )


def packet_classification(counts: dict[str, Any]) -> str:
    flows = int(counts["flows"])
    if int(counts["failedFlows"]):
        return "flow-failure"
    if int(counts["packetTerminalPorts"]):
        return "packet-terminal"
    if int(counts["preflowMissedPorts"]):
        return "preflow-missed"
    if int(counts["packetPorts"]) < flows:
        return "packet-missing"
    if int(counts["packetHandshakePorts"]) < flows:
        return "packet-handshake-missing"
    if int(counts["preflowPorts"]) < flows:
        return "preflow-missing"
    if int(counts["closedFlows"]) < flows or int(counts["lifecycleCompleteFlows"]) < flows:
        return "flow-lifecycle-incomplete"
    if int(counts["capacityEvents"]) == 0:
        return "capacity-missing"
    return "packet-surface-incomplete"


def packet_surface_totals(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "runs": len(rows),
        "cleanRuns": sum(1 for row in rows if row["clean"]),
        "failedRuns": sum(1 for row in rows if not row["clean"]),
        "classifications": aggregate(row["classification"] for row in rows),
        **{
            key: sum(int(row["current"].get(key) or 0) for row in rows)
            for key in PACKET_COUNT_KEYS
        },
        "packetTerminalByReason": merge_count_rows(
            row["current"]["packetTerminalByReason"] for row in rows
        ),
        "preflowCandidateByReason": merge_count_rows(
            row["current"]["preflowCandidateByReason"] for row in rows
        ),
        "preflowMissedByReason": merge_count_rows(
            row["current"]["preflowMissedByReason"] for row in rows
        ),
        "preflowMissedBySocketState": merge_count_rows(
            row["current"]["preflowMissedBySocketState"] for row in rows
        ),
    }


def packet_surface_conclusion(totals: dict[str, Any]) -> dict[str, Any]:
    clean = totals["runs"] > 0 and totals["failedRuns"] == 0
    return {
        "status": "clean" if clean else "packet-surface-needs-evidence",
        "nextAction": (
            "return-to-runtime-surface"
            if clean
            else "inspect-packet-preflow-session-promotion"
        ),
        "plannerPenaltySafe": False,
        "qualityPenaltySafe": False,
    }


def write_packet_surface_summary(output_dir: Path, summary: dict[str, Any]) -> None:
    (output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n"
    )
    write_packet_markdown(output_dir / "summary.md", summary)


def write_packet_markdown(path: Path, summary: dict[str, Any]) -> None:
    totals = summary["totals"]
    lines = [
        "# VM Private Runtime Packet Surface",
        "",
        f"- label: `{summary['label']}`",
        f"- status: `{summary['conclusion']['status']}`",
        f"- runs: `{totals['runs']}`",
        f"- clean runs: `{totals['cleanRuns']}`",
        f"- flows: `{totals['flows']}`",
        f"- packet ports: `{totals['packetPorts']}`",
        f"- packet handshakes: `{totals['packetHandshakePorts']}`",
        f"- preflow ports: `{totals['preflowPorts']}`",
        f"- packet terminals: `{totals['packetTerminalPorts']}`",
        f"- preflow missed: `{totals['preflowMissedPorts']}`",
        f"- capacity events: `{totals['capacityEvents']}`",
        f"- pressure events: `{totals['pressureEvents']}`",
        "",
        "## Runs",
        "",
    ]
    for row in summary["runs"]:
        lines.append(
            f"- `{row['label']}` classification=`{row['classification']}` "
            f"clean=`{row['clean']}`"
        )
    path.write_text("\n".join(lines) + "\n")


def packet_print(output_dir: Path, summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "outputDir": str(output_dir),
        "runs": summary["totals"]["runs"],
        "cleanRuns": summary["totals"]["cleanRuns"],
        "status": summary["conclusion"]["status"],
    }


def packet_handshake_ports(packets: dict[int, dict[str, Any]]) -> int:
    return sum(
        1
        for row in packets.values()
        if int(row.get("ingressSynPackets") or 0) > 0
        and int(row.get("egressSynAckPackets") or 0) > 0
    )


def count_events(report: dict[str, Any], kind: str) -> int:
    return sum(
        1
        for event in report.get("events", [])
        if isinstance(event, dict) and event.get("kind") == kind
    )


def aggregate_rows(rows: Any, field: str) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        key = str(row.get(field) or "")
        if key:
            counts[key] = counts.get(key, 0) + 1
    return [{"key": key, "count": counts[key]} for key in sorted(counts)]


def aggregate(values: Any) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for value in values:
        key = str(value or "")
        if key:
            counts[key] = counts.get(key, 0) + 1
    return [{"key": key, "count": counts[key]} for key in sorted(counts)]


def merge_count_rows(row_sets: Any) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for rows in row_sets:
        for row in rows:
            key = str(row.get("key") or "")
            if key:
                counts[key] = counts.get(key, 0) + int(row.get("count") or 0)
    return [{"key": key, "count": counts[key]} for key in sorted(counts)]


def load_optional_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text())
