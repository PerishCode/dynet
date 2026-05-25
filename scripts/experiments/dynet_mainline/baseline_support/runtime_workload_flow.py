from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from dynet_clash import runtime_gate


def runtime_workload_flow_source(path: Path) -> dict[str, Any]:
    summary = load_json(path)
    gate = runtime_gate.build(summary, str(path)) if summary else runtime_gate.missing()
    totals = gate.get("totals") or {}
    return {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "label": str(summary.get("label") or ""),
        "clean": bool(gate.get("clean")) and not any(privacy_flags(path, summary).values()),
        "classification": str(gate.get("classification") or ""),
        "failedChecks": [str(item) for item in gate.get("failedChecks", [])],
        "runs": int(totals.get("runs") or 0),
        "workloadAttempted": int(totals.get("workloadAttempted") or 0),
        "workloadFailure": int(totals.get("workloadFailure") or 0),
        "tcpAttemptedEntries": int(totals.get("tcpAttemptedEntries") or 0),
        "tcpAttemptedCoveredEntries": int(
            totals.get("tcpAttemptedCoveredEntries") or 0
        ),
        "runtimePreflowMatchedEntries": int(
            totals.get("runtimePreflowMatchedEntries") or 0
        ),
        "runtimePacketHandshakeEntries": int(
            totals.get("runtimePacketHandshakeEntries") or 0
        ),
        "tunCaptureMatchedEntries": int(totals.get("tunCaptureMatchedEntries") or 0),
        "unmatchedEntries": int(totals.get("unmatchedEntries") or 0),
        "runtimePacketTerminalEntries": int(
            totals.get("runtimePacketTerminalEntries") or 0
        ),
        "tcpFlowFailed": int(totals.get("tcpFlowFailed") or 0),
        "tcpSlotPressureEvents": int(totals.get("tcpSlotPressureEvents") or 0),
        "privacy": privacy_flags(path, summary),
        "gate": gate,
    }


def runtime_workload_flow_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "clean": bool(sources) and all(source["clean"] for source in sources),
        "classifications": sorted({
            source["classification"] for source in sources if source["classification"]
        }),
        "runs": sum(source["runs"] for source in sources),
        "workloadAttempted": sum(source["workloadAttempted"] for source in sources),
        "workloadFailure": sum(source["workloadFailure"] for source in sources),
        "tcpAttemptedEntries": sum(source["tcpAttemptedEntries"] for source in sources),
        "tcpAttemptedCoveredEntries": sum(
            source["tcpAttemptedCoveredEntries"] for source in sources
        ),
        "runtimePreflowMatchedEntries": sum(
            source["runtimePreflowMatchedEntries"] for source in sources
        ),
        "runtimePacketHandshakeEntries": sum(
            source["runtimePacketHandshakeEntries"] for source in sources
        ),
        "tunCaptureMatchedEntries": sum(
            source["tunCaptureMatchedEntries"] for source in sources
        ),
        "unmatchedEntries": sum(source["unmatchedEntries"] for source in sources),
        "runtimePacketTerminalEntries": sum(
            source["runtimePacketTerminalEntries"] for source in sources
        ),
        "tcpFlowFailed": sum(source["tcpFlowFailed"] for source in sources),
        "tcpSlotPressureEvents": sum(source["tcpSlotPressureEvents"] for source in sources),
        "sources": sources,
    }


def privacy_flags(path: Path, summary: dict[str, Any]) -> dict[str, bool]:
    summaries = run_summaries(path, summary)
    flags = empty_privacy_flags()
    for item in summaries:
        current = summary_privacy_flags(item)
        for key, value in current.items():
            flags[key] = flags[key] or value
    return flags


def run_summaries(path: Path, summary: dict[str, Any]) -> list[dict[str, Any]]:
    if summary.get("schema") == "dynet-vm-private-runtime-repeat/v1alpha1":
        return [
            load_json(run_summary_path)
            for run_summary_path in sorted(path.parent.glob("run-*/summary.json"))
        ]
    return [summary] if summary else []


def summary_privacy_flags(summary: dict[str, Any]) -> dict[str, bool]:
    privacy = summary.get("privacy") or {}
    metadata_privacy = (summary.get("metadata") or {}).get("privacy") or {}
    workload_privacy = ((summary.get("workloadProbe") or {}).get("privacy")) or {}
    tun_capture = ((summary.get("workloadProbe") or {}).get("tunCapture")) or {}
    return {
        "rawLogsStored": bool(privacy.get("rawLogsStored")),
        "rawPacketsStored": bool(privacy.get("rawPacketsStored"))
        or bool(tun_capture.get("rawLinesStored"))
        or bool(tun_capture.get("rawPcapStored")),
        "rawSecretsStored": bool(privacy.get("rawSecretsStored"))
        or bool(metadata_privacy.get("rawSecretsStored")),
        "responseBodiesStored": bool(privacy.get("responseBodiesStored"))
        or bool(privacy.get("rawResponseBodiesStored"))
        or bool(workload_privacy.get("responseBodiesStored")),
        "identityInformationSent": bool(privacy.get("identityInformationSent"))
        or bool(metadata_privacy.get("identityInformationSent"))
        or bool(workload_privacy.get("identityInformationSent")),
    }


def empty_privacy_flags() -> dict[str, bool]:
    return {
        "rawLogsStored": False,
        "rawPacketsStored": False,
        "rawSecretsStored": False,
        "responseBodiesStored": False,
        "identityInformationSent": False,
    }


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text())
