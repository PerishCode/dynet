from __future__ import annotations

import json
from pathlib import Path
from typing import Any


REPEAT_SCHEMA = "dynet-vm-private-runtime-repeat/v1alpha1"


def runtime_fallback_source(path: Path) -> dict[str, Any]:
    summary = load_json(path)
    if summary.get("schema") == REPEAT_SCHEMA:
        return runtime_fallback_repeat_source(path, summary)
    return runtime_fallback_run_source(path, summary)


def runtime_fallback_run_source(path: Path, summary: dict[str, Any]) -> dict[str, Any]:
    tcp = summary.get("tcpFlow") or {}
    workload = (summary.get("workloadProbe") or {}).get("totals") or {}
    return {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "label": str(summary.get("label") or ""),
        "mode": fallback_mode(tcp),
        "checksClean": checks_clean(summary),
        "workloadAttempted": int(workload.get("count") or 0),
        "workloadFailure": int(workload.get("failure") or 0),
        "tcpFlowFailed": int(tcp.get("failedFlows") or 0),
        "routeFallbackUsed": int(tcp.get("routeFallbackUsedFlows") or 0),
        "routeFallbackAttempts": int(tcp.get("routeFallbackAttemptEvents") or 0),
        "routeFallbackFailed": int(tcp.get("routeFallbackFailedFlows") or 0),
        "pathComplete": int(tcp.get("pathCompleteFlows") or 0),
        "lifecycleComplete": int(tcp.get("lifecycleCompleteFlows") or 0),
        "payloadBidirectional": int(tcp.get("payloadBidirectionalFlows") or 0),
        "stageFailedFlows": int(tcp.get("stageFailedFlows") or 0),
        "finalOutbounds": keyed_counts(tcp.get("routeFallbackByFinalOutbound")),
        "attemptedOutbounds": keyed_counts(tcp.get("routeFallbackByAttemptedOutbound")),
        "privacy": privacy_flags(summary),
    }


def runtime_fallback_repeat_source(path: Path, summary: dict[str, Any]) -> dict[str, Any]:
    totals = summary.get("totals") or {}
    final = keyed_counts(totals.get("tcpFlowRouteFallbackByFinalOutbound"))
    attempted = keyed_counts(totals.get("tcpFlowRouteFallbackByAttemptedOutbound"))
    return {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "label": str(summary.get("label") or ""),
        "mode": fallback_mode_from_final(final),
        "checksClean": repeat_checks_clean(totals),
        "workloadAttempted": int(totals.get("workloadAttempted") or 0),
        "workloadFailure": int(totals.get("workloadFailure") or 0),
        "tcpFlowFailed": int(totals.get("tcpFlowFailed") or 0),
        "routeFallbackUsed": int(totals.get("tcpFlowRouteFallbackUsed") or 0),
        "routeFallbackAttempts": int(totals.get("tcpFlowRouteFallbackAttempts") or 0),
        "routeFallbackFailed": int(totals.get("tcpFlowRouteFallbackFailed") or 0),
        "pathComplete": int(totals.get("tcpFlowPathComplete") or 0),
        "lifecycleComplete": int(totals.get("tcpFlowLifecycleComplete") or 0),
        "payloadBidirectional": int(
            totals.get("tcpFlowPayloadBidirectional") or 0
        ),
        "stageFailedFlows": int(totals.get("tcpFlowStageFailed") or 0),
        "finalOutbounds": final,
        "attemptedOutbounds": attempted,
        "privacy": repeat_privacy_flags(path, summary),
    }


def runtime_fallback_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "clean": bool(sources) and all(runtime_fallback_clean(source) for source in sources),
        "modes": sorted({source["mode"] for source in sources if source["mode"]}),
        "workloadAttempted": sum(source["workloadAttempted"] for source in sources),
        "workloadFailure": sum(source["workloadFailure"] for source in sources),
        "tcpFlowFailed": sum(source["tcpFlowFailed"] for source in sources),
        "routeFallbackUsed": sum(source["routeFallbackUsed"] for source in sources),
        "routeFallbackFailed": sum(source["routeFallbackFailed"] for source in sources),
        "stageFailedFlows": sum(source["stageFailedFlows"] for source in sources),
        "sources": sources,
    }


def runtime_fallback_clean(source: dict[str, Any]) -> bool:
    return (
        source["mode"] in {"direct", "non-direct"}
        and source["checksClean"]
        and source["workloadAttempted"] > 0
        and source["workloadFailure"] == 0
        and source["tcpFlowFailed"] == 0
        and source["routeFallbackUsed"] > 0
        and source["routeFallbackAttempts"] >= 2 * source["routeFallbackUsed"]
        and source["routeFallbackFailed"] == 0
        and source["pathComplete"] > 0
        and source["lifecycleComplete"] > 0
        and source["payloadBidirectional"] > 0
        and not any(source["privacy"].values())
    )


def fallback_mode(tcp: dict[str, Any]) -> str:
    return fallback_mode_from_final(keyed_counts(tcp.get("routeFallbackByFinalOutbound")))


def fallback_mode_from_final(final: dict[str, int]) -> str:
    if final.get("direct", 0) > 0:
        return "direct"
    if final.get("private-via-tunnel", 0) > 0 and final.get("direct", 0) == 0:
        return "non-direct"
    return "unknown"


def checks_clean(summary: dict[str, Any]) -> bool:
    checks = [item for item in summary.get("checks", []) if isinstance(item, dict)]
    return bool(checks) and all(item.get("passed") is True for item in checks)


def repeat_checks_clean(totals: dict[str, Any]) -> bool:
    runs = int(totals.get("runs") or 0)
    return (
        runs > 0
        and int(totals.get("passedRuns") or 0) == runs
        and int(totals.get("failedRuns") or 0) == 0
    )


def privacy_flags(summary: dict[str, Any]) -> dict[str, bool]:
    workload = summary.get("workloadProbe") or {}
    capture = workload.get("tunCapture") or {}
    workload_privacy = workload.get("privacy") or {}
    privacy = summary.get("privacy") or {}
    return {
        "rawLogsStored": bool(privacy.get("rawLogsStored")),
        "rawPacketsStored": bool(capture.get("rawPcapStored"))
        or bool(capture.get("rawLinesStored")),
        "rawSecretsStored": bool(privacy.get("rawSecretsStored")),
        "responseBodiesStored": bool(workload_privacy.get("responseBodiesStored")),
        "responseHeadersStored": bool(workload_privacy.get("responseHeadersStored")),
        "identityInformationSent": bool(privacy.get("identityInformationSent"))
        or bool(workload_privacy.get("identityInformationSent")),
    }


def repeat_privacy_flags(path: Path, summary: dict[str, Any]) -> dict[str, bool]:
    flags = privacy_flags(summary)
    for run_summary_path in sorted(path.parent.glob("run-*/summary.json")):
        flags = merge_privacy_flags(flags, privacy_flags(load_json(run_summary_path)))
    return flags


def merge_privacy_flags(
    left: dict[str, bool],
    right: dict[str, bool],
) -> dict[str, bool]:
    return {key: bool(left.get(key)) or bool(right.get(key)) for key in left}


def keyed_counts(rows: object) -> dict[str, int]:
    if not isinstance(rows, list):
        return {}
    result = {}
    for row in rows:
        if isinstance(row, dict) and row.get("key"):
            result[str(row["key"])] = int(row.get("count") or 0)
    return result


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text())
