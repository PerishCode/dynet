from __future__ import annotations

import json
from pathlib import Path
from typing import Any


REPEAT_SCHEMA = "dynet-vm-private-runtime-repeat/v1alpha1"

REQUIRED_CHECKS = {
    "tcp-blackbox-https",
    "tcp-flow-lifecycle-complete",
    "tcp-flow-path-complete",
    "tcp-flow-payload-bidirectional",
    "udp-session-events",
    "udp-attribution-events",
    "udp-direct-blackbox",
    "udp-sessions",
    "udp-upstream-bytes",
    "udp-downstream-bytes",
    "udp-no-session-failures",
}

CONTROL_FLAGS = {
    "forceBoundCandidate",
    "forcePrivateDownstreamFailure",
    "poisonBoundOnly",
    "poisonFirstBoundCandidate",
    "tcpRouteDirectFallback",
    "tcpRouteNonDirectFallback",
}


def runtime_udp_source(path: Path) -> dict[str, Any]:
    summary = load_json(path)
    if summary.get("schema") == REPEAT_SCHEMA:
        return runtime_udp_repeat_source(path, summary)
    return runtime_udp_run_source(path, summary)


def runtime_udp_repeat_source(path: Path, summary: dict[str, Any]) -> dict[str, Any]:
    totals = summary.get("totals") or {}
    runs = [
        load_json(run_summary_path)
        for run_summary_path in sorted(path.parent.glob("run-*/summary.json"))
    ]
    checks = merged_check_map(runs)
    udp = udp_totals(runs)
    tcp = tcp_totals(runs)
    return {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "label": str(summary.get("label") or ""),
        "runtimeDnsMode": str(summary.get("runtimeDnsMode") or ""),
        "tcpForward": bool(summary.get("tcpForward")),
        "udpForward": bool(summary.get("udpForward")),
        "udpDirectProbe": bool(summary.get("udpDirectProbe")),
        "runs": int(totals.get("runs") or 0),
        "passedRuns": int(totals.get("passedRuns") or 0),
        "failedRuns": int(totals.get("failedRuns") or 0),
        "runSummaryCount": len(runs),
        "checksClean": checks_clean(checks),
        "missingChecks": sorted(REQUIRED_CHECKS - set(checks)),
        "candidateControlClean": candidate_control_clean(summary.get("candidateControl")),
        **udp,
        **tcp,
        "privacy": repeat_privacy_flags(runs),
    }


def runtime_udp_run_source(path: Path, summary: dict[str, Any]) -> dict[str, Any]:
    checks = check_map(summary)
    failed_checks = int((summary.get("totals") or {}).get("failed") or 0)
    product = summary.get("productForwarding") or {}
    return {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "label": str(summary.get("label") or ""),
        "runtimeDnsMode": str(summary.get("runtimeDnsMode") or ""),
        "tcpForward": bool(product.get("tcpForwardingImplemented")),
        "udpForward": bool(product.get("udpForwardingImplemented")),
        "udpDirectProbe": bool((summary.get("udpProbe") or {}).get("ok")),
        "runs": 1,
        "passedRuns": 1 if failed_checks == 0 else 0,
        "failedRuns": 0 if failed_checks == 0 else 1,
        "runSummaryCount": 1,
        "checksClean": checks_clean(checks),
        "missingChecks": sorted(REQUIRED_CHECKS - set(checks)),
        "candidateControlClean": candidate_control_clean(summary.get("candidateControl")),
        **udp_totals([summary]),
        **tcp_totals([summary]),
        "privacy": privacy_flags(summary),
    }


def runtime_udp_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "clean": bool(sources) and all(runtime_udp_clean(source) for source in sources),
        "runtimeDnsModes": sorted({
            source["runtimeDnsMode"] for source in sources if source["runtimeDnsMode"]
        }),
        "runs": sum(source["runs"] for source in sources),
        "passedRuns": sum(source["passedRuns"] for source in sources),
        "failedRuns": sum(source["failedRuns"] for source in sources),
        "udpOk": sum(source["udpOk"] for source in sources),
        "udpSessions": sum(source["udpSessions"] for source in sources),
        "udpUpstreamBytes": sum(source["udpUpstreamBytes"] for source in sources),
        "udpDownstreamBytes": sum(source["udpDownstreamBytes"] for source in sources),
        "udpSessionFailures": sum(source["udpSessionFailures"] for source in sources),
        "udpDroppedPackets": sum(source["udpDroppedPackets"] for source in sources),
        "tcpFlowStarted": sum(source["tcpFlowStarted"] for source in sources),
        "tcpFlowFailed": sum(source["tcpFlowFailed"] for source in sources),
        "tcpFlowStageFailed": sum(source["tcpFlowStageFailed"] for source in sources),
        "sources": sources,
    }


def runtime_udp_clean(source: dict[str, Any]) -> bool:
    return (
        source["runtimeDnsMode"] == "config-chain"
        and source["tcpForward"]
        and source["udpForward"]
        and source["udpDirectProbe"]
        and source["runs"] > 0
        and source["passedRuns"] == source["runs"]
        and source["failedRuns"] == 0
        and source["runSummaryCount"] >= source["runs"]
        and source["checksClean"]
        and not source["missingChecks"]
        and source["candidateControlClean"]
        and source["udpOk"] == source["runs"]
        and source["udpSessions"] >= source["runs"]
        and source["udpUpstreamBytes"] >= source["runs"]
        and source["udpDownstreamBytes"] >= source["runs"]
        and source["udpSessionFailures"] == 0
        and source["udpDroppedPackets"] == 0
        and source["tcpFlowStarted"] > 0
        and source["tcpFlowPathComplete"] >= source["tcpFlowStarted"]
        and source["tcpFlowLifecycleComplete"] >= source["tcpFlowStarted"]
        and source["tcpFlowPayloadBidirectional"] >= source["tcpFlowStarted"]
        and source["tcpFlowFailed"] == 0
        and source["tcpFlowStageFailed"] == 0
        and not any(source["privacy"].values())
    )


def udp_totals(summaries: list[dict[str, Any]]) -> dict[str, int]:
    result = {
        "udpOk": 0,
        "udpSessions": 0,
        "udpUpstreamBytes": 0,
        "udpDownstreamBytes": 0,
        "udpSessionFailures": 0,
        "udpDroppedPackets": 0,
    }
    for summary in summaries:
        runtime = summary.get("runtime") or {}
        result["udpOk"] += 1 if (summary.get("udpProbe") or {}).get("ok") else 0
        result["udpSessions"] += int(runtime.get("udpSessions") or 0)
        result["udpUpstreamBytes"] += int(runtime.get("udpUpstreamBytes") or 0)
        result["udpDownstreamBytes"] += int(runtime.get("udpDownstreamBytes") or 0)
        result["udpSessionFailures"] += int(runtime.get("udpSessionFailures") or 0)
        result["udpDroppedPackets"] += int(runtime.get("udpDroppedPackets") or 0)
    return result


def tcp_totals(summaries: list[dict[str, Any]]) -> dict[str, int]:
    result = {
        "tcpFlowStarted": 0,
        "tcpFlowPathComplete": 0,
        "tcpFlowLifecycleComplete": 0,
        "tcpFlowPayloadBidirectional": 0,
        "tcpFlowFailed": 0,
        "tcpFlowStageFailed": 0,
    }
    for summary in summaries:
        tcp = summary.get("tcpFlow") or {}
        result["tcpFlowStarted"] += int(tcp.get("startedFlows") or 0)
        result["tcpFlowPathComplete"] += int(tcp.get("pathCompleteFlows") or 0)
        result["tcpFlowLifecycleComplete"] += int(
            tcp.get("lifecycleCompleteFlows") or 0
        )
        result["tcpFlowPayloadBidirectional"] += int(
            tcp.get("payloadBidirectionalFlows") or 0
        )
        result["tcpFlowFailed"] += int(tcp.get("failedFlows") or 0)
        result["tcpFlowStageFailed"] += int(tcp.get("stageFailedFlows") or 0)
    return result


def check_map(summary: dict[str, Any]) -> dict[str, bool]:
    result = {}
    for item in summary.get("checks", []):
        if isinstance(item, dict) and item.get("name"):
            result[str(item["name"])] = item.get("passed") is True
    return result


def merged_check_map(summaries: list[dict[str, Any]]) -> dict[str, bool]:
    result: dict[str, bool] = {}
    for summary in summaries:
        for name, passed in check_map(summary).items():
            result[name] = result.get(name, True) and passed
    return result


def checks_clean(checks: dict[str, bool]) -> bool:
    return bool(checks) and all(checks.values())


def candidate_control_clean(control: object) -> bool:
    if not isinstance(control, dict):
        return True
    return not any(bool(control.get(flag)) for flag in CONTROL_FLAGS)


def repeat_privacy_flags(summaries: list[dict[str, Any]]) -> dict[str, bool]:
    flags = empty_privacy_flags()
    for summary in summaries:
        flags = merge_privacy_flags(flags, privacy_flags(summary))
    return flags


def privacy_flags(summary: dict[str, Any]) -> dict[str, bool]:
    privacy = summary.get("privacy") or {}
    return {
        "rawLogsStored": bool(privacy.get("rawLogsStored")),
        "rawPacketsStored": bool(privacy.get("rawPacketsStored")),
        "rawSecretsStored": bool(privacy.get("rawSecretsStored")),
        "responseBodiesStored": bool(privacy.get("responseBodiesStored")),
        "responseHeadersStored": bool(privacy.get("responseHeadersStored")),
        "identityInformationSent": bool(privacy.get("identityInformationSent"))
        or bool(privacy.get("cookiesSent"))
        or bool(privacy.get("authorizationSent")),
    }


def empty_privacy_flags() -> dict[str, bool]:
    return {
        "rawLogsStored": False,
        "rawPacketsStored": False,
        "rawSecretsStored": False,
        "responseBodiesStored": False,
        "responseHeadersStored": False,
        "identityInformationSent": False,
    }


def merge_privacy_flags(
    left: dict[str, bool],
    right: dict[str, bool],
) -> dict[str, bool]:
    return {key: bool(left.get(key)) or bool(right.get(key)) for key in left}


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text())
