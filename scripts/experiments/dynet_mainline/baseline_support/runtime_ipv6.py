from __future__ import annotations

import json
from pathlib import Path
from typing import Any


REPEAT_SCHEMA = "dynet-vm-private-runtime-repeat/v1alpha1"

REQUIRED_CHECKS = {
    "ipv6-blackbox-no-response",
    "ipv6-denied-counter",
    "ipv6-denied-event",
    "tcp-blackbox-https",
    "tcp-flow-lifecycle-complete",
    "tcp-flow-path-complete",
    "tcp-flow-payload-bidirectional",
}

CONTROL_FLAGS = {
    "forceBoundCandidate",
    "forcePrivateDownstreamFailure",
    "poisonBoundOnly",
    "poisonFirstBoundCandidate",
    "tcpRouteDirectFallback",
    "tcpRouteNonDirectFallback",
}


def runtime_ipv6_source(path: Path) -> dict[str, Any]:
    summary = load_json(path)
    if summary.get("schema") == REPEAT_SCHEMA:
        return runtime_ipv6_repeat_source(path, summary)
    return runtime_ipv6_run_source(path, summary)


def runtime_ipv6_repeat_source(path: Path, summary: dict[str, Any]) -> dict[str, Any]:
    totals = summary.get("totals") or {}
    run_summaries = [
        load_json(run_summary_path)
        for run_summary_path in sorted(path.parent.glob("run-*/summary.json"))
    ]
    checks = merged_check_map(run_summaries)
    return {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "label": str(summary.get("label") or ""),
        "runtimeDnsMode": str(summary.get("runtimeDnsMode") or ""),
        "tcpForward": bool(summary.get("tcpForward")),
        "ipv6NoLeak": bool(summary.get("ipv6NoLeak")),
        "runs": int(totals.get("runs") or 0),
        "passedRuns": int(totals.get("passedRuns") or 0),
        "failedRuns": int(totals.get("failedRuns") or 0),
        "runSummaryCount": len(run_summaries),
        "checksClean": checks_clean(checks),
        "missingChecks": sorted(REQUIRED_CHECKS - set(checks)),
        "candidateControlClean": candidate_control_clean(summary.get("candidateControl")),
        "ipv6NoLeakOk": sum(1 for run in run_summaries if ipv6_probe_ok(run)),
        "ipv6PacketsDenied": int(totals.get("ipv6PacketsDenied") or 0),
        "ipDenials": int(totals.get("ipDenials") or 0),
        "dnsEarlyTimeouts": int(totals.get("dnsEarlyTimeouts") or 0),
        "tcpFlowStarted": int(totals.get("tcpFlowStarted") or 0),
        "tcpFlowPathComplete": int(totals.get("tcpFlowPathComplete") or 0),
        "tcpFlowLifecycleComplete": int(totals.get("tcpFlowLifecycleComplete") or 0),
        "tcpFlowPayloadBidirectional": int(
            totals.get("tcpFlowPayloadBidirectional") or 0
        ),
        "tcpFlowFailed": int(totals.get("tcpFlowFailed") or 0),
        "tcpFlowStageFailed": int(totals.get("tcpFlowStageFailed") or 0),
        "privacy": repeat_privacy_flags(run_summaries),
    }


def runtime_ipv6_run_source(path: Path, summary: dict[str, Any]) -> dict[str, Any]:
    checks = check_map(summary)
    totals = summary.get("totals") or {}
    runtime = summary.get("runtime") or {}
    tcp = summary.get("tcpFlow") or {}
    product = summary.get("productForwarding") or {}
    failed_checks = int(totals.get("failed") or 0)
    return {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "label": str(summary.get("label") or ""),
        "runtimeDnsMode": str(summary.get("runtimeDnsMode") or ""),
        "tcpForward": bool(product.get("tcpForwardingImplemented")),
        "ipv6NoLeak": bool(product.get("ipv6NoLeakGuardEnabled")),
        "runs": 1,
        "passedRuns": 1 if failed_checks == 0 else 0,
        "failedRuns": 0 if failed_checks == 0 else 1,
        "runSummaryCount": 1,
        "checksClean": checks_clean(checks),
        "missingChecks": sorted(REQUIRED_CHECKS - set(checks)),
        "candidateControlClean": candidate_control_clean(summary.get("candidateControl")),
        "ipv6NoLeakOk": 1 if ipv6_probe_ok(summary) else 0,
        "ipv6PacketsDenied": int(runtime.get("ipv6PacketsDenied") or 0),
        "ipDenials": int((summary.get("stability") or {}).get("ipDenials") or 0),
        "dnsEarlyTimeouts": int((summary.get("stability") or {}).get("dnsEarlyTimeouts") or 0),
        "tcpFlowStarted": int(tcp.get("startedFlows") or 0),
        "tcpFlowPathComplete": int(tcp.get("pathCompleteFlows") or 0),
        "tcpFlowLifecycleComplete": int(tcp.get("lifecycleCompleteFlows") or 0),
        "tcpFlowPayloadBidirectional": int(tcp.get("payloadBidirectionalFlows") or 0),
        "tcpFlowFailed": int(tcp.get("failedFlows") or 0),
        "tcpFlowStageFailed": int(tcp.get("stageFailedFlows") or 0),
        "privacy": privacy_flags(summary),
    }


def runtime_ipv6_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "clean": bool(sources) and all(runtime_ipv6_clean(source) for source in sources),
        "runtimeDnsModes": sorted({
            source["runtimeDnsMode"] for source in sources if source["runtimeDnsMode"]
        }),
        "runs": sum(source["runs"] for source in sources),
        "passedRuns": sum(source["passedRuns"] for source in sources),
        "failedRuns": sum(source["failedRuns"] for source in sources),
        "ipv6NoLeakOk": sum(source["ipv6NoLeakOk"] for source in sources),
        "ipv6PacketsDenied": sum(source["ipv6PacketsDenied"] for source in sources),
        "ipDenials": sum(source["ipDenials"] for source in sources),
        "tcpFlowStarted": sum(source["tcpFlowStarted"] for source in sources),
        "tcpFlowFailed": sum(source["tcpFlowFailed"] for source in sources),
        "tcpFlowStageFailed": sum(source["tcpFlowStageFailed"] for source in sources),
        "sources": sources,
    }


def runtime_ipv6_clean(source: dict[str, Any]) -> bool:
    return (
        source["runtimeDnsMode"] == "config-chain"
        and source["tcpForward"]
        and source["ipv6NoLeak"]
        and source["runs"] > 0
        and source["passedRuns"] == source["runs"]
        and source["failedRuns"] == 0
        and source["runSummaryCount"] >= source["runs"]
        and source["checksClean"]
        and not source["missingChecks"]
        and source["candidateControlClean"]
        and source["ipv6NoLeakOk"] == source["runs"]
        and source["ipv6PacketsDenied"] >= source["runs"]
        and source["ipDenials"] >= source["runs"]
        and source["dnsEarlyTimeouts"] == 0
        and source["tcpFlowStarted"] > 0
        and source["tcpFlowPathComplete"] >= source["tcpFlowStarted"]
        and source["tcpFlowLifecycleComplete"] >= source["tcpFlowStarted"]
        and source["tcpFlowPayloadBidirectional"] >= source["tcpFlowStarted"]
        and source["tcpFlowFailed"] == 0
        and source["tcpFlowStageFailed"] == 0
        and not any(source["privacy"].values())
    )


def ipv6_probe_ok(summary: dict[str, Any]) -> bool:
    return bool((summary.get("ipv6Probe") or {}).get("ok"))


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
