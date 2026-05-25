from __future__ import annotations

import json
from pathlib import Path
from typing import Any


REPEAT_SCHEMA = "dynet-vm-private-runtime-repeat/v1alpha1"
DNS_REFRESH_SCHEMA = "dynet-vm-private-runtime-dns-refresh/v1alpha1"

REQUIRED_CHECKS = {
    "dns-queries",
    "dns-forwarding",
    "dns-records",
    "all-dns-names-observed",
    "workload-dns-observed",
    "workload-all-success",
    "workload-flow-covered",
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


def runtime_dns_product_source(path: Path) -> dict[str, Any]:
    summary = load_json(path)
    if summary.get("schema") == REPEAT_SCHEMA:
        return runtime_dns_repeat_source(path, summary)
    return runtime_dns_run_source(path, summary)


def runtime_dns_repeat_source(path: Path, summary: dict[str, Any]) -> dict[str, Any]:
    totals = summary.get("totals") or {}
    run_summaries = [
        load_json(run_summary_path)
        for run_summary_path in sorted(path.parent.glob("run-*/summary.json"))
    ]
    checks = merged_check_map(run_summaries)
    runtime = runtime_totals(run_summaries)
    return {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "label": str(summary.get("label") or ""),
        "runtimeDnsMode": str(summary.get("runtimeDnsMode") or ""),
        "clientDnsTarget": str(summary.get("clientDnsTarget") or ""),
        "tcpForward": bool(summary.get("tcpForward")),
        "udpForward": bool(summary.get("udpForward")),
        "udpDirectProbe": bool(summary.get("udpDirectProbe")),
        "qualityStateUsed": bool(summary.get("qualityStateUsed")),
        "runs": int(totals.get("runs") or 0),
        "passedRuns": int(totals.get("passedRuns") or 0),
        "failedRuns": int(totals.get("failedRuns") or 0),
        "runSummaryCount": len(run_summaries),
        "checksClean": checks_clean(checks),
        "missingChecks": sorted(REQUIRED_CHECKS - set(checks)),
        "candidateControlClean": candidate_control_clean(summary.get("candidateControl")),
        "adapterTypes": adapter_types(run_summaries),
        "dnsNamesExpected": dns_names_expected(run_summaries),
        "dnsQueries": runtime["dnsQueries"],
        "dnsRecords": runtime["dnsRecords"],
        "proxiedDnsQueries": runtime["proxiedDnsQueries"],
        "workloadAttempted": int(totals.get("workloadAttempted") or 0),
        "workloadSuccess": int(totals.get("workloadSuccess") or 0),
        "workloadFailure": int(totals.get("workloadFailure") or 0),
        "dnsEarlyTimeouts": int(totals.get("dnsEarlyTimeouts") or 0),
        "tcpFlowFailed": int(totals.get("tcpFlowFailed") or 0),
        "tcpFlowPathComplete": int(totals.get("tcpFlowPathComplete") or 0),
        "tcpFlowPayloadBidirectional": int(
            totals.get("tcpFlowPayloadBidirectional") or 0
        ),
        "workloadFlowMatchedEntries": int(
            totals.get("workloadFlowMatchedEntries") or 0
        ),
        "workloadFlowRuntimePreflowMatchedEntries": int(
            totals.get("workloadFlowRuntimePreflowMatchedEntries") or 0
        ),
        "privacy": repeat_privacy_flags(run_summaries),
    }


def runtime_dns_run_source(path: Path, summary: dict[str, Any]) -> dict[str, Any]:
    checks = check_map(summary)
    workload = (summary.get("workloadProbe") or {}).get("totals") or {}
    tcp = summary.get("tcpFlow") or {}
    flow = summary.get("workloadFlow") or {}
    runtime = summary.get("runtime") or {}
    failed_checks = int((summary.get("totals") or {}).get("failed") or 0)
    return {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "label": str(summary.get("label") or ""),
        "runtimeDnsMode": str(summary.get("runtimeDnsMode") or ""),
        "clientDnsTarget": str(summary.get("clientDnsTarget") or ""),
        "tcpForward": bool(
            (summary.get("productForwarding") or {}).get("tcpForwardingImplemented")
        ),
        "udpForward": bool(
            (summary.get("productForwarding") or {}).get("udpForwardingImplemented")
        ),
        "udpDirectProbe": bool((summary.get("udpProbe") or {}).get("results")),
        "qualityStateUsed": bool(summary.get("qualityStateUsed")),
        "runs": 1,
        "passedRuns": 1 if failed_checks == 0 else 0,
        "failedRuns": 0 if failed_checks == 0 else 1,
        "runSummaryCount": 1,
        "checksClean": checks_clean(checks),
        "missingChecks": sorted(REQUIRED_CHECKS - set(checks)),
        "candidateControlClean": candidate_control_clean(summary.get("candidateControl")),
        "adapterTypes": adapter_types([summary]),
        "dnsNamesExpected": dns_names_expected([summary]),
        "dnsQueries": int(runtime.get("dnsQueries") or 0),
        "dnsRecords": int(runtime.get("dnsRecords") or 0),
        "proxiedDnsQueries": int(runtime.get("proxiedDnsQueries") or 0),
        "workloadAttempted": int(workload.get("count") or 0),
        "workloadSuccess": int(workload.get("success") or 0),
        "workloadFailure": int(workload.get("failure") or 0),
        "dnsEarlyTimeouts": int((summary.get("stability") or {}).get("dnsEarlyTimeouts") or 0),
        "tcpFlowFailed": int(tcp.get("failedFlows") or 0),
        "tcpFlowPathComplete": int(tcp.get("pathCompleteFlows") or 0),
        "tcpFlowPayloadBidirectional": int(tcp.get("payloadBidirectionalFlows") or 0),
        "workloadFlowMatchedEntries": int(flow.get("matchedEntries") or 0),
        "workloadFlowRuntimePreflowMatchedEntries": int(
            flow.get("runtimePreflowMatchedEntries") or 0
        ),
        "privacy": privacy_flags(summary),
    }


def runtime_dns_product_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "clean": bool(sources) and all(runtime_dns_product_clean(source) for source in sources),
        "adapterTypes": sorted({
            adapter
            for source in sources
            for adapter in source["adapterTypes"]
            if adapter
        }),
        "runtimeDnsModes": sorted({
            source["runtimeDnsMode"] for source in sources if source["runtimeDnsMode"]
        }),
        "clientDnsTargets": sorted({
            source["clientDnsTarget"] for source in sources if source["clientDnsTarget"]
        }),
        "runs": sum(source["runs"] for source in sources),
        "passedRuns": sum(source["passedRuns"] for source in sources),
        "failedRuns": sum(source["failedRuns"] for source in sources),
        "workloadAttempted": sum(source["workloadAttempted"] for source in sources),
        "workloadFailure": sum(source["workloadFailure"] for source in sources),
        "dnsQueries": sum(source["dnsQueries"] for source in sources),
        "dnsRecords": sum(source["dnsRecords"] for source in sources),
        "dnsEarlyTimeouts": sum(source["dnsEarlyTimeouts"] for source in sources),
        "tcpFlowFailed": sum(source["tcpFlowFailed"] for source in sources),
        "sources": sources,
    }


def runtime_dns_product_clean(source: dict[str, Any]) -> bool:
    return (
        source["runtimeDnsMode"] == "config-chain"
        and source["tcpForward"]
        and source["runs"] > 0
        and source["passedRuns"] == source["runs"]
        and source["failedRuns"] == 0
        and source["runSummaryCount"] >= source["runs"]
        and source["checksClean"]
        and not source["missingChecks"]
        and source["candidateControlClean"]
        and source["workloadAttempted"] > 0
        and source["workloadSuccess"] == source["workloadAttempted"]
        and source["workloadFailure"] == 0
        and source["dnsEarlyTimeouts"] == 0
        and source["dnsQueries"] > 0
        and source["dnsRecords"] >= source["dnsNamesExpected"] > 0
        and source["tcpFlowFailed"] == 0
        and source["tcpFlowPathComplete"] >= source["workloadAttempted"]
        and source["tcpFlowPayloadBidirectional"] >= source["workloadAttempted"]
        and source["workloadFlowMatchedEntries"] == source["workloadAttempted"]
        and source["workloadFlowRuntimePreflowMatchedEntries"] == source["workloadAttempted"]
        and not any(source["privacy"].values())
    )


def runtime_dns_refresh_source(path: Path) -> dict[str, Any]:
    summary = load_json(path)
    totals = summary.get("totals") or {}
    source = {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "label": str(summary.get("label") or ""),
        "runs": int(totals.get("runs") or 0),
        "changedRuns": int(totals.get("changedRuns") or 0),
        "inconsistentRuns": int(totals.get("inconsistentRuns") or 0),
        "dnsQueries": int(totals.get("dnsQueries") or 0),
        "dnsRecords": int(totals.get("dnsRecords") or 0),
        "proxiedDnsQueries": int(totals.get("proxiedDnsQueries") or 0),
        "queryReceivedEvents": int(totals.get("queryReceivedEvents") or 0),
        "resolveCompletedEvents": int(totals.get("resolveCompletedEvents") or 0),
        "reverseRecordEvents": int(totals.get("reverseRecordEvents") or 0),
        "resolveFailedEvents": int(totals.get("resolveFailedEvents") or 0),
        "proxiedCompletedEvents": int(totals.get("proxiedCompletedEvents") or 0),
        "terminalEvents": int(totals.get("terminalEvents") or 0),
        "queriesWithRecords": int(totals.get("queriesWithRecords") or 0),
        "queriesMissingCompletion": int(totals.get("queriesMissingCompletion") or 0),
        "completedMissingQuery": int(totals.get("completedMissingQuery") or 0),
        "failedMissingQuery": int(totals.get("failedMissingQuery") or 0),
        "recordsMissingQuery": int(totals.get("recordsMissingQuery") or 0),
        "classifications": count_keys(totals.get("classifications")),
        "privacy": empty_privacy_flags(),
    }
    source["clean"] = runtime_dns_refresh_clean(source)
    return source


def runtime_dns_refresh_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "clean": bool(sources) and all(source["clean"] for source in sources),
        "runs": sum(source["runs"] for source in sources),
        "changedRuns": sum(source["changedRuns"] for source in sources),
        "inconsistentRuns": sum(source["inconsistentRuns"] for source in sources),
        "dnsQueries": sum(source["dnsQueries"] for source in sources),
        "dnsRecords": sum(source["dnsRecords"] for source in sources),
        "resolveFailedEvents": sum(source["resolveFailedEvents"] for source in sources),
        "queriesMissingCompletion": sum(source["queriesMissingCompletion"] for source in sources),
        "classifications": sorted({
            classification
            for source in sources
            for classification in source["classifications"]
        }),
        "sources": sources,
    }


def runtime_dns_refresh_clean(source: dict[str, Any]) -> bool:
    return (
        source["schema"] == DNS_REFRESH_SCHEMA
        and source["runs"] > 0
        and source["changedRuns"] == 0
        and source["inconsistentRuns"] == 0
        and source["classifications"] == ["unchanged"]
        and source["dnsQueries"] > 0
        and source["queryReceivedEvents"] == source["dnsQueries"]
        and source["reverseRecordEvents"] == source["dnsRecords"]
        and source["terminalEvents"] == source["queryReceivedEvents"]
        and source["resolveCompletedEvents"] + source["resolveFailedEvents"] == source["queryReceivedEvents"]
        and source["queriesWithRecords"] == source["resolveCompletedEvents"]
        and source["queriesMissingCompletion"] == 0
        and source["completedMissingQuery"] == 0
        and source["failedMissingQuery"] == 0
        and source["recordsMissingQuery"] == 0
        and source["proxiedCompletedEvents"] == source["proxiedDnsQueries"]
        and not any(source["privacy"].values())
    )


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


def adapter_types(summaries: list[dict[str, Any]]) -> list[str]:
    types = set()
    for summary in summaries:
        metadata = summary.get("metadata") or {}
        for candidate in metadata.get("candidates", []):
            if isinstance(candidate, dict) and candidate.get("type"):
                types.add(str(candidate["type"]))
    return sorted(types)


def dns_names_expected(summaries: list[dict[str, Any]]) -> int:
    return sum(
        len(summary.get("dnsNames", []))
        for summary in summaries
        if isinstance(summary.get("dnsNames"), list)
    )


def runtime_totals(summaries: list[dict[str, Any]]) -> dict[str, int]:
    fields = ("dnsQueries", "dnsRecords", "proxiedDnsQueries")
    totals = {field: 0 for field in fields}
    for summary in summaries:
        runtime = summary.get("runtime") or {}
        for field in fields:
            totals[field] += int(runtime.get(field) or 0)
    return totals


def repeat_privacy_flags(summaries: list[dict[str, Any]]) -> dict[str, bool]:
    flags = empty_privacy_flags()
    for summary in summaries:
        flags = merge_privacy_flags(flags, privacy_flags(summary))
    return flags


def privacy_flags(summary: dict[str, Any]) -> dict[str, bool]:
    privacy = summary.get("privacy") or {}
    metadata_privacy = (summary.get("metadata") or {}).get("privacy") or {}
    workload = summary.get("workloadProbe") or {}
    workload_privacy = workload.get("privacy") or {}
    capture = workload.get("tunCapture") or {}
    return {
        "rawLogsStored": bool(privacy.get("rawLogsStored")),
        "rawPacketsStored": bool(capture.get("rawPcapStored"))
        or bool(capture.get("rawLinesStored")),
        "rawSecretsStored": bool(privacy.get("rawSecretsStored"))
        or bool(metadata_privacy.get("rawSecretsStored")),
        "responseBodiesStored": bool(workload_privacy.get("responseBodiesStored")),
        "responseHeadersStored": bool(workload_privacy.get("responseHeadersStored")),
        "identityInformationSent": bool(privacy.get("identityInformationSent"))
        or bool(workload_privacy.get("identityInformationSent"))
        or bool(metadata_privacy.get("identityInformationSent"))
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


def count_keys(rows: Any) -> list[str]:
    return sorted({
        str(row.get("key") or "")
        for row in rows or []
        if isinstance(row, dict) and row.get("key")
    })


def merge_privacy_flags(
    left: dict[str, bool],
    right: dict[str, bool],
) -> dict[str, bool]:
    return {key: bool(left.get(key)) or bool(right.get(key)) for key in left}


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text())
