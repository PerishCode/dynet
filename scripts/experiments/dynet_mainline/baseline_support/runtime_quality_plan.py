from __future__ import annotations

import json
from pathlib import Path
from typing import Any


REPEAT_SCHEMA = "dynet-vm-private-runtime-repeat/v1alpha1"
ROUTE_REFRESH_SCHEMA = "dynet-vm-private-runtime-route-refresh/v1alpha1"
SELECTION_REFRESH_SCHEMA = "dynet-vm-private-runtime-selection-refresh/v1alpha1"

REQUIRED_CHECKS = {
    "runtime-pass",
    "route-or-rule",
    "dialer-selected",
    "tcp-blackbox-https",
    "tcp-flow-lifecycle-complete",
    "tcp-flow-path-complete",
    "tcp-flow-payload-bidirectional",
    "workload-all-success",
    "workload-flow-covered",
    "quality-bound-candidate-set",
    "quality-bound-selected",
    "quality-bound-selected-has-quality",
    "quality-bound-selected-best",
}

CONTROL_FLAGS = {
    "forceBoundCandidate",
    "forcePrivateDownstreamFailure",
    "poisonBoundOnly",
    "poisonFirstBoundCandidate",
    "tcpRouteDirectFallback",
    "tcpRouteNonDirectFallback",
}


def runtime_quality_plan_source(path: Path) -> dict[str, Any]:
    summary = load_json(path)
    totals = summary.get("totals") or {}
    runs = run_summaries(path, summary)
    checks = merged_check_map(runs)
    runtime = runtime_totals(runs)
    return {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "label": str(summary.get("label") or ""),
        "runtimeDnsMode": str(summary.get("runtimeDnsMode") or ""),
        "tcpForward": bool(summary.get("tcpForward")),
        "qualityStateUsed": bool(summary.get("qualityStateUsed")),
        "runs": int(totals.get("runs") or (1 if runs else 0)),
        "passedRuns": int(totals.get("passedRuns") or 0),
        "failedRuns": int(totals.get("failedRuns") or 0),
        "runSummaryCount": len(runs),
        "checksClean": checks_clean(checks),
        "missingChecks": sorted(REQUIRED_CHECKS - set(checks)),
        "candidateControlClean": candidate_control_clean(summary.get("candidateControl")),
        "adapterTypes": adapter_types(runs),
        "workloadAttempted": int(totals.get("workloadAttempted") or 0),
        "workloadSuccess": int(totals.get("workloadSuccess") or 0),
        "workloadFailure": int(totals.get("workloadFailure") or 0),
        "qualityBoundCandidateSets": int(totals.get("qualityBoundCandidateSets") or 0),
        "qualityBoundSelectedWithQuality": int(
            totals.get("qualityBoundSelectedWithQuality") or 0
        ),
        "qualityBoundSelectedBehind": int(totals.get("qualityBoundSelectedBehind") or 0),
        "tcpFlowRouteGraphSelected": int(totals.get("tcpFlowRouteGraphSelected") or 0),
        "tcpFlowRouteMatched": int(totals.get("tcpFlowRouteMatched") or 0),
        "tcpFlowStarted": int(totals.get("tcpFlowStarted") or 0),
        "tcpFlowPathComplete": int(totals.get("tcpFlowPathComplete") or 0),
        "tcpFlowLifecycleComplete": int(totals.get("tcpFlowLifecycleComplete") or 0),
        "tcpFlowPayloadBidirectional": int(
            totals.get("tcpFlowPayloadBidirectional") or 0
        ),
        "tcpFlowFailed": int(totals.get("tcpFlowFailed") or 0),
        "tcpFlowStageFailed": int(totals.get("tcpFlowStageFailed") or 0),
        "tcpSessionFailures": runtime["tcpSessionFailures"],
        "tcpSlotPressureEvents": runtime["tcpSlotPressureEvents"],
        "privacy": repeat_privacy_flags(runs),
    }


def runtime_quality_plan_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "clean": bool(sources) and all(runtime_quality_plan_clean(source) for source in sources),
        "adapterTypes": sorted({
            adapter
            for source in sources
            for adapter in source["adapterTypes"]
            if adapter
        }),
        "runtimeDnsModes": sorted({
            source["runtimeDnsMode"] for source in sources if source["runtimeDnsMode"]
        }),
        "runs": sum(source["runs"] for source in sources),
        "passedRuns": sum(source["passedRuns"] for source in sources),
        "failedRuns": sum(source["failedRuns"] for source in sources),
        "workloadAttempted": sum(source["workloadAttempted"] for source in sources),
        "workloadFailure": sum(source["workloadFailure"] for source in sources),
        "qualityBoundCandidateSets": sum(
            source["qualityBoundCandidateSets"] for source in sources
        ),
        "qualityBoundSelectedWithQuality": sum(
            source["qualityBoundSelectedWithQuality"] for source in sources
        ),
        "qualityBoundSelectedBehind": sum(
            source["qualityBoundSelectedBehind"] for source in sources
        ),
        "tcpFlowRouteGraphSelected": sum(
            source["tcpFlowRouteGraphSelected"] for source in sources
        ),
        "tcpFlowRouteMatched": sum(source["tcpFlowRouteMatched"] for source in sources),
        "tcpFlowFailed": sum(source["tcpFlowFailed"] for source in sources),
        "tcpFlowStageFailed": sum(source["tcpFlowStageFailed"] for source in sources),
        "tcpSessionFailures": sum(source["tcpSessionFailures"] for source in sources),
        "sources": sources,
    }


def runtime_quality_plan_clean(source: dict[str, Any]) -> bool:
    quality_sets = int(source["qualityBoundCandidateSets"])
    return (
        source["runtimeDnsMode"] == "config-chain"
        and source["tcpForward"]
        and source["qualityStateUsed"]
        and source["runs"] > 0
        and source["passedRuns"] == source["runs"]
        and source["failedRuns"] == 0
        and source["runSummaryCount"] >= source["runs"]
        and source["checksClean"]
        and not source["missingChecks"]
        and source["candidateControlClean"]
        and bool(source["adapterTypes"])
        and source["workloadAttempted"] > 0
        and source["workloadSuccess"] == source["workloadAttempted"]
        and source["workloadFailure"] == 0
        and quality_sets > 0
        and source["qualityBoundSelectedWithQuality"] == quality_sets
        and source["qualityBoundSelectedBehind"] == 0
        and source["tcpFlowRouteGraphSelected"] >= quality_sets
        and source["tcpFlowRouteMatched"] >= quality_sets
        and source["tcpFlowStarted"] >= quality_sets
        and source["tcpFlowPathComplete"] >= quality_sets
        and source["tcpFlowLifecycleComplete"] >= quality_sets
        and source["tcpFlowPayloadBidirectional"] >= quality_sets
        and source["tcpFlowFailed"] == 0
        and source["tcpSessionFailures"] == 0
        and not any(source["privacy"].values())
    )


def runtime_route_refresh_source(path: Path) -> dict[str, Any]:
    summary = load_json(path)
    totals = summary.get("totals") or {}
    source = {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "label": str(summary.get("label") or ""),
        "runs": int(totals.get("runs") or 0),
        "changedRuns": int(totals.get("changedRuns") or 0),
        "classifications": count_keys(totals.get("classifications")),
        "routeMatchedFlows": int(totals.get("routeMatchedFlows") or 0),
        "planBypassedFlows": int(totals.get("planBypassedFlows") or 0),
        "routeGraphSelectedFlows": int(totals.get("routeGraphSelectedFlows") or 0),
        "boundCandidateSetFlows": int(totals.get("boundCandidateSetFlows") or 0),
        "boundGraphSelectedFlows": int(totals.get("boundGraphSelectedFlows") or 0),
        "cascadeSelectedFlows": int(totals.get("cascadeSelectedFlows") or 0),
        "boundAttemptStartedFlows": int(totals.get("boundAttemptStartedFlows") or 0),
        "boundAttemptSucceededFlows": int(totals.get("boundAttemptSucceededFlows") or 0),
        "privateConnectFlows": int(totals.get("privateConnectFlows") or 0),
        "pathCompleteFlows": int(totals.get("pathCompleteFlows") or 0),
        "failedFlows": int(totals.get("failedFlows") or 0),
        "privacy": empty_privacy_flags(),
    }
    source["clean"] = runtime_route_refresh_clean(source)
    return source


def runtime_route_refresh_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "clean": bool(sources) and all(source["clean"] for source in sources),
        "runs": sum(source["runs"] for source in sources),
        "changedRuns": sum(source["changedRuns"] for source in sources),
        "classifications": sorted({
            item for source in sources for item in source["classifications"]
        }),
        "routeEntryFlows": sum(route_entry_flows(source) for source in sources),
        "routeGraphSelectedFlows": sum(source["routeGraphSelectedFlows"] for source in sources),
        "boundGraphSelectedFlows": sum(source["boundGraphSelectedFlows"] for source in sources),
        "cascadeSelectedFlows": sum(source["cascadeSelectedFlows"] for source in sources),
        "privateConnectFlows": sum(source["privateConnectFlows"] for source in sources),
        "pathCompleteFlows": sum(source["pathCompleteFlows"] for source in sources),
        "failedFlows": sum(source["failedFlows"] for source in sources),
        "sources": sources,
    }


def runtime_route_refresh_clean(source: dict[str, Any]) -> bool:
    entries = route_entry_flows(source)
    return (
        source["schema"] == ROUTE_REFRESH_SCHEMA
        and source["runs"] > 0
        and source["changedRuns"] == 0
        and source["classifications"] == ["unchanged"]
        and entries > 0
        and source["routeGraphSelectedFlows"] >= source["routeMatchedFlows"]
        and source["boundCandidateSetFlows"] >= entries
        and source["boundGraphSelectedFlows"] >= entries
        and source["cascadeSelectedFlows"] >= entries
        and source["boundAttemptStartedFlows"] >= entries
        and source["boundAttemptSucceededFlows"] >= entries
        and source["privateConnectFlows"] <= entries
        and source["pathCompleteFlows"] >= entries
        and source["failedFlows"] == 0
        and not any(source["privacy"].values())
    )


def route_entry_flows(source: dict[str, Any]) -> int:
    return int(source["routeMatchedFlows"]) + int(source["planBypassedFlows"])


def runtime_selection_refresh_source(path: Path) -> dict[str, Any]:
    summary = load_json(path)
    totals = summary.get("totals") or {}
    source = {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "label": str(summary.get("label") or ""),
        "runs": int(totals.get("runs") or 0),
        "changedRuns": int(totals.get("changedRuns") or 0),
        "classifications": count_keys(totals.get("classifications")),
        "candidateSets": int(totals.get("candidateSets") or 0),
        "attemptCandidateSets": int(totals.get("attemptCandidateSets") or 0),
        "fallbackCandidateSets": int(totals.get("fallbackCandidateSets") or 0),
        "withBoundSelected": int(totals.get("withBoundSelected") or 0),
        "selectedWithQuality": int(totals.get("selectedWithQuality") or 0),
        "selectedBest": int(totals.get("selectedBest") or 0),
        "selectedBehind": int(totals.get("selectedBehind") or 0),
        "fallbackSelectedWithQuality": int(
            totals.get("fallbackSelectedWithQuality") or 0
        ),
        "fallbackSelectedBehind": int(totals.get("fallbackSelectedBehind") or 0),
        "privacy": empty_privacy_flags(),
    }
    source["clean"] = runtime_selection_refresh_clean(source)
    return source


def runtime_selection_refresh_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "clean": bool(sources) and all(source["clean"] for source in sources),
        "runs": sum(source["runs"] for source in sources),
        "changedRuns": sum(source["changedRuns"] for source in sources),
        "classifications": sorted({
            item for source in sources for item in source["classifications"]
        }),
        "candidateSets": sum(source["candidateSets"] for source in sources),
        "attemptCandidateSets": sum(source["attemptCandidateSets"] for source in sources),
        "fallbackCandidateSets": sum(source["fallbackCandidateSets"] for source in sources),
        "withBoundSelected": sum(source["withBoundSelected"] for source in sources),
        "selectedWithQuality": sum(source["selectedWithQuality"] for source in sources),
        "selectedBest": sum(source["selectedBest"] for source in sources),
        "selectedBehind": sum(source["selectedBehind"] for source in sources),
        "fallbackSelectedWithQuality": sum(
            source["fallbackSelectedWithQuality"] for source in sources
        ),
        "fallbackSelectedBehind": sum(
            source["fallbackSelectedBehind"] for source in sources
        ),
        "sources": sources,
    }


def runtime_selection_refresh_clean(source: dict[str, Any]) -> bool:
    candidate_sets = int(source["candidateSets"])
    fallback_sets = int(source["fallbackCandidateSets"])
    return (
        source["schema"] == SELECTION_REFRESH_SCHEMA
        and source["runs"] > 0
        and source["changedRuns"] == 0
        and source["classifications"] == ["unchanged"]
        and candidate_sets > 0
        and source["withBoundSelected"] == candidate_sets
        and source["selectedWithQuality"] <= candidate_sets
        and source["selectedBest"] == candidate_sets
        and source["selectedBehind"] == 0
        and source["attemptCandidateSets"] >= candidate_sets + fallback_sets
        and source["fallbackSelectedWithQuality"] <= fallback_sets
        and source["fallbackSelectedBehind"] <= fallback_sets
        and not any(source["privacy"].values())
    )


def run_summaries(path: Path, summary: dict[str, Any]) -> list[dict[str, Any]]:
    if summary.get("schema") == REPEAT_SCHEMA:
        return [
            load_json(run_summary_path)
            for run_summary_path in sorted(path.parent.glob("run-*/summary.json"))
        ]
    return [summary] if summary else []


def runtime_totals(summaries: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "tcpSessionFailures": sum(
            int((summary.get("runtime") or {}).get("tcpSessionFailures") or 0)
            for summary in summaries
        ),
        "tcpSlotPressureEvents": sum(
            int((summary.get("runtime") or {}).get("tcpSlotPressureEvents") or 0)
            for summary in summaries
        ),
    }


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
            if isinstance(candidate, dict):
                adapter_type = normalize_type(candidate.get("type"))
                if adapter_type:
                    types.add(adapter_type)
    return sorted(types)


def repeat_privacy_flags(summaries: list[dict[str, Any]]) -> dict[str, bool]:
    flags = empty_privacy_flags()
    for summary in summaries:
        current = privacy_flags(summary)
        for key, value in current.items():
            flags[key] = flags[key] or value
    return flags


def privacy_flags(summary: dict[str, Any]) -> dict[str, bool]:
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


def count_keys(rows: Any) -> list[str]:
    return sorted({
        str(row.get("key") or "")
        for row in rows or []
        if isinstance(row, dict) and row.get("key")
    })


def normalize_type(raw: object) -> str:
    value = str(raw or "").lower()
    if value in {"shadowsocks", "ss"}:
        return "ss"
    return value


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text())
