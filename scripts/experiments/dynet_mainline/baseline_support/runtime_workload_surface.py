from __future__ import annotations

import json
from pathlib import Path
from typing import Any


SCHEMA = "dynet-vm-private-runtime-workload-surface/v1alpha1"
FLOW_REFRESH_SCHEMA = "dynet-vm-private-runtime-flow-refresh/v1alpha1"
CASCADE_REFRESH_SCHEMA = "dynet-vm-private-runtime-cascade-refresh/v1alpha1"
PAYLOAD_SURFACE_SCHEMA = "dynet-vm-private-runtime-payload-surface/v1alpha1"
TARGET_IDENTITY_SCHEMA = (
    "dynet-vm-private-runtime-target-identity-refresh/v1alpha1"
)


def runtime_workload_surface_source(path: Path) -> dict[str, Any]:
    summary = load_json(path)
    conclusion = summary.get("conclusion") or {}
    totals = summary.get("totals") or {}
    source = {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "label": str(summary.get("label") or ""),
        "status": str(conclusion.get("status") or ""),
        "nextAction": str(conclusion.get("nextAction") or ""),
        "runs": int(totals.get("runs") or 0),
        "cleanRuns": int(totals.get("cleanRuns") or 0),
        "failedRuns": int(totals.get("failedRuns") or 0),
        "workloadAttempted": int(totals.get("workloadAttempted") or 0),
        "workloadFailure": int(totals.get("workloadFailure") or 0),
        "failedRows": int(totals.get("failedRows") or 0),
        "qualityCandidateSets": int(totals.get("qualityCandidateSets") or 0),
        "qualitySelectedWithQuality": int(
            totals.get("qualitySelectedWithQuality") or 0
        ),
        "qualitySelectedBehind": int(totals.get("qualitySelectedBehind") or 0),
        "preTcpFailures": int(totals.get("preTcpFailures") or 0),
        "packetTerminalFailures": int(totals.get("packetTerminalFailures") or 0),
        "runtimePacketMatchedFailures": int(
            totals.get("runtimePacketMatchedFailures") or 0
        ),
        "runtimeDnsFailures": int(totals.get("runtimeDnsFailures") or 0),
        "failedRowsWithRuntimeDnsFailure": int(
            totals.get("failedRowsWithRuntimeDnsFailure") or 0
        ),
        "cascadeFailedAttempts": int(totals.get("cascadeFailedAttempts") or 0),
        "cascadeRecoveredFlows": int(totals.get("cascadeRecoveredFlows") or 0),
        "mechanisms": mechanisms(conclusion),
        "privacy": privacy_flags(summary),
        "policy": policy_flags(summary),
    }
    source["clean"] = runtime_workload_surface_clean(source)
    return source


def runtime_workload_surface_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "clean": bool(sources) and all(source["clean"] for source in sources),
        "statuses": sorted({source["status"] for source in sources if source["status"]}),
        "nextActions": sorted({
            source["nextAction"] for source in sources if source["nextAction"]
        }),
        "runs": sum(source["runs"] for source in sources),
        "cleanRuns": sum(source["cleanRuns"] for source in sources),
        "failedRuns": sum(source["failedRuns"] for source in sources),
        "workloadAttempted": sum(source["workloadAttempted"] for source in sources),
        "workloadFailure": sum(source["workloadFailure"] for source in sources),
        "failedRows": sum(source["failedRows"] for source in sources),
        "qualityCandidateSets": sum(source["qualityCandidateSets"] for source in sources),
        "qualitySelectedWithQuality": sum(
            source["qualitySelectedWithQuality"] for source in sources
        ),
        "qualitySelectedBehind": sum(
            source["qualitySelectedBehind"] for source in sources
        ),
        "preTcpFailures": sum(source["preTcpFailures"] for source in sources),
        "packetTerminalFailures": sum(
            source["packetTerminalFailures"] for source in sources
        ),
        "runtimePacketMatchedFailures": sum(
            source["runtimePacketMatchedFailures"] for source in sources
        ),
        "runtimeDnsFailures": sum(source["runtimeDnsFailures"] for source in sources),
        "failedRowsWithRuntimeDnsFailure": sum(
            source["failedRowsWithRuntimeDnsFailure"] for source in sources
        ),
        "cascadeFailedAttempts": sum(
            source["cascadeFailedAttempts"] for source in sources
        ),
        "cascadeRecoveredFlows": sum(source["cascadeRecoveredFlows"] for source in sources),
        "mechanisms": sorted({
            mechanism for source in sources for mechanism in source["mechanisms"]
        }),
        "sources": sources,
    }


def runtime_workload_surface_clean(source: dict[str, Any]) -> bool:
    return (
        source["schema"] == SCHEMA
        and source["status"] == "clean"
        and source["runs"] > 0
        and source["cleanRuns"] == source["runs"]
        and source["failedRuns"] == 0
        and source["workloadAttempted"] > 0
        and source["workloadFailure"] == 0
        and source["failedRows"] == 0
        and source["qualityCandidateSets"] > 0
        and source["qualitySelectedWithQuality"] == source["qualityCandidateSets"]
        and source["qualitySelectedBehind"] == 0
        and not source["mechanisms"]
        and not source["policy"]["plannerPenaltySafe"]
        and not source["policy"]["qualityPenaltySafe"]
        and not source["policy"]["productEffectClaimSafe"]
        and not any(source["privacy"].values())
    )


def runtime_payload_surface_source(path: Path) -> dict[str, Any]:
    summary = load_json(path)
    totals = summary.get("totals") or {}
    conclusion = summary.get("conclusion") or {}
    source = {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "label": str(summary.get("label") or ""),
        "status": str(conclusion.get("status") or ""),
        "runs": int(totals.get("runs") or 0),
        "cleanRuns": int(totals.get("cleanRuns") or 0),
        "failedRuns": int(totals.get("failedRuns") or 0),
        "flows": int(totals.get("flows") or 0),
        "startedFlows": int(totals.get("startedFlows") or 0),
        "establishedFlows": int(totals.get("establishedFlows") or 0),
        "closedFlows": int(totals.get("closedFlows") or 0),
        "lifecycleCompleteFlows": int(totals.get("lifecycleCompleteFlows") or 0),
        "pathCompleteFlows": int(totals.get("pathCompleteFlows") or 0),
        "closedWithByteTotals": int(totals.get("closedWithByteTotals") or 0),
        "payloadStartedFlows": int(totals.get("payloadStartedFlows") or 0),
        "payloadReceivedFlows": int(totals.get("payloadReceivedFlows") or 0),
        "payloadBidirectionalFlows": int(totals.get("payloadBidirectionalFlows") or 0),
        "payloadCloseConsistent": int(totals.get("payloadCloseConsistent") or 0),
        "closedWithoutPayloadFlows": int(totals.get("closedWithoutPayloadFlows") or 0),
        "duplicateClosedFlows": int(totals.get("duplicateClosedFlows") or 0),
        "failedFlows": int(totals.get("failedFlows") or 0),
        "stageFailedFlows": int(totals.get("stageFailedFlows") or 0),
        "classifications": count_keys(totals.get("classifications")),
        "privacy": empty_privacy_flags(),
    }
    source["clean"] = runtime_payload_surface_clean(source)
    return source


def runtime_payload_surface_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "clean": bool(sources) and all(source["clean"] for source in sources),
        "statuses": sorted({source["status"] for source in sources if source["status"]}),
        "runs": sum(source["runs"] for source in sources),
        "cleanRuns": sum(source["cleanRuns"] for source in sources),
        "failedRuns": sum(source["failedRuns"] for source in sources),
        "flows": sum(source["flows"] for source in sources),
        "closedFlows": sum(source["closedFlows"] for source in sources),
        "payloadBidirectionalFlows": sum(
            source["payloadBidirectionalFlows"] for source in sources
        ),
        "payloadCloseConsistent": sum(
            source["payloadCloseConsistent"] for source in sources
        ),
        "closedWithoutPayloadFlows": sum(
            source["closedWithoutPayloadFlows"] for source in sources
        ),
        "duplicateClosedFlows": sum(source["duplicateClosedFlows"] for source in sources),
        "failedFlows": sum(source["failedFlows"] for source in sources),
        "stageFailedFlows": sum(source["stageFailedFlows"] for source in sources),
        "classifications": sorted({
            classification
            for source in sources
            for classification in source["classifications"]
        }),
        "sources": sources,
    }


def runtime_payload_surface_clean(source: dict[str, Any]) -> bool:
    flows = source["flows"]
    closed = source["closedFlows"]
    return (
        source["schema"] == PAYLOAD_SURFACE_SCHEMA
        and source["status"] == "clean"
        and source["runs"] > 0
        and source["cleanRuns"] == source["runs"]
        and source["failedRuns"] == 0
        and source["classifications"] == ["clean"]
        and flows > 0
        and source["startedFlows"] == flows
        and source["establishedFlows"] == flows
        and closed == flows
        and source["lifecycleCompleteFlows"] == flows
        and source["pathCompleteFlows"] == flows
        and source["closedWithByteTotals"] == closed
        and source["payloadStartedFlows"] == closed
        and source["payloadReceivedFlows"] == closed
        and source["payloadBidirectionalFlows"] == closed
        and source["payloadCloseConsistent"] == closed
        and source["closedWithoutPayloadFlows"] == 0
        and source["duplicateClosedFlows"] == 0
        and source["failedFlows"] == 0
        and not any(source["privacy"].values())
    )


def runtime_flow_refresh_source(path: Path) -> dict[str, Any]:
    summary = load_json(path)
    totals = summary.get("totals") or {}
    source = {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "label": str(summary.get("label") or ""),
        "runs": int(totals.get("runs") or 0),
        "changedRuns": int(totals.get("changedRuns") or 0),
        "recoveredStageSeparatedRuns": int(
            totals.get("recoveredStageSeparatedRuns") or 0
        ),
        "classifications": count_keys(totals.get("classifications")),
        "privacy": empty_privacy_flags(),
    }
    source["clean"] = runtime_flow_refresh_clean(source)
    return source


def runtime_flow_refresh_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "clean": bool(sources) and all(source["clean"] for source in sources),
        "runs": sum(source["runs"] for source in sources),
        "changedRuns": sum(source["changedRuns"] for source in sources),
        "recoveredStageSeparatedRuns": sum(
            source["recoveredStageSeparatedRuns"] for source in sources
        ),
        "classifications": sorted({
            classification
            for source in sources
            for classification in source["classifications"]
        }),
        "sources": sources,
    }


def runtime_flow_refresh_clean(source: dict[str, Any]) -> bool:
    return (
        source["schema"] == FLOW_REFRESH_SCHEMA
        and source["runs"] > 0
        and source["changedRuns"] == 0
        and source["classifications"] == ["unchanged"]
        and not any(source["privacy"].values())
    )


def runtime_cascade_refresh_source(path: Path) -> dict[str, Any]:
    summary = load_json(path)
    totals = summary.get("totals") or {}
    source = {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "label": str(summary.get("label") or ""),
        "runs": int(totals.get("runs") or 0),
        "changedRuns": int(totals.get("changedRuns") or 0),
        "failedAttempts": int(totals.get("failedAttempts") or 0),
        "retryableFailures": int(totals.get("retryableFailures") or 0),
        "stoppedFailures": int(totals.get("stoppedFailures") or 0),
        "stoppedBoundExhaustedFlows": int(totals.get("stoppedBoundExhaustedFlows") or 0),
        "stoppedNonBoundFlows": int(totals.get("stoppedNonBoundFlows") or 0),
        "stoppedRetryableFailures": int(totals.get("stoppedRetryableFailures") or 0),
        "recoveredFlows": int(totals.get("recoveredFlows") or 0),
        "stoppedFlowStopReasons": count_keys(totals.get("stoppedFlowByStopReason")),
        "classifications": count_keys(totals.get("classifications")),
        "privacy": empty_privacy_flags(),
    }
    source.update(cascade_failure_accounting(source))
    source["clean"] = runtime_cascade_refresh_clean(source)
    return source


def runtime_cascade_refresh_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "clean": bool(sources) and all(source["clean"] for source in sources),
        "runs": sum(source["runs"] for source in sources),
        "changedRuns": sum(source["changedRuns"] for source in sources),
        "failedAttempts": sum(source["failedAttempts"] for source in sources),
        "retryableFailures": sum(source["retryableFailures"] for source in sources),
        "stoppedFailures": sum(source["stoppedFailures"] for source in sources),
        "stoppedBoundExhaustedFlows": sum(
            source["stoppedBoundExhaustedFlows"] for source in sources
        ),
        "stoppedNonBoundFlows": sum(
            source["stoppedNonBoundFlows"] for source in sources
        ),
        "stoppedRetryableFailures": sum(
            source["stoppedRetryableFailures"] for source in sources
        ),
        "recoveredFlows": sum(source["recoveredFlows"] for source in sources),
        "unaccountedFailedAttempts": sum(
            source["unaccountedFailedAttempts"] for source in sources
        ),
        "unaccountedRetryableFailures": sum(
            source["unaccountedRetryableFailures"] for source in sources
        ),
        "unaccountedStoppedFailures": sum(
            source["unaccountedStoppedFailures"] for source in sources
        ),
        "stoppedFlowStopReasons": sorted({
            reason for source in sources for reason in source["stoppedFlowStopReasons"]
        }),
        "classifications": sorted({
            classification
            for source in sources
            for classification in source["classifications"]
        }),
        "sources": sources,
    }


def runtime_cascade_refresh_clean(source: dict[str, Any]) -> bool:
    allowed_stop_reasons = {"bound-candidates-exhausted", "non-bound-failure"}
    return (
        source["schema"] == CASCADE_REFRESH_SCHEMA
        and source["runs"] > 0
        and source["changedRuns"] == 0
        and source["classifications"] == ["unchanged"]
        and source["unaccountedFailedAttempts"] == 0
        and source["unaccountedRetryableFailures"] == 0
        and source["unaccountedStoppedFailures"] == 0
        and set(source["stoppedFlowStopReasons"]) <= allowed_stop_reasons
        and not any(source["privacy"].values())
    )


def cascade_failure_accounting(source: dict[str, Any]) -> dict[str, int]:
    return {
        "unaccountedFailedAttempts": (
            source["failedAttempts"]
            - source["retryableFailures"]
            - source["stoppedFailures"]
        ),
        "unaccountedRetryableFailures": (
            source["retryableFailures"]
            - source["recoveredFlows"]
            - source["stoppedRetryableFailures"]
        ),
        "unaccountedStoppedFailures": source["stoppedFailures"]
        - source["stoppedBoundExhaustedFlows"]
        - source["stoppedNonBoundFlows"],
    }


def runtime_target_identity_source(path: Path) -> dict[str, Any]:
    summary = load_json(path)
    totals = summary.get("totals") or {}
    source = {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "label": str(summary.get("label") or ""),
        "runs": int(totals.get("runs") or 0),
        "changedRuns": int(totals.get("changedRuns") or 0),
        "connectingEvents": int(totals.get("connectingEvents") or 0),
        "adapterConnectEvents": int(totals.get("adapterConnectEvents") or 0),
        "withConnectTarget": int(totals.get("withConnectTarget") or 0),
        "withAdapterTarget": int(totals.get("withAdapterTarget") or 0),
        "withIdentityDomain": int(totals.get("withIdentityDomain") or 0),
        "withTargetAddressSource": int(totals.get("withTargetAddressSource") or 0),
        "targetChainFlows": int(totals.get("targetChainFlows") or 0),
        "targetChainMatched": int(totals.get("targetChainMatched") or 0),
        "targetChainMismatched": int(totals.get("targetChainMismatched") or 0),
        "targetChainMissingAdapter": int(
            totals.get("targetChainMissingAdapter") or 0
        ),
        "targetChainMissingConnect": int(
            totals.get("targetChainMissingConnect") or 0
        ),
        "targetChainDuplicateAdapterFlows": int(
            totals.get("targetChainDuplicateAdapterFlows") or 0
        ),
        "classifications": count_keys(totals.get("classifications")),
        "privacy": empty_privacy_flags(),
    }
    source["clean"] = runtime_target_identity_clean(source)
    return source


def runtime_target_identity_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "clean": bool(sources) and all(source["clean"] for source in sources),
        "runs": sum(source["runs"] for source in sources),
        "changedRuns": sum(source["changedRuns"] for source in sources),
        "connectingEvents": sum(source["connectingEvents"] for source in sources),
        "adapterConnectEvents": sum(source["adapterConnectEvents"] for source in sources),
        "targetChainFlows": sum(source["targetChainFlows"] for source in sources),
        "targetChainMatched": sum(source["targetChainMatched"] for source in sources),
        "targetChainMismatched": sum(
            source["targetChainMismatched"] for source in sources
        ),
        "targetChainMissingAdapter": sum(
            source["targetChainMissingAdapter"] for source in sources
        ),
        "targetChainMissingConnect": sum(
            source["targetChainMissingConnect"] for source in sources
        ),
        "targetChainDuplicateAdapterFlows": sum(
            source["targetChainDuplicateAdapterFlows"] for source in sources
        ),
        "classifications": sorted({
            classification
            for source in sources
            for classification in source["classifications"]
        }),
        "sources": sources,
    }


def runtime_target_identity_clean(source: dict[str, Any]) -> bool:
    return (
        source["schema"] == TARGET_IDENTITY_SCHEMA
        and source["runs"] > 0
        and source["changedRuns"] == 0
        and source["classifications"] == ["unchanged"]
        and source["connectingEvents"] > 0
        and source["adapterConnectEvents"] > 0
        and source["withConnectTarget"] == source["connectingEvents"]
        and source["withIdentityDomain"] == source["connectingEvents"]
        and source["withTargetAddressSource"] == source["connectingEvents"]
        and source["withAdapterTarget"] == source["adapterConnectEvents"]
        and source["targetChainFlows"] > 0
        and source["targetChainMatched"] + source["targetChainMissingAdapter"] == source["targetChainFlows"]
        and source["targetChainMismatched"] == 0
        and source["targetChainMissingConnect"] == 0
        and source["targetChainDuplicateAdapterFlows"] == 0
        and not any(source["privacy"].values())
    )


def mechanisms(conclusion: dict[str, Any]) -> list[str]:
    return sorted({
        str(item.get("mechanism") or "")
        for item in conclusion.get("mechanisms") or []
        if isinstance(item, dict) and item.get("mechanism")
    })


def policy_flags(summary: dict[str, Any]) -> dict[str, bool]:
    policy = summary.get("policy") or {}
    conclusion = summary.get("conclusion") or {}
    return {
        "plannerPenaltySafe": bool(policy.get("plannerPenaltySafe"))
        or bool(conclusion.get("plannerPenaltySafe")),
        "qualityPenaltySafe": bool(policy.get("qualityPenaltySafe"))
        or bool(conclusion.get("qualityPenaltySafe")),
        "productEffectClaimSafe": bool(policy.get("productEffectClaimSafe"))
        or bool(conclusion.get("productEffectClaimSafe")),
    }


def privacy_flags(summary: dict[str, Any]) -> dict[str, bool]:
    privacy = summary.get("privacy") or {}
    return {
        "rawLogsStored": bool(privacy.get("rawLogsStored")),
        "rawPacketsStored": bool(privacy.get("rawPacketsStored")),
        "rawSecretsStored": bool(privacy.get("rawSecretsStored")),
        "responseBodiesStored": bool(privacy.get("responseBodiesStored"))
        or bool(privacy.get("rawResponseBodiesStored")),
        "identityInformationSent": bool(privacy.get("identityInformationSent")),
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


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text())
