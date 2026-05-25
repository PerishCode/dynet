from __future__ import annotations

import json
from pathlib import Path


def product_effect() -> dict[str, object]:
    return {
        "schema": "dynet-tunnel-private-adapter-product-effect/v1alpha1",
        "status": "product-effect-parity-candidate",
        "adapterType": "trojan",
        "recommendedUse": "eligible-for-product-effect-parity-review",
        "plannerPenaltySafe": False,
        "conclusion": {
            "productEffectParityClaimSafe": True,
            "notReadyReasons": [],
        },
        "dynetRuntimeProduct": {
            "clean": True,
            "workloadAttempted": 32,
            "workloadFailure": 0,
            "tcpFlowFailed": 0,
            "tcpSlotPressureEvents": 4,
        },
        "pairedProductEffect": {
            "windows": 4,
            "pairedEntries": 24,
            "parityCandidate": True,
        },
        "privacy": {
            "rawLogsStored": False,
            "rawSecretsStored": False,
            "identityInformationSent": False,
        },
    }


def runtime_pressure() -> dict[str, object]:
    return {
        "schema": "dynet-vm-private-runtime-pressure/v1alpha1",
        "status": "observe-only-product-clean",
        "policy": {
            "plannerPenaltySafe": False,
            "qualityPenaltySafe": False,
            "productEffectClaimSafe": False,
        },
        "conclusion": {
            "pressureShape": "separated-handshake-wait-and-slot-admission-pressure",
        },
        "totals": {
            "workloadAttempted": 32,
            "workloadFailure": 0,
            "tcpFlowFailed": 0,
            "stageFailures": 4,
            "stageUnrecoveredFailures": 0,
            "slotPressureEvents": 331,
            "slowStageEvents": 5,
            "slowFailedStageEvents": 5,
            "slowStageMaxMs": 8481,
            "scheduleLagMaxMs": 3568,
            "runsWithStageWithoutSlotPressure": 1,
            "runsWithSlotWithoutStagePressure": 1,
            "runsWithStageAndSlotPressure": 0,
            "runsAtPortSlotLimit": 1,
            "slotActiveAtCapacityEvents": 0,
            "slotActiveOverCapacityEvents": 0,
            "slotCapacityMissingEvents": 0,
            "classifications": [
                {
                    "count": 1,
                    "key": "product-clean-handshake-wait-budget-pressure",
                },
                {
                    "count": 1,
                    "key": "product-clean-slot-admission-pressure",
                },
            ],
        },
        "privacy": {
            "rawLogsStored": False,
            "rawPacketsStored": False,
            "rawResponseBodiesStored": False,
            "rawSecretsStored": False,
        },
    }


def runtime_fallback(mode: str) -> dict[str, object]:
    final = "direct" if mode == "direct" else "private-via-tunnel"
    attempted = ["private-via-tunnel", final]
    if mode == "non-direct":
        attempted = ["private-via-poison-bound", "private-via-tunnel"]
    return {
        "schema": "dynet-vm-private-runtime-summary/v1alpha1",
        "label": f"route-{mode}-fallback",
        "checks": [{"name": "runtime-pass", "passed": True}],
        "privacy": {
            "rawSecretsStored": False,
            "identityInformationSent": False,
        },
        "tcpFlow": {
            "failedFlows": 0,
            "routeFallbackUsedFlows": 1,
            "routeFallbackAttemptEvents": 2,
            "routeFallbackFailedFlows": 0,
            "pathCompleteFlows": 1,
            "lifecycleCompleteFlows": 1,
            "payloadBidirectionalFlows": 1,
            "stageFailedFlows": 1,
            "routeFallbackByFinalOutbound": [{"key": final, "count": 1}],
            "routeFallbackByAttemptedOutbound": [
                {"key": key, "count": 1} for key in attempted
            ],
        },
        "workloadProbe": {
            "totals": {"count": 1, "success": 1, "failure": 0, "successRate": 1.0},
            "privacy": {
                "identityInformationSent": False,
                "responseBodiesStored": False,
                "responseHeadersStored": False,
            },
            "tunCapture": {"rawLinesStored": False, "rawPcapStored": False},
        },
    }


def runtime_fallback_repeat(mode: str) -> dict[str, object]:
    final = "direct" if mode == "direct" else "private-via-tunnel"
    attempted = ["private-via-tunnel", final]
    if mode == "non-direct":
        attempted = ["private-via-poison-bound", "private-via-tunnel"]
    return {
        "schema": "dynet-vm-private-runtime-repeat/v1alpha1",
        "label": f"route-{mode}-fallback-repeat",
        "totals": {
            "runs": 2,
            "passedRuns": 2,
            "failedRuns": 0,
            "workloadAttempted": 8,
            "workloadFailure": 0,
            "tcpFlowFailed": 0,
            "tcpFlowRouteFallbackUsed": 12,
            "tcpFlowRouteFallbackAttempts": 24,
            "tcpFlowRouteFallbackFailed": 0,
            "tcpFlowPathComplete": 12,
            "tcpFlowLifecycleComplete": 12,
            "tcpFlowPayloadBidirectional": 12,
            "tcpFlowStageFailed": 12,
            "tcpFlowRouteFallbackByFinalOutbound": [
                {"key": final, "count": 12},
            ],
            "tcpFlowRouteFallbackByAttemptedOutbound": [
                {"key": key, "count": 12} for key in attempted
            ],
        },
    }


def write_fallback_repeat(root: Path, mode: str) -> Path:
    repeat_dir = root / "fallback-repeat"
    repeat_dir.mkdir()
    repeat = write_json(repeat_dir / "summary.json", runtime_fallback_repeat(mode))
    run_dir = repeat_dir / "run-01"
    run_dir.mkdir()
    write_json(run_dir / "summary.json", runtime_fallback(mode))
    return repeat


def runtime_dns_repeat(
    adapter_type: str,
    runtime_dns_mode: str = "config-chain",
) -> dict[str, object]:
    return {
        "schema": "dynet-vm-private-runtime-repeat/v1alpha1",
        "label": f"{adapter_type}-dns-product-repeat",
        "runtimeDnsMode": runtime_dns_mode,
        "clientDnsTarget": "8.8.8.8:53",
        "tcpForward": True,
        "udpForward": False,
        "udpDirectProbe": False,
        "qualityStateUsed": True,
        "candidateControl": {
            "forceBoundCandidate": None,
            "forcePrivateDownstreamFailure": False,
            "poisonBoundOnly": False,
            "poisonFirstBoundCandidate": False,
            "tcpRouteDirectFallback": False,
            "tcpRouteNonDirectFallback": False,
        },
        "totals": {
            "runs": 2,
            "passedRuns": 2,
            "failedRuns": 0,
            "workloadAttempted": 8,
            "workloadSuccess": 8,
            "workloadFailure": 0,
            "dnsEarlyTimeouts": 0,
            "tcpFlowFailed": 0,
            "tcpFlowPathComplete": 8,
            "tcpFlowPayloadBidirectional": 8,
            "workloadFlowMatchedEntries": 8,
            "workloadFlowRuntimePreflowMatchedEntries": 8,
        },
    }


def runtime_dns_run(
    adapter_type: str,
    runtime_dns_mode: str = "config-chain",
) -> dict[str, object]:
    return {
        "schema": "dynet-vm-private-runtime-run/v1alpha1",
        "label": f"{adapter_type}-dns-product-run",
        "dnsNames": ["api.github.com", "chatgpt.com"],
        "runtimeDnsMode": runtime_dns_mode,
        "clientDnsTarget": "8.8.8.8:53",
        "qualityStateUsed": True,
        "candidateControl": {
            "forceBoundCandidate": None,
            "forcePrivateDownstreamFailure": False,
            "poisonBoundOnly": False,
            "poisonFirstBoundCandidate": False,
            "tcpRouteDirectFallback": False,
            "tcpRouteNonDirectFallback": False,
        },
        "metadata": {
            "candidates": [{"tag": "tunnel-001", "type": adapter_type}],
            "privacy": {
                "rawSecretsStored": False,
                "identityInformationSent": False,
            },
        },
        "privacy": {
            "rawSecretsStored": False,
            "identityInformationSent": False,
            "cookiesSent": False,
            "authorizationSent": False,
        },
        "runtime": {
            "dnsQueries": 2,
            "dnsRecords": 4,
            "proxiedDnsQueries": 0,
        },
        "productForwarding": {
            "tcpForwardingImplemented": True,
            "udpForwardingImplemented": False,
        },
        "stability": {"dnsEarlyTimeouts": 0},
        "tcpFlow": {
            "failedFlows": 0,
            "pathCompleteFlows": 4,
            "payloadBidirectionalFlows": 4,
        },
        "workloadFlow": {
            "matchedEntries": 4,
            "runtimePreflowMatchedEntries": 4,
        },
        "workloadProbe": {
            "totals": {"count": 4, "success": 4, "failure": 0},
            "privacy": {
                "identityInformationSent": False,
                "responseBodiesStored": False,
                "responseHeadersStored": False,
            },
            "tunCapture": {"rawLinesStored": False, "rawPcapStored": False},
        },
        "checks": [
            {"name": "runtime-pass", "passed": True},
            {"name": "dns-queries", "passed": True},
            {"name": "dns-forwarding", "passed": True},
            {"name": "dns-records", "passed": True},
            {"name": "all-dns-names-observed", "passed": True},
            {"name": "workload-dns-observed", "passed": True},
            {"name": "workload-all-success", "passed": True},
            {"name": "workload-flow-covered", "passed": True},
            {"name": "tcp-flow-path-complete", "passed": True},
            {"name": "tcp-flow-payload-bidirectional", "passed": True},
        ],
        "totals": {"failed": 0},
    }


def write_dns_repeat(
    root: Path,
    adapter_type: str,
    runtime_dns_mode: str = "config-chain",
) -> Path:
    repeat_dir = root / "dns-product-repeat"
    repeat_dir.mkdir()
    repeat = write_json(
        repeat_dir / "summary.json",
        runtime_dns_repeat(adapter_type, runtime_dns_mode),
    )
    for index in range(1, 3):
        run_dir = repeat_dir / f"run-{index:02d}"
        run_dir.mkdir()
        write_json(run_dir / "summary.json", runtime_dns_run(adapter_type, runtime_dns_mode))
    return repeat


def runtime_ipv6_repeat(runtime_dns_mode: str = "config-chain") -> dict[str, object]:
    return {
        "schema": "dynet-vm-private-runtime-repeat/v1alpha1",
        "label": "ipv6-no-leak-repeat",
        "runtimeDnsMode": runtime_dns_mode,
        "tcpForward": True,
        "ipv6NoLeak": True,
        "candidateControl": {
            "forceBoundCandidate": None,
            "forcePrivateDownstreamFailure": False,
            "poisonBoundOnly": False,
            "poisonFirstBoundCandidate": False,
            "tcpRouteDirectFallback": False,
            "tcpRouteNonDirectFallback": False,
        },
        "totals": {
            "runs": 2,
            "passedRuns": 2,
            "failedRuns": 0,
            "ipv6PacketsDenied": 2,
            "ipDenials": 2,
            "dnsEarlyTimeouts": 0,
            "tcpFlowStarted": 2,
            "tcpFlowPathComplete": 2,
            "tcpFlowLifecycleComplete": 2,
            "tcpFlowPayloadBidirectional": 2,
            "tcpFlowFailed": 0,
            "tcpFlowStageFailed": 0,
        },
    }


def runtime_ipv6_run(runtime_dns_mode: str = "config-chain") -> dict[str, object]:
    return {
        "schema": "dynet-vm-private-runtime-run/v1alpha1",
        "label": "ipv6-no-leak-run",
        "runtimeDnsMode": runtime_dns_mode,
        "candidateControl": {
            "forceBoundCandidate": None,
            "forcePrivateDownstreamFailure": False,
            "poisonBoundOnly": False,
            "poisonFirstBoundCandidate": False,
            "tcpRouteDirectFallback": False,
            "tcpRouteNonDirectFallback": False,
        },
        "privacy": {
            "rawSecretsStored": False,
            "identityInformationSent": False,
            "cookiesSent": False,
            "authorizationSent": False,
        },
        "productForwarding": {
            "tcpForwardingImplemented": True,
            "ipv6NoLeakGuardEnabled": True,
        },
        "runtime": {"ipv6PacketsDenied": 1},
        "stability": {"ipDenials": 1, "dnsEarlyTimeouts": 0},
        "ipv6Probe": {"ok": True},
        "tcpFlow": {
            "startedFlows": 1,
            "pathCompleteFlows": 1,
            "lifecycleCompleteFlows": 1,
            "payloadBidirectionalFlows": 1,
            "failedFlows": 0,
            "stageFailedFlows": 0,
        },
        "checks": [
            {"name": "tcp-blackbox-https", "passed": True},
            {"name": "tcp-flow-lifecycle-complete", "passed": True},
            {"name": "tcp-flow-path-complete", "passed": True},
            {"name": "tcp-flow-payload-bidirectional", "passed": True},
            {"name": "ipv6-blackbox-no-response", "passed": True},
            {"name": "ipv6-denied-counter", "passed": True},
            {"name": "ipv6-denied-event", "passed": True},
        ],
        "totals": {"failed": 0},
    }


def write_ipv6_repeat(
    root: Path,
    runtime_dns_mode: str = "config-chain",
) -> Path:
    repeat_dir = root / "ipv6-repeat"
    repeat_dir.mkdir()
    repeat = write_json(
        repeat_dir / "summary.json",
        runtime_ipv6_repeat(runtime_dns_mode),
    )
    for index in range(1, 3):
        run_dir = repeat_dir / f"run-{index:02d}"
        run_dir.mkdir()
        write_json(run_dir / "summary.json", runtime_ipv6_run(runtime_dns_mode))
    return repeat


def runtime_guardrail() -> dict[str, object]:
    return {
        "schema": "dynet-vm-private-runtime-run/v1alpha1",
        "label": "downstream-stop",
        "commandExitCode": 0,
        "runtimeDnsMode": "udp-diagnostic-override",
        "candidateControl": {
            "forcePrivateDownstreamFailure": True,
        },
        "checks": [
            {"name": "install-apply", "passed": True},
            {"name": "runtime-report-emitted", "passed": True},
            {"name": "downstream-bound-stage-succeeded", "passed": True},
            {"name": "private-downstream-stage-failed", "passed": True},
            {"name": "downstream-error-disposition", "passed": True},
            {"name": "cascade-non-bound-stop", "passed": True},
            {"name": "cascade-no-second-attempt", "passed": True},
            {"name": "uninstall-cleanup", "passed": True},
        ],
        "privacy": {
            "rawLogsStored": False,
            "rawPacketsStored": False,
            "rawSecretsStored": False,
            "responseBodiesStored": False,
            "responseHeadersStored": False,
            "identityInformationSent": False,
        },
    }


def runtime_guardrail_without(check_name: str) -> dict[str, object]:
    guardrail = runtime_guardrail()
    guardrail["checks"] = [
        item
        for item in guardrail["checks"]
        if isinstance(item, dict) and item["name"] != check_name
    ]
    return guardrail


def paired_read_surface() -> dict[str, object]:
    return {
        "schema": "dynet-clash-paired-read-surface-batch/v1alpha1",
        "conclusion": {
            "status": "dynet-later-read-surface-repeat-drift",
            "classificationClean": True,
        },
        "actionableConclusion": {
            "status": "fresh-config-clean-noncurrent-controls-excluded",
            "action": "exclude-stale-config-controls-from-pressure-bisection",
            "readFailureCount": 0,
            "excludedReadFailureCount": 3,
            "plannerFeedback": "none",
            "qualityFeedback": "none",
            "runtimePolicy": "do-not-change-from-this-artifact-alone",
        },
        "pressureBoundary": {
            "status": "no-dynet-read-failure-in-scope",
            "sourceCount": 2,
        },
        "totals": {"readFailureCount": 3},
        "privacy": {
            "rawLogsStored": False,
            "rawSecretsStored": False,
            "responseBodiesStored": False,
        },
    }


def recommendation() -> dict[str, object]:
    return {
        "schema": "dynet-clash-product-effect-recommendation/v1alpha1",
        "recommendation": {
            "status": "observe-saved-config-drift-repeat-clean",
            "action": "exclude-stale-config-controls-from-pressure-bisection",
            "plannerFeedback": "none",
            "qualityFeedback": "none",
            "runtimePolicy": "do-not-change-from-this-artifact-alone",
            "probePolicy": "no-product-retry-from-this-artifact-alone",
            "pairedPressure": {
                "actionableStatus": "fresh-config-clean-noncurrent-controls-excluded",
                "freshConfig": {"clean": True},
            },
        },
        "privacy": {
            "rawLogsStored": False,
            "rawSecretsStored": False,
            "responseBodiesStored": False,
        },
    }


def write_json(path: Path, data: dict[str, object]) -> Path:
    path.write_text(json.dumps(data, indent=2, sort_keys=True))
    return path


def noop(_: object) -> int:
    return 0
