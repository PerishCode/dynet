from __future__ import annotations

import json
from pathlib import Path

from tests.tunnel_private.quality.support.mainline_baseline import write_json


def runtime_udp_repeat(runtime_dns_mode: str = "config-chain") -> dict[str, object]:
    return {
        "schema": "dynet-vm-private-runtime-repeat/v1alpha1",
        "label": "udp-direct-repeat",
        "runtimeDnsMode": runtime_dns_mode,
        "tcpForward": True,
        "udpForward": True,
        "udpDirectProbe": True,
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
        },
    }


def runtime_udp_run(runtime_dns_mode: str = "config-chain") -> dict[str, object]:
    return {
        "schema": "dynet-vm-private-runtime-run/v1alpha1",
        "label": "udp-direct-run",
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
            "udpForwardingImplemented": True,
        },
        "runtime": {
            "udpSessions": 1,
            "udpUpstreamBytes": 48,
            "udpDownstreamBytes": 48,
            "udpSessionFailures": 0,
            "udpDroppedPackets": 0,
        },
        "udpProbe": {"ok": True, "sentBytes": 48, "receivedBytes": 48},
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
            {"name": "udp-session-events", "passed": True},
            {"name": "udp-attribution-events", "passed": True},
            {"name": "udp-direct-blackbox", "passed": True},
            {"name": "udp-sessions", "passed": True},
            {"name": "udp-upstream-bytes", "passed": True},
            {"name": "udp-downstream-bytes", "passed": True},
            {"name": "udp-no-session-failures", "passed": True},
        ],
        "totals": {"failed": 0},
    }


def write_udp_repeat(
    root: Path,
    runtime_dns_mode: str = "config-chain",
) -> Path:
    repeat_dir = root / "udp-repeat"
    repeat_dir.mkdir()
    repeat = write_json(
        repeat_dir / "summary.json",
        runtime_udp_repeat(runtime_dns_mode),
    )
    for index in range(1, 3):
        run_dir = repeat_dir / f"run-{index:02d}"
        run_dir.mkdir()
        write_json(run_dir / "summary.json", runtime_udp_run(runtime_dns_mode))
    return repeat


def write_udp_session_surface(root: Path, failed_runs: int = 0) -> Path:
    clean = not failed_runs
    return write_json(root / "udp-session.json", {
        "schema": "dynet-vm-private-runtime-udp-session-surface/v1alpha1",
        "label": "udp-session",
        "conclusion": {
            "status": "clean" if clean else "udp-session-surface-needs-evidence",
        },
        "totals": {
            "runs": 2,
            "cleanRuns": 2 - failed_runs,
            "failedRuns": failed_runs,
            "classifications": [
                {"key": "clean" if clean else "udp-session-failure", "count": 2},
            ],
            "sessions": 2,
            "reportedSessions": 2,
            "startedSessions": 2,
            "attributedSessions": 2,
            "connectingSessions": 2,
            "establishedSessions": 2,
            "payloadSentSessions": 2,
            "payloadReceivedSessions": 2 - failed_runs,
            "payloadBidirectionalSessions": 2 - failed_runs,
            "closedSessions": 0,
            "closedWithByteTotals": 0,
            "failedSessions": failed_runs,
            "deniedSessions": 0,
            "failedEvents": failed_runs,
            "deniedEvents": 0,
            "sentEvents": 2,
            "receivedEvents": 2 - failed_runs,
            "sentBytes": 96,
            "receivedBytes": 96 - (48 * failed_runs),
            "reportedUpstreamBytes": 96,
            "reportedDownstreamBytes": 96 - (48 * failed_runs),
            "reportedFailures": failed_runs,
            "reportedDroppedPackets": 0,
            "closedByReason": [],
            "failedByErrorType": [
                {"key": "udp-write", "count": failed_runs},
            ] if failed_runs else [],
            "deniedByErrorType": [],
        },
    })


def write_ipv6_denial_surface(root: Path, failed_runs: int = 0) -> Path:
    clean = not failed_runs
    return write_json(root / "ipv6-denial.json", {
        "schema": "dynet-vm-private-runtime-ipv6-denial-surface/v1alpha1",
        "label": "ipv6-denial",
        "conclusion": {
            "status": "clean" if clean else "ipv6-denial-surface-needs-evidence",
        },
        "totals": ipv6_denial_totals(clean, failed_runs),
    })


def ipv6_denial_totals(clean: bool, failed_runs: int) -> dict[str, object]:
    denials = 2 - failed_runs
    return {
        "runs": 2,
        "cleanRuns": 2 - failed_runs,
        "failedRuns": failed_runs,
        "classifications": [
            {"key": "clean" if clean else "ipv6-denial-missing", "count": 2},
        ],
        "denials": denials,
        "reportedIpv6PacketsDenied": denials,
        "ipv6Denials": denials,
        "nonIpv6Denials": 0,
        "missingFieldEvents": 0,
        "flows": 2,
        "startedFlows": 2,
        "establishedFlows": 2,
        "closedFlows": 2,
        "lifecycleCompleteFlows": 2,
        "pathCompleteFlows": 2,
        "payloadBidirectionalFlows": 2,
        "failedFlows": 0,
        "stageFailedFlows": 0,
        "byIpVersion": [{"key": "6", "count": denials}],
        "byProtocol": [{"key": "udp", "count": denials}],
        "byDestinationPort": [{"key": "443", "count": denials}],
        "byReasonBucket": [
            {"key": "ipv6-forwarding-not-implemented", "count": denials},
        ],
    }


def write_quality_workload(source: Path, unmatched: int) -> Path:
    data = json.loads(source.read_text())
    if unmatched:
        data["totals"]["workloadFlowUnmatchedEntries"] = unmatched
    return write_json(source.parent / "quality-workload.json", data)


def write_takeover_lifecycle_surface(root: Path, failed_runs: int = 0) -> Path:
    clean = not failed_runs
    return write_json(root / "takeover-lifecycle.json", {
        "schema": "dynet-vm-private-runtime-takeover-lifecycle-surface/v1alpha1",
        "label": "takeover-lifecycle",
        "conclusion": {
            "status": "clean" if clean else "takeover-lifecycle-surface-needs-evidence",
        },
        "totals": takeover_lifecycle_totals(clean, failed_runs),
    })


def write_retained_artifact_surface(root: Path, failed_runs: int = 0) -> Path:
    clean = not failed_runs
    return write_json(root / "retained-artifact.json", {
        "schema": "dynet-vm-private-runtime-retained-artifact-surface/v1alpha1",
        "label": "retained-artifact",
        "conclusion": {
            "status": "clean" if clean else "retained-artifact-surface-needs-evidence",
        },
        "totals": retained_artifact_totals(clean, failed_runs),
    })


def write_exit_limit_surface(root: Path, failed_runs: int = 0) -> Path:
    clean = not failed_runs
    return write_json(root / "exit-limit.json", {
        "schema": "dynet-vm-private-runtime-exit-limit-surface/v1alpha1",
        "label": "exit-limit",
        "conclusion": {
            "status": "clean" if clean else "exit-limit-surface-needs-evidence",
        },
        "totals": exit_limit_totals(clean, failed_runs),
    })


def write_collection_stage_surface(root: Path, failed_runs: int = 0) -> Path:
    clean = not failed_runs
    return write_json(root / "collection-stage.json", {
        "schema": "dynet-vm-private-runtime-collection-stage-surface/v1alpha1",
        "label": "collection-stage",
        "conclusion": {
            "status": "clean" if clean else "collection-stage-surface-needs-evidence",
        },
        "totals": collection_stage_totals(clean, failed_runs),
    })


def collection_stage_totals(clean: bool, failed_runs: int) -> dict[str, object]:
    runs = 2
    return {
        "runs": runs,
        "cleanRuns": runs - failed_runs,
        "failedRuns": failed_runs,
        "classifications": [
            {"key": "clean" if clean else "collection-stage-order-invalid", "count": runs},
        ],
        "stageReports": runs,
        "stageCount": 24,
        "stagePassed": 24,
        "stageFailed": 0,
        "requiredStages": 12,
        "requiredPassed": 12,
        "requiredMissing": 0,
        "collectArtifactExpected": 12,
        "collectArtifactPresent": 12,
        "collectStageExpected": 12,
        "collectStagePassed": 12,
        "collectStageMissing": 0,
        "orderViolations": failed_runs,
        "cleanupLast": runs - failed_runs,
        "timingFieldsComplete": 24,
        "unsafePrivacyFlags": 0,
        "stageNames": [{"key": "run-acceptance", "count": 2}],
        "missingRequiredStages": [],
        "missingCollectStages": [],
        "missingArtifacts": [],
        "unsafeFlagNames": [],
    }


def exit_limit_totals(clean: bool, failed_runs: int) -> dict[str, object]:
    runs = 2
    return {
        "runs": runs,
        "cleanRuns": runs - failed_runs,
        "failedRuns": failed_runs,
        "classifications": [
            {"key": "clean" if clean else "runtime-limit-reason-missing", "count": runs},
        ],
        "commandExitZero": runs,
        "runtimePass": runs,
        "runtimeLimitReason": runs - failed_runs,
        "failedChecks": 0,
        "tcpExpectedTerminalSessions": 8,
        "tcpClosedSessions": 8,
        "tcpLimitRuns": runs,
        "tcpLimitSatisfiedRuns": runs,
        "udpDownstreamLimitRuns": 0,
        "udpDownstreamSatisfiedRuns": 0,
        "diagnosticDnsTunLimitRuns": 0,
        "diagnosticDnsTunSatisfiedRuns": 0,
        "runtimeTimeoutReasons": 0,
        "unsafePrivacyFlags": 0,
        "limitEvidence": [{"key": "tcp-terminal-limit", "count": runs}],
        "unsafeFlagNames": [],
    }


def retained_artifact_totals(clean: bool, failed_runs: int) -> dict[str, object]:
    runs = 2
    forbidden = failed_runs
    return {
        "runs": runs,
        "cleanRuns": runs - failed_runs,
        "failedRuns": failed_runs,
        "classifications": [
            {"key": "clean" if clean else "unsafe-privacy-flag", "count": runs},
        ],
        "totalFiles": 24 + forbidden,
        "jsonFiles": 18,
        "markdownFiles": 2,
        "diagnosticTextFiles": 8,
        "requiredJsonPresent": 10,
        "requiredJsonMissing": 0,
        "optionalJsonFiles": 8,
        "summaryArtifacts": runs,
        "runtimeReports": runs,
        "installReports": runs,
        "uninstallReports": runs,
        "stageReports": runs,
        "workloadProbeReports": runs,
        "metadataReports": runs,
        "tcpProbeReports": runs,
        "privacyReports": runs,
        "metadataPrivacyReports": runs,
        "workloadPrivacyReports": runs,
        "remoteSecretConfigCleaned": runs,
        "resolvedIpsRedacted": runs,
        "unsafePrivacyFlags": forbidden,
        "pcapFiles": 0,
        "rawPacketFiles": 0,
        "secretLikeFiles": 0,
        "externalProxyLogFiles": 0,
        "responseBodyFiles": 0,
        "responseHeaderFiles": 0,
        "tunRawLinesStored": 0,
        "tunRawPcapStored": 0,
        "workloadResponseBodiesStored": 0,
        "workloadResponseHeadersStored": 0,
        "workloadResolvedIpAddressesStored": 0,
        "fileKinds": [{"key": "json", "count": 18}],
        "missingRequiredArtifacts": [],
        "unsafeFlagNames": [
            {"key": "privacy.rawSecretsStored", "count": forbidden},
        ] if forbidden else [],
    }


def takeover_lifecycle_totals(clean: bool, failed_runs: int) -> dict[str, object]:
    runs = 2
    return {
        "runs": runs,
        "cleanRuns": runs - failed_runs,
        "failedRuns": failed_runs,
        "classifications": [
            {"key": "clean" if clean else "cleanup-resource-present", "count": runs},
        ],
        "installReports": runs,
        "uninstallReports": runs,
        "stageReports": runs,
        "summaryInstallPassed": runs,
        "summaryUninstallPassed": runs,
        "installChecks": 46,
        "installPassedChecks": 46,
        "installFailedChecks": 0,
        "installRequiredPassed": 14,
        "uninstallChecks": 18,
        "uninstallPassedChecks": 18,
        "uninstallFailedChecks": 0,
        "uninstallRequiredPassed": 12,
        "installResources": 14,
        "installOwnedResources": 14,
        "installPresentResources": 12,
        "installRequiredPresent": 12,
        "uninstallResources": 14,
        "uninstallOwnedResources": 14,
        "uninstallPresentResources": failed_runs,
        "uninstallRequiredAbsent": 14 - failed_runs,
        "stageCount": 34,
        "stagePassed": 34,
        "stageFailed": 0,
        "stageRequiredPassed": 8,
        "diagnostics": 0,
        "failedInstallChecks": [],
        "failedUninstallChecks": [],
        "installResourceKinds": resource_kinds(),
        "uninstallResourceKinds": resource_kinds(),
        "stageNames": [
            {"key": "collect-install-report", "count": 2},
            {"key": "collect-uninstall-report", "count": 2},
            {"key": "cleanup-guest-files", "count": 2},
            {"key": "run-acceptance", "count": 2},
        ],
    }


def resource_kinds() -> list[dict[str, object]]:
    return [
        {"key": "nft-dropin", "count": 2},
        {"key": "nft-table", "count": 2},
        {"key": "route-table", "count": 2},
        {"key": "runtime-dir", "count": 2},
        {"key": "socket-mark", "count": 2},
        {"key": "state-dir", "count": 2},
        {"key": "tun", "count": 2},
    ]
