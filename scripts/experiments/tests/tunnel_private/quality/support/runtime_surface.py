from __future__ import annotations

from pathlib import Path

from tests.tunnel_private.quality.support.mainline_baseline import write_json


def write_workload_surface(root: Path, failed_rows: int = 0) -> Path:
    status = "packet-terminal-workload-surface" if failed_rows else "clean"
    return write_json(root / "workload-surface.json", {
        "schema": "dynet-vm-private-runtime-workload-surface/v1alpha1",
        "label": "workload-surface",
        "conclusion": {
            "status": status,
            "nextAction": "return-to-product-effect",
            "plannerPenaltySafe": False,
            "qualityPenaltySafe": False,
            "productEffectClaimSafe": False,
            "mechanisms": workload_surface_mechanisms(failed_rows),
        },
        "policy": {
            "plannerPenaltySafe": False,
            "qualityPenaltySafe": False,
            "productEffectClaimSafe": False,
        },
        "totals": {
            "runs": 2,
            "cleanRuns": 2 - min(failed_rows, 1),
            "failedRuns": min(failed_rows, 1),
            "workloadAttempted": 8,
            "workloadFailure": failed_rows,
            "failedRows": failed_rows,
            "qualityCandidateSets": 8,
            "qualitySelectedWithQuality": 8,
            "qualitySelectedBehind": 0,
            "preTcpFailures": 0,
            "packetTerminalFailures": failed_rows,
        },
    })


def write_payload_surface(root: Path, failed_runs: int = 0) -> Path:
    return write_json(root / "payload-surface.json", {
        "schema": "dynet-vm-private-runtime-payload-surface/v1alpha1",
        "label": "payload-surface",
        "conclusion": {"status": "clean" if not failed_runs else "payload-surface-needs-evidence"},
        "totals": {
            "runs": 2,
            "cleanRuns": 2 - failed_runs,
            "failedRuns": failed_runs,
            "classifications": [
                {"key": "clean" if not failed_runs else "payload-missing", "count": 2},
            ],
            "flows": 8,
            "startedFlows": 8,
            "establishedFlows": 8,
            "closedFlows": 8,
            "lifecycleCompleteFlows": 8,
            "pathCompleteFlows": 8,
            "closedWithByteTotals": 8,
            "payloadStartedFlows": 8,
            "payloadReceivedFlows": 8,
            "payloadBidirectionalFlows": 8,
            "payloadCloseConsistent": 8,
            "closedWithoutPayloadFlows": failed_runs,
            "duplicateClosedFlows": 0,
            "failedFlows": 0,
            "stageFailedFlows": 1,
        },
    })


def write_close_surface(root: Path, failed_runs: int = 0) -> Path:
    clean = not failed_runs
    return write_json(root / "close-surface.json", {
        "schema": "dynet-vm-private-runtime-close-surface/v1alpha1",
        "label": "close-surface",
        "conclusion": {
            "status": "clean" if clean else "close-surface-needs-evidence",
        },
        "totals": {
            "runs": 2,
            "cleanRuns": 2 - failed_runs,
            "failedRuns": failed_runs,
            "classifications": [
                {"key": "clean" if clean else "duplicate-close", "count": 2},
            ],
            "flows": 8,
            "startedFlows": 8,
            "establishedFlows": 8,
            "closedFlows": 8,
            "failedFlows": 0,
            "terminalEvents": 8,
            "closedReasonFlows": 8,
            "closedWithByteTotals": 8,
            "payloadBidirectionalFlows": 8,
            "payloadCloseConsistent": 8,
            "lifecycleCompleteFlows": 8,
            "pathCompleteFlows": 8,
            "closedWithoutPayloadFlows": 0,
            "duplicateClosedFlows": failed_runs,
            "closedByReason": [{"key": "outbound-eof", "count": 8}],
            "failedBySurface": [],
        },
    })


def write_stage_surface(root: Path, failed_runs: int = 0, unrecovered: int = 0) -> Path:
    clean = not failed_runs and not unrecovered
    return write_json(root / "stage-surface.json", {
        "schema": "dynet-vm-private-runtime-stage-surface/v1alpha1",
        "label": "stage-surface",
        "conclusion": {"status": "clean" if clean else "stage-surface-needs-evidence"},
        "totals": {
            "runs": 2,
            "cleanRuns": 2 - min(failed_runs + unrecovered, 1),
            "failedRuns": min(failed_runs + unrecovered, 1),
            "classifications": [
                {"key": "clean" if clean else "unrecovered-stage-failure", "count": 2},
            ],
            "flows": 8,
            "stageFlows": 8,
            "stageEvents": 20,
            "successStageEvents": 19,
            "failedStageEvents": 1,
            "stageFailedFlows": 1,
            "recoveredStageFailedFlows": max(0, 1 - unrecovered),
            "unrecoveredStageFailedFlows": unrecovered,
            "pathCompleteFlows": 8,
            "lifecycleCompleteFlows": 8,
            "payloadBidirectionalFlows": 8,
            "failedFlows": 0,
            "failedBySurface": [{"key": "trojan-tls-handshake:trojan", "count": 1}],
            "failedByDisposition": [{"key": "reset", "count": 1}],
        },
    })


def write_timing_surface(root: Path, failed_runs: int = 0) -> Path:
    clean = not failed_runs
    return write_json(root / "timing-surface.json", {
        "schema": "dynet-vm-private-runtime-timing-surface/v1alpha1",
        "label": "timing-surface",
        "conclusion": {"status": "clean" if clean else "timing-surface-needs-evidence"},
        "totals": {
            "runs": 2,
            "cleanRuns": 2 - failed_runs,
            "failedRuns": failed_runs,
            "classifications": [
                {"key": "clean" if clean else "timing-incomplete", "count": 2},
            ],
            "flows": 8,
            "startedFlows": 8,
            "attributedFlows": 8,
            "connectingFlows": 8,
            "establishedFlows": 8,
            "firstPayloadFlows": 8,
            "firstDownstreamFlows": 8,
            "closedFlows": 8,
            "failedFlows": 0,
            "orderedFlows": 8,
            "timings": {
                "closedMs": {"p95": 1200},
                "firstDownstreamMs": {"p95": 600},
            },
        },
    })


def write_dns_timing(root: Path, failed_runs: int = 0) -> Path:
    clean = not failed_runs
    return write_json(root / "dns-timing.json", {
        "schema": "dynet-vm-private-runtime-dns-timing-surface/v1alpha1",
        "label": "dns-timing",
        "conclusion": {"status": "clean" if clean else "dns-timing-surface-needs-evidence"},
        "totals": {
            "runs": 2,
            "cleanRuns": 2 - failed_runs,
            "failedRuns": failed_runs,
            "classifications": [
                {"key": "clean" if clean else "dns-failure", "count": 2},
            ],
            "queries": 8,
            "receivedQueries": 8,
            "completedQueries": 8,
            "failedQueries": failed_runs,
            "queriesWithRecords": 8,
            "records": 10,
            "orderedQueries": 8,
            "completedWithElapsed": 8,
            "resolveMs": {"p95": 180},
            "reportedElapsedMs": {"p95": 180},
        },
    })


def write_outbound_timing(root: Path, failed_runs: int = 0) -> Path:
    clean = not failed_runs
    return write_json(root / "outbound-timing.json", {
        "schema": "dynet-vm-private-runtime-outbound-timing-surface/v1alpha1",
        "label": "outbound-timing",
        "conclusion": {
            "status": "clean" if clean else "outbound-timing-surface-needs-evidence",
        },
        "totals": {
            "runs": 2,
            "cleanRuns": 2 - failed_runs,
            "failedRuns": failed_runs,
            "classifications": [
                {"key": "clean" if clean else "cascade-success-missing", "count": 2},
            ],
            "flows": 8,
            "attemptEvents": 9,
            "successfulAttemptEvents": 8,
            "failedAttemptEvents": 1,
            "attemptFlows": 8,
            "successfulAttemptFlows": 8,
            "cascadeEvents": 9,
            "successfulCascadeEvents": 8,
            "failedCascadeEvents": 1,
            "cascadeFlows": 8,
            "successfulCascadeFlows": 8 - failed_runs,
            "stageEvents": 32,
            "successStageEvents": 31,
            "failedStageEvents": 1,
            "stageFlows": 8,
            "failureFlows": 1,
            "recoveredFailureFlows": 1 - min(failed_runs, 1),
            "unrecoveredFailureFlows": min(failed_runs, 1),
            "pathCompleteFlows": 8,
            "lifecycleCompleteFlows": 8,
            "payloadBidirectionalFlows": 8,
            "failedFlows": 0,
            "failedByCascadeScope": [{"key": "bound", "count": 1}],
            "failedAttemptByProtocol": [{"key": "trojan", "count": 1}],
            "failedStageBySurface": [{"key": "trojan-tls-handshake:trojan", "count": 1}],
            "failedStageByDisposition": [{"key": "reset", "count": 1}],
            "timings": {
                "successfulAttemptElapsedMs": {"p95": 300},
                "successfulCascadeElapsedMs": {"p95": 320},
                "successfulStageElapsedMs": {"p95": 280},
            },
        },
    })


def write_packet_surface(root: Path, failed_runs: int = 0) -> Path:
    clean = not failed_runs
    return write_json(root / "packet-surface.json", {
        "schema": "dynet-vm-private-runtime-packet-surface/v1alpha1",
        "label": "packet-surface",
        "conclusion": {
            "status": "clean" if clean else "packet-surface-needs-evidence",
        },
        "totals": {
            "runs": 2,
            "cleanRuns": 2 - failed_runs,
            "failedRuns": failed_runs,
            "classifications": [
                {"key": "clean" if clean else "preflow-missing", "count": 2},
            ],
            "flows": 8,
            "startedFlows": 8,
            "closedFlows": 8,
            "failedFlows": 0,
            "lifecycleCompleteFlows": 8,
            "pathCompleteFlows": 8,
            "packetPorts": 8,
            "packetHandshakePorts": 8,
            "preflowPorts": 8 - failed_runs,
            "packetTerminalPorts": 0,
            "preflowCandidatePorts": 0,
            "preflowMissedPorts": failed_runs,
            "capacityEvents": 2,
            "pressureEvents": 1,
            "ingressControlPackets": 16,
            "ingressSynPackets": 8,
            "egressControlPackets": 16,
            "egressSynAckPackets": 8,
            "ingressPayloadPackets": 8,
            "ingressPayloadBytes": 2048,
            "egressPayloadPackets": 8,
            "egressPayloadBytes": 4096,
            "finPackets": 0,
            "rstPackets": 0,
            "packetTerminalByReason": [],
            "preflowCandidateByReason": [],
            "preflowMissedByReason": [
                {"key": "missing-preflow", "count": failed_runs},
            ] if failed_runs else [],
            "preflowMissedBySocketState": [
                {"key": "closed", "count": failed_runs},
            ] if failed_runs else [],
        },
    })


def write_outbound_gate(root: Path, failed_runs: int = 0) -> Path:
    clean = not failed_runs
    return write_json(root / "outbound-gate.json", {
        "schema": "dynet-vm-private-runtime-outbound-gate-surface/v1alpha1",
        "label": "outbound-gate",
        "conclusion": {
            "status": "clean" if clean else "outbound-gate-surface-needs-evidence",
        },
        "totals": {
            "runs": 2,
            "cleanRuns": 2 - failed_runs,
            "failedRuns": failed_runs,
            "classifications": [
                {"key": "clean" if clean else "bound-egress-missing", "count": 2},
            ],
            "flows": 8,
            "startedFlows": 8,
            "closedFlows": 8,
            "failedFlows": 0,
            "lifecycleCompleteFlows": 8,
            "pathCompleteFlows": 8,
            "payloadBidirectionalFlows": 8,
            "admissionEvents": 16,
            "egressEvents": 16,
            "admissionFlows": 8,
            "egressFlows": 8,
            "routeAdmissionEvents": 8,
            "routeAdmissionFlows": 8,
            "routeEgressEvents": 8,
            "routeEgressFlows": 8,
            "routeEgressSelectedFlows": 8,
            "routeEgressMismatches": 0,
            "boundAdmissionEvents": 8,
            "boundAdmissionFlows": 8,
            "boundEgressEvents": 8 - failed_runs,
            "boundEgressFlows": 8 - failed_runs,
            "boundEgressSelectedFlows": 8 - failed_runs,
            "admissionMissingOutboundEvents": 0,
            "egressMissingSelectedEvents": 0,
            "unknownScopeEvents": 0,
            "nonTcpTransportEvents": 0,
            "eventsByScope": [
                {"key": "dialer-bound", "count": 16 - failed_runs},
                {"key": "tcp-route", "count": 16},
            ],
        },
    })


def workload_surface_mechanisms(failed_rows: int) -> list[dict[str, object]]:
    if not failed_rows:
        return []
    return [
        {
            "mechanism": "packet-terminal-before-runtime-session",
            "count": failed_rows,
        }
    ]


def write_flow_refresh(root: Path, changed_runs: int = 0) -> Path:
    return write_json(root / "flow-refresh.json", {
        "schema": "dynet-vm-private-runtime-flow-refresh/v1alpha1",
        "label": "flow-refresh",
        "totals": {
            "runs": 2,
            "changedRuns": changed_runs,
            "recoveredStageSeparatedRuns": 0,
            "classifications": [
                {"key": "changed" if changed_runs else "unchanged", "count": 2},
            ],
        },
    })


def write_dns_refresh(root: Path, inconsistent_runs: int = 0, failed_queries: int = 0) -> Path:
    classification = "inconsistent-events" if inconsistent_runs else "unchanged"
    completed = 8 - failed_queries
    return write_json(root / "dns-refresh.json", {
        "schema": "dynet-vm-private-runtime-dns-refresh/v1alpha1",
        "label": "dns-refresh",
        "totals": {
            "runs": 2,
            "changedRuns": 0,
            "inconsistentRuns": inconsistent_runs,
            "dnsQueries": 8,
            "dnsRecords": completed,
            "proxiedDnsQueries": 0,
            "queryReceivedEvents": 8,
            "resolveCompletedEvents": completed,
            "reverseRecordEvents": completed,
            "resolveFailedEvents": failed_queries,
            "proxiedCompletedEvents": 0,
            "terminalEvents": 8,
            "queriesWithRecords": completed,
            "queriesMissingCompletion": 0,
            "completedMissingQuery": 0,
            "failedMissingQuery": 0,
            "recordsMissingQuery": 0,
            "classifications": [{"key": classification, "count": 2}],
        },
    })


def write_route_refresh(
    root: Path, changed_runs: int = 0, private_connect_flows: int = 8,
) -> Path:
    return write_json(root / "route-refresh.json", {
        "schema": "dynet-vm-private-runtime-route-refresh/v1alpha1",
        "label": "route-refresh",
        "totals": {
            "runs": 2,
            "changedRuns": changed_runs,
            "classifications": [{"key": "changed" if changed_runs else "unchanged", "count": 2}],
            "routeMatchedFlows": 8,
            "planBypassedFlows": 0,
            "routeGraphSelectedFlows": 8,
            "boundCandidateSetFlows": 8,
            "boundGraphSelectedFlows": 8,
            "cascadeSelectedFlows": 8,
            "boundAttemptStartedFlows": 8,
            "boundAttemptSucceededFlows": 8,
            "privateConnectFlows": private_connect_flows,
            "pathCompleteFlows": 8,
            "failedFlows": changed_runs,
        },
    })


def write_selection_refresh(
    root: Path, changed_runs: int = 0, selected_behind: int = 0,
    selected_with_quality: int = 8, fallback_selected_with_quality: int = 1,
    fallback_selected_behind: int = 1,
) -> Path:
    return write_json(root / "selection-refresh.json", {
        "schema": "dynet-vm-private-runtime-selection-refresh/v1alpha1",
        "label": "selection-refresh",
        "totals": {
            "runs": 2,
            "changedRuns": changed_runs,
            "classifications": [
                {"key": "changed" if changed_runs else "unchanged", "count": 2},
            ],
            "candidateSets": 8,
            "attemptCandidateSets": 9,
            "fallbackCandidateSets": 1,
            "withBoundSelected": 8,
            "selectedWithQuality": selected_with_quality,
            "selectedBest": 8 - selected_behind,
            "selectedBehind": selected_behind,
            "fallbackSelectedWithQuality": fallback_selected_with_quality,
            "fallbackSelectedBehind": fallback_selected_behind,
        },
    })


def write_cascade_refresh(root: Path, changed_runs: int = 0) -> Path:
    return write_json(root / "cascade-refresh.json", {
        "schema": "dynet-vm-private-runtime-cascade-refresh/v1alpha1",
        "label": "cascade-refresh",
        "totals": {
            "runs": 2,
            "changedRuns": changed_runs,
            "failedAttempts": 1,
            "retryableFailures": 1,
            "stoppedFailures": changed_runs,
            "stoppedBoundExhaustedFlows": 0,
            "recoveredFlows": 1,
            "classifications": [
                {"key": "changed" if changed_runs else "unchanged", "count": 2},
            ],
        },
    })


def write_target_identity_refresh(root: Path, mismatched: int = 0, missing_adapter: int = 0) -> Path:
    matched = 8 - mismatched - missing_adapter
    classification = "changed" if mismatched else "unchanged"
    return write_json(root / "target-identity-refresh.json", {
        "schema": "dynet-vm-private-runtime-target-identity-refresh/v1alpha1",
        "label": "target-identity-refresh",
        "totals": {
            "runs": 2,
            "changedRuns": 1 if mismatched else 0,
            "connectingEvents": 8,
            "adapterConnectEvents": 8 - missing_adapter,
            "withConnectTarget": 8,
            "withAdapterTarget": 8 - missing_adapter,
            "withIdentityDomain": 8,
            "withTargetAddressSource": 8,
            "targetChainFlows": 8,
            "targetChainMatched": matched,
            "targetChainMismatched": mismatched,
            "targetChainMissingAdapter": missing_adapter,
            "targetChainMissingConnect": 0,
            "targetChainDuplicateAdapterFlows": 0,
            "classifications": [
                {"key": classification, "count": 2},
            ],
        },
    })
