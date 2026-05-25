from __future__ import annotations

from pathlib import Path

from tests.tunnel_private.quality.support.mainline_baseline import write_json


def write_event_stream_surface(root: Path, failed_runs: int = 0) -> Path:
    clean = not failed_runs
    return write_json(root / "event-stream.json", {
        "schema": "dynet-vm-private-runtime-event-stream-surface/v1alpha1",
        "label": "event-stream",
        "conclusion": {
            "status": "clean" if clean else "event-stream-surface-needs-evidence",
        },
        "totals": event_stream_totals(clean, failed_runs),
    })


def write_event_correlation_surface(root: Path, failed_runs: int = 0) -> Path:
    clean = not failed_runs
    return write_json(root / "event-correlation.json", {
        "schema": "dynet-vm-private-runtime-event-correlation-surface/v1alpha1",
        "label": "event-correlation",
        "conclusion": {
            "status": "clean" if clean else "event-correlation-surface-needs-evidence",
        },
        "totals": event_correlation_totals(clean, failed_runs),
    })


def write_event_causality_surface(root: Path, failed_runs: int = 0) -> Path:
    clean = not failed_runs
    return write_json(root / "event-causality.json", {
        "schema": "dynet-vm-private-runtime-event-causality-surface/v1alpha1",
        "label": "event-causality",
        "conclusion": {
            "status": "clean" if clean else "event-causality-surface-needs-evidence",
        },
        "totals": event_causality_totals(clean, failed_runs),
    })


def write_outbound_retry_surface(root: Path, failed_runs: int = 0) -> Path:
    clean = not failed_runs
    return write_json(root / "outbound-retry.json", {
        "schema": "dynet-vm-private-runtime-outbound-retry-surface/v1alpha1",
        "label": "outbound-retry",
        "conclusion": {
            "status": "clean" if clean else "outbound-retry-surface-needs-evidence",
        },
        "totals": outbound_retry_totals(clean, failed_runs),
    })


def write_outbound_attempt_surface(root: Path, failed_runs: int = 0) -> Path:
    clean = not failed_runs
    return write_json(root / "outbound-attempt.json", {
        "schema": "dynet-vm-private-runtime-outbound-attempt-surface/v1alpha1",
        "label": "outbound-attempt",
        "conclusion": {
            "status": "clean" if clean else "outbound-attempt-surface-needs-evidence",
        },
        "totals": outbound_attempt_totals(clean, failed_runs),
    })


def write_stage_chain_surface(root: Path, failed_runs: int = 0) -> Path:
    clean = not failed_runs
    return write_json(root / "stage-chain.json", {
        "schema": "dynet-vm-private-runtime-outbound-stage-chain-surface/v1alpha1",
        "label": "stage-chain",
        "conclusion": {
            "status": "clean" if clean else "stage-chain-surface-needs-evidence",
        },
        "totals": stage_chain_totals(clean, failed_runs),
    })


def write_tcp_pressure_surface(root: Path, failed_runs: int = 0) -> Path:
    clean = not failed_runs
    return write_json(root / "tcp-pressure.json", {
        "schema": "dynet-vm-private-runtime-tcp-pressure-surface/v1alpha1",
        "label": "tcp-pressure",
        "conclusion": {
            "status": "clean" if clean else "tcp-pressure-surface-needs-evidence",
        },
        "totals": tcp_pressure_totals(clean, failed_runs),
    })


def write_dns_forward_surface(root: Path, failed_runs: int = 0) -> Path:
    clean = not failed_runs
    return write_json(root / "dns-forward.json", {
        "schema": "dynet-vm-private-runtime-dns-forward-surface/v1alpha1",
        "label": "dns-forward",
        "conclusion": {
            "status": "clean" if clean else "dns-forward-surface-needs-evidence",
        },
        "totals": dns_forward_totals(clean, failed_runs),
    })


def write_route_decision_surface(root: Path, failed_runs: int = 0) -> Path:
    clean = not failed_runs
    return write_json(root / "route-decision.json", {
        "schema": "dynet-vm-private-runtime-route-decision-surface/v1alpha1",
        "label": "route-decision",
        "conclusion": {
            "status": "clean" if clean else "route-decision-surface-needs-evidence",
        },
        "totals": route_decision_totals(clean, failed_runs),
    })


def route_decision_totals(clean: bool, failed_runs: int) -> dict[str, object]:
    return {
        "runs": 2,
        "cleanRuns": 2 - failed_runs,
        "failedRuns": failed_runs,
        "classifications": [
            {"key": "clean" if clean else "route-counter-mismatch", "count": 2},
        ],
        "eventReports": 2,
        "runtimePass": 2,
        "events": 80,
        "reportedRouteDecisions": 10,
        "routeMatchedEvents": 10,
        "routeDecisionCounterMismatches": failed_runs,
        "tcpRouteMatched": 8,
        "udpRouteMatched": 2,
        "unknownTransportRouteMatched": 0,
        "routeMatchedMissingStatus": 0,
        "routeMatchedMissingOutbound": 0,
        "routeMatchedMissingTransport": 0,
        "tcpRouteMissingFlowId": 0,
        "tcpRouteMissingSession": 0,
        "tcpRouteGraphSelected": 8,
        "tcpRouteMissingGraph": 0,
        "tcpRouteGraphWithoutRoute": 0,
        "udpRouteGraphSelected": 2,
        "udpRouteGraphMismatches": 0,
        "routeGraphMissingSelected": 0,
        "routeGraphMissingRequested": 0,
        "planBypassedEvents": 2,
        "planCandidateGraphSelected": 2,
        "planBypassMissingGraph": 0,
        "planGraphWithoutBypass": 0,
        "routeCandidateSets": 2,
        "routeCandidateMissingGraph": 0,
        "routeCandidateMissingSelected": 0,
        "routeCandidateMissingCount": 0,
        "decisionPaths": [
            {"key": "tcp-route", "count": 8},
            {"key": "udp-route", "count": 2},
            {"key": "plan-candidate", "count": 2},
        ],
    }


def dns_forward_totals(clean: bool, failed_runs: int) -> dict[str, object]:
    return {
        "runs": 2,
        "cleanRuns": 2 - failed_runs,
        "failedRuns": failed_runs,
        "classifications": [
            {"key": "clean" if clean else "forward-terminal-missing", "count": 2},
        ],
        "eventReports": 2,
        "runtimePass": 2,
        "events": 40,
        "dnsQueries": 2,
        "diagnosticQueries": 2,
        "ruleBypassQueries": 2,
        "planBypassedQueries": 2,
        "proxyForwardQueries": 2,
        "terminalCompletedQueries": 0,
        "terminalFailureQueries": 2 - failed_runs,
        "orderChecked": 2,
        "orderViolations": 0,
        "ruleMissingPlanBypass": 0,
        "planBypassMissingRule": 0,
        "planBypassMissingForward": 0,
        "forwardMissingPlanBypass": 0,
        "forwardMissingTerminal": failed_runs,
        "forwardMissingOutbound": 0,
        "forwardMissingUpstream": 0,
        "failureMissingResponseCode": 0,
        "failureMissingDisposition": 0,
        "nonUdpForward": 0,
        "nonDnsRuleBypass": 0,
    }


def tcp_pressure_totals(clean: bool, failed_runs: int) -> dict[str, object]:
    return {
        "runs": 2,
        "cleanRuns": 2 - failed_runs,
        "failedRuns": failed_runs,
        "classifications": [
            {"key": "clean" if clean else "pressure-count-mismatch", "count": 2},
        ],
        "eventReports": 2,
        "runtimePass": 2,
        "events": 120,
        "tcpSessions": 8,
        "tcpClosedSessions": 8,
        "tcpUnclosedSessions": 0,
        "tcpSessionFailures": 0,
        "reportedCapacity": 32,
        "reportedSlotsPerPort": 16,
        "reportedListenPorts": 4,
        "reportedActiveSlotsMax": 16,
        "reportedPressureEvents": 4,
        "capacityEvents": 2,
        "pressureEvents": 4 + failed_runs,
        "capacityMissingForTcpRuns": 0,
        "capacityMissingFields": 0,
        "capacityMismatches": 0,
        "capacityFormulaMismatches": 0,
        "pressureCountMismatches": failed_runs,
        "pressureMissingFields": 0,
        "pressureCapacityMismatches": 0,
        "pressureActiveOverCapacity": 0,
        "pressureActiveOverReportedMax": 0,
    }


def outbound_retry_totals(clean: bool, failed_runs: int) -> dict[str, object]:
    return {
        "runs": 2,
        "cleanRuns": 2 - failed_runs,
        "failedRuns": failed_runs,
        "classifications": [
            {"key": "clean" if clean else "non-retryable-continued", "count": 2},
        ],
        "eventReports": 2,
        "runtimePass": 2,
        "events": 120,
        "cascadeAttempts": 10,
        "cascadeSuccesses": 8,
        "cascadeFailures": 2,
        "retryableCascadeFailures": 1,
        "retryableWithNextAttempt": 1,
        "retryableMissingNextAttempt": 0,
        "nonRetryableCascadeFailures": 1,
        "nonRetryableWithNextAttempt": failed_runs,
        "nonRetryableWithoutNextAttempt": 1 - min(failed_runs, 1),
        "boundRetryFailures": 1,
        "boundRetryMissingStopReason": 0,
        "boundRetryMissingNextAttempt": 0,
        "boundExhaustedStops": 1,
        "boundExhaustedRecoveredFlows": 1 - min(failed_runs, 1),
        "boundExhaustedUnrecoveredFlows": 0,
        "nonBoundStops": 0,
        "nonBoundWithNextAttempt": 0,
        "failureScopeMissing": 0,
        "retryAllowedMissing": 0,
        "retryStopReasonMissing": 0,
        "invalidRetryStopReasons": 0,
        "retryableNonBoundFailures": 0,
        "successScopeMismatches": 0,
        "tcpFailureFlows": 2,
        "tcpRecoveredFailureFlows": 2,
        "tcpUnrecoveredFailureFlows": 0,
        "dnsFailureQueries": 0,
        "dnsTerminalFailureQueries": 0,
    }


def outbound_attempt_totals(clean: bool, failed_runs: int) -> dict[str, object]:
    return {
        "runs": 2,
        "cleanRuns": 2 - failed_runs,
        "failedRuns": failed_runs,
        "classifications": [
            {"key": "clean" if clean else "attempt-start-without-finish", "count": 2},
        ],
        "eventReports": 2,
        "runtimePass": 2,
        "events": 120,
        "attemptStarts": 12,
        "attemptFinishes": 12,
        "attemptPairs": 12,
        "finishWithoutStart": 0,
        "startWithoutFinish": failed_runs,
        "attemptOrderViolations": 0,
        "attemptStatusMissing": 0,
        "attemptInvalidStatus": 0,
        "attemptProtocolMissing": 0,
        "attemptInvalidProtocol": 0,
        "attemptTransportMissing": 0,
        "attemptInvalidTransport": 0,
        "attemptReferenceMissing": 0,
        "attemptOutboundMissing": 0,
        "attemptFinishElapsedMissing": 0,
        "failedAttemptErrorTypeMissing": 0,
        "failedAttemptDispositionMissing": 0,
        "successfulAttempts": 10,
        "failedAttempts": 2,
        "sessionTcpAttempts": 10,
        "sessionTcpAttemptsMissingRoute": 0,
        "attemptsWithStage": 12,
        "attemptsMissingStage": 0,
        "cascadeStarts": 10,
        "cascadeFinishes": 10,
        "cascadePairs": 10,
        "cascadeFinishWithoutStart": 0,
        "cascadeStartWithoutFinish": 0,
        "cascadeOrderViolations": 0,
        "cascadeStatusMissing": 0,
        "cascadeInvalidStatus": 0,
        "cascadeReferenceMissing": 0,
        "cascadeAttemptMissing": 0,
        "cascadeFailureScopeMissing": 0,
        "cascadeFailureRetryAllowedMissing": 0,
        "cascadeFailureRetryStopReasonMissing": 0,
        "cascadeWithOutboundAttempt": 10,
        "cascadeMissingOutboundAttempt": 0,
        "attemptProtocols": [{"key": "tcp-connect", "count": 10}],
        "attemptTransports": [{"key": "tcp", "count": 10}],
        "attemptStatuses": [{"key": "tcp-connect:success", "count": 10}],
        "cascadeStatuses": [{"key": "success:none", "count": 10}],
    }


def stage_chain_totals(clean: bool, failed_runs: int) -> dict[str, object]:
    return {
        "runs": 2,
        "cleanRuns": 2 - failed_runs,
        "failedRuns": failed_runs,
        "classifications": [
            {"key": "clean" if clean else "success-required-stage-missing", "count": 2},
        ],
        "eventReports": 2,
        "runtimePass": 2,
        "events": 120,
        "stageEvents": 40,
        "attempts": 12,
        "knownProfileAttempts": 12,
        "unknownProfileAttempts": 0,
        "successAttempts": 10,
        "failedAttempts": 2,
        "successMissingRequiredStages": failed_runs,
        "failedMissingFailureStage": 0,
        "stageStatusMissing": 0,
        "stageKindMissing": 0,
        "stageNameMissing": 0,
        "stageReferenceMissing": 0,
        "stageOutboundMissing": 0,
        "stageElapsedMissing": 0,
        "stageFailureDispositionMissing": 0,
        "stageFailureErrorTypeMissing": 0,
        "attemptProfiles": [{"key": "tcp-connect:trojan:success", "count": 10}],
        "stageProfiles": [{"key": "trojan:tcp-connect:success", "count": 10}],
        "missingRequiredStages": [],
        "failedStageProfiles": [{"key": "trojan:trojan-tls-handshake:failed", "count": 2}],
    }


def event_causality_totals(clean: bool, failed_runs: int) -> dict[str, object]:
    return {
        "runs": 2,
        "cleanRuns": 2 - failed_runs,
        "failedRuns": failed_runs,
        "classifications": [
            {"key": "clean" if clean else "tcp-order-invalid", "count": 2},
        ],
        "eventReports": 2,
        "runtimePass": 2,
        "events": 40,
        "tcpFlows": 4,
        "udpFlows": 2,
        "dnsQueries": 2,
        "tcpOrderChecked": 4,
        "tcpMissingOrderEvents": 0,
        "tcpOrderViolations": failed_runs,
        "tcpTerminalOrderViolations": 0,
        "udpOrderChecked": 2,
        "udpMissingOrderEvents": 0,
        "udpOrderViolations": 0,
        "dnsOrderChecked": 2,
        "dnsMissingTerminalEvents": 0,
        "dnsOrderViolations": 0,
        "dnsReverseOrderViolations": 0,
        "outboundAttemptStarts": 4,
        "outboundAttemptFinishes": 4,
        "unmatchedOutboundAttemptFinishes": 0,
        "outboundAttemptOrderViolations": 0,
        "outboundAttemptCountMismatches": 0,
        "cascadeAttemptStarts": 4,
        "cascadeAttemptFinishes": 4,
        "unmatchedCascadeAttemptFinishes": 0,
        "cascadeAttemptOrderViolations": 0,
        "cascadeAttemptCountMismatches": 0,
        "egressEvents": 6,
        "egressMissingAdmission": 0,
        "egressBeforeAdmission": 0,
        "stageEvents": 12,
        "stageMissingAttempt": 0,
        "stageBeforeAttempt": 0,
    }


def event_stream_totals(clean: bool, failed_runs: int) -> dict[str, object]:
    runs = 2
    return {
        "runs": runs,
        "cleanRuns": runs - failed_runs,
        "failedRuns": failed_runs,
        "classifications": [
            {"key": "clean" if clean else "event-sequence-gap", "count": runs},
        ],
        "eventReports": runs,
        "runtimePass": runs,
        "events": 40,
        "eventKinds": 12,
        "invalidEventObjects": 0,
        "invalidSchemaEvents": 0,
        "missingKindEvents": 0,
        "missingFieldsEvents": 0,
        "missingSequenceEvents": 0,
        "missingTimestampEvents": 0,
        "duplicateSequences": 0,
        "sequenceGaps": failed_runs,
        "sequenceStartMismatches": 0,
        "sequenceEndMismatches": 0,
        "sequenceOrderViolations": 0,
        "timestampOrderViolations": 0,
        "unknownEventKinds": 0,
        "missingRequiredFields": 0,
        "counterMismatches": 0,
        "byteCounterMismatches": 0,
        "eventKindCounts": [{"key": "tcp-session-started", "count": 2}],
        "missingFieldNames": [],
        "counterMismatchNames": [],
        "byteCounterMismatchNames": [],
    }


def event_correlation_totals(clean: bool, failed_runs: int) -> dict[str, object]:
    runs = 2
    return {
        "runs": runs,
        "cleanRuns": runs - failed_runs,
        "failedRuns": failed_runs,
        "classifications": [
            {"key": "clean" if clean else "orphan-flow-ref", "count": runs},
        ],
        "eventReports": runs,
        "runtimePass": runs,
        "events": 40,
        "tcpFlows": 4,
        "udpFlows": 2,
        "dnsQueries": 2,
        "flowIdReferences": 30,
        "dnsQueryReferences": 2,
        "sessionReferences": 20,
        "orphanFlowRefs": failed_runs,
        "orphanDnsQueryRefs": 0,
        "unknownFlowPrefixes": 0,
        "duplicateTcpRoots": 0,
        "duplicateUdpRoots": 0,
        "duplicateDnsRoots": 0,
        "sessionMismatches": 0,
        "missingTcpAttribution": 0,
        "missingTcpRoute": 0,
        "missingTcpConnecting": 0,
        "missingTcpEstablished": 0,
        "missingTcpFirstWrite": 0,
        "missingTcpPayloadReceived": 0,
        "missingTcpClosed": 0,
        "duplicateTcpClosed": 0,
        "missingUdpAttribution": 0,
        "missingUdpConnecting": 0,
        "missingUdpEstablished": 0,
        "missingUdpPayloadSent": 0,
        "missingUdpPayloadReceived": 0,
        "missingDnsTerminal": 0,
        "duplicateDnsTerminal": 0,
        "issueKinds": [{"key": "orphan-tcp-flow-ref", "count": failed_runs}] if failed_runs else [],
    }
