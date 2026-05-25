from __future__ import annotations

import argparse


REPEAT_MARKDOWN_KEYS = """
runs passedRuns failedRuns receiveWindowChallengeAcks dnsEarlyTimeouts protocolShortReadErrors udpSessionFailures
udpDroppedPackets ipv6PacketsDenied qualityBoundCandidateSets qualityBoundSelectedBehind qualityBoundSelectedWithQuality
workloadFailedRuns workloadAttempted workloadSuccess workloadFailure workloadStrictFailedRuns workloadErrors workloadFailedBySurface
workloadFlowMatchedEntries workloadFlowUnmatchedEntries workloadFlowTcpAttemptedEntries workloadFlowTcpAttemptedCoveredEntries
workloadFlowPreTcpEntries workloadFlowMatchedFlowAttempts workloadFlowMatchedDuplicateFlowEntries
workloadFlowMatchedRecoveredFailureEntries workloadFlowMatchedFlowFailedAttempts
workloadFlowMatchedFlowStageFailedAttempts workloadFlowFailureSurfaces tcpActiveSlotsMax
tcpSlotPressureEvents workloadFlowCoveredEntries
workloadFlowPacketTerminalEntries workloadFlowRuntimePacketMatchedEntries workloadFlowRuntimePacketTerminalEntries
workloadFlowRuntimePacketTerminalByReason workloadFlowUnmatchedRuntimePacketMatched
workloadFlowUnmatchedRuntimePacketTerminalMatched workloadFlowUnmatchedRuntimePacketTerminalByReason
workloadFlowUnmatchedRuntimePacketTerminalFailureByReason tcpFlowLifecycleComplete
tcpFlowPathComplete tcpFlowClosedWithoutPayload tcpFlowClosedByReason tcpFlowClosedWithoutPayloadByReason
tcpFlowPayloadBidirectional tcpFlowPayloadCloseConsistent tcpFlowFailedAfterPathComplete tcpFlowFailedAfterUpstreamOnly
tcpFlowRouteMatched tcpFlowRouteGraphSelected tcpFlowRuleMatched tcpFlowPlanBypassed
tcpFlowRouteFallbackCandidate tcpFlowRouteFallbackAttempts tcpFlowRouteFallbackUsed
tcpFlowRouteFallbackEstablished tcpFlowRouteFallbackFailed
tcpFlowRouteFallbackByRouteSelected tcpFlowRouteFallbackByFinalOutbound tcpFlowRouteFallbackByAttemptedOutbound
tcpFlowFailedByErrorType tcpFlowFailedBySurface tcpFlowStageFailed tcpFlowStageFailureBySurface
cascadeFinishedAttempts cascadeFailedAttempts cascadeRetryableFailures cascadeStoppedFailures cascadeRecoveredFlows
cascadeStoppedFlows cascadeStoppedBoundExhaustedFlows cascadeFailedByScope cascadeFailedByDisposition
cascadeFailedByStage cascadeFailedByStageSurface cascadeFailedByStageDisposition cascadeFailedByStopReason
cascadeStoppedFlowByStopReason cascadeStoppedFlowByStageSurface cascadeStoppedFlowByAttemptCount
""".split()


def field_pairs(tokens: str) -> tuple[tuple[str, str], ...]:
    return tuple((left, right) for left, right in (token.split("=", 1) for token in tokens.split()))


RUN_SUM_FIELDS = "receiveWindowChallengeAcks dnsEarlyTimeouts protocolShortReadErrors pendingFrameTimeouts udpSessionFailures udpDroppedPackets ipv6PacketsDenied ipDenials workloadAttempted workloadSuccess workloadFailure workloadTunWitnessedFailures workloadRouteViaDynetFailures tcpSlotPressureEvents".split()
RUN_LIST_FIELDS = "workloadErrors workloadFailedByProbe workloadFailedByStage workloadFailedBySurface".split()
QUALITY_SUM_FIELDS = field_pairs("qualityBoundCandidateSets=candidateSets qualityBoundSelectedBehind=selectedBehind qualityBoundSelectedWithQuality=selectedWithQuality")
CASCADE_SUM_FIELDS = field_pairs("""
cascadeStartedAttempts=startedAttempts cascadeFinishedAttempts=finishedAttempts
cascadeSuccessAttempts=successAttempts cascadeFailedAttempts=failedAttempts
cascadeRetryableFailures=retryableFailures cascadeStoppedFailures=stoppedFailures
cascadeStoppedFlows=stoppedFlows cascadeStoppedBoundExhaustedFlows=stoppedBoundExhaustedFlows
cascadeRecoveredFlows=recoveredFlows
""")
CASCADE_LIST_FIELDS = field_pairs(
    "cascadeFailedByScope=failedByScope cascadeFailedByDisposition=failedByDisposition "
    "cascadeFailedByStage=failedByStage cascadeFailedByStageSurface=failedByStageSurface "
    "cascadeFailedByStageDisposition=failedByStageDisposition "
    "cascadeFailedByStopReason=failedByStopReason "
    "cascadeStoppedFlowByStopReason=stoppedFlowByStopReason "
    "cascadeStoppedFlowByStageSurface=stoppedFlowByStageSurface "
    "cascadeStoppedFlowByAttemptCount=stoppedFlowByAttemptCount"
)
WORKLOAD_FLOW_SUM_FIELDS = field_pairs("""
workloadFlowEntries=entries workloadFlowEntriesWithLocalPort=entriesWithLocalPort
workloadFlowTcpAttemptedEntries=tcpAttemptedEntries workloadFlowPreTcpEntries=preTcpEntries
workloadFlowTcpAttemptedEntriesWithLocalPort=tcpAttemptedEntriesWithLocalPort
workloadFlowTcpAttemptedCoveredEntries=tcpAttemptedCoveredEntries workloadFlowCoveredEntries=coveredEntries
workloadFlowTcpAttemptedUnmatchedEntries=tcpAttemptedUnmatchedEntries
workloadFlowMatchedEntries=matchedEntries workloadFlowUnmatchedEntries=unmatchedEntries
workloadFlowPacketTerminalEntries=packetTerminalEntries
workloadFlowUnmatchedPacketTerminalEntries=unmatchedPacketTerminalEntries
workloadFlowUnmatchedNonTerminalEntries=unmatchedNonTerminalEntries
workloadFlowMatchedFailures=matchedFailures workloadFlowUnmatchedFailures=unmatchedFailures
workloadFlowMatchedFlowAttempts=matchedFlowAttempts
workloadFlowMatchedDuplicateFlowEntries=matchedDuplicateFlowEntries
workloadFlowMatchedRecoveredFailureEntries=matchedRecoveredFailureEntries
workloadFlowMatchedFlowFailedAttempts=matchedFlowFailedAttempts
workloadFlowMatchedFlowStageFailedAttempts=matchedFlowStageFailedAttempts
workloadFlowMatchedPathComplete=matchedPathComplete workloadFlowMatchedLifecycleComplete=matchedLifecycleComplete
workloadFlowMatchedPayloadStarted=matchedPayloadStarted workloadFlowMatchedPayloadBidirectional=matchedPayloadBidirectional
workloadFlowMatchedClosed=matchedClosed workloadFlowMatchedFlowFailed=matchedFlowFailed
workloadFlowRuntimePreflowMatchedEntries=runtimePreflowMatchedEntries
workloadFlowUnmatchedRuntimePreflowMatched=unmatchedRuntimePreflowMatched
workloadFlowUnmatchedRuntimePreflowMatchedFailures=unmatchedRuntimePreflowMatchedFailures
workloadFlowRuntimePacketMatchedEntries=runtimePacketMatchedEntries
workloadFlowTcpAttemptedRuntimePacketMatchedEntries=tcpAttemptedRuntimePacketMatchedEntries
workloadFlowRuntimePacketHandshakeEntries=runtimePacketHandshakeEntries
workloadFlowRuntimePacketTerminalEntries=runtimePacketTerminalEntries
workloadFlowRuntimeIngressSynMatchedEntries=runtimeIngressSynMatchedEntries
workloadFlowTcpAttemptedRuntimeIngressSynMatchedEntries=tcpAttemptedRuntimeIngressSynMatchedEntries
workloadFlowRuntimeEgressSynAckMatchedEntries=runtimeEgressSynAckMatchedEntries
workloadFlowUnmatchedRuntimePacketMatched=unmatchedRuntimePacketMatched
workloadFlowUnmatchedRuntimePacketMatchedFailures=unmatchedRuntimePacketMatchedFailures
workloadFlowUnmatchedRuntimePacketTerminalMatched=unmatchedRuntimePacketTerminalMatched
workloadFlowUnmatchedRuntimePacketTerminalFailures=unmatchedRuntimePacketTerminalFailures
workloadFlowUnmatchedTcpConnectedRuntimePacketMissing=unmatchedTcpConnectedRuntimePacketMissing
workloadFlowTunCaptureMatchedEntries=tunCaptureMatchedEntries
workloadFlowTcpAttemptedTunCaptureMatchedEntries=tcpAttemptedTunCaptureMatchedEntries
workloadFlowUnmatchedTunCaptureMatched=unmatchedTunCaptureMatched
workloadFlowUnmatchedTunCaptureMatchedFailures=unmatchedTunCaptureMatchedFailures
workloadFlowUnmatchedTcpConnectedTunCaptureMissing=unmatchedTcpConnectedTunCaptureMissing
workloadFlowUnmatchedTcpConnectedFailures=unmatchedTcpConnectedFailures
workloadFlowUnmatchedRouteViaDynetFailures=unmatchedRouteViaDynetFailures
workloadFlowUnmatchedTunWitnessedFailures=unmatchedTunWitnessedFailures
""")
WORKLOAD_FLOW_LIST_FIELDS = field_pairs(
    "workloadFlowFailureSurfaces=failureSurfaces workloadFlowUnmatchedFailureSurfaces=unmatchedFailureSurfaces "
    "workloadFlowRuntimePacketTerminalByReason=runtimePacketTerminalByReason "
    "workloadFlowUnmatchedRuntimePacketTerminalByReason=unmatchedRuntimePacketTerminalByReason "
    "workloadFlowUnmatchedRuntimePacketTerminalFailureByReason=unmatchedRuntimePacketTerminalFailureByReason"
)
TCP_FLOW_SUM_FIELDS = field_pairs("""
tcpFlowStarted=startedFlows tcpFlowLifecycleComplete=lifecycleCompleteFlows tcpFlowPathComplete=pathCompleteFlows
tcpFlowClosedWithByteTotals=closedWithByteTotals tcpFlowClosedWithoutPayload=closedWithoutPayloadFlows
tcpFlowPayloadStarted=payloadStartedFlows tcpFlowPayloadBidirectional=payloadBidirectionalFlows
tcpFlowPayloadCloseConsistent=payloadCloseConsistent tcpFlowFailed=failedFlows
tcpFlowFailedAfterPathComplete=failedAfterPathComplete tcpFlowFailedAfterUpstreamOnly=failedAfterUpstreamOnly
tcpFlowRouteMatched=routeMatchedFlows tcpFlowRouteGraphSelected=routeGraphSelectedFlows
tcpFlowRuleMatched=ruleMatchedFlows tcpFlowPlanBypassed=planBypassedFlows
tcpFlowRouteCandidateSet=routeCandidateSetFlows
tcpFlowRouteFallbackCandidate=routeFallbackCandidateFlows
tcpFlowRouteFallbackAttempts=routeFallbackAttemptEvents
tcpFlowRouteFallbackUsed=routeFallbackUsedFlows
tcpFlowRouteFallbackEstablished=routeFallbackEstablishedFlows
tcpFlowRouteFallbackFailed=routeFallbackFailedFlows
tcpFlowDuplicateClosed=duplicateClosedFlows tcpFlowStageFailed=stageFailedFlows
""")
TCP_FLOW_LIST_FIELDS = field_pairs(
    "tcpFlowClosedByReason=closedByReason tcpFlowClosedWithoutPayloadByReason=closedWithoutPayloadByReason "
    "tcpFlowRouteFallbackByRouteSelected=routeFallbackByRouteSelected "
    "tcpFlowRouteFallbackByFinalOutbound=routeFallbackByFinalOutbound "
    "tcpFlowRouteFallbackByAttemptedOutbound=routeFallbackByAttemptedOutbound "
    "tcpFlowFailedByErrorType=failedByErrorType tcpFlowFailedBySurface=failedBySurface "
    "tcpFlowStageFailureByErrorType=stageFailureByErrorType tcpFlowStageFailureByStage=stageFailureByStage "
    "tcpFlowStageFailureBySurface=stageFailureBySurface"
)


def build_repeat_totals(runs: list[dict], args: argparse.Namespace) -> dict:
    failed_runs = [run for run in runs if not run.get("passed")]
    totals = {
        "runs": len(runs),
        "passedRuns": len(runs) - len(failed_runs),
        "failedRuns": len(failed_runs),
        "workloadFailedRuns": sum(
            1
            for run in runs
            if run.get("workloadSuccessRate") is not None
            and float(run.get("workloadSuccessRate") or 0) < float(args.workload_min_success_rate)
        ),
        "workloadStrictFailedRuns": sum(1 for run in runs if int(run.get("workloadFailure") or 0) > 0),
        "tcpActiveSlotsMax": max((int(run.get("tcpActiveSlotsMax") or 0) for run in runs), default=0),
    }
    add_run_sums(totals, runs, RUN_SUM_FIELDS)
    add_run_lists(totals, runs, RUN_LIST_FIELDS)
    add_nested_sums(totals, runs, "boundSelection", QUALITY_SUM_FIELDS)
    add_nested_sums(totals, runs, "cascadeAttempts", CASCADE_SUM_FIELDS)
    add_nested_lists(totals, runs, "cascadeAttempts", CASCADE_LIST_FIELDS)
    add_nested_sums(totals, runs, "workloadFlow", WORKLOAD_FLOW_SUM_FIELDS)
    add_nested_lists(totals, runs, "workloadFlow", WORKLOAD_FLOW_LIST_FIELDS)
    add_nested_sums(totals, runs, "tcpFlow", TCP_FLOW_SUM_FIELDS)
    add_nested_lists(totals, runs, "tcpFlow", TCP_FLOW_LIST_FIELDS)
    return totals


def add_run_sums(totals: dict, runs: list[dict], fields: list[str]) -> None:
    for field in fields:
        totals[field] = sum(int(run.get(field) or 0) for run in runs)


def add_run_lists(totals: dict, runs: list[dict], fields: list[str]) -> None:
    for field in fields:
        totals[field] = aggregate_list(runs, field)


def add_nested_sums(
    totals: dict,
    runs: list[dict],
    section: str,
    fields: tuple[tuple[str, str], ...],
) -> None:
    for total_field, source_field in fields:
        totals[total_field] = sum(int(run.get(section, {}).get(source_field) or 0) for run in runs)


def add_nested_lists(
    totals: dict,
    runs: list[dict],
    section: str,
    fields: tuple[tuple[str, str], ...],
) -> None:
    for total_field, source_field in fields:
        totals[total_field] = aggregate_list(runs, source_field, section)


def aggregate_list(runs: list[dict], field: str, section: str | None = None) -> list[dict]:
    counts: dict[str, int] = {}
    for run in runs:
        values = run.get(section, {}).get(field, []) if section else run.get(field, [])
        for item in values:
            key = str(item.get("key") or "unknown")
            counts[key] = counts.get(key, 0) + int(item.get("count") or 0)
    return [{"key": key, "count": counts[key]} for key in sorted(counts)]
