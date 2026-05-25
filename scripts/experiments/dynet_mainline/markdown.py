from __future__ import annotations

from pathlib import Path
from typing import Any


def write_markdown(path: Path, summary: dict[str, Any]) -> None:
    conclusion = summary["conclusion"]
    lines = [
        "# Dynet Mainline Baseline Gate",
        "",
        f"- status: `{summary['status']}`",
        f"- recommended use: `{summary['recommendedUse']}`",
        f"- planner penalty safe: `{summary['plannerPenaltySafe']}`",
        f"- quality penalty safe: `{summary['qualityPenaltySafe']}`",
        f"- runtime policy: `{summary['runtimePolicy']}`",
        "",
        "## Evidence",
        "",
    ]
    lines.extend(evidence_lines(summary))
    lines.extend(["", "## Gates", ""])
    for item in summary["gates"]:
        lines.append(f"- `{item['id']}` severity=`{item['severity']}` passed=`{item['passed']}` actual=`{item['actual']}` expected=`{item['expected']}`")
    lines.extend(["", "## Next Actions", ""])
    for item in conclusion["nextActions"]:
        lines.append(f"- `{item['id']}` evidence=`{item['evidence']}` priority=`{item['priority']}` plannerPenaltySafe=`{item['plannerPenaltySafe']}`")
    path.write_text("\n".join(lines) + "\n")


def evidence_lines(summary: dict[str, Any]) -> list[str]:
    adapter = summary["adapterProductEffect"]
    pressure = summary["runtimePressure"]
    fallback = summary["runtimeFallback"]
    runtime_dns = summary["runtimeDnsProduct"]
    dns_refresh = summary["runtimeDnsRefresh"]
    dns_forward = summary["runtimeDnsForward"]
    runtime_udp = summary["runtimeUdpDirect"]
    ipv6 = summary["runtimeIpv6NoLeak"]
    guardrail = summary["runtimeGuardrail"]
    read_surface = summary["pairedReadSurface"]
    recommendations = summary["recommendations"]
    return [
        f"- adapter product-effect: clean=`{adapter['clean']}` "
        f"adapters=`{adapter['adapterTypes']}` "
        f"workload=`{adapter['runtimeWorkloadAttempted']}` "
        f"paired=`{adapter['pairedWindows']}/{adapter['pairedEntries']}`",
        f"- runtime pressure: clean=`{pressure['clean']}` "
        f"workloadFailure=`{pressure['workloadFailure']}` "
        f"unrecoveredStageFailures=`{pressure['stageUnrecoveredFailures']}` "
        f"slotPressure=`{pressure['slotPressureEvents']}` "
        f"slowStage=`{pressure['slowStageEvents']}` "
        f"shape=`{pressure['pressureShapes']}`",
        f"- runtime fallback: clean=`{fallback['clean']}` "
        f"modes=`{fallback['modes']}` "
        f"workloadFailure=`{fallback['workloadFailure']}` "
        f"routeFallbackFailed=`{fallback['routeFallbackFailed']}`",
        f"- runtime DNS product: clean=`{runtime_dns['clean']}` "
        f"adapters=`{runtime_dns['adapterTypes']}` "
        f"modes=`{runtime_dns['runtimeDnsModes']}` "
        f"workloadFailure=`{runtime_dns['workloadFailure']}` "
        f"dnsEarlyTimeouts=`{runtime_dns['dnsEarlyTimeouts']}`",
        f"- runtime DNS refresh: clean=`{dns_refresh['clean']}` "
        f"runs=`{dns_refresh['runs']}` "
        f"changedRuns=`{dns_refresh['changedRuns']}` "
        f"inconsistentRuns=`{dns_refresh['inconsistentRuns']}` "
        f"queries=`{dns_refresh['dnsQueries']}`",
        f"- runtime DNS forward: clean=`{dns_forward['clean']}` "
        f"runs=`{dns_forward['cleanRuns']}/{dns_forward['runs']}` "
        f"diagnostic=`{dns_forward['diagnosticQueries']}` "
        f"forward=`{dns_forward['proxyForwardQueries']}` "
        f"failure=`{dns_forward['terminalFailureQueries']}` "
        f"orderViolations=`{dns_forward['orderViolations']}`",
        *runtime_correlation_lines(summary),
        *quality_state_evidence_lines(summary),
        f"- runtime UDP direct: clean=`{runtime_udp['clean']}` "
        f"runs=`{runtime_udp['passedRuns']}/{runtime_udp['runs']}` "
        f"downstreamBytes=`{runtime_udp['udpDownstreamBytes']}` "
        f"udpFailures=`{runtime_udp['udpSessionFailures']}` "
        f"udpDropped=`{runtime_udp['udpDroppedPackets']}`",
        f"- runtime IPv6 no-leak: clean=`{ipv6['clean']}` "
        f"runs=`{ipv6['passedRuns']}/{ipv6['runs']}` "
        f"denied=`{ipv6['ipv6PacketsDenied']}` "
        f"tcpFailed=`{ipv6['tcpFlowFailed']}` "
        f"tcpStageFailed=`{ipv6['tcpFlowStageFailed']}`",
        f"- runtime guardrail: clean=`{guardrail['clean']}` "
        f"runtimeDnsModes=`{guardrail['runtimeDnsModes']}` "
        f"nonBoundStops=`{guardrail['nonBoundStops']}` "
        f"noSecondAttempts=`{guardrail['noSecondAttempts']}` "
        f"downstreamDispositions=`{guardrail['downstreamDispositions']}`",
        f"- paired read-surface: clean=`{read_surface['clean']}` "
        f"actionableReadFailures=`{read_surface['actionableReadFailureCount']}` "
        f"excludedReadFailures=`{read_surface['excludedReadFailureCount']}` "
        f"totalReadFailures=`{read_surface['totalReadFailureCount']}`",
        f"- recommendations: clean=`{recommendations['clean']}` "
        f"statuses=`{recommendations['statuses']}` actions=`{recommendations['actions']}`",
    ]


def runtime_correlation_lines(summary: dict[str, Any]) -> list[str]:
    quality_plan = summary["runtimeQualityPlan"]
    route_refresh = summary["runtimeRouteRefresh"]
    selection_refresh = summary["runtimeSelectionRefresh"]
    workload_flow = summary["runtimeWorkloadFlow"]
    quality_workload = summary["runtimeQualityWorkload"]
    flow_refresh = summary["runtimeFlowRefresh"]
    cascade_refresh = summary["runtimeCascadeRefresh"]
    target_identity = summary["runtimeTargetIdentity"]
    return [
        f"- runtime quality plan: clean=`{quality_plan['clean']}` "
        f"adapters=`{quality_plan['adapterTypes']}` "
        f"qualitySets=`{quality_plan['qualityBoundCandidateSets']}` "
        f"selectedWithQuality=`{quality_plan['qualityBoundSelectedWithQuality']}` "
        f"selectedBehind=`{quality_plan['qualityBoundSelectedBehind']}` "
        f"stageFailed=`{quality_plan['tcpFlowStageFailed']}`",
        f"- runtime route refresh: clean=`{route_refresh['clean']}` "
        f"runs=`{route_refresh['runs']}` "
        f"changedRuns=`{route_refresh['changedRuns']}` "
        f"routeEntries=`{route_refresh['routeEntryFlows']}` "
        f"pathComplete=`{route_refresh['pathCompleteFlows']}`",
        f"- runtime selection refresh: clean=`{selection_refresh['clean']}` "
        f"runs=`{selection_refresh['runs']}` "
        f"changedRuns=`{selection_refresh['changedRuns']}` "
        f"candidateSets=`{selection_refresh['candidateSets']}` "
        f"selectedBest=`{selection_refresh['selectedBest']}` "
        f"selectedBehind=`{selection_refresh['selectedBehind']}`",
        f"- runtime workload flow: clean=`{workload_flow['clean']}` "
        f"classifications=`{workload_flow['classifications']}` "
        f"workload=`{workload_flow['workloadAttempted']}` "
        f"covered=`{workload_flow['tcpAttemptedCoveredEntries']}/"
        f"{workload_flow['tcpAttemptedEntries']}` "
        f"unmatched=`{workload_flow['unmatchedEntries']}` "
        f"terminal=`{workload_flow['runtimePacketTerminalEntries']}`",
        f"- runtime quality workload: clean=`{quality_workload['clean']}` "
        f"adapters=`{quality_workload['adapterTypes']}` "
        f"workload=`{quality_workload['workloadAttempted']}` "
        f"qualitySets=`{quality_workload['qualityBoundCandidateSets']}` "
        f"matched=`{quality_workload['workloadFlowMatchedEntries']}` "
        f"unmatched=`{quality_workload['workloadFlowUnmatchedEntries']}` "
        f"recoveredStage=`{quality_workload['workloadFlowMatchedRecoveredFailureEntries']}`",
        *runtime_surface_lines(summary),
        f"- runtime flow refresh: clean=`{flow_refresh['clean']}` "
        f"runs=`{flow_refresh['runs']}` "
        f"changedRuns=`{flow_refresh['changedRuns']}` "
        f"classifications=`{flow_refresh['classifications']}`",
        f"- runtime cascade refresh: clean=`{cascade_refresh['clean']}` "
        f"runs=`{cascade_refresh['runs']}` "
        f"changedRuns=`{cascade_refresh['changedRuns']}` "
        f"failedAttempts=`{cascade_refresh['failedAttempts']}` "
        f"recoveredFlows=`{cascade_refresh['recoveredFlows']}`",
        f"- runtime target identity: clean=`{target_identity['clean']}` "
        f"runs=`{target_identity['runs']}` "
        f"changedRuns=`{target_identity['changedRuns']}` "
        f"matched=`{target_identity['targetChainMatched']}/"
        f"{target_identity['targetChainFlows']}` "
        f"mismatched=`{target_identity['targetChainMismatched']}`",
    ]


def runtime_surface_lines(summary: dict[str, Any]) -> list[str]:
    workload_surface = summary["runtimeWorkloadSurface"]
    close_surface = summary["runtimeCloseSurface"]
    payload_surface = summary["runtimePayloadSurface"]
    stage_surface = summary["runtimeStageSurface"]
    timing_surface = summary["runtimeTimingSurface"]
    dns_timing = summary["runtimeDnsTiming"]
    outbound_timing = summary["runtimeOutboundTiming"]
    outbound_attempt = summary["runtimeOutboundAttempt"]
    failure_attribution = summary["runtimeFailureAttribution"]
    failure_impact = summary["runtimeFailureImpact"]
    route_decision = summary["runtimeRouteDecision"]
    outbound_gate = summary["runtimeOutboundGate"]
    outbound_retry = summary["runtimeOutboundRetry"]
    packet_surface = summary["runtimePacketSurface"]
    round_gap = summary["runtimeRoundGap"]
    round_gap_compare = summary["runtimeRoundGapCompare"]
    tcp_pressure = summary["runtimeTcpPressure"]
    return [
        f"- runtime workload surface: clean=`{workload_surface['clean']}` "
        f"status=`{workload_surface['statuses']}` "
        f"runs=`{workload_surface['cleanRuns']}/{workload_surface['runs']}` "
        f"failedRows=`{workload_surface['failedRows']}` "
        f"mechanisms=`{workload_surface['mechanisms']}`",
        f"- runtime close surface: clean=`{close_surface['clean']}` "
        f"runs=`{close_surface['cleanRuns']}/{close_surface['runs']}` "
        f"flows=`{close_surface['flows']}` "
        f"terminal=`{close_surface['terminalEvents']}` "
        f"closedReason=`{close_surface['closedReasonFlows']}` "
        f"duplicateClosed=`{close_surface['duplicateClosedFlows']}` "
        f"reasons=`{close_surface['closedByReason']}`",
        f"- runtime payload surface: clean=`{payload_surface['clean']}` "
        f"runs=`{payload_surface['cleanRuns']}/{payload_surface['runs']}` "
        f"flows=`{payload_surface['flows']}` "
        f"bidirectional=`{payload_surface['payloadBidirectionalFlows']}` "
        f"closeConsistent=`{payload_surface['payloadCloseConsistent']}` "
        f"failedFlows=`{payload_surface['failedFlows']}`",
        *event_surface_lines(summary),
        f"- runtime stage surface: clean=`{stage_surface['clean']}` "
        f"runs=`{stage_surface['cleanRuns']}/{stage_surface['runs']}` "
        f"flows=`{stage_surface['flows']}` "
        f"stageEvents=`{stage_surface['stageEvents']}` "
        f"failedStageEvents=`{stage_surface['failedStageEvents']}` "
        f"unrecoveredStageFailedFlows=`{stage_surface['unrecoveredStageFailedFlows']}`",
        f"- runtime timing surface: clean=`{timing_surface['clean']}` "
        f"runs=`{timing_surface['cleanRuns']}/{timing_surface['runs']}` "
        f"flows=`{timing_surface['flows']}` "
        f"ordered=`{timing_surface['orderedFlows']}` "
        f"closedP95Ms=`{timing_surface['closedP95Ms']}` "
        f"firstDownstreamP95Ms=`{timing_surface['firstDownstreamP95Ms']}`",
        f"- runtime DNS timing: clean=`{dns_timing['clean']}` "
        f"runs=`{dns_timing['cleanRuns']}/{dns_timing['runs']}` "
        f"queries=`{dns_timing['queries']}` "
        f"completed=`{dns_timing['completedQueries']}` "
        f"failed=`{dns_timing['failedQueries']}` "
        f"resolveP95Ms=`{dns_timing['resolveP95Ms']}`",
        outbound_timing_line(outbound_timing),
        outbound_attempt_line(outbound_attempt),
        candidate_set_line(summary),
        stage_chain_line(summary),
        route_decision_line(route_decision),
        f"- runtime outbound gate: clean=`{outbound_gate['clean']}` "
        f"runs=`{outbound_gate['cleanRuns']}/{outbound_gate['runs']}` "
        f"flows=`{outbound_gate['flows']}` "
        f"routeAdmission=`{outbound_gate['routeAdmissionFlows']}` "
        f"routeEgress=`{outbound_gate['routeEgressFlows']}` "
        f"boundAdmission=`{outbound_gate['boundAdmissionFlows']}` "
        f"boundEgress=`{outbound_gate['boundEgressFlows']}` "
        f"routeMismatches=`{outbound_gate['routeEgressMismatches']}`",
        outbound_retry_line(outbound_retry),
        packet_surface_line(packet_surface),
        tcp_pressure_line(tcp_pressure),
        udp_session_line(summary["runtimeUdpSession"]),
        ipv6_denial_line(summary["runtimeIpv6Denial"]),
        takeover_lifecycle_line(summary["runtimeTakeoverLifecycle"]),
        retained_artifact_line(summary["runtimeRetainedArtifact"]),
        exit_limit_line(summary["runtimeExitLimit"]),
        collection_stage_line(summary["runtimeCollectionStage"]),
        f"- runtime round gap: clean=`{round_gap['clean']}` runs=`{round_gap['cleanRuns']}/{round_gap['runs']}` status=`{round_gap['statuses']}` failedRuns=`{round_gap['failedRuns']}` compareClean=`{round_gap_compare['clean']}` compareStatus=`{round_gap_compare['statuses']}` rawDetailKeys=`{sorted(set(round_gap['rawDetailKeys']) | set(round_gap_compare['rawDetailKeys']))}`",
    ]


def event_surface_lines(summary: dict[str, Any]) -> list[str]:
    return [
        event_stream_line(summary["runtimeEventStream"]),
        event_correlation_line(summary["runtimeEventCorrelation"]),
        event_causality_line(summary["runtimeEventCausality"]),
        failure_attribution_line(summary),
        failure_impact_line(summary["runtimeFailureImpact"]),
    ]


def udp_session_line(udp_session: dict[str, Any]) -> str:
    return (
        f"- runtime UDP session: clean=`{udp_session['clean']}` "
        f"runs=`{udp_session['cleanRuns']}/{udp_session['runs']}` "
        f"sessions=`{udp_session['sessions']}` "
        f"established=`{udp_session['establishedSessions']}` "
        f"bidirectional=`{udp_session['payloadBidirectionalSessions']}` "
        f"sentBytes=`{udp_session['sentBytes']}` "
        f"receivedBytes=`{udp_session['receivedBytes']}` "
        f"failures=`{udp_session['failedEvents']}`"
    )


def route_decision_line(decision: dict[str, Any]) -> str:
    return (
        f"- runtime route decision: clean=`{decision['clean']}` "
        f"runs=`{decision['cleanRuns']}/{decision['runs']}` "
        f"routeMatched=`{decision['routeMatchedEvents']}` "
        f"planBypassed=`{decision['planBypassedEvents']}` "
        f"counterMismatches=`{decision['routeDecisionCounterMismatches']}` "
        f"tcpMissingGraph=`{decision['tcpRouteMissingGraph']}` "
        f"udpGraphMismatches=`{decision['udpRouteGraphMismatches']}`"
    )


def outbound_timing_line(timing: dict[str, Any]) -> str:
    return (
        f"- runtime outbound timing: clean=`{timing['clean']}` "
        f"runs=`{timing['cleanRuns']}/{timing['runs']}` "
        f"flows=`{timing['flows']}` "
        f"attempts=`{timing['attemptEvents']}` "
        f"cascades=`{timing['cascadeEvents']}` "
        f"failedAttempts=`{timing['failedAttemptEvents']}` "
        f"unrecovered=`{timing['unrecoveredFailureFlows']}` "
        f"cascadeP95Ms=`{timing['cascadeP95Ms']}`"
    )


def outbound_attempt_line(attempt: dict[str, Any]) -> str:
    return (
        f"- runtime outbound attempt: clean=`{attempt['clean']}` "
        f"runs=`{attempt['cleanRuns']}/{attempt['runs']}` "
        f"attempts=`{attempt['attemptFinishes']}` "
        f"failed=`{attempt['failedAttempts']}` "
        f"pairGaps=`{attempt['finishWithoutStart'] + attempt['startWithoutFinish']}` "
        f"missingStage=`{attempt['attemptsMissingStage']}` "
        f"missingRoute=`{attempt['sessionTcpAttemptsMissingRoute']}` "
        f"missingCascadeAttempt=`{attempt['cascadeMissingOutboundAttempt']}`"
    )


def candidate_set_line(summary: dict[str, Any]) -> str:
    candidate = summary["runtimeCandidateSet"]
    quality = summary["runtimeCandidateQuality"]
    return (
        f"- runtime candidate set: clean=`{candidate['clean']}` runs=`{candidate['cleanRuns']}/{candidate['runs']}` "
        f"sets=`{candidate['candidateSets']}` scopes=`{candidate['scopes']}` "
        f"types=`{candidate['candidateTypes']}` "
        f"missingGraph=`{candidate['missingGraph']}` "
        f"selectedMissing=`{candidate['selectedMissingFromList'] + candidate['selectedMissingFromJson']}` qualityClean=`{quality['clean']}` "
        f"qualitySets=`{quality['qualityCandidateSets']}` qualityBehind=`{quality['selectedBehind']}` recoveredBehind=`{quality['recoveredSelectedBehind']}`"
    )


def stage_chain_line(summary: dict[str, Any]) -> str:
    chain = summary["runtimeStageChain"]
    order = summary["runtimeStageOrder"]
    return (
        f"- runtime stage chain: clean=`{chain['clean']}` runs=`{chain['cleanRuns']}/{chain['runs']}` "
        f"attempts=`{chain['attempts']}` stageEvents=`{chain['stageEvents']}` "
        f"unknownProfiles=`{chain['unknownProfileAttempts']}` "
        f"missingSuccessStages=`{chain['successMissingRequiredStages']}` "
        f"failedMissingStage=`{chain['failedMissingFailureStage']}` orderClean=`{order['clean']}` "
        f"ordered=`{order['orderedAttempts']}/{order['attempts']}` orderViolations=`{order['stageOrderViolations']}`"
    )


def failure_attribution_line(summary: dict[str, Any]) -> str:
    failure, propagation = summary["runtimeFailureAttribution"], summary["runtimeFailurePropagation"]
    return (
        f"- runtime failure attribution: clean=`{failure['clean']}` runs=`{failure['cleanRuns']}/{failure['runs']}` "
        f"signals=`{failure['failureSignals']}` "
        f"classified=`{failure['classifiedSignals']}` unknown=`{failure['unknownSignals']}` "
        f"missingEvidence=`{failure['missingEvidenceSignals']}` "
        f"categories=`{failure['categories']}` propagationClean=`{propagation['clean']}` failedAttempts=`{propagation['failedAttempts']}` "
        f"failedCascades=`{propagation['failedCascades']}`"
    )


def failure_impact_line(impact: dict[str, Any]) -> str:
    return (
        f"- runtime failure impact: clean=`{impact['clean']}` "
        f"runs=`{impact['cleanRuns']}/{impact['runs']}` "
        f"signals=`{impact['failureSignals']}` "
        f"recovered=`{impact['recoveredSignals']}` "
        f"controlled=`{impact['controlledSignals']}` "
        f"maskedNode=`{impact['maskedNodeSuspectSignals']}` "
        f"unboundedNode=`{impact['unboundedNodeSuspectSignals']}` "
        f"unsafePenalty=`{impact['unsafePenaltySignals']}`"
    )


def packet_surface_line(packet_surface: dict[str, Any]) -> str:
    return (
        f"- runtime packet surface: clean=`{packet_surface['clean']}` "
        f"runs=`{packet_surface['cleanRuns']}/{packet_surface['runs']}` "
        f"flows=`{packet_surface['flows']}` "
        f"handshakes=`{packet_surface['packetHandshakePorts']}` "
        f"preflows=`{packet_surface['preflowPorts']}` "
        f"terminals=`{packet_surface['packetTerminalPorts']}` "
        f"preflowMissed=`{packet_surface['preflowMissedPorts']}` "
        f"pressureEvents=`{packet_surface['pressureEvents']}`"
    )


def tcp_pressure_line(pressure: dict[str, Any]) -> str:
    return (
        f"- runtime TCP pressure: clean=`{pressure['clean']}` "
        f"runs=`{pressure['cleanRuns']}/{pressure['runs']}` "
        f"tcpSessions=`{pressure['tcpSessions']}` "
        f"capacityEvents=`{pressure['capacityEvents']}` "
        f"pressureEvents=`{pressure['pressureEvents']}` "
        f"unclosed=`{pressure['tcpUnclosedSessions']}` "
        f"pressureMismatches=`{pressure['pressureCountMismatches']}`"
    )


def outbound_retry_line(retry: dict[str, Any]) -> str:
    return (
        f"- runtime outbound retry: clean=`{retry['clean']}` "
        f"runs=`{retry['cleanRuns']}/{retry['runs']}` "
        f"cascadeFailures=`{retry['cascadeFailures']}` "
        f"retryableMissing=`{retry['retryableMissingNextAttempt']}` "
        f"nonRetryableContinued=`{retry['nonRetryableWithNextAttempt']}` "
        f"boundExhaustedUnrecovered=`{retry['boundExhaustedUnrecoveredFlows']}` "
        f"nonBoundContinued=`{retry['nonBoundWithNextAttempt']}`"
    )


def event_stream_line(event_stream: dict[str, Any]) -> str:
    return (
        f"- runtime event stream: clean=`{event_stream['clean']}` "
        f"runs=`{event_stream['cleanRuns']}/{event_stream['runs']}` "
        f"events=`{event_stream['events']}` "
        f"kinds=`{len(event_stream['eventKindCounts'])}` "
        f"sequenceGaps=`{event_stream['sequenceGaps']}` "
        f"counterMismatches=`{event_stream['counterMismatches']}` "
        f"byteMismatches=`{event_stream['byteCounterMismatches']}`"
    )


def event_correlation_line(correlation: dict[str, Any]) -> str:
    return (
        f"- runtime event correlation: clean=`{correlation['clean']}` "
        f"runs=`{correlation['cleanRuns']}/{correlation['runs']}` "
        f"tcpFlows=`{correlation['tcpFlows']}` "
        f"udpFlows=`{correlation['udpFlows']}` "
        f"dnsQueries=`{correlation['dnsQueries']}` "
        f"orphanFlowRefs=`{correlation['orphanFlowRefs']}` "
        f"sessionMismatches=`{correlation['sessionMismatches']}`"
    )


def event_causality_line(causality: dict[str, Any]) -> str:
    return (
        f"- runtime event causality: clean=`{causality['clean']}` "
        f"runs=`{causality['cleanRuns']}/{causality['runs']}` "
        f"tcpOrder=`{causality['tcpOrderViolations']}` "
        f"udpOrder=`{causality['udpOrderViolations']}` "
        f"dnsOrder=`{causality['dnsOrderViolations']}` "
        f"egressMissingAdmission=`{causality['egressMissingAdmission']}` "
        f"stageMissingAttempt=`{causality['stageMissingAttempt']}`"
    )


def ipv6_denial_line(ipv6_denial: dict[str, Any]) -> str:
    return (
        f"- runtime IPv6 denial: clean=`{ipv6_denial['clean']}` "
        f"runs=`{ipv6_denial['cleanRuns']}/{ipv6_denial['runs']}` "
        f"denials=`{ipv6_denial['denials']}` "
        f"reported=`{ipv6_denial['reportedIpv6PacketsDenied']}` "
        f"nonIpv6=`{ipv6_denial['nonIpv6Denials']}` "
        f"flows=`{ipv6_denial['flows']}` "
        f"failedFlows=`{ipv6_denial['failedFlows']}`"
    )


def takeover_lifecycle_line(lifecycle: dict[str, Any]) -> str:
    return (
        f"- runtime takeover lifecycle: clean=`{lifecycle['clean']}` "
        f"runs=`{lifecycle['cleanRuns']}/{lifecycle['runs']}` "
        f"installReports=`{lifecycle['installReports']}` "
        f"uninstallReports=`{lifecycle['uninstallReports']}` "
        f"cleanupPresent=`{lifecycle['uninstallPresentResources']}` "
        f"diagnostics=`{lifecycle['diagnostics']}`"
    )


def retained_artifact_line(retention: dict[str, Any]) -> str:
    return (
        f"- runtime retained artifact: clean=`{retention['clean']}` "
        f"runs=`{retention['cleanRuns']}/{retention['runs']}` "
        f"missing=`{retention['requiredJsonMissing']}` "
        f"unsafeFlags=`{retention['unsafePrivacyFlags']}` "
        f"pcap=`{retention['pcapFiles']}` "
        f"rawPackets=`{retention['rawPacketFiles']}` "
        f"responses=`{retention['responseBodyFiles'] + retention['responseHeaderFiles']}`"
    )


def exit_limit_line(exit_limit: dict[str, Any]) -> str:
    return (
        f"- runtime exit limit: clean=`{exit_limit['clean']}` "
        f"runs=`{exit_limit['cleanRuns']}/{exit_limit['runs']}` "
        f"commandExitZero=`{exit_limit['commandExitZero']}` "
        f"limitReason=`{exit_limit['runtimeLimitReason']}` "
        f"timeoutReasons=`{exit_limit['runtimeTimeoutReasons']}` "
        f"evidence=`{exit_limit['limitEvidence']}`"
    )


def collection_stage_line(collection: dict[str, Any]) -> str:
    return (
        f"- runtime collection stage: clean=`{collection['clean']}` "
        f"runs=`{collection['cleanRuns']}/{collection['runs']}` "
        f"stageFailed=`{collection['stageFailed']}` "
        f"requiredMissing=`{collection['requiredMissing']}` "
        f"collectMissing=`{collection['collectStageMissing']}` "
        f"orderViolations=`{collection['orderViolations']}`"
    )


def quality_state_evidence_lines(summary: dict[str, Any]) -> list[str]:
    quality_feedback = summary["qualityFeedbackBoundary"]
    plan_quality = summary["planQualityStateBridge"]
    return [
        f"- quality feedback boundary: clean=`{quality_feedback['clean']}` "
        f"categories=`{quality_feedback['categories']}` "
        f"repeatedGaps=`{quality_feedback['repeatedQualityGaps']}` "
        f"penaltyObservations=`{quality_feedback['penaltyObservations']}` "
        f"promotionProofs=`{quality_feedback['promotionProofs']}`",
        f"- plan quality-state bridge: clean=`{plan_quality['clean']}` "
        f"adapters=`{plan_quality['adapterTypes']}` "
        f"modes=`{plan_quality['feedbackModes']}` "
        f"requested=`{plan_quality['requestedModes']}` "
        f"rows=`{plan_quality['passedRows']}/{plan_quality['rows']}` "
        f"selectedBehind=`{plan_quality['selectedBehind']}`",
    ]
