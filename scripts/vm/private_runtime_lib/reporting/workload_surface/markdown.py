from __future__ import annotations

from pathlib import Path
from typing import Any


def write_workload_surface_markdown(path: Path, summary: dict[str, Any]) -> None:
    totals = summary["totals"]
    conclusion = summary["conclusion"]
    lines = [
        "# VM Private Runtime Workload Surface",
        "",
        f"- label: `{summary['label']}`",
        f"- status: `{conclusion['status']}`",
        f"- next action: `{conclusion['nextAction']}`",
        f"- runs: `{totals['runs']}` failedRuns=`{totals['failedRuns']}`",
        (
            f"- workload: `{totals['workloadSuccess']}/{totals['workloadAttempted']}` "
            f"failedRows=`{totals['failedRows']}`"
        ),
        f"- failed by mechanism: `{totals['failedByMechanism']}`",
        f"- failed by surface: `{totals['failedBySurface']}`",
        f"- failed by stage: `{totals['failedByStage']}`",
        f"- terminal reasons: `{totals['runtimePacketTerminalByReason']}`",
        f"- terminal close signals: `{totals['packetTerminalByCloseSignal']}`",
        f"- terminal preflow candidates: `{totals['packetTerminalPreflowCandidates']}` reasons=`{totals['packetTerminalPreflowCandidateByReason']}`",
        f"- terminal preflow missed: `{totals['packetTerminalPreflowMissed']}` reasons=`{totals['packetTerminalPreflowMissedByReason']}`",
        f"- terminal ingress payload bytes: `{totals['packetTerminalIngressPayloadBytes']}`",
        f"- runtime DNS failures: `{totals['runtimeDnsFailures']}` matchedFailedRows=`{totals['failedRowsWithRuntimeDnsFailure']}`",
        f"- runtime DNS dispositions: `{totals['failedByRuntimeDnsDisposition']}`",
        f"- cascade stopped failed rows: `{totals['failedRowsWithCascadeStoppedFlow']}` exhausted=`{totals['cascadeStoppedFlowCandidateExhaustedFailures']}`",
        f"- cascade stopped stages: `{totals['failedByCascadeStoppedFlowStageSurface']}`",
        f"- schedule lag max ms: `{totals['scheduleLagMaxMs']}`",
        f"- policy: planner=`{conclusion['plannerPenaltySafe']}` quality=`{conclusion['qualityPenaltySafe']}` productEffect=`{conclusion['productEffectClaimSafe']}`",
        "",
        "## Mechanisms",
        "",
    ]
    append_mechanisms(lines, conclusion)
    append_runs(lines, summary)
    append_failed_rows(lines, summary)
    path.write_text("\n".join(lines) + "\n")


def append_mechanisms(lines: list[str], conclusion: dict[str, Any]) -> None:
    if not conclusion["mechanisms"]:
        lines.append("- none")
    for item in conclusion["mechanisms"]:
        lines.append(
            f"- `{item['mechanism']}` count=`{item['count']}` "
            f"category=`{item['category']}` action=`{item['nextAction']}`"
        )


def append_runs(lines: list[str], summary: dict[str, Any]) -> None:
    lines.extend(["", "## Runs", ""])
    for row in summary["runs"]:
        lines.append(
            f"- `{row['label']}` classification=`{row['roundGapClassification']}` "
            f"passed=`{row['passed']}` workload=`{row['workload']['success']}/{row['workload']['attempted']}` "
            f"failedRows=`{len(row['schedule']['failedRows'])}`"
        )


def append_failed_rows(lines: list[str], summary: dict[str, Any]) -> None:
    lines.extend(["", "## Failed Rows", ""])
    if not summary["failedRows"]:
        lines.append("- none")
    for row in summary["failedRows"]:
        lines.append(
            f"- `{row['runLabel']}` id=`{row['id']}` domain=`{row['domain']}` "
            f"mechanism=`{row['mechanism']}` surface=`{row['failureSurface']}` "
            f"stage=`{row['errorStage']}` type=`{row['errorType']}` "
            f"tcpConnected=`{row['workloadTcpConnectOk']}` routeDynet=`{row['workloadRouteViaDynet']}` "
            f"tunWitnessed=`{row['workloadTunWitnessed']}` terminalReason=`{row['runtimePacketTerminalReason']}` "
            f"terminalClose=`{row['runtimePacketTerminalCloseSignal']}` "
            f"terminalIngressPayloadBytes=`{row['runtimePacketTerminalIngressPayloadBytes']}` "
            f"preflowCandidate=`{row['runtimePreflowCandidateMatched']}` "
            f"preflowCandidateReason=`{row['runtimePreflowCandidateReason']}` "
            f"preflowMissed=`{row['runtimePreflowMissedMatched']}` "
            f"preflowMissedReason=`{row['runtimePreflowMissedReason']}` "
            f"dnsRuntime=`{row['runtimeDnsFailureMatched']}` dnsDisposition=`{row['runtimeDnsFailureDisposition']}` "
            f"dnsResponse=`{row['runtimeDnsFailureResponseCode']}` "
            f"cascadeStopped=`{row['cascadeStoppedFlowMatched']}` "
            f"cascadeStopReason=`{row['cascadeStoppedFlowStopReason']}` "
            f"cascadeStage=`{row['cascadeStoppedFlowStageSurface']}` "
            f"lagMs=`{row['scheduleLagMs']}`"
        )
