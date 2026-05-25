from __future__ import annotations

from pathlib import Path
from typing import Any


def write_round_gap_markdown(path: Path, summary: dict[str, Any]) -> None:
    totals = summary["totals"]
    lines = [
        "# VM Private Runtime Round-Gap Batch",
        "",
        f"- label: `{summary['label']}`",
        f"- conclusion: `{summary['conclusion']['status']}`",
        f"- next action: `{summary['conclusion']['nextAction']}`",
        f"- cascade conclusion: `{summary['conclusion']['cascade']['status']}`",
        f"- cascade action: `{summary['conclusion']['cascade']['nextAction']}`",
        f"- cascade reason: `{summary['conclusion']['cascade']['reason']}`",
        f"- runs: `{totals['runs']}`",
        f"- gaps: `{totals['gapCount']}`",
        f"- clean runs: `{totals['cleanRuns']}`",
        f"- failed runs: `{totals['failedRuns']}`",
        f"- workload: `{totals['workloadSuccess']}/{totals['workloadAttempted']}`",
        f"- classifications: `{totals['classifications']}`",
        f"- flow refresh changed runs: `{totals['flowRefreshChangedRuns']}`",
        f"- flow refresh classifications: `{totals['flowRefreshClassifications']}`",
        f"- terminal reasons: `{totals['terminalByReason']}`",
        f"- stage failures: `{totals['stageFailureBySurface']}`",
        f"- stage dispositions: `{totals['stageFailureByDisposition']}`",
        f"- cascade failures: `{totals['cascadeFailedAttempts']}`",
        f"- cascade stopped flows: `{totals['cascadeStoppedFlows']}` exhausted=`{totals['cascadeStoppedBoundExhaustedFlows']}`",
        f"- cascade dispositions: `{totals['cascadeFailedByDisposition']}`",
        f"- cascade stages: `{totals['cascadeFailedByStageSurface']}`",
        f"- cascade stage dispositions: `{totals['cascadeFailedByStageDisposition']}`",
        f"- cascade stop reasons: `{totals['cascadeFailedByStopReason']}`",
        f"- cascade stopped flow stages: `{totals['cascadeStoppedFlowByStageSurface']}`",
        f"- failure phases: `{totals['failedByPhase']}`",
        f"- cleanup actions: `{totals['failedByCleanupAction']}`",
        f"- failure stages: `{totals['failedByFailureStage']}`",
        f"- slow stage events: `{totals['slowStageEvents']}`",
        f"- slow stage max ms: `{totals['slowStageMaxMs']}`",
        f"- slow stage surfaces: `{totals['slowStageBySurface']}`",
        f"- failed workload mechanisms: `{totals['failedWorkloadMechanisms']}`",
        f"- recovered flow mechanisms: `{totals['recoveredFlowMechanisms']}`",
        f"- schedule lag max ms: `{totals['scheduleLagMaxMs']}`",
        f"- planner penalty safe: `{summary['policy']['plannerPenaltySafe']}`",
        f"- quality penalty safe: `{summary['policy']['qualityPenaltySafe']}`",
        f"- policy reason: `{summary['policy']['reason']}`",
        "",
        "## Gaps",
        "",
    ]
    for item in summary["byGap"]:
        lines.append(gap_line(item))
    lines.extend(["", "## Runs", ""])
    for row in summary["runs"]:
        lines.append(run_line(row))
    path.write_text("\n".join(lines) + "\n")


def gap_line(item: dict[str, Any]) -> str:
    return (
        f"- `{item['gapMs']}` status=`{item['status']}` runs=`{item['runs']}` "
        f"clean=`{item['cleanRuns']}` "
        f"workload=`{item['workloadSuccess']}/{item['workloadAttempted']}` "
        f"lagMaxMs=`{item['scheduleLagMaxMs']}` "
        f"terminals=`{item['terminalByReason']}` "
        f"stages=`{item['stageFailureBySurface']}` "
        f"stageDispositions=`{item['stageFailureByDisposition']}` "
        f"flowRefreshChanged=`{item['flowRefreshChangedRuns']}` "
        f"flowRefresh=`{item['flowRefreshClassifications']}` "
        f"cascadeFailed=`{item['cascadeFailedAttempts']}` "
        f"cascadeStoppedFlows=`{item['cascadeStoppedFlows']}` "
        f"cascadeDispositions=`{item['cascadeFailedByDisposition']}` "
        f"cascadeStages=`{item['cascadeFailedByStageSurface']}` "
        f"cascadeStageDispositions=`{item['cascadeFailedByStageDisposition']}` "
        f"cascadeStops=`{item['cascadeFailedByStopReason']}` "
        f"cascadeStoppedStages=`{item['cascadeStoppedFlowByStageSurface']}` "
        f"phases=`{item['failedByPhase']}` "
        f"cleanup=`{item['failedByCleanupAction']}` "
        f"failureStages=`{item['failedByFailureStage']}` "
        f"slowStages=`{item['slowStageEvents']}` "
        f"slowMaxMs=`{item['slowStageMaxMs']}` "
        f"failedMechanisms=`{item['failedWorkloadMechanisms']}` "
        f"recoveredMechanisms=`{item['recoveredFlowMechanisms']}`"
    )


def run_line(row: dict[str, Any]) -> str:
    return (
        f"- `{row['label']}` gapMs=`{row['gapMs']}` passed=`{row['passed']}` "
        f"classification=`{row['classification']}` "
        f"workload=`{row['workload']['success']}/{row['workload']['attempted']}` "
        f"lagMaxMs=`{row['schedule']['lagMaxMs']}` "
        f"terminals=`{row['surfaces']['runtimePacketTerminalByReason']}` "
        f"stages=`{row['surfaces']['stageFailureBySurface']}` "
        f"stageDispositions=`{row['surfaces']['stageFailureByDisposition']}` "
        f"flowRefresh=`{row['flowRefresh']['classification']}` "
        f"flowRefreshChanged=`{row['flowRefresh']['changed']}` "
        f"cascadeFailed=`{row['cascade']['failedAttempts']}` "
        f"cascadeStoppedFlows=`{row['cascade']['stoppedFlows']}` "
        f"cascadeDispositions=`{row['cascade']['failedByDisposition']}` "
        f"cascadeStages=`{row['cascade']['failedByStageSurface']}` "
        f"cascadeStageDispositions=`{row['cascade']['failedByStageDisposition']}` "
        f"cascadeStops=`{row['cascade']['failedByStopReason']}` "
        f"cascadeStoppedStages=`{row['cascade']['stoppedFlowByStageSurface']}` "
        f"phases=`{row['surfaces']['failedByPhase']}` "
        f"cleanup=`{row['surfaces']['failedByCleanupAction']}` "
        f"failureStages=`{row['surfaces']['failedByFailureStage']}` "
        f"slowStages=`{row['stageBlocking']['slowStageEvents']}` "
        f"slowMaxMs=`{row['stageBlocking']['slowStageMaxMs']}` "
        f"failedMechanisms=`{row['mechanisms']['failedWorkloadByMechanism']}` "
        f"recoveredMechanisms=`{row['mechanisms']['recoveredFlowByMechanism']}`"
    )
