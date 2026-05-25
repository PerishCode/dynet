from __future__ import annotations

from pathlib import Path
from typing import Any


def write_markdown(path: Path, summary: dict[str, Any]) -> None:
    runtime = summary["runtime"]
    lines = [
        "# Tunnel/Private Adapter Maturity",
        "",
        f"- adapter: `{summary['adapterType']}`",
        f"- status: `{summary['status']}`",
        f"- recommended use: `{summary['recommendedUse']}`",
        f"- planner penalty safe: `{summary['plannerPenaltySafe']}`",
        "",
        "## Runtime",
        "",
        f"- runs: `{runtime['runs']}` clean=`{runtime['clean']}` "
        f"workload=`{runtime['workloadSuccess']}/{runtime['workloadAttempted']}` "
        f"workloadFailures=`{format_count_rows(runtime['workloadFailedBySurface'])}` "
        f"primaryCandidates=`{runtime['uniquePrimarySelectedCandidates']}` "
        f"runtimeTargets=`{runtime['runtimeTargetHostCount']}` "
        f"fallbackSelections=`{runtime['qualityBoundFallbackCandidateSets']}` "
        f"stagePressure=`{runtime['tcpFlowStageFailed']}`",
        f"- flow refresh: sources=`{runtime['flowRefreshSourceCount']}` "
        f"changedRuns=`{runtime['flowRefreshChangedRuns']}` "
        f"classifications=`{format_count_rows(runtime['flowRefreshClassifications'])}`",
        f"- cascade stage: sources=`{runtime['cascadeStageSourceCount']}` "
        f"failedAttempts=`{runtime['cascadeStageFailedAttempts']}` "
        f"retryable=`{runtime['cascadeStageRetryableFailures']}` "
        f"stopped=`{runtime['cascadeStageStoppedFailures']}` "
        f"surfaces=`{format_count_rows(runtime['cascadeStageFailedByStageSurface'])}` "
        f"dispositions=`{format_count_rows(runtime['cascadeStageFailedByStageDisposition'])}`",
        "",
        "## Gates",
        "",
    ]
    for item in summary["gates"]:
        lines.append(
            f"- `{item['id']}` severity=`{item['severity']}` "
            f"passed=`{item['passed']}` actual=`{item['actual']}` expected=`{item['expected']}`"
        )
    lines.extend(["", "## Next Actions", ""])
    for item in summary["conclusion"]["nextActions"]:
        lines.append(
            f"- `{item['id']}` evidence=`{item['evidence']}` "
            f"priority=`{item['priority']}` plannerPenaltySafe=`{item['plannerPenaltySafe']}`"
        )
    path.write_text("\n".join(lines) + "\n")


def format_count_rows(rows: list[dict[str, Any]]) -> str:
    items = [
        f"{row.get('key')}:{row.get('count')}"
        for row in rows
        if row.get("key")
    ]
    return ",".join(items) if items else "none"
