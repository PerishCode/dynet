from __future__ import annotations

from pathlib import Path
from typing import Any


def write_markdown(path: Path, summary: dict[str, Any]) -> None:
    conclusion = summary["conclusion"]
    maturity = summary["maturity"]
    dynet = summary["dynetProduct"]
    runtime = summary["dynetRuntimeProduct"]
    clash = summary["clashProduct"]
    paired = summary["pairedProductEffect"]
    lines = [
        "# Tunnel/Private Adapter Product Effect",
        "",
        f"- adapter: `{summary['adapterType']}`",
        f"- status: `{summary['status']}`",
        f"- recommended use: `{summary['recommendedUse']}`",
        f"- product-effect parity claim safe: `{conclusion['productEffectParityClaimSafe']}`",
        f"- planner penalty safe: `{summary['plannerPenaltySafe']}`",
        "",
        "## Evidence",
        "",
        f"- maturity: status=`{maturity['status']}` "
        f"recoveredStagePressure=`{maturity['recoveredStagePressureObserved']}` "
        f"flowRefreshChangedRuns=`{maturity['flowRefreshChangedRuns']}` "
        f"cascadeStagePressure=`{maturity['cascadeStagePressureObserved']}` "
        f"cascadeStageFailedAttempts=`{maturity['cascadeStageFailedAttempts']}` "
        f"cascadeStageRecoveredFlows=`{maturity['cascadeStageRecoveredFlows']}` "
        f"cascadeStageStoppedFailures=`{maturity['cascadeStageStoppedFailures']}`",
        f"- dynet linux product: clean=`{dynet['clean']}` "
        f"passed=`{dynet['passed']}/{dynet['runs']}` "
        f"targets=`{dynet['targetHostCount']}`",
        f"- dynet run TUN runtime: clean=`{runtime['clean']}` "
        f"workload=`{runtime['workloadSuccess']}/{runtime['workloadAttempted']}` "
        f"workloadFailures=`{format_count_rows(runtime['workloadFailedBySurface'])}` "
        f"carrier=`{runtime['runtimeCarrier']}`",
        f"- clash product surface: pass=`{clash['passCount']}/{clash['candidateCount']}` "
        f"interfaceName=`{clash['interfaceNameConfigured']}` "
        f"targetHostsKnown=`{clash['targetHostsKnown']}`",
        f"- paired product-effect: windows=`{paired['windows']}` "
        f"entries=`{paired['pairedEntries']}` carriers=`{paired['runtimeCarriers']}` "
        f"parity=`{paired['parityCandidate']}`",
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
    for item in conclusion["nextActions"]:
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
