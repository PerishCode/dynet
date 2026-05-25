from __future__ import annotations

from pathlib import Path
from typing import Any


def write_markdown(path: Path, summary: dict[str, Any]) -> None:
    lines = [
        "# Dynet Mainline Adapter Coverage",
        "",
        f"- status: `{summary['status']}`",
        f"- recommended use: `{summary['recommendedUse']}`",
        f"- expected adapters: `{summary['expectedAdapterTypes']}`",
        f"- planner penalty safe: `{summary['plannerPenaltySafe']}`",
        f"- quality penalty safe: `{summary['qualityPenaltySafe']}`",
        "",
        "## Baseline",
        "",
    ]
    baseline = summary["mainlineBaseline"]
    for source in baseline["sources"]:
        lines.append(baseline_source_line(source))
    lines.extend([
        "",
        "## Adapters",
        "",
    ])
    for row in summary["adapters"]:
        lines.append(
            f"- `{row['adapterType']}` level=`{row['coverageLevel']}` "
            f"providerMatched=`{row['providerMatched']}` "
            f"providerAvailability=`{row['providerAvailability']['availability']}` "
            f"currentCompatible=`{row['providerAvailability']['currentCompatible']}` "
            f"runtimeRuns=`{row['runtimeRepeat']['runs']}` "
            f"productSources=`{row['productEffect']['sourceCount']}` "
            f"gaps=`{row['gaps']}` next=`{row['nextAction']}`"
        )
    lines.extend(["", "## Runtime Fallback", ""])
    fallback = summary["runtimeFallback"]
    lines.append(
        f"- clean: `{fallback['clean']}` modes=`{fallback['modes']}` "
        f"used=`{fallback['routeFallbackUsed']}` failed=`{fallback['routeFallbackFailed']}`"
    )
    lines.extend(["", "## Next Actions", ""])
    for item in summary["conclusion"]["nextActions"]:
        adapter = f" adapter=`{item['adapterType']}`" if item.get("adapterType") else ""
        lines.append(
            f"- `{item['id']}` priority=`{item['priority']}`{adapter} "
            f"plannerPenaltySafe=`{item['plannerPenaltySafe']}`"
        )
    runtime_work = summary["conclusion"].get("nextRuntimeWork", [])
    if runtime_work:
        lines.extend(["", "## Runtime Work", ""])
        for item in runtime_work:
            lines.append(
                f"- `{item['id']}` priority=`{item['priority']}` "
                f"plannerPenaltySafe=`{item['plannerPenaltySafe']}`"
            )
    path.write_text("\n".join(lines) + "\n")


def baseline_source_line(source: dict[str, Any]) -> str:
    fields = [
        "runtimeFallbackClean",
        "runtimeDnsProductClean",
        "runtimeDnsRefreshClean",
        "runtimeQualityPlanClean",
        "runtimeRouteRefreshClean",
        "runtimeSelectionRefreshClean",
        "runtimeWorkloadFlowClean",
        "runtimeQualityWorkloadClean",
        "runtimeWorkloadSurfaceClean",
        "runtimeCloseSurfaceClean",
        "runtimePayloadSurfaceClean",
        "runtimeEventStreamClean",
        "runtimeEventCorrelationClean",
        "runtimeEventCausalityClean",
        "runtimeStageSurfaceClean",
        "runtimeTimingSurfaceClean",
        "runtimeDnsTimingClean",
        "runtimeOutboundTimingClean",
        "runtimeOutboundGateClean",
        "runtimeOutboundRetryClean",
        "runtimePacketSurfaceClean",
        "runtimeTcpPressureClean",
        "runtimeUdpSessionClean",
        "runtimeIpv6DenialClean",
        "runtimeTakeoverLifecycleClean",
        "runtimeRetainedArtifactClean",
        "runtimeExitLimitClean",
        "runtimeCollectionStageClean",
        "runtimeFlowRefreshClean",
        "runtimeCascadeRefreshClean",
        "runtimeTargetIdentityClean",
        "qualityFeedbackBoundaryClean",
        "planQualityStateBridgeClean",
        "runtimeUdpDirectClean",
        "runtimeIpv6NoLeakClean",
        "runtimeGuardrailClean",
    ]
    return " ".join([f"- status=`{source['status']}`"] + [
        f"{field}=`{source[field]}`" for field in fields
    ])
