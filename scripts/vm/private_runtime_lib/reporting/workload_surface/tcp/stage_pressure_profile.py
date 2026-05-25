from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from common import Lab, validate_name
from scripts.lib.jsonio import load_summary
from scripts.lib.nv import count_keys, merge_items
from scripts.lib.privacy import empty_privacy_flags


SCHEMA = "dynet-vm-private-runtime-stage-pressure-profile/v1alpha1"
ROUND_GAP_SCHEMA = "dynet-vm-private-runtime-round-gap-batch/v1alpha1"
COUNT_FIELDS = """
roundGapRuns cleanControlRuns failedRuns stageFailureEvents workloadFailure
recoveredFlowCount cascadeFailedAttempts cascadeRetryableFailures
cascadeStoppedFailures cascadeStoppedBoundExhaustedFlows selectedBehind
tcpSlotPressureEvents scheduleLagMaxMs slowStageEvents pendingRetryEvents
pendingRetries pendingElapsedMs
""".split()


def command_stage_pressure_profile(_lab: Lab, args: argparse.Namespace) -> None:
    label = validate_name(args.label or "stage-pressure-profile", "label")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = build_stage_pressure_summary(label, output_dir, [Path(item) for item in args.input])
    write_stage_pressure_summary(output_dir, summary)
    print(json.dumps(stage_pressure_print(output_dir, summary), sort_keys=True))


def build_stage_pressure_summary(
    label: str,
    output_dir: Path,
    inputs: list[Path],
) -> dict[str, Any]:
    sources = [stage_pressure_source(path) for path in inputs]
    totals = stage_pressure_totals(sources)
    conclusion = stage_pressure_conclusion(totals)
    return {
        "schema": SCHEMA,
        "label": label,
        "outputDir": str(output_dir),
        "sources": sources,
        "totals": totals,
        "conclusion": conclusion,
        "policy": {
            "plannerPenaltySafe": False,
            "qualityPenaltySafe": False,
            "reason": conclusion["reason"],
        },
        "privacy": empty_privacy_flags(),
    }


def stage_pressure_source(path: Path) -> dict[str, Any]:
    summary = load_summary(path)
    totals = summary.get("totals") or {}
    conclusion = summary.get("conclusion") or {}
    policy = summary.get("policy") or {}
    return {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "label": str(summary.get("label") or path.stem),
        "roundGapStatus": str(conclusion.get("status") or ""),
        "roundGapNextAction": str(conclusion.get("nextAction") or ""),
        "plannerPenaltySafe": bool(conclusion.get("plannerPenaltySafe"))
        or bool(policy.get("plannerPenaltySafe")),
        "qualityPenaltySafe": bool(conclusion.get("qualityPenaltySafe"))
        or bool(policy.get("qualityPenaltySafe")),
        **source_counts(totals),
        "classifications": count_keys(totals.get("classifications")),
        "stageSurfaces": count_keys(totals.get("stageFailureBySurface")),
        "stageDispositions": count_keys(totals.get("stageFailureByDisposition")),
        "failureStages": count_keys(totals.get("failedByFailureStage")),
        "replayScopes": count_keys(totals.get("failedByReplaySafe")),
        "cascadeScopes": count_keys(totals.get("cascadeFailedByScope")),
        "cascadeStopReasons": count_keys(totals.get("cascadeFailedByStopReason")),
        "recoveredMechanisms": count_keys(totals.get("recoveredFlowMechanisms")),
        "pendingWaitClasses": count_keys(totals.get("pendingWaitClasses")),
        "runProfiles": run_profiles(summary),
    }


def source_counts(totals: dict[str, Any]) -> dict[str, int]:
    return {
        "roundGapRuns": int_value(totals.get("runs")),
        "cleanControlRuns": int_value(totals.get("cleanRuns")),
        "failedRuns": int_value(totals.get("failedRuns")),
        "stageFailureEvents": count_total(totals.get("stageFailureBySurface")),
        "workloadFailure": int_value(totals.get("workloadFailure")),
        "recoveredFlowCount": count_total(totals.get("recoveredFlowMechanisms")),
        "cascadeFailedAttempts": int_value(totals.get("cascadeFailedAttempts")),
        "cascadeRetryableFailures": int_value(totals.get("cascadeRetryableFailures")),
        "cascadeStoppedFailures": int_value(totals.get("cascadeStoppedFailures")),
        "cascadeStoppedBoundExhaustedFlows": int_value(
            totals.get("cascadeStoppedBoundExhaustedFlows")
        ),
        "selectedBehind": int_value(totals.get("selectedBehind")),
        "tcpSlotPressureEvents": int_value(totals.get("tcpSlotPressureEvents")),
        "scheduleLagMaxMs": int_value(totals.get("scheduleLagMaxMs")),
        "slowStageEvents": int_value(totals.get("slowStageEvents")),
        "slowStageMaxMs": int_value(totals.get("slowStageMaxMs")),
        "pendingRetryEvents": int_value(totals.get("pendingRetryEvents")),
        "pendingRetries": int_value(totals.get("pendingRetries")),
        "pendingRetriesMax": int_value(totals.get("pendingRetriesMax")),
        "pendingElapsedMs": int_value(totals.get("pendingElapsedMs")),
        "pendingElapsedMaxMs": int_value(totals.get("pendingElapsedMaxMs")),
        "pendingBudgetMs": int_value(totals.get("pendingBudgetMs")),
        "pendingSleepMs": int_value(totals.get("pendingSleepMs")),
    }


def stage_pressure_totals(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        **{field: sum(source[field] for source in sources) for field in COUNT_FIELDS},
        "classifications": merge_items(sources, "classifications"),
        "roundGapStatuses": aggregate(source["roundGapStatus"] for source in sources),
        "stageSurfaces": merge_items(sources, "stageSurfaces"),
        "stageDispositions": merge_items(sources, "stageDispositions"),
        "failureStages": merge_items(sources, "failureStages"),
        "replayScopes": merge_items(sources, "replayScopes"),
        "cascadeScopes": merge_items(sources, "cascadeScopes"),
        "cascadeStopReasons": merge_items(sources, "cascadeStopReasons"),
        "recoveredMechanisms": merge_items(sources, "recoveredMechanisms"),
        "pendingWaitClasses": merge_items(sources, "pendingWaitClasses"),
        "profileCount": profile_count(sources),
        "pressureRunCount": sum(
            1
            for source in sources
            for profile in source["runProfiles"]
            if int_value(profile.get("stageFailureEvents"))
        ),
        "maxStageFailureEventsInRun": max(
            (
                int_value(profile.get("stageFailureEvents"))
                for source in sources
                for profile in source["runProfiles"]
            ),
            default=0,
        ),
        "slowStageMaxMs": max((source["slowStageMaxMs"] for source in sources), default=0),
        "pendingRetriesMax": max((source["pendingRetriesMax"] for source in sources), default=0),
        "pendingElapsedMaxMs": max(
            (source["pendingElapsedMaxMs"] for source in sources),
            default=0,
        ),
        "pendingBudgetMs": max((source["pendingBudgetMs"] for source in sources), default=0),
        "pendingSleepMs": max((source["pendingSleepMs"] for source in sources), default=0),
        "runProfiles": [
            profile
            for source in sources
            for profile in source["runProfiles"]
        ],
        "schemaMismatchSources": sum(1 for source in sources if source["schema"] != ROUND_GAP_SCHEMA),
        "penaltySafeSources": sum(
            1 for source in sources if source["plannerPenaltySafe"] or source["qualityPenaltySafe"]
        ),
    }


def stage_pressure_conclusion(totals: dict[str, Any]) -> dict[str, Any]:
    status = profile_status(totals)
    return {
        "status": status,
        "nextAction": next_action(status),
        "reason": reason(status),
        "plannerPenaltySafe": False,
        "qualityPenaltySafe": False,
    }


def profile_status(totals: dict[str, Any]) -> str:
    if focused_profile_clean(totals):
        return "stage-pressure-profile-clean"
    if product_profile_clean(totals):
        return "stage-pressure-product-clean"
    return "stage-pressure-profile-needs-evidence"


def focused_profile_clean(totals: dict[str, Any]) -> bool:
    return common_clean(totals) and (
        totals["failedRuns"] > 0
        and totals["stageFailureEvents"] > 0
        and totals["workloadFailure"] > 0
        and totals["profileCount"] == 1
        and totals["stageDispositions"] == ["pending-timeout"]
        and totals["cascadeScopes"] == ["bound"]
        and totals["selectedBehind"] == 0
        and totals["tcpSlotPressureEvents"] == 0
    )


def product_profile_clean(totals: dict[str, Any]) -> bool:
    stage_shape_ok = (
        totals["stageFailureEvents"] == 0
        or (
            totals["profileCount"] == 1
            and totals["stageDispositions"] == ["pending-timeout"]
            and totals["cascadeScopes"] == ["bound"]
        )
    )
    return common_clean(totals) and (
        totals["failedRuns"] == 0
        and totals["cleanControlRuns"] == totals["roundGapRuns"]
        and totals["workloadFailure"] == 0
        and totals["cascadeStoppedFailures"] == 0
        and totals["cascadeStoppedBoundExhaustedFlows"] == 0
        and totals["classifications"] == ["clean"]
        and totals["selectedBehind"] == 0
        and stage_shape_ok
    )


def common_clean(totals: dict[str, Any]) -> bool:
    return (
        totals["sourceCount"] > 0
        and totals["schemaMismatchSources"] == 0
        and totals["roundGapRuns"] > 0
        and totals["cleanControlRuns"] > 0
        and totals["penaltySafeSources"] == 0
    )


def profile_count(sources: list[dict[str, Any]]) -> int:
    return len({
        (surface, disposition)
        for source in sources
        for surface in source["stageSurfaces"]
        for disposition in source["stageDispositions"]
    })


def run_profiles(summary: dict[str, Any]) -> list[dict[str, Any]]:
    profiles = []
    for row in summary.get("runs") or []:
        if not isinstance(row, dict):
            continue
        profiles.append(run_profile(row))
    return profiles


def run_profile(row: dict[str, Any]) -> dict[str, Any]:
    cascade = row.get("cascade") or {}
    surfaces = row.get("surfaces") or {}
    stage_blocking = row.get("stageBlocking") or {}
    workload = row.get("workload") or {}
    workload_flow = row.get("workloadFlow") or {}
    runtime = row.get("runtime") or {}
    quality = row.get("quality") or {}
    return {
        "label": str(row.get("label") or ""),
        "classification": str(row.get("classification") or ""),
        "stageFailureEvents": count_total(surfaces.get("stageFailureBySurface")),
        "stageSurfaces": list(surfaces.get("stageFailureBySurface") or []),
        "stageDispositions": list(surfaces.get("stageFailureByDisposition") or []),
        "cascadeFailedAttempts": int_value(cascade.get("failedAttempts")),
        "cascadeRetryableFailures": int_value(cascade.get("retryableFailures")),
        "cascadeRecoveredFlows": int_value(cascade.get("recoveredFlows")),
        "cascadeStoppedFailures": int_value(cascade.get("stoppedFailures")),
            "slowStageEvents": int_value(stage_blocking.get("slowStageEvents")),
            "slowStageMaxMs": int_value(stage_blocking.get("slowStageMaxMs")),
            "pendingRetryEvents": int_value(stage_blocking.get("pendingRetryEvents")),
            "pendingRetries": int_value(stage_blocking.get("pendingRetries")),
            "pendingRetriesMax": int_value(stage_blocking.get("pendingRetriesMax")),
            "pendingElapsedMs": int_value(stage_blocking.get("pendingElapsedMs")),
            "pendingElapsedMaxMs": int_value(stage_blocking.get("pendingElapsedMaxMs")),
            "pendingBudgetMs": int_value(stage_blocking.get("pendingBudgetMs")),
            "pendingSleepMs": int_value(stage_blocking.get("pendingSleepMs")),
            "pendingWaitClasses": list(stage_blocking.get("pendingWaitClasses") or []),
            "matchedRecoveredFailureEntries": int_value(
                workload_flow.get("matchedRecoveredFailureEntries")
            ),
        "matchedFlowStageFailedAttempts": int_value(
            workload_flow.get("matchedFlowStageFailedAttempts")
        ),
        "workloadFailure": int_value(workload.get("failure")),
        "tcpSlotPressureEvents": int_value(runtime.get("tcpSlotPressureEvents")),
        "selectedBehind": int_value(quality.get("selectedBehind")),
    }


def reason(status: str) -> str:
    if status == "stage-pressure-profile-clean":
        return "stage pressure is focused, bounded, has clean controls, and remains observe-only"
    if status == "stage-pressure-product-clean":
        return "product surface is clean; recovered stage pressure remains observe-only"
    return "stage pressure is too broad or incomplete for focused hardening"


def next_action(status: str) -> str:
    if status == "stage-pressure-profile-clean":
        return "harden-focused-stage-pressure-without-policy-change"
    if status == "stage-pressure-product-clean":
        return "return-to-mainline-product-effect-with-pressure-observe"
    return "inspect-stage-pressure-profile"


def write_stage_pressure_summary(output_dir: Path, summary: dict[str, Any]) -> None:
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    write_stage_pressure_markdown(output_dir / "summary.md", summary)


def write_stage_pressure_markdown(path: Path, summary: dict[str, Any]) -> None:
    totals = summary["totals"]
    lines = [
        "# VM Private Runtime Stage Pressure Profile",
        "",
        f"- label: `{summary['label']}`",
        f"- status: `{summary['conclusion']['status']}`",
        f"- stage surfaces: `{totals['stageSurfaces']}`",
        f"- dispositions: `{totals['stageDispositions']}`",
        f"- cascade scopes: `{totals['cascadeScopes']}`",
        f"- clean controls: `{totals['cleanControlRuns']}`",
        f"- stage failures: `{totals['stageFailureEvents']}`",
        f"- pressure runs: `{totals['pressureRunCount']}`",
        f"- max stage failures in run: `{totals['maxStageFailureEventsInRun']}`",
        f"- selected behind: `{totals['selectedBehind']}`",
        f"- slot pressure: `{totals['tcpSlotPressureEvents']}`",
        f"- run profiles: `{totals['runProfiles']}`",
    ]
    path.write_text("\n".join(lines) + "\n")


def stage_pressure_print(output_dir: Path, summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "outputDir": str(output_dir),
        "status": summary["conclusion"]["status"],
        "stageFailureEvents": summary["totals"]["stageFailureEvents"],
        "profileCount": summary["totals"]["profileCount"],
    }


def aggregate(values: Any) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for value in values:
        key = str(value or "unknown")
        counts[key] = counts.get(key, 0) + 1
    return [{"key": key, "count": counts[key]} for key in sorted(counts)]


def count_total(rows: Any) -> int:
    return sum(int_value(row.get("count")) for row in rows or [] if isinstance(row, dict))


def int_value(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
