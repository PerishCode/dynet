from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from common import CommandError, Lab, validate_name
from private_runtime_lib.reporting.pressure.events import (
    SLOW_STAGE_MS,
    int_value,
    slot_rows,
    slow_stage_rows,
    stage_rows,
)
from private_runtime_lib.reporting.pressure.run_rows import (
    all_checks_passed,
    pressure_run_row,
)


SCHEMA = "dynet-vm-private-runtime-pressure/v1alpha1"
REPEAT_SCHEMA = "dynet-vm-private-runtime-repeat/v1alpha1"
ROUND_GAP_SCHEMA = "dynet-vm-private-runtime-round-gap-batch/v1alpha1"
EXPANDABLE_SCHEMAS = {REPEAT_SCHEMA, ROUND_GAP_SCHEMA}


def command_pressure(_lab: Lab, args: argparse.Namespace) -> None:
    label = validate_name(args.label or "pressure", "label")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    report = pressure_report(label, output_dir, [Path(path) for path in args.input])
    write_json(output_dir / "summary.json", report)
    write_markdown(output_dir / "summary.md", report)
    print(json.dumps({"outputDir": str(output_dir), "status": report["status"]}, sort_keys=True))


def pressure_report(label: str, output_dir: Path, inputs: list[Path]) -> dict[str, Any]:
    sources = [input_source(path) for path in inputs]
    runs = [run for source in sources for run in source["runs"]]
    stage = [row for run in runs for row in stage_rows(run)]
    slots = [row for run in runs for row in slot_rows(run)]
    slow = [row for run in runs for row in slow_stage_rows(run)]
    run_rows = [
        pressure_run_row(
            run,
            stage_rows(run),
            slot_rows(run),
            slow_stage_rows(run),
        )
        for run in runs
    ]
    totals = pressure_totals(sources, runs, stage, slots, slow, run_rows)
    conclusion = pressure_conclusion(totals)
    return {
        "schema": SCHEMA,
        "label": label,
        "outputDir": str(output_dir),
        "status": conclusion["status"],
        "conclusion": conclusion,
        "totals": totals,
        "runPressure": run_pressure_summary(run_rows),
        "stagePressure": sanitized_stage_pressure(stage),
        "slotPressure": {
            "byRun": aggregate_count(slots, "run", "events"),
            "byPorts": aggregate_count(slots, "ports", "events"),
            "byActiveSlots": aggregate_count(slots, "activeSlots", "events"),
            "byCapacity": aggregate_count(slots, "capacity", "events"),
        },
        "slowStagePressure": {
            "thresholdMs": SLOW_STAGE_MS,
            "byRun": aggregate_count(slow, "run", "events"),
            "bySurface": aggregate_count(slow, "surface", "events"),
        },
        "policy": {
            "plannerPenaltySafe": False,
            "qualityPenaltySafe": False,
            "productEffectClaimSafe": False,
            "reason": "pressure report is observe-only; penalties require repeated runtime-backed node evidence",
        },
        "privacy": {
            "rawSecretsStored": False,
            "rawLogsStored": False,
            "rawPacketsStored": False,
            "rawResponseBodiesStored": False,
        },
        "sources": [source_row(source) for source in sources],
        "inputs": [str(path) for path in inputs],
    }


def input_source(path: Path) -> dict[str, Any]:
    summary_path = summary_json_path(path)
    summary = load_json(summary_path)
    label = str(summary.get("label") or path.name)
    return {
        "label": label,
        "path": str(path),
        "summaryPath": str(summary_path),
        "schema": str(summary.get("schema") or "unknown"),
        "totals": source_totals(summary),
        "runs": source_runs(summary_path, summary, label),
    }


def summary_json_path(path: Path) -> Path:
    return path / "summary.json" if path.is_dir() else path


def source_runs(
    summary_path: Path,
    summary: dict[str, Any],
    source_label: str,
) -> list[dict[str, Any]]:
    runs = summary.get("runs")
    if summary.get("schema") in EXPANDABLE_SCHEMAS and isinstance(runs, list):
        return [
            run_ref(summary_path.parent, item, source_label)
            for item in runs
            if isinstance(item, dict)
        ]
    return [run_ref(summary_path.parent, summary, source_label)]


def run_ref(base: Path, run: dict[str, Any], source_label: str) -> dict[str, Any]:
    path = Path(str(run.get("path") or base))
    if not path.is_absolute():
        path = path if path.exists() else base / path
        path = path.resolve(strict=False)
    return {
        "source": source_label,
        "label": str(run.get("label") or path.name),
        "path": path,
        "summary": run,
        "events": runtime_events(path, run),
    }


def runtime_events(path: Path, run: dict[str, Any]) -> list[dict[str, Any]]:
    report = run.get("runtimeReport")
    if isinstance(report, dict) and isinstance(report.get("events"), list):
        return report["events"]
    report_path = path / "runtime-report.json" if path.is_dir() else path
    if not report_path.exists():
        return []
    data = load_json(report_path)
    events = data.get("events")
    return events if isinstance(events, list) else []


def source_totals(summary: dict[str, Any]) -> dict[str, Any]:
    totals = summary.get("totals")
    if isinstance(totals, dict) and "runs" in totals:
        return repeat_source_totals(totals)
    return run_source_totals(summary)


def repeat_source_totals(totals: dict[str, Any]) -> dict[str, Any]:
    return {
        "runs": int_value(totals.get("runs")),
        "passedRuns": int_value(totals.get("passedRuns") or totals.get("cleanRuns")),
        "failedRuns": int_value(totals.get("failedRuns")),
        "workloadAttempted": int_value(totals.get("workloadAttempted")),
        "workloadSuccess": int_value(totals.get("workloadSuccess")),
        "workloadFailure": int_value(totals.get("workloadFailure")),
        "tcpFlowFailed": int_value(totals.get("tcpFlowFailed")),
        "tcpFlowStageFailed": int_value(totals.get("tcpFlowStageFailed")),
        "tcpFlowPathComplete": int_value(totals.get("tcpFlowPathComplete")),
        "tcpFlowPayloadBidirectional": int_value(totals.get("tcpFlowPayloadBidirectional")),
        "tcpSlotPressureEvents": int_value(totals.get("tcpSlotPressureEvents")),
        "slowStageEvents": int_value(totals.get("slowStageEvents")),
        "slowFailedStageEvents": int_value(totals.get("slowFailedStageEvents")),
        "slowStageMaxMs": int_value(totals.get("slowStageMaxMs")),
        "slowStageElapsedMs": int_value(totals.get("slowStageElapsedMs")),
        "scheduleLagMaxMs": int_value(totals.get("scheduleLagMaxMs")),
        "cascadeFailedAttempts": int_value(totals.get("cascadeFailedAttempts")),
        "cascadeRecoveredFlows": int_value(totals.get("cascadeRecoveredFlows")),
    }


def run_source_totals(summary: dict[str, Any]) -> dict[str, Any]:
    workload = summary.get("workloadProbe", {}).get("totals", {})
    tcp_flow = summary.get("tcpFlow", {})
    cascade = summary.get("cascadeAttempts", {})
    passed = all_checks_passed(summary)
    workload_attempted = int_value(workload.get("count")) or int_value(
        workload.get("success")
    ) + int_value(workload.get("failure"))
    return {
        "runs": 1,
        "passedRuns": 1 if passed else 0,
        "failedRuns": 0 if passed else 1,
        "workloadAttempted": workload_attempted,
        "workloadSuccess": int_value(workload.get("success")),
        "workloadFailure": int_value(workload.get("failure")),
        "tcpFlowFailed": int_value(tcp_flow.get("failedFlows")),
        "tcpFlowStageFailed": int_value(tcp_flow.get("stageFailedFlows")),
        "tcpFlowPathComplete": int_value(tcp_flow.get("pathCompleteFlows")),
        "tcpFlowPayloadBidirectional": int_value(tcp_flow.get("payloadBidirectionalFlows")),
        "tcpSlotPressureEvents": int_value(
            summary.get("runtime", {}).get("tcpSlotPressureEvents")
        ),
        "slowStageEvents": 0,
        "slowFailedStageEvents": 0,
        "slowStageMaxMs": 0,
        "slowStageElapsedMs": 0,
        "scheduleLagMaxMs": 0,
        "cascadeFailedAttempts": int_value(cascade.get("failedAttempts")),
        "cascadeRecoveredFlows": int_value(cascade.get("recoveredFlows")),
    }


def pressure_totals(
    sources: list[dict[str, Any]],
    runs: list[dict[str, Any]],
    stage_rows: list[dict[str, Any]],
    slot_rows: list[dict[str, Any]],
    slow_rows: list[dict[str, Any]],
    run_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    workload_attempted = sum_total_or_rows(
        sources, "workloadAttempted", run_rows, "workloadAttempted"
    )
    workload_success = sum_total_or_rows(
        sources, "workloadSuccess", run_rows, "workloadSuccess"
    )
    workload_failure = sum_total_or_rows(
        sources, "workloadFailure", run_rows, "workloadFailure"
    )
    tcp_flow_failed = sum_total_or_rows(sources, "tcpFlowFailed", run_rows, "tcpFlowFailed")
    tcp_path_complete = sum_total_or_rows(
        sources, "tcpFlowPathComplete", run_rows, "tcpFlowPathComplete"
    )
    tcp_payload = sum_total_or_rows(
        sources, "tcpFlowPayloadBidirectional", run_rows, "tcpFlowPayloadBidirectional"
    )
    return {
        "sources": len(sources),
        "runs": len(runs),
        "passedRuns": sum_total(sources, "passedRuns"),
        "failedRuns": sum_total(sources, "failedRuns"),
        "workloadAttempted": workload_attempted,
        "workloadSuccess": workload_success,
        "workloadFailure": workload_failure,
        "tcpFlowFailed": tcp_flow_failed,
        "tcpFlowStageFailed": sum_total(sources, "tcpFlowStageFailed"),
        "tcpFlowPathComplete": tcp_path_complete,
        "tcpFlowPayloadBidirectional": tcp_payload,
        "stageFailures": len(stage_rows),
        "stageRecoveredFailures": sum(1 for row in stage_rows if row["recovered"]),
        "stageUnrecoveredFailures": sum(1 for row in stage_rows if not row["recovered"]),
        "boundStageFailures": sum(1 for row in stage_rows if row["scope"] == "bound"),
        "slotPressureEvents": sum(int(row["events"]) for row in slot_rows),
        "sourceSlotPressureEvents": sum_total(sources, "tcpSlotPressureEvents"),
        "slotActiveAtCapacityEvents": sum(
            int(row["events"])
            for row in slot_rows
            if int(row["capacity"]) > 0 and int(row["activeSlots"]) == int(row["capacity"])
        ),
        "slotActiveOverCapacityEvents": sum(
            int(row["events"])
            for row in slot_rows
            if int(row["capacity"]) > 0 and int(row["activeSlots"]) > int(row["capacity"])
        ),
        "slotCapacityMissingEvents": sum(
            int(row["events"]) for row in slot_rows if int(row["capacity"]) == 0
        ),
        "slowStageEvents": sum(int(row["events"]) for row in slow_rows),
        "slowFailedStageEvents": sum(
            int(row["events"]) for row in slow_rows if ":failed:" in row["surface"]
        ),
        "slowStageMaxMs": max((int(row["elapsedMs"]) for row in slow_rows), default=0),
        "slowStageElapsedMs": sum(
            int(row["elapsedMs"]) * int(row["events"]) for row in slow_rows
        ),
        "sourceSlowStageEvents": sum_total(sources, "slowStageEvents"),
        "sourceSlowFailedStageEvents": sum_total(sources, "slowFailedStageEvents"),
        "scheduleLagMaxMs": max(source_total(sources, "scheduleLagMaxMs"), default=0),
        "runsWithStagePressure": sum(1 for row in run_rows if int(row["stageFailures"]) > 0),
        "runsWithSlotPressure": sum(1 for row in run_rows if int(row["slotPressureEvents"]) > 0),
        "runsWithSlowStagePressure": sum(1 for row in run_rows if int(row["slowStageEvents"]) > 0),
        "runsWithStageAndSlotPressure": sum(
            1 for row in run_rows
            if int(row["stageFailures"]) > 0 and int(row["slotPressureEvents"]) > 0
        ),
        "runsWithStageWithoutSlotPressure": sum(
            1 for row in run_rows
            if int(row["stageFailures"]) > 0 and int(row["slotPressureEvents"]) == 0
        ),
        "runsWithSlotWithoutStagePressure": sum(
            1 for row in run_rows
            if int(row["slotPressureEvents"]) > 0 and int(row["stageFailures"]) == 0
        ),
        "runsAtPortSlotLimit": sum(
            1 for row in run_rows
            if int(row["slotPressureEvents"]) > 0
            and int(row["tcpListenSlotsPerPort"]) > 0
            and int(row["tcpActiveSlotsMax"]) >= int(row["tcpListenSlotsPerPort"])
        ),
        "cascadeFailedAttempts": sum_total(sources, "cascadeFailedAttempts"),
        "cascadeRecoveredFlows": sum_total(sources, "cascadeRecoveredFlows"),
        "classifications": aggregate_values(row["classification"] for row in run_rows),
    }


def pressure_conclusion(totals: dict[str, Any]) -> dict[str, Any]:
    product_clean = product_surface_clean(totals)
    all_recovered = int(totals["stageUnrecoveredFailures"]) == 0
    status = pressure_status(totals, product_clean, all_recovered)
    return {
        "status": status,
        "productSurfaceClean": product_clean,
        "allStageFailuresRecovered": all_recovered,
        "pressureShape": pressure_shape(totals, product_clean, all_recovered),
        "nextAction": pressure_next_action(status),
    }


def pressure_status(
    totals: dict[str, Any],
    product_clean: bool,
    all_recovered: bool,
) -> str:
    if not product_clean or not all_recovered:
        return "needs-runtime-pressure-classification"
    if int(totals["stageFailures"]) > 0 or int(totals["slotPressureEvents"]) > 0:
        return "observe-only-product-clean"
    if int(totals["sourceSlotPressureEvents"]) > 0:
        return "observe-only-product-clean"
    return "clean"


def product_surface_clean(totals: dict[str, Any]) -> bool:
    workload_attempted = int(totals["workloadAttempted"])
    workload_complete = (
        workload_attempted > 0
        and int(totals["workloadSuccess"]) == workload_attempted
        and int(totals["workloadFailure"]) == 0
    )
    return (
        int(totals["runs"]) > 0
        and int(totals["failedRuns"]) == 0
        and workload_complete
        and int(totals["tcpFlowFailed"]) == 0
        and int(totals["tcpFlowPathComplete"]) >= workload_attempted
        and int(totals["tcpFlowPayloadBidirectional"]) >= workload_attempted
    )


def pressure_next_action(status: str) -> str:
    if status == "clean":
        return "clean"
    if status == "observe-only-product-clean":
        return "retain-pressure-as-observe-only-and-collect-repeat-candidate-evidence"
    return "split-product-failure-from-runtime-pressure-before-any-penalty"


def pressure_shape(
    totals: dict[str, Any],
    product_clean: bool,
    all_recovered: bool,
) -> str:
    if not product_clean or not all_recovered:
        return "needs-runtime-pressure-classification"
    stage = int(totals["stageFailures"]) > 0 or int(totals["slowFailedStageEvents"]) > 0
    slot = int(totals["slotPressureEvents"]) > 0
    slow = int(totals["slowStageEvents"]) > 0
    separated = (
        int(totals["runsWithStageWithoutSlotPressure"]) > 0
        and int(totals["runsWithSlotWithoutStagePressure"]) > 0
        and int(totals["runsWithStageAndSlotPressure"]) == 0
    )
    if separated:
        return "separated-handshake-wait-and-slot-admission-pressure"
    if stage and slot:
        return "coincident-stage-and-slot-pressure"
    if stage:
        return "handshake-wait-budget-pressure"
    if slot:
        return "slot-admission-pressure"
    if slow:
        return "slow-stage-pressure"
    return "no-residual-pressure"


def run_pressure_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "rows": rows,
        "byClassification": aggregate_values(row["classification"] for row in rows),
    }


def sanitized_stage_pressure(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "failureCount": len(rows),
        "recoveredFailures": sum(1 for row in rows if row["recovered"]),
        "unrecoveredFailures": sum(1 for row in rows if not row["recovered"]),
        "byScope": aggregate(rows, "scope"),
        "byStageDisposition": aggregate_tuple(rows, ["stage", "disposition"]),
        "byStopReason": aggregate(rows, "stopReason"),
        "byRun": aggregate(rows, "run"),
        "byAttemptOrdinal": aggregate(rows, "attempt"),
        "byCandidateCount": aggregate(rows, "candidateCount"),
    }


def source_row(source: dict[str, Any]) -> dict[str, Any]:
    return {
        "label": source["label"],
        "path": source["path"],
        "summaryPath": source["summaryPath"],
        "schema": source["schema"],
        "runs": len(source["runs"]),
        "totals": source["totals"],
    }


def sum_total(sources: list[dict[str, Any]], key: str) -> int:
    return sum(int(source["totals"].get(key) or 0) for source in sources)


def sum_total_or_rows(
    sources: list[dict[str, Any]],
    source_key: str,
    rows: list[dict[str, Any]],
    row_key: str,
) -> int:
    total = sum_total(sources, source_key)
    if total:
        return total
    return sum(int(row.get(row_key) or 0) for row in rows)

def source_total(sources: list[dict[str, Any]], key: str) -> list[int]:
    return [int(source["totals"].get(key) or 0) for source in sources]

def aggregate(rows: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    return count_rows(str(row.get(key) or "unknown") for row in rows)

def aggregate_values(values: Any) -> list[dict[str, Any]]:
    return count_rows(str(value or "unknown") for value in values)

def aggregate_tuple(rows: list[dict[str, Any]], keys: list[str]) -> list[dict[str, Any]]:
    return count_rows(
        ":".join(str(row.get(key) or "unknown") for key in keys)
        for row in rows
    )

def aggregate_count(rows: list[dict[str, Any]], key: str, count_key: str) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for row in rows:
        value = str(row.get(key) or "unknown")
        counts[value] = counts.get(value, 0) + int(row.get(count_key) or 0)
    return [{"key": key, "count": counts[key]} for key in sorted(counts)]

def count_rows(values: Any) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return [{"key": key, "count": counts[key]} for key in sorted(counts)]

def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise CommandError(f"missing JSON artifact: {path}")
    return json.loads(path.read_text())

def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")

def write_markdown(path: Path, report: dict[str, Any]) -> None:
    totals = report["totals"]
    lines = [
        "# Runtime Pressure",
        "",
        f"- status: `{report['status']}`",
        f"- runs: `{totals['runs']}`",
        f"- stage failures: `{totals['stageFailures']}`",
        f"- recovered stage failures: `{totals['stageRecoveredFailures']}`",
        f"- slot pressure events: `{totals['slotPressureEvents']}`",
        f"- slow stage events: `{totals['slowStageEvents']}`",
        f"- pressure shape: `{report['conclusion']['pressureShape']}`",
        f"- planner penalty safe: `{report['policy']['plannerPenaltySafe']}`",
        f"- product surface clean: `{report['conclusion']['productSurfaceClean']}`",
        f"- next action: `{report['conclusion']['nextAction']}`",
        "",
        "## Run Pressure",
    ]
    for row in report["runPressure"]["rows"]:
        lines.append(
            f"- `{row['label']}` classification=`{row['classification']}` "
            f"stage=`{row['stageFailures']}` slot=`{row['slotPressureEvents']}` "
            f"slow=`{row['slowStageEvents']}`"
        )
    lines.extend(["", "## Slot Pressure By Run"])
    for row in report["slotPressure"]["byRun"]:
        lines.append(f"- `{row['key']}` events=`{row['count']}`")
    path.write_text("\n".join(lines) + "\n")
