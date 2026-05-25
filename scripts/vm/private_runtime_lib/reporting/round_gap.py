from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from common import Lab, validate_name
from private_runtime_lib.reporting.cascade_refresh import (
    cascade_refresh_brief,
    refreshed_cascade_summary,
)
from private_runtime_lib.reporting.cascade_stop import (
    aggregate_lists,
    aggregate_strings,
    cascade_stop_fields,
    cascade_stop_for_flow,
    cascade_stop_index,
    count_items,
    int_fields,
)
from private_runtime_lib.reporting.flow_refresh import refreshed_flow_summary
from private_runtime_lib.reporting.round_gap_conclusion import (
    cascade_brief,
    cascade_totals,
    penalty_reason,
    round_gap_conclusion,
)
from private_runtime_lib.reporting.round_gap_markdown import write_round_gap_markdown
from private_runtime_lib.reporting.round_gap_stage import stage_blocking_summary, stage_blocking_totals


ROUND_GAP_SCHEMA = "dynet-vm-private-runtime-round-gap-batch/v1alpha1"
WORKLOAD_ITEM_FIELDS = "id domain scheduledOffsetMs scheduleLagMs errorStage errorType errorClass elapsedMs".split()
FLOW_BOOL_FIELDS = """
flowMatched flowRecoveredFailure runtimePreflowMatched runtimePacketMatched
runtimePacketTerminalMatched runtimePacketTerminalHandshakeComplete
runtimePacketTerminalPromotedToSession runtimePreflowCandidateMatched
runtimePreflowMissedMatched tunCaptureMatched workloadTcpConnectOk
workloadRouteViaDynet workloadTunWitnessed
""".split()
FLOW_VALUE_FIELDS = """
runtimePacketTerminalReason runtimePreflowCandidateReason runtimePreflowMissedReason
runtimePreflowMissedSocketState runtimePreflowMissedTerminalReason failureSurface
""".split()
FLOW_INT_FIELDS = """
flowMatchedCount flowFailedCount flowStageFailedCount
runtimePacketTerminalIngressControlPackets runtimePacketTerminalEgressControlPackets
runtimePacketTerminalIngressPayloadPackets runtimePacketTerminalIngressPayloadBytes
runtimePacketTerminalEgressPayloadPackets runtimePacketTerminalEgressPayloadBytes
runtimePacketTerminalFinPackets runtimePacketTerminalRstPackets
runtimePreflowCandidateIngressPayloadBytes runtimePreflowCandidateEgressPayloadBytes
runtimePreflowCandidateFinPackets runtimePreflowCandidateRstPackets
runtimePreflowMissedIngressPayloadBytes runtimePreflowMissedEgressPayloadBytes
runtimePreflowMissedFinPackets runtimePreflowMissedRstPackets
runtimeIngressSynPackets runtimeEgressSynAckPackets runtimeFinPackets runtimeRstPackets
tunCaptureSynPackets tunCaptureSynAckPackets
""".split()

def command_round_gap(_lab: Lab, args: argparse.Namespace) -> None:
    label = validate_name(args.label or "round-gap", "label")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = build_round_gap_summary(label, output_dir, [Path(item) for item in args.run_dir])
    write_round_gap_summary(output_dir, summary)
    print(
        json.dumps(
            {
                "outputDir": str(output_dir),
                "runs": summary["totals"]["runs"],
                "gapCount": summary["totals"]["gapCount"],
                "cleanRuns": summary["totals"]["cleanRuns"],
                "penaltySafe": summary["totals"]["penaltySafe"],
            },
            sort_keys=True,
        )
    )


def build_round_gap_summary(label: str, output_dir: Path, run_dirs: list[Path]) -> dict[str, Any]:
    rows = [round_gap_row(run_dir, load_run_summary(run_dir)) for run_dir in run_dirs]
    by_gap = [gap_summary(gap_ms, gap_rows) for gap_ms, gap_rows in group_by_gap(rows)]
    totals = round_gap_totals(rows, by_gap)
    reason = penalty_reason(rows)
    return {
        "schema": ROUND_GAP_SCHEMA,
        "label": label,
        "outputDir": str(output_dir),
        "runs": rows,
        "byGap": by_gap,
        "totals": totals,
        "conclusion": round_gap_conclusion(rows, totals, reason),
        "policy": {
            "plannerPenaltySafe": False,
            "qualityPenaltySafe": False,
            "reason": reason,
        },
    }


def load_run_summary(run_dir: Path) -> dict[str, Any]:
    path = run_dir / "summary.json" if run_dir.is_dir() else run_dir
    with path.open() as fh:
        return json.load(fh)


def round_gap_row(
    run_dir: Path,
    summary: dict[str, Any],
    *,
    include_failed_rows: bool = False,
) -> dict[str, Any]:
    summary, flow_refresh = refreshed_flow_summary(run_dir, summary)
    summary, cascade_refresh = refreshed_cascade_summary(run_dir, summary)
    workload = summary.get("workloadProbe", {})
    workload_totals = workload.get("totals", {})
    workload_flow = summary.get("workloadFlow", {})
    tcp_flow = summary.get("tcpFlow", {})
    selection = summary.get("selection", {}).get("boundSelection", {})
    cascade = cascade_brief(summary)
    raw_cascade = (summary.get("selection") or {}).get("cascadeAttempts") or {}
    if not isinstance(raw_cascade, dict):
        raw_cascade = {}
    stability = summary.get("stability", {})
    failed_checks = [item.get("name") for item in summary.get("checks", []) if not item.get("passed")]
    flow_index = flow_rows_by_id(workload_flow)
    failed_workload_mechanism_names = failed_workload_mechanisms(workload, flow_index)
    recovered_flow_mechanism_names = recovered_flow_mechanisms(workload_flow)
    failed_rows = (
        failed_workload_rows(workload, flow_index, cascade_stop_index(raw_cascade))
        if include_failed_rows
        else []
    )
    stage_blocking = stage_blocking_summary(run_dir, summary)
    terminal = list(workload_flow.get("runtimePacketTerminalByReason") or [])
    stage_failure = list(tcp_flow.get("stageFailureBySurface") or [])
    schedule = {
        "lagMaxMs": max_schedule_lag(workload),
        "failedRowCount": len(failed_workload_mechanism_names),
    }
    mechanisms = {
        "failedWorkloadCount": len(failed_workload_mechanism_names),
        "failedWorkloadByMechanism": aggregate_strings(failed_workload_mechanism_names),
        "recoveredFlowCount": len(recovered_flow_mechanism_names),
        "recoveredFlowByMechanism": aggregate_strings(recovered_flow_mechanism_names),
    }
    if include_failed_rows:
        schedule["failedRows"] = failed_rows
        mechanisms["failedWorkloadRows"] = failed_rows
    row = {
        "label": summary.get("label"),
        "path": str(run_dir),
        "gapMs": infer_round_gap_ms(workload),
        "passed": int(summary.get("totals", {}).get("failed") or 0) == 0,
        "failedChecks": failed_checks,
        "workload": {
            "attempted": int(workload_totals.get("count") or 0),
            "success": int(workload_totals.get("success") or 0),
            "failure": int(workload_totals.get("failure") or 0),
            "successRate": workload_totals.get("successRate"),
            "errors": stability.get("workloadErrors", []),
        },
        "runtime": {
            "tcpSessionFailures": summary.get("runtime", {}).get("tcpSessionFailures"),
            "tcpActiveSlotsMax": summary.get("runtime", {}).get("tcpActiveSlotsMax"),
            "tcpSlotPressureEvents": summary.get("runtime", {}).get("tcpSlotPressureEvents"),
        },
        "quality": quality_brief(selection),
        "flowRefresh": flow_refresh_brief(flow_refresh),
        "cascadeRefresh": cascade_refresh_brief(cascade_refresh),
        "cascade": cascade,
        "surfaces": {
            "runtimePacketTerminalByReason": terminal,
            "unmatchedRuntimePacketTerminalByReason": list(
                workload_flow.get("unmatchedRuntimePacketTerminalByReason") or []
            ),
            "stageFailureBySurface": stage_failure,
            "stageFailureByErrorType": list(tcp_flow.get("stageFailureByErrorType") or []),
            "stageFailureByDisposition": list(tcp_flow.get("stageFailureByDisposition") or []),
            "failedByPhase": list(tcp_flow.get("failedByPhase") or []),
            "failedByCleanupAction": list(tcp_flow.get("failedByCleanupAction") or []),
            "failedByReplaySafe": list(tcp_flow.get("failedByReplaySafe") or []),
            "failedByFailureStage": list(tcp_flow.get("failedByFailureStage") or []),
            "workloadErrors": stability.get("workloadErrors", []),
        },
        "workloadFlow": {
            "matchedEntries": workload_flow.get("matchedEntries"),
            "unmatchedEntries": workload_flow.get("unmatchedEntries"),
            "coveredEntries": workload_flow.get("coveredEntries"),
            "matchedRecoveredFailureEntries": workload_flow.get("matchedRecoveredFailureEntries"),
            "matchedFlowFailedAttempts": workload_flow.get("matchedFlowFailedAttempts"),
            "matchedFlowStageFailedAttempts": workload_flow.get("matchedFlowStageFailedAttempts"),
        },
        "schedule": schedule,
        "mechanisms": mechanisms,
        "stageBlocking": stage_blocking,
    }
    row["classification"] = classify_round_gap_row(row)
    row["penaltySafe"] = False
    return row


def quality_brief(selection: dict[str, Any]) -> dict[str, Any]:
    return {
        "candidateSets": selection.get("candidateSets"),
        "selectedWithQuality": selection.get("selectedWithQuality"),
        "selectedBehind": selection.get("selectedBehind"),
        "selectedBest": selection.get("selectedBest"),
    }


def flow_refresh_brief(flow_refresh: dict[str, Any]) -> dict[str, Any]:
    return {
        "available": flow_refresh["available"],
        "classification": flow_refresh["classification"],
        "changed": flow_refresh["changed"],
        "changes": flow_refresh["changes"],
    }


def flow_rows_by_id(workload_flow: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = {}
    for item in workload_flow.get("rows", []):
        if not isinstance(item, dict):
            continue
        workload_id = item.get("workloadId")
        if workload_id is not None:
            rows.setdefault(str(workload_id), item)
    return rows


def failed_workload_mechanisms(
    workload: dict[str, Any],
    flow_rows_by_id: dict[str, dict[str, Any]],
) -> list[str]:
    rows = []
    for item in workload.get("results", []):
        if item.get("ok"):
            continue
        flow_row = flow_rows_by_id.get(str(item.get("id")))
        rows.append(failed_workload_mechanism(item, flow_row or {}))
    return rows


def failed_workload_rows(
    workload: dict[str, Any],
    flow_rows_by_id: dict[str, dict[str, Any]],
    stopped_cascade_rows_by_flow: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    rows = []
    for item in workload.get("results", []):
        if item.get("ok"):
            continue
        flow = flow_rows_by_id.get(str(item.get("id"))) or {}
        rows.append(
            {
                **{field: item.get(field) for field in WORKLOAD_ITEM_FIELDS},
                "localPortPresent": item.get("localPort") is not None,
                "mechanism": failed_workload_mechanism(item, flow),
                "flowId": flow.get("flowId"),
                "flowIds": list(flow.get("flowIds") or []),
                **{field: bool(flow.get(field)) for field in FLOW_BOOL_FIELDS},
                **{field: flow.get(field) for field in FLOW_VALUE_FIELDS},
                **int_fields(flow, FLOW_INT_FIELDS),
                **cascade_stop_fields(
                    cascade_stop_for_flow(flow, stopped_cascade_rows_by_flow)
                ),
            }
        )
    return rows


def recovered_flow_mechanisms(workload_flow: dict[str, Any]) -> list[str]:
    rows = []
    for item in workload_flow.get("rows", []):
        if not isinstance(item, dict) or not item.get("flowRecoveredFailure"):
            continue
        rows.append(recovered_flow_mechanism(item))
    return rows


def failed_workload_mechanism(item: dict[str, Any], flow_row: dict[str, Any]) -> str:
    if flow_row.get("flowStageFailedCount"):
        return "failed-workload-with-runtime-stage-failure"
    if flow_row.get("flowFailedCount"):
        return "failed-workload-with-runtime-flow-failure"
    if flow_row.get("flowMatched"):
        return "workload-protocol-after-runtime-session"
    if flow_row.get("runtimePacketTerminalMatched"):
        return "packet-terminal-before-runtime-session"
    if flow_row.get("runtimePacketMatched"):
        return "runtime-packet-without-session"
    if flow_row.get("tunCaptureMatched"):
        return "tun-capture-without-runtime-packet"
    if flow_row.get("workloadTcpConnectOk") or item.get("localPort") is not None:
        return "workload-connected-without-runtime-evidence"
    return "pre-tcp-workload-failure"


def recovered_flow_mechanism(row: dict[str, Any]) -> str:
    if row.get("flowStageFailedCount"):
        return "recovered-runtime-stage-failure-before-success"
    if row.get("flowFailedCount"):
        return "recovered-runtime-flow-failure-before-success"
    return "recovered-runtime-duplicate-flow-before-success"


def infer_round_gap_ms(workload: dict[str, Any]) -> int | None:
    results = workload.get("results", [])
    offsets = [
        int(item.get("scheduledOffsetMs") or 0)
        for item in results
        if isinstance(item, dict) and str(item.get("id") or "").endswith("-r2")
    ]
    if offsets:
        return min(offsets)
    seed = str(workload.get("seed") or "")
    match = re.search(r"roundgap(?:(\d+)s|(\d+)ms)", seed)
    if not match:
        return None
    if match.group(1):
        return int(match.group(1)) * 1000
    return int(match.group(2))


def max_schedule_lag(workload: dict[str, Any]) -> int:
    values = [
        int(item.get("scheduleLagMs") or 0)
        for item in workload.get("results", [])
        if isinstance(item, dict)
    ]
    return max(values, default=0)


def classify_round_gap_row(row: dict[str, Any]) -> str:
    if row["passed"]:
        return "clean"
    terminal = count_items(row["surfaces"]["runtimePacketTerminalByReason"])
    stage_failures = count_items(row["surfaces"]["stageFailureBySurface"])
    tcp_failures = int(row["runtime"].get("tcpSessionFailures") or 0)
    recovered = int(row["workloadFlow"].get("matchedRecoveredFailureEntries") or 0)
    lag_max = int(row["schedule"].get("lagMaxMs") or 0)
    if stage_failures and lag_max >= 5000:
        return "stage-pressure-with-schedule-lag"
    if stage_failures:
        return "outbound-stage-pressure"
    if terminal and not tcp_failures:
        return "preflow-terminal-before-runtime-session"
    if terminal:
        return "preflow-terminal-with-runtime-failures"
    if recovered:
        return "recovered-hidden-stage-pressure"
    if row["workload"]["failure"]:
        return "workload-protocol-surface"
    return "runtime-gate-failure"


def group_by_gap(rows: list[dict[str, Any]]) -> list[tuple[int | None, list[dict[str, Any]]]]:
    groups: dict[int | None, list[dict[str, Any]]] = {}
    for row in rows:
        groups.setdefault(row.get("gapMs"), []).append(row)
    return [(gap, groups[gap]) for gap in sorted(groups, key=lambda item: -1 if item is None else item)]


def gap_summary(gap_ms: int | None, rows: list[dict[str, Any]]) -> dict[str, Any]:
    classifications = aggregate_strings(row["classification"] for row in rows)
    clean_runs = sum(1 for row in rows if row["classification"] == "clean")
    return {
        "gapMs": gap_ms,
        "runs": len(rows),
        "cleanRuns": clean_runs,
        "failedRuns": len(rows) - clean_runs,
        "status": gap_status(rows),
        "classificationCounts": classifications,
        "workloadAttempted": sum(int(row["workload"]["attempted"] or 0) for row in rows),
        "workloadSuccess": sum(int(row["workload"]["success"] or 0) for row in rows),
        "workloadFailure": sum(int(row["workload"]["failure"] or 0) for row in rows),
        "terminalByReason": aggregate_lists(
            row["surfaces"]["runtimePacketTerminalByReason"] for row in rows
        ),
        "stageFailureBySurface": aggregate_lists(
            row["surfaces"]["stageFailureBySurface"] for row in rows
        ),
        "failedByPhase": aggregate_lists(row["surfaces"]["failedByPhase"] for row in rows),
        "failedByCleanupAction": aggregate_lists(
            row["surfaces"]["failedByCleanupAction"] for row in rows
        ),
        "failedByReplaySafe": aggregate_lists(
            row["surfaces"]["failedByReplaySafe"] for row in rows
        ),
        "failedByFailureStage": aggregate_lists(
            row["surfaces"]["failedByFailureStage"] for row in rows
        ),
        "stageFailureByDisposition": aggregate_lists(
            row["surfaces"]["stageFailureByDisposition"] for row in rows
        ),
        "workloadErrors": aggregate_lists(row["workload"]["errors"] for row in rows),
        "failedWorkloadMechanisms": aggregate_lists(
            row["mechanisms"]["failedWorkloadByMechanism"] for row in rows
        ),
        "recoveredFlowMechanisms": aggregate_lists(
            row["mechanisms"]["recoveredFlowByMechanism"] for row in rows
        ),
        "scheduleLagMaxMs": max((int(row["schedule"]["lagMaxMs"] or 0) for row in rows), default=0),
        **stage_blocking_totals(rows),
        "selectedBehind": sum(int(row["quality"].get("selectedBehind") or 0) for row in rows),
        "tcpSlotPressureEvents": sum(
            int(row["runtime"].get("tcpSlotPressureEvents") or 0) for row in rows
        ),
        "flowRefreshChangedRuns": sum(1 for row in rows if row["flowRefresh"]["changed"]),
        "flowRefreshClassifications": aggregate_strings(
            row["flowRefresh"]["classification"] for row in rows
        ),
        **cascade_totals(rows),
    }


def gap_status(rows: list[dict[str, Any]]) -> str:
    classes = {row["classification"] for row in rows}
    if classes == {"clean"}:
        return "repeat-clean" if len(rows) > 1 else "single-clean"
    if classes == {"preflow-terminal-before-runtime-session"}:
        return "repeat-preflow-terminal" if len(rows) > 1 else "single-preflow-terminal"
    if "stage-pressure-with-schedule-lag" in classes:
        return "pressure-transition"
    if len(classes) > 1:
        return "mixed-surface"
    return next(iter(classes))


def round_gap_totals(rows: list[dict[str, Any]], by_gap: list[dict[str, Any]]) -> dict[str, Any]:
    clean_runs = sum(1 for row in rows if row["passed"])
    return {
        "runs": len(rows),
        "gapCount": len(by_gap),
        "cleanRuns": clean_runs,
        "failedRuns": len(rows) - clean_runs,
        "workloadAttempted": sum(int(row["workload"]["attempted"] or 0) for row in rows),
        "workloadSuccess": sum(int(row["workload"]["success"] or 0) for row in rows),
        "workloadFailure": sum(int(row["workload"]["failure"] or 0) for row in rows),
        "classifications": aggregate_strings(row["classification"] for row in rows),
        "terminalByReason": aggregate_lists(
            row["surfaces"]["runtimePacketTerminalByReason"] for row in rows
        ),
        "stageFailureBySurface": aggregate_lists(
            row["surfaces"]["stageFailureBySurface"] for row in rows
        ),
        "failedByPhase": aggregate_lists(row["surfaces"]["failedByPhase"] for row in rows),
        "failedByCleanupAction": aggregate_lists(
            row["surfaces"]["failedByCleanupAction"] for row in rows
        ),
        "failedByReplaySafe": aggregate_lists(
            row["surfaces"]["failedByReplaySafe"] for row in rows
        ),
        "failedByFailureStage": aggregate_lists(
            row["surfaces"]["failedByFailureStage"] for row in rows
        ),
        "stageFailureByDisposition": aggregate_lists(
            row["surfaces"]["stageFailureByDisposition"] for row in rows
        ),
        "workloadErrors": aggregate_lists(row["workload"]["errors"] for row in rows),
        "failedWorkloadMechanisms": aggregate_lists(
            row["mechanisms"]["failedWorkloadByMechanism"] for row in rows
        ),
        "recoveredFlowMechanisms": aggregate_lists(
            row["mechanisms"]["recoveredFlowByMechanism"] for row in rows
        ),
        "scheduleLagMaxMs": max((int(row["schedule"]["lagMaxMs"] or 0) for row in rows), default=0),
        **stage_blocking_totals(rows),
        "selectedBehind": sum(int(row["quality"].get("selectedBehind") or 0) for row in rows),
        "tcpSlotPressureEvents": sum(
            int(row["runtime"].get("tcpSlotPressureEvents") or 0) for row in rows
        ),
        "flowRefreshChangedRuns": sum(1 for row in rows if row["flowRefresh"]["changed"]),
        "flowRefreshClassifications": aggregate_strings(
            row["flowRefresh"]["classification"] for row in rows
        ),
        **cascade_totals(rows),
        "penaltySafe": False,
    }


def write_round_gap_summary(output_dir: Path, summary: dict[str, Any]) -> None:
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    write_round_gap_markdown(output_dir / "summary.md", summary)
