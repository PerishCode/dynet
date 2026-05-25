from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from private_runtime_lib.reporting.pressure.events import int_value


def pressure_run_row(
    run: dict[str, Any],
    stage_rows: list[dict[str, Any]],
    slot_rows: list[dict[str, Any]],
    slow_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    summary = run_level_summary(run)
    runtime = runtime_report(run)
    workload = summary.get("workloadProbe", {}).get("totals", {})
    workload_attempted = int_value(workload.get("count")) or (
        int_value(workload.get("success")) + int_value(workload.get("failure"))
    )
    tcp_flow = summary.get("tcpFlow") or {}
    row = {
        "label": run["label"],
        "source": run["source"],
        "path": str(run["path"]),
        "productSurfaceClean": run_product_surface_clean(summary),
        "workloadAttempted": workload_attempted,
        "workloadSuccess": int_value(workload.get("success")),
        "workloadFailure": int_value(workload.get("failure")),
        "tcpFlowFailed": int_value(tcp_flow.get("failedFlows")),
        "tcpFlowPathComplete": int_value(tcp_flow.get("pathCompleteFlows")),
        "tcpFlowPayloadBidirectional": int_value(tcp_flow.get("payloadBidirectionalFlows")),
        "stageFailures": len(stage_rows),
        "stageRecoveredFailures": sum(1 for item in stage_rows if item["recovered"]),
        "stageUnrecoveredFailures": sum(1 for item in stage_rows if not item["recovered"]),
        "slotPressureEvents": sum(int(item["events"]) for item in slot_rows),
        "slowStageEvents": sum(int(item["events"]) for item in slow_rows),
        "slowFailedStageEvents": sum(
            int(item["events"]) for item in slow_rows if ":failed:" in item["surface"]
        ),
        "slowStageMaxMs": max((int(item["elapsedMs"]) for item in slow_rows), default=0),
        "tcpActiveSlotsMax": int_value(runtime.get("tcpActiveSlotsMax")),
        "tcpListenCapacity": int_value(runtime.get("tcpListenCapacity")),
        "tcpListenSlotsPerPort": int_value(runtime.get("tcpListenSlotsPerPort")),
    }
    row["classification"] = run_pressure_classification(row)
    return row


def run_level_summary(run: dict[str, Any]) -> dict[str, Any]:
    summary_path = Path(run["path"]) / "summary.json"
    if summary_path.exists():
        return load_json(summary_path)
    return run["summary"]


def runtime_report(run: dict[str, Any]) -> dict[str, Any]:
    report_path = Path(run["path"]) / "runtime-report.json"
    if report_path.exists():
        return load_json(report_path)
    return {}


def run_product_surface_clean(summary: dict[str, Any]) -> bool:
    workload = summary.get("workloadProbe", {}).get("totals", {})
    tcp_flow = summary.get("tcpFlow") or {}
    workload_attempted = int_value(workload.get("count")) or (
        int_value(workload.get("success")) + int_value(workload.get("failure"))
    )
    return (
        all_checks_passed(summary)
        and workload_attempted > 0
        and int_value(workload.get("success")) == workload_attempted
        and int_value(workload.get("failure")) == 0
        and int_value(tcp_flow.get("failedFlows")) == 0
        and int_value(tcp_flow.get("pathCompleteFlows")) >= workload_attempted
        and int_value(tcp_flow.get("payloadBidirectionalFlows")) >= workload_attempted
    )


def run_pressure_classification(row: dict[str, Any]) -> str:
    if not row["productSurfaceClean"] or row["stageUnrecoveredFailures"]:
        return "needs-runtime-pressure-classification"
    stage = int(row["stageFailures"]) > 0 or int(row["slowFailedStageEvents"]) > 0
    slot = int(row["slotPressureEvents"]) > 0
    slow = int(row["slowStageEvents"]) > 0
    if stage and slot:
        return "product-clean-stage-and-slot-pressure"
    if stage:
        return "product-clean-handshake-wait-budget-pressure"
    if slot:
        return "product-clean-slot-admission-pressure"
    if slow:
        return "product-clean-slow-stage-pressure"
    return "product-clean-no-pressure"


def all_checks_passed(summary: dict[str, Any]) -> bool:
    checks = summary.get("checks")
    if isinstance(summary.get("passed"), bool):
        return bool(summary["passed"])
    if not isinstance(checks, list):
        return False
    return all(bool(item.get("passed")) for item in checks if isinstance(item, dict))


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())
