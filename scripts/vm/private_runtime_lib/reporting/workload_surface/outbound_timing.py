from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from common import Lab, validate_name
from private_runtime_lib.briefs import fields
from private_runtime_lib.tcp_flow import tcp_flow_brief, tcp_flow_rows


OUTBOUND_TIMING_SCHEMA = "dynet-vm-private-runtime-outbound-timing-surface/v1alpha1"
REPEAT_SCHEMA = "dynet-vm-private-runtime-repeat/v1alpha1"


def command_outbound_timing_surface(_lab: Lab, args: argparse.Namespace) -> None:
    label = validate_name(args.label or "outbound-timing-surface", "label")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = build_outbound_timing_summary(
        label,
        output_dir,
        [Path(item) for item in args.input],
    )
    write_outbound_timing_summary(output_dir, summary)
    print(json.dumps(outbound_timing_print(output_dir, summary), sort_keys=True))


def build_outbound_timing_summary(
    label: str,
    output_dir: Path,
    inputs: list[Path],
) -> dict[str, Any]:
    rows = [outbound_timing_row(path) for path in expand_inputs(inputs)]
    totals = outbound_timing_totals(rows)
    return {
        "schema": OUTBOUND_TIMING_SCHEMA,
        "label": label,
        "outputDir": str(output_dir),
        "runs": [public_row(row) for row in rows],
        "totals": totals,
        "conclusion": outbound_timing_conclusion(totals),
        "policy": {
            "plannerPenaltySafe": False,
            "qualityPenaltySafe": False,
            "reason": "Outbound timing is runtime shape evidence, not penalty proof.",
        },
    }


def expand_inputs(inputs: list[Path]) -> list[Path]:
    paths: list[Path] = []
    for path in inputs:
        summary = load_optional_json(path / "summary.json")
        if summary.get("schema") == REPEAT_SCHEMA:
            paths.extend(
                Path(row["path"])
                for row in summary.get("runs", [])
                if isinstance(row, dict) and row.get("path")
            )
        else:
            paths.append(path)
    return paths


def outbound_timing_row(run_dir: Path) -> dict[str, Any]:
    summary = load_optional_json(run_dir / "summary.json")
    report = load_optional_json(run_dir / "runtime-report.json")
    attempts = outbound_attempt_rows(report)
    cascades = cascade_attempt_rows(report)
    stages = outbound_stage_rows(report)
    flows = tcp_flow_rows(report) if report else []
    current = outbound_timing_counts(
        attempts,
        cascades,
        stages,
        flows,
        tcp_flow_brief(report),
    )
    clean = outbound_timing_clean(current)
    return {
        "label": summary.get("label") or run_dir.name,
        "path": str(run_dir),
        "classification": "clean" if clean else outbound_timing_classification(current),
        "clean": clean,
        "current": current,
        "_attempts": attempts,
        "_cascades": cascades,
        "_stages": stages,
    }


def outbound_attempt_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for event in report.get("events", []):
        if not isinstance(event, dict) or event.get("kind") != "outbound-attempt-finished":
            continue
        event_fields = fields(event)
        flow_id = event_fields.get("flowId")
        if not flow_id or not flow_id.startswith("tcp-session-"):
            continue
        rows.append({
            "flowId": flow_id,
            "status": event_fields.get("status") or "unknown",
            "protocol": event_fields.get("kind") or event_fields.get("protocol") or "unknown",
            "elapsedMs": optional_int(event_fields.get("elapsedMs")),
        })
    return rows


def cascade_attempt_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for event in report.get("events", []):
        if not isinstance(event, dict):
            continue
        if event.get("kind") != "dialer-cascade-attempt-finished":
            continue
        event_fields = fields(event)
        flow_id = event_fields.get("flowId")
        if not flow_id or not flow_id.startswith("tcp-session-"):
            continue
        rows.append({
            "flowId": flow_id,
            "status": event_fields.get("status") or "unknown",
            "failureScope": event_fields.get("failureScope") or "none",
            "elapsedMs": optional_int(event_fields.get("elapsedMs")),
        })
    return rows


def outbound_stage_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for event in report.get("events", []):
        if not isinstance(event, dict) or event.get("kind") != "outbound-stage-finished":
            continue
        event_fields = fields(event)
        flow_id = event_fields.get("flowId")
        if not flow_id or not flow_id.startswith("tcp-session-"):
            continue
        rows.append({
            "flowId": flow_id,
            "stage": event_fields.get("stage") or "unknown",
            "kind": event_fields.get("kind") or "unknown",
            "status": event_fields.get("status") or "unknown",
            "disposition": event_fields.get("errorDisposition") or "none",
            "elapsedMs": optional_int(event_fields.get("elapsedMs")),
        })
    return rows


def outbound_timing_counts(
    attempts: list[dict[str, Any]],
    cascades: list[dict[str, Any]],
    stages: list[dict[str, Any]],
    flows: list[dict[str, Any]],
    flow_brief: dict[str, Any],
) -> dict[str, Any]:
    failed_flow_ids = failure_flow_ids(attempts, cascades, stages)
    recovered = {
        str(row["flowId"])
        for row in flows
        if row.get("flowId") in failed_flow_ids and flow_recovered(row)
    }
    success_attempts = [row for row in attempts if row["status"] == "success"]
    success_cascades = [row for row in cascades if row["status"] == "success"]
    success_stages = [row for row in stages if row["status"] == "success"]
    failed_stages = [row for row in stages if row["status"] == "failed"]
    return {
        "flows": int(flow_brief.get("flows") or 0),
        "attemptEvents": len(attempts),
        "successfulAttemptEvents": len(success_attempts),
        "failedAttemptEvents": count_status(attempts, "failed"),
        "attemptFlows": count_flows(attempts),
        "successfulAttemptFlows": count_flows(success_attempts),
        "cascadeEvents": len(cascades),
        "successfulCascadeEvents": len(success_cascades),
        "failedCascadeEvents": count_status(cascades, "failed"),
        "cascadeFlows": count_flows(cascades),
        "successfulCascadeFlows": count_flows(success_cascades),
        "stageEvents": len(stages),
        "successStageEvents": len(success_stages),
        "failedStageEvents": len(failed_stages),
        "stageFlows": count_flows(stages),
        "failureFlows": len(failed_flow_ids),
        "recoveredFailureFlows": len(recovered),
        "unrecoveredFailureFlows": len(failed_flow_ids - recovered),
        "pathCompleteFlows": int(flow_brief.get("pathCompleteFlows") or 0),
        "lifecycleCompleteFlows": int(flow_brief.get("lifecycleCompleteFlows") or 0),
        "payloadBidirectionalFlows": int(flow_brief.get("payloadBidirectionalFlows") or 0),
        "failedFlows": int(flow_brief.get("failedFlows") or 0),
        "failedByCascadeScope": aggregate(cascades, "failureScope", status="failed"),
        "failedAttemptByProtocol": aggregate(attempts, "protocol", status="failed"),
        "failedStageBySurface": aggregate_stage_surface(failed_stages),
        "failedStageByDisposition": aggregate(failed_stages, "disposition"),
        "timings": timing_groups(attempts, cascades, stages),
    }


def failure_flow_ids(
    attempts: list[dict[str, Any]],
    cascades: list[dict[str, Any]],
    stages: list[dict[str, Any]],
) -> set[str]:
    return {
        str(row["flowId"])
        for row in [*attempts, *cascades, *stages]
        if row.get("status") == "failed" and row.get("flowId")
    }


def flow_recovered(row: dict[str, Any]) -> bool:
    return (
        not row.get("failed")
        and bool(row.get("established"))
        and bool(row.get("closed"))
        and int(row.get("firstWriteBytes") or 0) > 0
        and int(row.get("receivedBytes") or 0) > 0
    )


def outbound_timing_clean(counts: dict[str, Any]) -> bool:
    flows = int(counts["flows"])
    return (
        flows > 0
        and counts["attemptFlows"] == flows
        and counts["successfulAttemptFlows"] == flows
        and counts["cascadeFlows"] == flows
        and counts["successfulCascadeFlows"] == flows
        and counts["stageFlows"] == flows
        and counts["stageEvents"] > 0
        and counts["successStageEvents"] > 0
        and counts["unrecoveredFailureFlows"] == 0
        and counts["failedFlows"] == 0
        and counts["pathCompleteFlows"] == flows
        and counts["lifecycleCompleteFlows"] == flows
        and counts["payloadBidirectionalFlows"] == flows
    )


def outbound_timing_classification(counts: dict[str, Any]) -> str:
    if int(counts["failedFlows"]):
        return "flow-failure"
    if int(counts["unrecoveredFailureFlows"]):
        return "unrecovered-outbound-failure"
    if int(counts["successfulCascadeFlows"]) < int(counts["flows"]):
        return "cascade-success-missing"
    if int(counts["successfulAttemptFlows"]) < int(counts["flows"]):
        return "attempt-success-missing"
    if int(counts["stageFlows"]) < int(counts["flows"]):
        return "stage-timing-missing"
    return "outbound-timing-incomplete"


def outbound_timing_totals(rows: list[dict[str, Any]]) -> dict[str, Any]:
    current_rows = [row["current"] for row in rows]
    attempts = [attempt for row in rows for attempt in row["_attempts"]]
    cascades = [cascade for row in rows for cascade in row["_cascades"]]
    stages = [stage for row in rows for stage in row["_stages"]]
    return {
        "runs": len(rows),
        "cleanRuns": sum(1 for row in rows if row["clean"]),
        "failedRuns": sum(1 for row in rows if not row["clean"]),
        "classifications": aggregate_values(row["classification"] for row in rows),
        **numeric_totals(current_rows),
        "failedByCascadeScope": merge_count_rows(
            row["failedByCascadeScope"] for row in current_rows
        ),
        "failedAttemptByProtocol": merge_count_rows(
            row["failedAttemptByProtocol"] for row in current_rows
        ),
        "failedStageBySurface": merge_count_rows(
            row["failedStageBySurface"] for row in current_rows
        ),
        "failedStageByDisposition": merge_count_rows(
            row["failedStageByDisposition"] for row in current_rows
        ),
        "timings": timing_groups(attempts, cascades, stages),
    }


def numeric_totals(rows: list[dict[str, Any]]) -> dict[str, int]:
    keys = [
        "flows",
        "attemptEvents",
        "successfulAttemptEvents",
        "failedAttemptEvents",
        "attemptFlows",
        "successfulAttemptFlows",
        "cascadeEvents",
        "successfulCascadeEvents",
        "failedCascadeEvents",
        "cascadeFlows",
        "successfulCascadeFlows",
        "stageEvents",
        "successStageEvents",
        "failedStageEvents",
        "stageFlows",
        "failureFlows",
        "recoveredFailureFlows",
        "unrecoveredFailureFlows",
        "pathCompleteFlows",
        "lifecycleCompleteFlows",
        "payloadBidirectionalFlows",
        "failedFlows",
    ]
    return {key: sum(int(row.get(key) or 0) for row in rows) for key in keys}


def outbound_timing_conclusion(totals: dict[str, Any]) -> dict[str, Any]:
    clean = totals["runs"] > 0 and totals["failedRuns"] == 0
    return {
        "status": "clean" if clean else "outbound-timing-surface-needs-evidence",
        "nextAction": (
            "return-to-runtime-surface"
            if clean
            else "inspect-outbound-attempt-cascade-and-stage-timing"
        ),
        "plannerPenaltySafe": False,
        "qualityPenaltySafe": False,
    }


def public_row(row: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in row.items() if not key.startswith("_")}


def timing_groups(
    attempts: list[dict[str, Any]],
    cascades: list[dict[str, Any]],
    stages: list[dict[str, Any]],
) -> dict[str, dict[str, int]]:
    success_attempts = [row for row in attempts if row["status"] == "success"]
    success_cascades = [row for row in cascades if row["status"] == "success"]
    success_stages = [row for row in stages if row["status"] == "success"]
    failed_stages = [row for row in stages if row["status"] == "failed"]
    return {
        "attemptElapsedMs": timing_stats(elapsed_values(attempts)),
        "successfulAttemptElapsedMs": timing_stats(elapsed_values(success_attempts)),
        "cascadeElapsedMs": timing_stats(elapsed_values(cascades)),
        "successfulCascadeElapsedMs": timing_stats(elapsed_values(success_cascades)),
        "stageElapsedMs": timing_stats(elapsed_values(stages)),
        "successfulStageElapsedMs": timing_stats(elapsed_values(success_stages)),
        "failedStageElapsedMs": timing_stats(elapsed_values(failed_stages)),
    }


def elapsed_values(rows: list[dict[str, Any]]) -> list[int]:
    return [
        int(row["elapsedMs"])
        for row in rows
        if isinstance(row.get("elapsedMs"), int) and int(row["elapsedMs"]) >= 0
    ]


def timing_stats(values: list[int]) -> dict[str, int]:
    clean_values = sorted(value for value in values if value >= 0)
    if not clean_values:
        return {"count": 0, "min": 0, "avg": 0, "p95": 0, "max": 0}
    return {
        "count": len(clean_values),
        "min": clean_values[0],
        "avg": sum(clean_values) // len(clean_values),
        "p95": percentile(clean_values, 95),
        "max": clean_values[-1],
    }


def percentile(values: list[int], percent: int) -> int:
    index = min(len(values) - 1, max(0, (len(values) * percent + 99) // 100 - 1))
    return values[index]


def count_status(rows: list[dict[str, Any]], status: str) -> int:
    return sum(1 for row in rows if row.get("status") == status)


def count_flows(rows: list[dict[str, Any]]) -> int:
    return len({str(row["flowId"]) for row in rows if row.get("flowId")})


def aggregate(
    rows: list[dict[str, Any]],
    field: str,
    *,
    status: str | None = None,
) -> list[dict[str, Any]]:
    return aggregate_values(
        str(row.get(field) or "unknown")
        for row in rows
        if status is None or row.get("status") == status
    )


def aggregate_stage_surface(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return aggregate_values(
        f"{row.get('stage') or 'unknown'}:{row.get('kind') or 'unknown'}"
        for row in rows
    )


def aggregate_values(values: Any) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for value in values:
        key = str(value or "unknown")
        counts[key] = counts.get(key, 0) + 1
    return [{"key": key, "count": counts[key]} for key in sorted(counts)]


def merge_count_rows(row_sets: Any) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for rows in row_sets:
        for row in rows:
            key = str(row.get("key") or "")
            if key:
                counts[key] = counts.get(key, 0) + int(row.get("count") or 0)
    return [{"key": key, "count": counts[key]} for key in sorted(counts)]


def optional_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def write_outbound_timing_summary(output_dir: Path, summary: dict[str, Any]) -> None:
    (output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n"
    )
    write_outbound_timing_markdown(output_dir / "summary.md", summary)


def write_outbound_timing_markdown(path: Path, summary: dict[str, Any]) -> None:
    totals = summary["totals"]
    lines = [
        "# VM Private Runtime Outbound Timing Surface",
        "",
        f"- label: `{summary['label']}`",
        f"- status: `{summary['conclusion']['status']}`",
        f"- runs: `{totals['runs']}`",
        f"- clean runs: `{totals['cleanRuns']}`",
        f"- flows: `{totals['flows']}`",
        f"- attempt events: `{totals['attemptEvents']}`",
        f"- cascade events: `{totals['cascadeEvents']}`",
        f"- failed attempts: `{totals['failedAttemptEvents']}`",
        f"- failed cascades: `{totals['failedCascadeEvents']}`",
        f"- unrecovered failure flows: `{totals['unrecoveredFailureFlows']}`",
        f"- cascade success p95 ms: `{totals['timings']['successfulCascadeElapsedMs']['p95']}`",
        "",
        "## Runs",
        "",
    ]
    for row in summary["runs"]:
        lines.append(
            f"- `{row['label']}` classification=`{row['classification']}` "
            f"clean=`{row['clean']}`"
        )
    path.write_text("\n".join(lines) + "\n")


def outbound_timing_print(output_dir: Path, summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "outputDir": str(output_dir),
        "runs": summary["totals"]["runs"],
        "cleanRuns": summary["totals"]["cleanRuns"],
        "status": summary["conclusion"]["status"],
    }


def load_optional_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open() as fh:
        value = json.load(fh)
    return value if isinstance(value, dict) else {}
