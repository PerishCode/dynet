from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

from common import Lab, validate_name
from private_runtime_lib.briefs import fields
from private_runtime_lib.tcp_flow import tcp_flow_brief, tcp_flow_rows


STAGE_SURFACE_SCHEMA = "dynet-vm-private-runtime-stage-surface/v1alpha1"
REPEAT_SCHEMA = "dynet-vm-private-runtime-repeat/v1alpha1"


def command_stage_surface(_lab: Lab, args: argparse.Namespace) -> None:
    label = validate_name(args.label or "stage-surface", "label")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = build_stage_surface_summary(
        label,
        output_dir,
        [Path(item) for item in args.input],
    )
    write_stage_surface_summary(output_dir, summary)
    print(json.dumps(stage_print(output_dir, summary), sort_keys=True))


def build_stage_surface_summary(
    label: str,
    output_dir: Path,
    inputs: list[Path],
) -> dict[str, Any]:
    rows = [stage_surface_row(path) for path in expand_inputs(inputs)]
    totals = stage_surface_totals(rows)
    return {
        "schema": STAGE_SURFACE_SCHEMA,
        "label": label,
        "outputDir": str(output_dir),
        "runs": rows,
        "totals": totals,
        "conclusion": stage_surface_conclusion(totals),
        "policy": {
            "plannerPenaltySafe": False,
            "qualityPenaltySafe": False,
            "reason": "Stage surface is execution evidence, not penalty proof.",
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


def stage_surface_row(run_dir: Path) -> dict[str, Any]:
    summary = load_optional_json(run_dir / "summary.json")
    report = load_optional_json(run_dir / "runtime-report.json")
    stage_rows = outbound_stage_rows(report)
    flow_rows = tcp_flow_rows(report) if report else []
    current = stage_counts(stage_rows, flow_rows, tcp_flow_brief(report))
    clean = stage_counts_clean(current)
    return {
        "label": summary.get("label") or run_dir.name,
        "path": str(run_dir),
        "classification": "clean" if clean else stage_classification(current),
        "clean": clean,
        "current": current,
    }


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
            "kind": event_fields.get("kind") or "unknown",
            "stage": event_fields.get("stage") or "unknown",
            "status": event_fields.get("status") or "unknown",
            "disposition": event_fields.get("errorDisposition") or "none",
        })
    return rows


def stage_counts(
    stage_rows: list[dict[str, Any]],
    flow_rows: list[dict[str, Any]],
    flow_brief: dict[str, Any],
) -> dict[str, Any]:
    failed_flow_ids = {
        str(row["flowId"])
        for row in stage_rows
        if row["status"] == "failed" and row.get("flowId")
    }
    recovered = {
        str(row["flowId"])
        for row in flow_rows
        if row.get("flowId") in failed_flow_ids and flow_recovered(row)
    }
    stage_flow_ids = {str(row["flowId"]) for row in stage_rows if row.get("flowId")}
    failed_rows = [row for row in stage_rows if row["status"] == "failed"]
    success_rows = [row for row in stage_rows if row["status"] == "success"]
    return {
        "flows": int(flow_brief.get("flows") or 0),
        "stageFlows": len(stage_flow_ids),
        "stageEvents": len(stage_rows),
        "successStageEvents": len(success_rows),
        "failedStageEvents": len(failed_rows),
        "stageFailedFlows": len(failed_flow_ids),
        "recoveredStageFailedFlows": len(recovered),
        "unrecoveredStageFailedFlows": len(failed_flow_ids - recovered),
        "pathCompleteFlows": int(flow_brief.get("pathCompleteFlows") or 0),
        "lifecycleCompleteFlows": int(flow_brief.get("lifecycleCompleteFlows") or 0),
        "payloadBidirectionalFlows": int(flow_brief.get("payloadBidirectionalFlows") or 0),
        "failedFlows": int(flow_brief.get("failedFlows") or 0),
        "byStage": aggregate(stage_rows, "stage"),
        "byKind": aggregate(stage_rows, "kind"),
        "successBySurface": aggregate_surface(success_rows),
        "failedBySurface": aggregate_surface(failed_rows),
        "failedByDisposition": aggregate(failed_rows, "disposition"),
    }


def flow_recovered(row: dict[str, Any]) -> bool:
    return (
        not row.get("failed")
        and bool(row.get("established"))
        and bool(row.get("closed"))
        and int(row.get("firstWriteBytes") or 0) > 0
        and int(row.get("receivedBytes") or 0) > 0
    )


def stage_counts_clean(counts: dict[str, Any]) -> bool:
    flows = int(counts["flows"])
    return (
        flows > 0
        and int(counts["stageFlows"]) == flows
        and int(counts["stageEvents"]) > 0
        and int(counts["successStageEvents"]) > 0
        and int(counts["unrecoveredStageFailedFlows"]) == 0
        and int(counts["failedFlows"]) == 0
        and int(counts["pathCompleteFlows"]) == flows
        and int(counts["lifecycleCompleteFlows"]) == flows
        and int(counts["payloadBidirectionalFlows"]) == flows
    )


def stage_classification(counts: dict[str, Any]) -> str:
    if int(counts["failedFlows"]):
        return "flow-failure"
    if int(counts["unrecoveredStageFailedFlows"]):
        return "unrecovered-stage-failure"
    if int(counts["stageFlows"]) < int(counts["flows"]):
        return "stage-incomplete"
    return "stage-surface-incomplete"


def stage_surface_totals(rows: list[dict[str, Any]]) -> dict[str, Any]:
    numeric = [
        "flows",
        "stageFlows",
        "stageEvents",
        "successStageEvents",
        "failedStageEvents",
        "stageFailedFlows",
        "recoveredStageFailedFlows",
        "unrecoveredStageFailedFlows",
        "pathCompleteFlows",
        "lifecycleCompleteFlows",
        "payloadBidirectionalFlows",
        "failedFlows",
    ]
    return {
        "runs": len(rows),
        "cleanRuns": sum(1 for row in rows if row["clean"]),
        "failedRuns": sum(1 for row in rows if not row["clean"]),
        "classifications": aggregate_values(row["classification"] for row in rows),
        **{
            key: sum(int(row["current"].get(key) or 0) for row in rows)
            for key in numeric
        },
        "byStage": merge_count_rows(row["current"]["byStage"] for row in rows),
        "byKind": merge_count_rows(row["current"]["byKind"] for row in rows),
        "failedBySurface": merge_count_rows(
            row["current"]["failedBySurface"] for row in rows
        ),
        "failedByDisposition": merge_count_rows(
            row["current"]["failedByDisposition"] for row in rows
        ),
    }


def stage_surface_conclusion(totals: dict[str, Any]) -> dict[str, Any]:
    clean = totals["runs"] > 0 and totals["failedRuns"] == 0
    return {
        "status": "clean" if clean else "stage-surface-needs-evidence",
        "nextAction": (
            "return-to-runtime-surface"
            if clean
            else "inspect-stage-failure-recovery-and-flow-completion"
        ),
        "plannerPenaltySafe": False,
        "qualityPenaltySafe": False,
    }


def write_stage_surface_summary(output_dir: Path, summary: dict[str, Any]) -> None:
    (output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n"
    )
    write_stage_markdown(output_dir / "summary.md", summary)


def write_stage_markdown(path: Path, summary: dict[str, Any]) -> None:
    totals = summary["totals"]
    lines = [
        "# VM Private Runtime Stage Surface",
        "",
        f"- label: `{summary['label']}`",
        f"- status: `{summary['conclusion']['status']}`",
        f"- runs: `{totals['runs']}`",
        f"- clean runs: `{totals['cleanRuns']}`",
        f"- flows: `{totals['flows']}`",
        f"- stage events: `{totals['stageEvents']}`",
        f"- failed stage events: `{totals['failedStageEvents']}`",
        f"- recovered stage failed flows: `{totals['recoveredStageFailedFlows']}`",
        f"- unrecovered stage failed flows: `{totals['unrecoveredStageFailedFlows']}`",
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


def stage_print(output_dir: Path, summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "outputDir": str(output_dir),
        "runs": summary["totals"]["runs"],
        "cleanRuns": summary["totals"]["cleanRuns"],
        "status": summary["conclusion"]["status"],
    }


def aggregate(rows: list[dict[str, Any]], field: str) -> list[dict[str, Any]]:
    return aggregate_values(str(row.get(field) or "unknown") for row in rows)


def aggregate_surface(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return aggregate_values(
        f"{row.get('stage') or 'unknown'}:{row.get('kind') or 'unknown'}"
        for row in rows
    )


def aggregate_values(values: Any) -> list[dict[str, Any]]:
    counts: Counter[str] = Counter(str(value or "unknown") for value in values)
    return [{"key": key, "count": counts[key]} for key in sorted(counts)]


def merge_count_rows(row_sets: Any) -> list[dict[str, Any]]:
    counts: Counter[str] = Counter()
    for rows in row_sets:
        for row in rows:
            key = str(row.get("key") or "")
            if key:
                counts[key] += int(row.get("count") or 0)
    return [{"key": key, "count": counts[key]} for key in sorted(counts)]


def load_json(path: Path) -> dict[str, Any]:
    with path.open() as fh:
        value = json.load(fh)
    return value if isinstance(value, dict) else {}


def load_optional_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return load_json(path)
