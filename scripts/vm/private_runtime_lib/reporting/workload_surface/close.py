from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from common import Lab, validate_name
from private_runtime_lib.tcp_flow import tcp_flow_brief


CLOSE_SURFACE_SCHEMA = "dynet-vm-private-runtime-close-surface/v1alpha1"
REPEAT_SCHEMA = "dynet-vm-private-runtime-repeat/v1alpha1"
CLOSE_KEYS = [
    "flows",
    "startedFlows",
    "establishedFlows",
    "closedFlows",
    "failedFlows",
    "lifecycleCompleteFlows",
    "pathCompleteFlows",
    "closedWithByteTotals",
    "payloadBidirectionalFlows",
    "payloadCloseConsistent",
    "closedWithoutPayloadFlows",
    "duplicateClosedFlows",
    "failedAfterUpstreamOnly",
    "failedAfterPathComplete",
]


def command_close_surface(_lab: Lab, args: argparse.Namespace) -> None:
    label = validate_name(args.label or "close-surface", "label")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = build_close_surface_summary(
        label,
        output_dir,
        [Path(item) for item in args.input],
    )
    write_close_surface_summary(output_dir, summary)
    print(json.dumps(close_print(output_dir, summary), sort_keys=True))


def build_close_surface_summary(
    label: str,
    output_dir: Path,
    inputs: list[Path],
) -> dict[str, Any]:
    rows = [close_surface_row(path) for path in expand_inputs(inputs)]
    totals = close_surface_totals(rows)
    return {
        "schema": CLOSE_SURFACE_SCHEMA,
        "label": label,
        "outputDir": str(output_dir),
        "runs": rows,
        "totals": totals,
        "conclusion": close_surface_conclusion(totals),
        "policy": {
            "plannerPenaltySafe": False,
            "qualityPenaltySafe": False,
            "reason": "Close surface is terminal execution evidence, not penalty proof.",
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


def close_surface_row(run_dir: Path) -> dict[str, Any]:
    summary = load_optional_json(run_dir / "summary.json")
    runtime_path = run_dir / "runtime-report.json"
    current = close_counts(
        tcp_flow_brief(load_json(runtime_path))
        if runtime_path.exists()
        else summary.get("tcpFlow", {})
    )
    clean = close_counts_clean(current)
    return {
        "label": summary.get("label") or run_dir.name,
        "path": str(run_dir),
        "classification": "clean" if clean else close_classification(current),
        "clean": clean,
        "current": current,
    }


def close_counts(tcp_flow: dict[str, Any]) -> dict[str, Any]:
    closed_by_reason = count_rows(tcp_flow.get("closedByReason"))
    failed_by_surface = count_rows(tcp_flow.get("failedBySurface"))
    counts = {key: int(tcp_flow.get(key) or 0) for key in CLOSE_KEYS}
    terminal_events = counts["closedFlows"] + counts["failedFlows"]
    return {
        **counts,
        "terminalEvents": terminal_events,
        "closedReasonFlows": sum(int(row["count"]) for row in closed_by_reason),
        "closedByReason": closed_by_reason,
        "failedBySurface": failed_by_surface,
    }


def close_counts_clean(counts: dict[str, Any]) -> bool:
    flows = int(counts["flows"])
    return (
        flows > 0
        and counts["startedFlows"] == flows
        and counts["establishedFlows"] == flows
        and counts["closedFlows"] == flows
        and counts["terminalEvents"] == flows
        and counts["closedReasonFlows"] == flows
        and counts["closedWithByteTotals"] == flows
        and counts["payloadBidirectionalFlows"] == flows
        and counts["payloadCloseConsistent"] == flows
        and counts["lifecycleCompleteFlows"] == flows
        and counts["pathCompleteFlows"] == flows
        and counts["closedWithoutPayloadFlows"] == 0
        and counts["duplicateClosedFlows"] == 0
        and counts["failedFlows"] == 0
    )


def close_classification(counts: dict[str, Any]) -> str:
    if int(counts["failedFlows"]):
        return "flow-failure"
    if int(counts["duplicateClosedFlows"]):
        return "duplicate-close"
    if int(counts["closedReasonFlows"]) < int(counts["closedFlows"]):
        return "close-reason-missing"
    if int(counts["payloadCloseConsistent"]) < int(counts["closedFlows"]):
        return "payload-close-inconsistent"
    if int(counts["terminalEvents"]) < int(counts["flows"]):
        return "terminal-incomplete"
    return "close-surface-incomplete"


def close_surface_totals(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "runs": len(rows),
        "cleanRuns": sum(1 for row in rows if row["clean"]),
        "failedRuns": sum(1 for row in rows if not row["clean"]),
        "classifications": aggregate(row["classification"] for row in rows),
        **{
            key: sum(int(row["current"].get(key) or 0) for row in rows)
            for key in [*CLOSE_KEYS, "terminalEvents", "closedReasonFlows"]
        },
        "closedByReason": merge_count_rows(
            row["current"]["closedByReason"] for row in rows
        ),
        "failedBySurface": merge_count_rows(
            row["current"]["failedBySurface"] for row in rows
        ),
    }


def close_surface_conclusion(totals: dict[str, Any]) -> dict[str, Any]:
    clean = totals["runs"] > 0 and totals["failedRuns"] == 0
    return {
        "status": "clean" if clean else "close-surface-needs-evidence",
        "nextAction": (
            "return-to-runtime-surface"
            if clean
            else "inspect-terminal-close-reason-and-byte-accounting"
        ),
        "plannerPenaltySafe": False,
        "qualityPenaltySafe": False,
    }


def write_close_surface_summary(output_dir: Path, summary: dict[str, Any]) -> None:
    (output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n"
    )
    write_close_markdown(output_dir / "summary.md", summary)


def write_close_markdown(path: Path, summary: dict[str, Any]) -> None:
    totals = summary["totals"]
    lines = [
        "# VM Private Runtime Close Surface",
        "",
        f"- label: `{summary['label']}`",
        f"- status: `{summary['conclusion']['status']}`",
        f"- runs: `{totals['runs']}`",
        f"- clean runs: `{totals['cleanRuns']}`",
        f"- flows: `{totals['flows']}`",
        f"- terminal events: `{totals['terminalEvents']}`",
        f"- closed with reason: `{totals['closedReasonFlows']}`",
        f"- duplicate closes: `{totals['duplicateClosedFlows']}`",
        f"- failed flows: `{totals['failedFlows']}`",
        f"- closed by reason: `{totals['closedByReason']}`",
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


def close_print(output_dir: Path, summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "outputDir": str(output_dir),
        "runs": summary["totals"]["runs"],
        "cleanRuns": summary["totals"]["cleanRuns"],
        "status": summary["conclusion"]["status"],
    }


def count_rows(rows: Any) -> list[dict[str, Any]]:
    return [
        {"key": str(row.get("key") or "unknown"), "count": int(row.get("count") or 0)}
        for row in rows or []
        if isinstance(row, dict)
    ]


def merge_count_rows(row_sets: Any) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for rows in row_sets:
        for row in rows:
            key = str(row.get("key") or "")
            if key:
                counts[key] = counts.get(key, 0) + int(row.get("count") or 0)
    return [{"key": key, "count": counts[key]} for key in sorted(counts)]


def aggregate(values: Any) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for value in values:
        key = str(value or "unknown")
        counts[key] = counts.get(key, 0) + 1
    return [{"key": key, "count": counts[key]} for key in sorted(counts)]


def load_json(path: Path) -> dict[str, Any]:
    with path.open() as fh:
        value = json.load(fh)
    return value if isinstance(value, dict) else {}


def load_optional_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return load_json(path)
