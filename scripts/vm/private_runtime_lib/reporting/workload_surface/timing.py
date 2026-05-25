from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from common import Lab, validate_name
from private_runtime_lib.briefs import fields


TIMING_SURFACE_SCHEMA = "dynet-vm-private-runtime-timing-surface/v1alpha1"
REPEAT_SCHEMA = "dynet-vm-private-runtime-repeat/v1alpha1"
TIMING_MARKS = {
    "tcp-session-started": "startedMs",
    "tcp-session-attributed": "attributedMs",
    "tcp-session-outbound-connecting": "connectingMs",
    "tcp-session-established": "establishedMs",
    "tcp-session-payload-first-write": "firstPayloadMs",
    "tcp-session-payload-received": "firstDownstreamMs",
    "tcp-session-closed": "closedMs",
    "tcp-session-failed": "failedMs",
}
DELTA_KEYS = [
    "attributedMs",
    "connectingMs",
    "establishedMs",
    "firstPayloadMs",
    "firstDownstreamMs",
    "closedMs",
]
COUNT_KEYS = [
    "flows",
    "startedFlows",
    "attributedFlows",
    "connectingFlows",
    "establishedFlows",
    "firstPayloadFlows",
    "firstDownstreamFlows",
    "closedFlows",
    "failedFlows",
    "orderedFlows",
]


def command_timing_surface(_lab: Lab, args: argparse.Namespace) -> None:
    label = validate_name(args.label or "timing-surface", "label")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = build_timing_surface_summary(
        label,
        output_dir,
        [Path(item) for item in args.input],
    )
    write_timing_surface_summary(output_dir, summary)
    print(json.dumps(timing_print(output_dir, summary), sort_keys=True))


def build_timing_surface_summary(
    label: str,
    output_dir: Path,
    inputs: list[Path],
) -> dict[str, Any]:
    rows = [timing_surface_row(path) for path in expand_inputs(inputs)]
    totals = timing_surface_totals(rows)
    return {
        "schema": TIMING_SURFACE_SCHEMA,
        "label": label,
        "outputDir": str(output_dir),
        "runs": [public_timing_row(row) for row in rows],
        "totals": totals,
        "conclusion": timing_surface_conclusion(totals),
        "policy": {
            "plannerPenaltySafe": False,
            "qualityPenaltySafe": False,
            "reason": "Timing surface is runtime shape evidence, not penalty proof.",
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


def timing_surface_row(run_dir: Path) -> dict[str, Any]:
    summary = load_optional_json(run_dir / "summary.json")
    report = load_optional_json(run_dir / "runtime-report.json")
    mark_rows = timing_rows(report)
    delta_rows = [timing_deltas(row) for row in mark_rows]
    current = timing_counts(mark_rows, delta_rows)
    clean = timing_counts_clean(current)
    return {
        "label": summary.get("label") or run_dir.name,
        "path": str(run_dir),
        "classification": "clean" if clean else timing_classification(current),
        "clean": clean,
        "current": current,
        "_deltas": delta_rows,
    }


def public_timing_row(row: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in row.items() if not key.startswith("_")}


def timing_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for event in report.get("events", []):
        if not isinstance(event, dict):
            continue
        mark = TIMING_MARKS.get(str(event.get("kind")))
        if not mark or not isinstance(event.get("emittedAtUnixMs"), int):
            continue
        event_fields = fields(event)
        flow_id = event_fields.get("flowId")
        if not flow_id or not flow_id.startswith("tcp-session-"):
            continue
        row = rows.setdefault(flow_id, {"flowId": flow_id})
        row[mark] = min_optional(row.get(mark), int(event["emittedAtUnixMs"]))
    return list(rows.values())


def timing_counts(
    rows: list[dict[str, Any]],
    deltas: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "flows": len(rows),
        "startedFlows": count_with(rows, "startedMs"),
        "attributedFlows": count_with(deltas, "attributedMs"),
        "connectingFlows": count_with(deltas, "connectingMs"),
        "establishedFlows": count_with(deltas, "establishedMs"),
        "firstPayloadFlows": count_with(deltas, "firstPayloadMs"),
        "firstDownstreamFlows": count_with(deltas, "firstDownstreamMs"),
        "closedFlows": count_with(deltas, "closedMs"),
        "failedFlows": count_with(deltas, "failedMs"),
        "orderedFlows": sum(1 for row in deltas if timing_ordered(row)),
        "timings": {key: timing_stats(deltas, key) for key in DELTA_KEYS},
    }


def timing_deltas(row: dict[str, Any]) -> dict[str, Any]:
    start = row.get("startedMs")
    if not isinstance(start, int):
        return {}
    return {
        key: value - start
        for key, value in row.items()
        if key != "flowId" and isinstance(value, int) and value >= start
    }


def timing_ordered(row: dict[str, Any]) -> bool:
    sequence = [
        row.get("startedMs"),
        row.get("attributedMs"),
        row.get("connectingMs"),
        row.get("establishedMs"),
        row.get("firstPayloadMs"),
        row.get("firstDownstreamMs"),
        row.get("closedMs"),
    ]
    values = [int(value) for value in sequence if isinstance(value, int)]
    return len(values) == len(sequence) and values == sorted(values)


def timing_stats(rows: list[dict[str, Any]], key: str) -> dict[str, int]:
    values = sorted(int(row[key]) for row in rows if isinstance(row.get(key), int))
    if not values:
        return {"count": 0, "min": 0, "avg": 0, "p95": 0, "max": 0}
    return {
        "count": len(values),
        "min": values[0],
        "avg": sum(values) // len(values),
        "p95": percentile(values, 95),
        "max": values[-1],
    }


def timing_counts_clean(counts: dict[str, Any]) -> bool:
    flows = int(counts["flows"])
    return (
        flows > 0
        and counts["startedFlows"] == flows
        and counts["attributedFlows"] == flows
        and counts["connectingFlows"] == flows
        and counts["establishedFlows"] == flows
        and counts["firstPayloadFlows"] == flows
        and counts["firstDownstreamFlows"] == flows
        and counts["closedFlows"] == flows
        and counts["failedFlows"] == 0
        and counts["orderedFlows"] == flows
    )


def timing_classification(counts: dict[str, Any]) -> str:
    if int(counts["failedFlows"]):
        return "flow-failure"
    if int(counts["orderedFlows"]) < int(counts["flows"]):
        return "timing-order-incomplete"
    return "timing-incomplete"


def timing_surface_totals(rows: list[dict[str, Any]]) -> dict[str, Any]:
    all_deltas = [
        delta
        for row in rows
        for delta in row["_deltas"]
    ]
    return {
        "runs": len(rows),
        "cleanRuns": sum(1 for row in rows if row["clean"]),
        "failedRuns": sum(1 for row in rows if not row["clean"]),
        "classifications": aggregate(row["classification"] for row in rows),
        **{
            key: sum(int(row["current"].get(key) or 0) for row in rows)
            for key in COUNT_KEYS
        },
        "timings": {key: timing_stats(all_deltas, key) for key in DELTA_KEYS},
    }


def timing_surface_conclusion(totals: dict[str, Any]) -> dict[str, Any]:
    clean = totals["runs"] > 0 and totals["failedRuns"] == 0
    return {
        "status": "clean" if clean else "timing-surface-needs-evidence",
        "nextAction": (
            "return-to-runtime-surface"
            if clean
            else "inspect-tcp-lifecycle-timing-marks"
        ),
        "plannerPenaltySafe": False,
        "qualityPenaltySafe": False,
    }


def write_timing_surface_summary(output_dir: Path, summary: dict[str, Any]) -> None:
    (output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n"
    )
    write_timing_markdown(output_dir / "summary.md", summary)


def write_timing_markdown(path: Path, summary: dict[str, Any]) -> None:
    totals = summary["totals"]
    lines = [
        "# VM Private Runtime Timing Surface",
        "",
        f"- label: `{summary['label']}`",
        f"- status: `{summary['conclusion']['status']}`",
        f"- runs: `{totals['runs']}`",
        f"- clean runs: `{totals['cleanRuns']}`",
        f"- flows: `{totals['flows']}`",
        f"- ordered flows: `{totals['orderedFlows']}`",
        f"- closed p95 ms: `{totals['timings']['closedMs']['p95']}`",
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


def timing_print(output_dir: Path, summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "outputDir": str(output_dir),
        "runs": summary["totals"]["runs"],
        "cleanRuns": summary["totals"]["cleanRuns"],
        "status": summary["conclusion"]["status"],
    }


def count_with(rows: list[dict[str, Any]], key: str) -> int:
    return sum(1 for row in rows if isinstance(row.get(key), int))


def percentile(values: list[int], percent: int) -> int:
    index = min(len(values) - 1, max(0, (len(values) * percent + 99) // 100 - 1))
    return values[index]


def min_optional(left: Any, right: int) -> int:
    return min(left, right) if isinstance(left, int) else right


def aggregate(values: Any) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for value in values:
        key = str(value or "unknown")
        counts[key] = counts.get(key, 0) + 1
    return [{"key": key, "count": counts[key]} for key in sorted(counts)]


def load_optional_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open() as fh:
        value = json.load(fh)
    return value if isinstance(value, dict) else {}
