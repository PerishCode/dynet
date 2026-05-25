from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from common import Lab, validate_name
from private_runtime_lib.tcp_flow import tcp_flow_brief


PAYLOAD_SURFACE_SCHEMA = "dynet-vm-private-runtime-payload-surface/v1alpha1"
REPEAT_SCHEMA = "dynet-vm-private-runtime-repeat/v1alpha1"

PAYLOAD_KEYS = [
    "flows",
    "startedFlows",
    "establishedFlows",
    "closedFlows",
    "lifecycleCompleteFlows",
    "pathCompleteFlows",
    "closedWithByteTotals",
    "payloadStartedFlows",
    "payloadReceivedFlows",
    "payloadBidirectionalFlows",
    "payloadCloseConsistent",
    "closedWithoutPayloadFlows",
    "duplicateClosedFlows",
    "failedFlows",
    "stageFailedFlows",
    "failedAfterUpstreamOnly",
    "failedAfterPathComplete",
]


def command_payload_surface(_lab: Lab, args: argparse.Namespace) -> None:
    label = validate_name(args.label or "payload-surface", "label")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = build_payload_surface_summary(
        label,
        output_dir,
        [Path(item) for item in args.input],
    )
    write_payload_surface_summary(output_dir, summary)
    print(json.dumps(payload_print(output_dir, summary), sort_keys=True))


def build_payload_surface_summary(
    label: str,
    output_dir: Path,
    inputs: list[Path],
) -> dict[str, Any]:
    rows = [payload_surface_row(path) for path in expand_inputs(inputs)]
    totals = payload_surface_totals(rows)
    return {
        "schema": PAYLOAD_SURFACE_SCHEMA,
        "label": label,
        "outputDir": str(output_dir),
        "runs": rows,
        "totals": totals,
        "conclusion": payload_surface_conclusion(totals),
        "policy": {
            "plannerPenaltySafe": False,
            "qualityPenaltySafe": False,
            "reason": "Payload surface is execution evidence, not penalty proof.",
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


def payload_surface_row(run_dir: Path) -> dict[str, Any]:
    summary = load_optional_json(run_dir / "summary.json")
    runtime_path = run_dir / "runtime-report.json"
    current = payload_counts(
        tcp_flow_brief(load_json(runtime_path))
        if runtime_path.exists()
        else summary.get("tcpFlow", {})
    )
    clean = payload_counts_clean(current)
    return {
        "label": summary.get("label") or run_dir.name,
        "path": str(run_dir),
        "classification": "clean" if clean else payload_classification(current),
        "clean": clean,
        "current": current,
    }


def payload_counts(tcp_flow: dict[str, Any]) -> dict[str, int]:
    return {key: int(tcp_flow.get(key) or 0) for key in PAYLOAD_KEYS}


def payload_counts_clean(counts: dict[str, int]) -> bool:
    flows = counts["flows"]
    closed = counts["closedFlows"]
    return (
        flows > 0
        and counts["startedFlows"] == flows
        and counts["establishedFlows"] == flows
        and closed == flows
        and counts["lifecycleCompleteFlows"] == flows
        and counts["pathCompleteFlows"] == flows
        and counts["closedWithByteTotals"] == closed
        and counts["payloadStartedFlows"] == closed
        and counts["payloadReceivedFlows"] == closed
        and counts["payloadBidirectionalFlows"] == closed
        and counts["payloadCloseConsistent"] == closed
        and counts["closedWithoutPayloadFlows"] == 0
        and counts["duplicateClosedFlows"] == 0
        and counts["failedFlows"] == 0
    )


def payload_classification(counts: dict[str, int]) -> str:
    if counts["failedFlows"]:
        return "flow-failure"
    if counts["duplicateClosedFlows"]:
        return "duplicate-close"
    if counts["closedWithoutPayloadFlows"]:
        return "payload-missing"
    if counts["payloadCloseConsistent"] < counts["payloadStartedFlows"]:
        return "payload-close-inconsistent"
    return "payload-incomplete"


def payload_surface_totals(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "runs": len(rows),
        "cleanRuns": sum(1 for row in rows if row["clean"]),
        "failedRuns": sum(1 for row in rows if not row["clean"]),
        "classifications": aggregate(row["classification"] for row in rows),
        **{
            key: sum(int(row["current"].get(key) or 0) for row in rows)
            for key in PAYLOAD_KEYS
        },
    }


def payload_surface_conclusion(totals: dict[str, Any]) -> dict[str, Any]:
    clean = totals["runs"] > 0 and totals["failedRuns"] == 0
    return {
        "status": "clean" if clean else "payload-surface-needs-evidence",
        "nextAction": (
            "return-to-runtime-surface"
            if clean
            else "inspect-payload-lifecycle-and-byte-accounting"
        ),
        "plannerPenaltySafe": False,
        "qualityPenaltySafe": False,
    }


def write_payload_surface_summary(output_dir: Path, summary: dict[str, Any]) -> None:
    (output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n"
    )
    write_payload_markdown(output_dir / "summary.md", summary)


def write_payload_markdown(path: Path, summary: dict[str, Any]) -> None:
    totals = summary["totals"]
    lines = [
        "# VM Private Runtime Payload Surface",
        "",
        f"- label: `{summary['label']}`",
        f"- status: `{summary['conclusion']['status']}`",
        f"- runs: `{totals['runs']}`",
        f"- clean runs: `{totals['cleanRuns']}`",
        f"- flows: `{totals['flows']}`",
        f"- payload bidirectional: `{totals['payloadBidirectionalFlows']}`",
        f"- payload close consistent: `{totals['payloadCloseConsistent']}`",
        f"- failed flows: `{totals['failedFlows']}`",
        f"- duplicate closes: `{totals['duplicateClosedFlows']}`",
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


def payload_print(output_dir: Path, summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "outputDir": str(output_dir),
        "runs": summary["totals"]["runs"],
        "cleanRuns": summary["totals"]["cleanRuns"],
        "status": summary["conclusion"]["status"],
    }


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
