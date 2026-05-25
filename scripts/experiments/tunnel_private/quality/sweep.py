from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Callable

from tunnel_private_config import write_json


SWEEP_SCHEMA = "dynet-tunnel-private-quality-sweep/v1alpha1"
SWEEP_SUMMARY_SCHEMA = "dynet-tunnel-private-quality-sweep-summary/v1alpha1"
RunRegression = Callable[[argparse.Namespace], int]


def command_quality_sweep(
    args: argparse.Namespace,
    *,
    run_regression: RunRegression,
) -> int:
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    for offset in sweep_offsets(args):
        for target in args.target_url:
            phase = phase_args(args, output_dir, target, offset)
            code = run_regression(phase)
            rows.append(run_row(phase, code))
    summary = sweep_summary(args, rows)
    write_json(output_dir / "summary.json", summary)
    write_markdown(output_dir / "summary.md", summary)
    print(json.dumps(print_summary(output_dir, summary), sort_keys=True))
    if bool(getattr(args, "sweep_allow_failures", False)):
        return 0
    return 0 if summary["status"] == "pass" else 1


def command_quality_sweep_summary(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    sweeps = [load_json(Path(path)) for path in args.sweep_summary]
    summary = combined_summary(sweeps, args.sweep_summary)
    write_json(output_dir / "summary.json", summary)
    write_combined_markdown(output_dir / "summary.md", summary)
    print(json.dumps(print_summary(output_dir, summary), sort_keys=True))
    return 0 if summary["status"] == "pass" else 1


def sweep_offsets(args: argparse.Namespace) -> list[int]:
    offsets = getattr(args, "sweep_offset", None)
    if offsets:
        return [int(item) for item in offsets]
    return [int(getattr(args, "candidate_offset", 0) or 0)]


def phase_args(
    args: argparse.Namespace,
    output_dir: Path,
    target: str,
    offset: int,
) -> argparse.Namespace:
    values = dict(vars(args))
    values.update(
        {
            "target_url": target,
            "candidate_offset": offset,
            "output_dir": str(output_dir / f"offset-{offset:03d}-{slug(target)}"),
        }
    )
    return argparse.Namespace(**values)


def run_row(args: argparse.Namespace, code: int) -> dict[str, Any]:
    summary_path = Path(args.output_dir) / "summary.json"
    summary = load_json(summary_path)
    target = str(args.target_url)
    offset = int(getattr(args, "candidate_offset", 0) or 0)
    return {
        "label": row_label(target, offset),
        "targetUrl": target,
        "candidateOffset": offset,
        "outputDir": str(Path(args.output_dir).name),
        "exitCode": code,
        "status": summary.get("status", "missing"),
        "strictStatus": summary.get("strictStatus", "missing"),
        "selected": summary.get("plan", {}).get("selected"),
        "selectedBehind": summary.get("plan", {}).get("quality", {}).get("selectedBehind"),
        "matrix": summary.get("matrix", {}).get("totals", {}),
        "compare": summary.get("compare") or {},
    }


def sweep_summary(args: argparse.Namespace, rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema": SWEEP_SCHEMA,
        "status": "pass" if all(item["status"] == "pass" for item in rows) else "fail",
        "strictStatus": "pass" if all(item["strictStatus"] == "pass" for item in rows) else "fail",
        "gateMode": str(getattr(args, "gate_mode", "product")),
        "refreshProbeMode": str(getattr(args, "refresh_probe_mode", "auto")),
        "protocol": str(getattr(args, "protocol", "https-head")),
        "supportedTypes": list(getattr(args, "supported_type", []) or []),
        "limits": {
            "candidateLimit": getattr(args, "limit", None),
            "candidateOffsets": sweep_offsets(args),
            "targets": list(getattr(args, "target_url", []) or []),
        },
        "totals": totals(rows),
        "markerSummary": marker_summary(rows),
        "runs": rows,
    }


def combined_summary(sweeps: list[dict[str, Any]], paths: list[str]) -> dict[str, Any]:
    rows = [
        combined_row(row, path)
        for sweep, path in zip(sweeps, paths)
        for row in sweep.get("runs", [])
    ]
    return {
        "schema": SWEEP_SUMMARY_SCHEMA,
        "status": "pass" if all(row.get("status") == "pass" for row in rows) else "fail",
        "strictStatus": "pass" if all(row.get("strictStatus") == "pass" for row in rows) else "fail",
        "sources": paths,
        "sourceSummaries": [
            source_summary(sweep, path) for sweep, path in zip(sweeps, paths)
        ],
        "limits": {
            "candidateOffsets": sorted({int(row.get("candidateOffset") or 0) for row in rows}),
            "targets": sorted({str(row.get("targetUrl")) for row in rows}),
        },
        "totals": combined_totals(rows),
        "markerSummary": marker_summary(rows),
        "runs": rows,
    }


def combined_row(row: dict[str, Any], source_path: str) -> dict[str, Any]:
    result = dict(row)
    target = str(result.get("targetUrl") or "")
    offset = int(result.get("candidateOffset") or 0)
    result.setdefault("label", row_label(target, offset))
    result["source"] = source_path
    result["runPath"] = run_path(source_path, str(result.get("outputDir") or ""))
    return result


def source_summary(sweep: dict[str, Any], source_path: str) -> dict[str, Any]:
    return {
        "path": source_path,
        "status": sweep.get("status", "missing"),
        "strictStatus": sweep.get("strictStatus", "missing"),
        "limits": sweep.get("limits", {}),
        "totals": sweep.get("totals", {}),
    }


def run_path(source_path: str, output_dir: str) -> str:
    if not output_dir:
        return ""
    path = Path(output_dir)
    if path.is_absolute():
        return str(path)
    return str(Path(source_path).parent / path)


def combined_totals(rows: list[dict[str, Any]]) -> dict[str, int]:
    base = totals(rows)
    base["matrixFailures"] = sum(int(row.get("matrix", {}).get("failed") or 0) for row in rows)
    base["selectedBehindMax"] = max((int(row.get("selectedBehind") or 0) for row in rows), default=0)
    return base


def totals(rows: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "runs": len(rows),
        "passed": sum(1 for item in rows if item["status"] == "pass"),
        "failed": sum(1 for item in rows if item["status"] != "pass"),
        "strictPassed": sum(1 for item in rows if item["strictStatus"] == "pass"),
        "strictFailed": sum(1 for item in rows if item["strictStatus"] != "pass"),
    }


def marker_summary(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        markers = (row.get("compare") or {}).get("markerSummary", {}) or {}
        for marker, count in markers.items():
            counts[str(marker)] = counts.get(str(marker), 0) + int(count)
    return dict(sorted(counts.items()))


def row_label(target: str, offset: int) -> str:
    return f"offset-{offset:03d}-{slug(target)}"


def slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-") or "target"


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text())


def print_summary(output_dir: Path, summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "outputDir": str(output_dir),
        "status": summary["status"],
        "strictStatus": summary["strictStatus"],
        **summary["totals"],
    }


def write_markdown(path: Path, summary: dict[str, Any]) -> None:
    lines = [
        "# Tunnel/Private Quality Sweep",
        "",
        f"- status: `{summary['status']}`",
        f"- strict status: `{summary['strictStatus']}`",
        f"- runs: `{summary['totals']['runs']}`",
        f"- passed: `{summary['totals']['passed']}`",
        f"- failed: `{summary['totals']['failed']}`",
        f"- strict failed: `{summary['totals']['strictFailed']}`",
        "",
        "## Runs",
        "",
    ]
    for row in summary["runs"]:
        lines.append(
            f"- `{row['status']}` strict=`{row['strictStatus']}` "
            f"label=`{row['label']}` selected=`{row.get('selected')}` "
            f"behind=`{row.get('selectedBehind')}` "
            f"matrixFailed=`{row['matrix'].get('failed')}`"
        )
    path.write_text("\n".join(lines) + "\n")


def write_combined_markdown(path: Path, summary: dict[str, Any]) -> None:
    lines = [
        "# Tunnel/Private Quality Sweep Summary",
        "",
        f"- status: `{summary['status']}`",
        f"- strict status: `{summary['strictStatus']}`",
        f"- runs: `{summary['totals']['runs']}`",
        f"- passed: `{summary['totals']['passed']}`",
        f"- failed: `{summary['totals']['failed']}`",
        f"- matrix failures: `{summary['totals']['matrixFailures']}`",
        f"- selected behind max: `{summary['totals']['selectedBehindMax']}`",
        "",
        "## Sources",
        "",
    ]
    for source in summary["sourceSummaries"]:
        lines.append(
            f"- `{source['status']}` strict=`{source['strictStatus']}` "
            f"path=`{source['path']}`"
        )
    lines.extend([
        "",
        "## Runs",
        "",
    ])
    for row in summary["runs"]:
        lines.append(
            f"- `{row['status']}` strict=`{row['strictStatus']}` "
            f"label=`{row['label']}` selected=`{row.get('selected')}` "
            f"behind=`{row.get('selectedBehind')}` "
            f"matrixFailed=`{row['matrix'].get('failed')}` "
            f"path=`{row.get('runPath')}`"
        )
    path.write_text("\n".join(lines) + "\n")
