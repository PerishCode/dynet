from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from tunnel_private.quality.readiness.protocol_followup import (
    int_or_zero,
    load_json,
    write_json,
)


BATCH_SCHEMA = "dynet-tunnel-private-protocol-followup-batch/v1alpha1"


def command_protocol_followup_batch(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = protocol_followup_batch([Path(path) for path in args.summary or []])
    write_json(output_dir / "summary.json", summary)
    write_batch_markdown(output_dir / "summary.md", summary)
    print(json.dumps(print_summary(output_dir, summary), sort_keys=True))
    return 0 if summary["sourceCount"] else 1


def protocol_followup_batch(paths: list[Path]) -> dict[str, Any]:
    sources = [followup_source(path) for path in paths]
    failures = [failure for source in sources for failure in source["readFailures"]]
    surfaces = surface_rows(failures)
    conclusion = conclusion_summary(sources, surfaces)
    return {
        "schema": BATCH_SCHEMA,
        "sourceCount": len(sources),
        "totals": {
            "readFailureCount": sum_int(sources, "readFailureCount"),
            "readFailureUnclassifiedCount": sum_int(
                sources,
                "readFailureUnclassifiedCount",
            ),
            "currentReadStageFailures": sum_int(sources, "currentReadStageFailures"),
            "windowsWithReadFailure": sum(1 for item in sources if item["readFailureCount"] > 0),
        },
        "readFailureSurfaces": surfaces,
        "sources": sources,
        "conclusion": conclusion,
        "privacy": {"rawSecretsStored": False, "rawLogsStored": False},
    }


def followup_source(path: Path) -> dict[str, Any]:
    summary = load_json(path)
    conclusion = summary.get("conclusion") or {}
    report = summary.get("reportEvidence") or {}
    failures = [
        source_failure(source)
        for source in report.get("sources", [])
        if isinstance(source, dict)
        and isinstance(source.get("readFailure"), dict)
        and source["readFailure"]
    ]
    return {
        "path": str(path),
        "status": str(conclusion.get("status") or ""),
        "readFailureCount": int(report.get("readFailureCount") or 0),
        "readFailureUnclassifiedCount": int(report.get("readFailureUnclassifiedCount") or 0),
        "currentReadStageFailures": int(conclusion.get("currentReadStageFailures") or 0),
        "readFailures": failures,
    }


def source_failure(source: dict[str, Any]) -> dict[str, Any]:
    failure = source["readFailure"]
    return {
        "path": str(source.get("path") or ""),
        "marker": str(failure.get("marker") or ""),
        "disposition": str(failure.get("disposition") or ""),
        "protocolStage": str(failure.get("protocolStage") or ""),
        "context": str(failure.get("context") or ""),
        "stage": str(failure.get("stage") or ""),
        "outbound": str(failure.get("outbound") or ""),
        "pendingBudgetMs": int_or_zero(failure.get("pendingBudgetMs")),
    }


def surface_rows(failures: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: dict[tuple[str, str, str, str, str], int] = {}
    for failure in failures:
        key = (
            failure["marker"],
            failure["disposition"],
            failure["protocolStage"],
            failure["context"],
            failure["stage"],
        )
        counts[key] = counts.get(key, 0) + 1
    return [
        {
            "marker": marker,
            "disposition": disposition,
            "protocolStage": protocol_stage,
            "context": context,
            "stage": stage,
            "count": count,
        }
        for (marker, disposition, protocol_stage, context, stage), count in sorted(counts.items())
    ]


def conclusion_summary(
    sources: list[dict[str, Any]],
    surfaces: list[dict[str, Any]],
) -> dict[str, Any]:
    windows_with_failure = sum(1 for item in sources if item["readFailureCount"] > 0)
    repeated = [item for item in surfaces if int(item["count"]) > 1]
    if windows_with_failure >= 2 and len(surfaces) == 1:
        status = "read-surface-repeated-stable"
    elif windows_with_failure >= 2:
        status = "read-surface-repeated-drift"
    elif windows_with_failure == 1:
        status = "read-surface-observed-once"
    else:
        status = "read-surface-clean"
    return {
        "status": status,
        "windowsWithReadFailure": windows_with_failure,
        "surfaceKinds": len(surfaces),
        "repeatedSurfaceKinds": len(repeated),
        "classificationClean": sum_int(sources, "readFailureUnclassifiedCount") == 0,
    }


def sum_int(rows: list[dict[str, Any]], key: str) -> int:
    return sum(int(row.get(key) or 0) for row in rows)


def print_summary(output_dir: Path, summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "outputDir": str(output_dir),
        "status": summary["conclusion"]["status"],
        "sourceCount": summary["sourceCount"],
        "readFailureCount": summary["totals"]["readFailureCount"],
        "surfaceKinds": summary["conclusion"]["surfaceKinds"],
        "classificationClean": summary["conclusion"]["classificationClean"],
    }


def write_batch_markdown(path: Path, summary: dict[str, Any]) -> None:
    conclusion = summary["conclusion"]
    lines = [
        "# Tunnel/Private Protocol Follow-Up Batch",
        "",
        f"- status: `{conclusion['status']}`",
        f"- source count: `{summary['sourceCount']}`",
        f"- read failure count: `{summary['totals']['readFailureCount']}`",
        f"- classification clean: `{conclusion['classificationClean']}`",
        "",
        "## Read Surfaces",
        "",
    ]
    for surface in summary["readFailureSurfaces"]:
        lines.append(
            "- "
            f"marker=`{surface['marker']}` disposition=`{surface['disposition']}` "
            f"protocolStage=`{surface['protocolStage']}` context=`{surface['context']}` "
            f"stage=`{surface['stage']}` "
            f"count=`{surface['count']}`"
        )
    path.write_text("\n".join(lines) + "\n")
