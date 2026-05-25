from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from common import Lab, validate_name
from private_runtime_lib.briefs import selection_brief
from private_runtime_lib.reporting.cascade_stop import (
    CASCADE_COUNT_KEYS,
    CASCADE_KEYS,
    CASCADE_TOTAL_KEYS,
    aggregate_lists,
    cascade_control_counts,
    cascade_counts,
    int_value,
)
from private_runtime_lib.tcp_flow import tcp_flow_brief


CASCADE_REFRESH_SCHEMA = "dynet-vm-private-runtime-cascade-refresh/v1alpha1"
ROUTE_REFRESH_SCHEMA = "dynet-vm-private-runtime-route-refresh/v1alpha1"
SELECTION_REFRESH_SCHEMA = "dynet-vm-private-runtime-selection-refresh/v1alpha1"

ROUTE_KEYS = [
    "ruleMatchedFlows",
    "routeMatchedFlows",
    "planBypassedFlows",
    "routeCandidateSetFlows",
    "routeGraphSelectedFlows",
    "boundCandidateSetFlows",
    "boundGraphSelectedFlows",
    "cascadeSelectedFlows",
    "boundAttemptStartedFlows",
    "boundAttemptSucceededFlows",
    "privateConnectFlows",
    "pathCompleteFlows",
    "lifecycleCompleteFlows",
    "failedFlows",
    "stageFailedFlows",
]

SELECTION_KEYS = [
    "candidateSets",
    "attemptCandidateSets",
    "fallbackCandidateSets",
    "withBoundSelected",
    "selectedWithQuality",
    "selectedBest",
    "selectedBehind",
    "fallbackSelectedWithQuality",
    "fallbackSelectedBehind",
]


def command_cascade_refresh(_lab: Lab, args: argparse.Namespace) -> None:
    label = validate_name(args.label or "cascade-refresh", "label")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = build_cascade_refresh_summary(
        label,
        output_dir,
        [Path(item) for item in args.run_dir],
    )
    write_cascade_refresh_summary(output_dir, summary)
    print(
        json.dumps(
            {
                "outputDir": str(output_dir),
                "runs": summary["totals"]["runs"],
                "changedRuns": summary["totals"]["changedRuns"],
            },
            sort_keys=True,
        )
    )


def command_route_refresh(_lab: Lab, args: argparse.Namespace) -> None:
    label = validate_name(args.label or "route-refresh", "label")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = build_route_refresh_summary(label, output_dir, [Path(item) for item in args.run_dir])
    write_route_refresh_summary(output_dir, summary)
    print(json.dumps(refresh_print(output_dir, summary), sort_keys=True))


def command_selection_refresh(_lab: Lab, args: argparse.Namespace) -> None:
    label = validate_name(args.label or "selection-refresh", "label")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = build_selection_refresh_summary(
        label,
        output_dir,
        [Path(item) for item in args.run_dir],
    )
    write_selection_refresh_summary(output_dir, summary)
    print(json.dumps(refresh_print(output_dir, summary), sort_keys=True))


def build_cascade_refresh_summary(
    label: str,
    output_dir: Path,
    run_dirs: list[Path],
) -> dict[str, Any]:
    rows = [cascade_refresh_row(run_dir) for run_dir in run_dirs]
    return {
        "schema": CASCADE_REFRESH_SCHEMA,
        "label": label,
        "outputDir": str(output_dir),
        "runs": rows,
        "totals": cascade_refresh_totals(rows),
    }


def build_selection_refresh_summary(
    label: str,
    output_dir: Path,
    run_dirs: list[Path],
) -> dict[str, Any]:
    rows = [selection_refresh_row(run_dir) for run_dir in run_dirs]
    return {
        "schema": SELECTION_REFRESH_SCHEMA,
        "label": label,
        "outputDir": str(output_dir),
        "runs": rows,
        "totals": selection_refresh_totals(rows),
    }


def build_route_refresh_summary(label: str, output_dir: Path, run_dirs: list[Path]) -> dict[str, Any]:
    rows = [route_refresh_row(run_dir) for run_dir in run_dirs]
    return {
        "schema": ROUTE_REFRESH_SCHEMA,
        "label": label,
        "outputDir": str(output_dir),
        "runs": rows,
        "totals": route_refresh_totals(rows),
    }


def cascade_refresh_row(run_dir: Path) -> dict[str, Any]:
    previous = load_optional_json(run_dir / "summary.json")
    _refreshed, refresh = refreshed_cascade_summary(run_dir, previous)
    current = cascade_counts(refresh["current"])
    previous_cascade = previous.get("selection", {}).get("cascadeAttempts", {})
    return {
        "label": previous.get("label") or run_dir.name,
        "path": str(run_dir),
        "classification": refresh["classification"],
        "changed": refresh["changed"],
        "changes": refresh["changes"],
        "control": cascade_control_counts(refresh["current"]),
        "current": current,
        "previous": {key: previous_cascade.get(key) for key in CASCADE_KEYS},
    }


def selection_refresh_row(run_dir: Path) -> dict[str, Any]:
    previous = load_optional_json(run_dir / "summary.json")
    current = refreshed_selection_summary(run_dir, previous)
    previous_selection = selection_counts(
        previous.get("selection", {}).get("boundSelection", {})
    )
    current_selection = selection_counts(current)
    changes = selection_changes(previous_selection, current_selection)
    return {
        "label": previous.get("label") or run_dir.name,
        "path": str(run_dir),
        "classification": "changed" if changes else "unchanged",
        "changed": bool(changes),
        "changes": changes,
        "current": current_selection,
        "previous": previous_selection,
    }


def route_refresh_row(run_dir: Path) -> dict[str, Any]:
    previous = load_optional_json(run_dir / "summary.json")
    current = refreshed_route_summary(run_dir, previous)
    previous_route = route_counts(previous.get("tcpFlow", {}))
    current_route = route_counts(current)
    changes = route_changes(previous_route, current_route)
    return {
        "label": previous.get("label") or run_dir.name,
        "path": str(run_dir),
        "classification": "changed" if changes else "unchanged",
        "changed": bool(changes),
        "changes": changes,
        "current": current_route,
        "previous": previous_route,
    }


def selection_refresh_totals(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "runs": len(rows),
        "changedRuns": sum(1 for row in rows if row["changed"]),
        "classifications": aggregate(row["classification"] for row in rows),
        **{key: sum(int_value(row["current"].get(key)) for row in rows) for key in SELECTION_KEYS},
    }


def cascade_refresh_totals(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "runs": len(rows),
        "changedRuns": sum(1 for row in rows if row["changed"]),
        "classifications": aggregate(row["classification"] for row in rows),
        **{key: sum(int_value(row["current"].get(key)) for row in rows) for key in CASCADE_TOTAL_KEYS},
        **{key: aggregate_lists(row["current"].get(key) for row in rows) for key in CASCADE_COUNT_KEYS},
        "stoppedNonBoundFlows": sum(
            int_value(row["control"].get("stoppedNonBoundFlows")) for row in rows
        ),
        "stoppedRetryableFailures": sum(
            int_value(row["control"].get("stoppedRetryableFailures"))
            for row in rows
        ),
    }


def route_refresh_totals(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "runs": len(rows),
        "changedRuns": sum(1 for row in rows if row["changed"]),
        "classifications": aggregate(row["classification"] for row in rows),
        **{key: sum(int_value(row["current"].get(key)) for row in rows) for key in ROUTE_KEYS},
    }


def refreshed_cascade_summary(
    run_dir: Path,
    previous: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    runtime_path = run_dir / "runtime-report.json"
    if not run_dir.is_dir() or not runtime_path.exists():
        return previous, empty_refresh(previous)
    runtime_report = load_json(runtime_path)
    current = selection_brief(runtime_report).get("cascadeAttempts", {})
    previous_cascade = previous.get("selection", {}).get("cascadeAttempts", {})
    changes = metric_changes(previous_cascade, current)
    refreshed = {
        **previous,
        "selection": {
            **previous.get("selection", {}),
            "cascadeAttempts": current,
        },
    }
    return refreshed, {
        "available": True,
        "classification": "changed" if changes else "unchanged",
        "changed": bool(changes),
        "changes": changes,
        "current": current,
    }


def empty_refresh(previous: dict[str, Any]) -> dict[str, Any]:
    return {
        "available": False,
        "classification": "summary-only",
        "changed": False,
        "changes": [],
        "current": previous.get("selection", {}).get("cascadeAttempts", {}),
    }


def refreshed_selection_summary(run_dir: Path, previous: dict[str, Any]) -> dict[str, Any]:
    runtime_path = run_dir / "runtime-report.json"
    if not run_dir.is_dir() or not runtime_path.exists():
        return previous.get("selection", {}).get("boundSelection", {})
    return selection_brief(load_json(runtime_path)).get("boundSelection", {})


def refreshed_route_summary(run_dir: Path, previous: dict[str, Any]) -> dict[str, Any]:
    runtime_path = run_dir / "runtime-report.json"
    if not run_dir.is_dir() or not runtime_path.exists():
        return previous.get("tcpFlow", {})
    return tcp_flow_brief(load_json(runtime_path))


def cascade_refresh_brief(cascade_refresh: dict[str, Any]) -> dict[str, Any]:
    return {
        "available": cascade_refresh["available"],
        "classification": cascade_refresh["classification"],
        "changed": cascade_refresh["changed"],
        "changes": cascade_refresh["changes"],
    }


def metric_changes(
    previous: dict[str, Any],
    current: dict[str, Any],
) -> list[dict[str, Any]]:
    return [
        {"key": key, "previous": previous.get(key), "current": current.get(key)}
        for key in CASCADE_KEYS
        if previous.get(key) != current.get(key)
    ]


def selection_counts(source: dict[str, Any]) -> dict[str, Any]:
    return {key: source.get(key) for key in SELECTION_KEYS}


def selection_changes(
    previous: dict[str, Any],
    current: dict[str, Any],
) -> list[dict[str, Any]]:
    return [
        {"key": key, "previous": previous.get(key), "current": current.get(key)}
        for key in SELECTION_KEYS
        if previous.get(key) != current.get(key)
    ]


def route_counts(source: dict[str, Any]) -> dict[str, Any]:
    return {key: source.get(key) for key in ROUTE_KEYS}


def route_changes(
    previous: dict[str, Any],
    current: dict[str, Any],
) -> list[dict[str, Any]]:
    return [
        {"key": key, "previous": previous.get(key), "current": current.get(key)}
        for key in ROUTE_KEYS
        if previous.get(key) != current.get(key)
    ]


def write_cascade_refresh_summary(output_dir: Path, summary: dict[str, Any]) -> None:
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    write_markdown(output_dir / "summary.md", summary)


def write_route_refresh_summary(output_dir: Path, summary: dict[str, Any]) -> None:
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    write_route_markdown(output_dir / "summary.md", summary)


def write_selection_refresh_summary(output_dir: Path, summary: dict[str, Any]) -> None:
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    write_selection_markdown(output_dir / "summary.md", summary)


def write_markdown(path: Path, summary: dict[str, Any]) -> None:
    lines = [
        "# VM Private Runtime Cascade Refresh",
        "",
        f"- label: `{summary['label']}`",
        f"- runs: `{summary['totals']['runs']}`",
        f"- changed runs: `{summary['totals']['changedRuns']}`",
        f"- classifications: `{summary['totals']['classifications']}`",
        f"- failed attempts: `{summary['totals']['failedAttempts']}`",
        f"- recovered flows: `{summary['totals']['recoveredFlows']}`",
        "",
        "## Runs",
        "",
    ]
    for row in summary["runs"]:
        lines.append(
            f"- `{row['label']}` classification=`{row['classification']}` "
            f"changed=`{row['changed']}` changes=`{row['changes']}`"
        )
    path.write_text("\n".join(lines) + "\n")


def write_selection_markdown(path: Path, summary: dict[str, Any]) -> None:
    totals = summary["totals"]
    lines = [
        "# VM Private Runtime Selection Refresh",
        "",
        f"- label: `{summary['label']}`",
        f"- runs: `{totals['runs']}`",
        f"- changed runs: `{totals['changedRuns']}`",
        f"- classifications: `{totals['classifications']}`",
        f"- candidate sets: `{totals['candidateSets']}`",
        f"- selected with quality: `{totals['selectedWithQuality']}`",
        f"- selected best: `{totals['selectedBest']}`",
        f"- selected behind: `{totals['selectedBehind']}`",
        "",
        "## Runs",
        "",
    ]
    for row in summary["runs"]:
        lines.append(
            f"- `{row['label']}` classification=`{row['classification']}` "
            f"changed=`{row['changed']}` changes=`{row['changes']}`"
        )
    path.write_text("\n".join(lines) + "\n")


def write_route_markdown(path: Path, summary: dict[str, Any]) -> None:
    totals = summary["totals"]
    lines = [
        "# VM Private Runtime Route Refresh",
        "",
        f"- label: `{summary['label']}`",
        f"- runs: `{totals['runs']}`",
        f"- changed runs: `{totals['changedRuns']}`",
        f"- classifications: `{totals['classifications']}`",
        f"- route graph selected: `{totals['routeGraphSelectedFlows']}`",
        f"- bound graph selected: `{totals['boundGraphSelectedFlows']}`",
        f"- path complete: `{totals['pathCompleteFlows']}`",
        "",
        "## Runs",
        "",
    ]
    for row in summary["runs"]:
        lines.append(
            f"- `{row['label']}` classification=`{row['classification']}` "
            f"changed=`{row['changed']}` changes=`{row['changes']}`"
        )
    path.write_text("\n".join(lines) + "\n")


def refresh_print(output_dir: Path, summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "outputDir": str(output_dir),
        "runs": summary["totals"]["runs"],
        "changedRuns": summary["totals"]["changedRuns"],
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
