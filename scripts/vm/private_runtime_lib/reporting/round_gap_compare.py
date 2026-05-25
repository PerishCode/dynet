from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from common import Lab, validate_name


SCHEMA = "dynet-vm-private-runtime-round-gap-compare/v1alpha1"


def command_round_gap_compare(_lab: Lab, args: argparse.Namespace) -> None:
    label = validate_name(args.label or "round-gap-compare", "label")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    report = build_compare_report(
        label,
        output_dir,
        Path(args.baseline),
        Path(args.candidate),
        args.baseline_label,
        args.candidate_label,
    )
    write_compare_report(output_dir, report)
    print(
        json.dumps(
            {
                "outputDir": str(output_dir),
                "status": report["conclusion"]["status"],
                "nextAction": report["conclusion"]["nextAction"],
            },
            sort_keys=True,
        )
    )


def build_compare_report(
    label: str,
    output_dir: Path,
    baseline_path: Path,
    candidate_path: Path,
    baseline_label: str | None = None,
    candidate_label: str | None = None,
) -> dict[str, Any]:
    baseline = load_summary(baseline_path)
    candidate = load_summary(candidate_path)
    deltas = mechanism_deltas(baseline, candidate)
    conclusion = compare_conclusion(baseline, candidate, deltas)
    return {
        "schema": SCHEMA,
        "label": label,
        "outputDir": str(output_dir),
        "inputs": {
            "baseline": str(baseline_path),
            "candidate": str(candidate_path),
        },
        "baseline": summary_brief(baseline, baseline_label),
        "candidate": summary_brief(candidate, candidate_label),
        "deltas": deltas,
        "conclusion": conclusion,
        "policy": {
            "plannerPenaltySafe": False,
            "qualityPenaltySafe": False,
            "reason": conclusion["reason"],
        },
    }


def load_summary(path: Path) -> dict[str, Any]:
    source = path / "summary.json" if path.is_dir() else path
    return json.loads(source.read_text())


def summary_brief(summary: dict[str, Any], label: str | None) -> dict[str, Any]:
    totals = summary.get("totals") or {}
    conclusion = summary.get("conclusion") or {}
    return {
        "label": label or summary.get("label"),
        "status": conclusion.get("status"),
        "nextAction": conclusion.get("nextAction"),
        "runs": int(totals.get("runs") or 0),
        "workloadAttempted": int(totals.get("workloadAttempted") or 0),
        "workloadSuccess": int(totals.get("workloadSuccess") or 0),
        "workloadFailure": int(totals.get("workloadFailure") or 0),
        "terminalCount": count_keyed(totals.get("terminalByReason")),
        "stageFailureCount": count_keyed(totals.get("stageFailureBySurface")),
        "recoveredFlowCount": count_keyed(totals.get("recoveredFlowMechanisms")),
        "flowRefreshChangedRuns": int(totals.get("flowRefreshChangedRuns") or 0),
        "flowRefreshClassifications": totals.get("flowRefreshClassifications") or [],
        "slowStageEvents": int(totals.get("slowStageEvents") or 0),
        "slowStageMaxMs": int(totals.get("slowStageMaxMs") or 0),
        "scheduleLagMaxMs": int(totals.get("scheduleLagMaxMs") or 0),
        "classifications": totals.get("classifications") or [],
    }


def mechanism_deltas(
    baseline: dict[str, Any],
    candidate: dict[str, Any],
) -> dict[str, Any]:
    base = summary_brief(baseline, None)
    current = summary_brief(candidate, None)
    return {
        "workloadSuccess": delta(current, base, "workloadSuccess"),
        "workloadFailure": delta(current, base, "workloadFailure"),
        "terminalCount": delta(current, base, "terminalCount"),
        "stageFailureCount": delta(current, base, "stageFailureCount"),
        "recoveredFlowCount": delta(current, base, "recoveredFlowCount"),
        "flowRefreshChangedRuns": delta(current, base, "flowRefreshChangedRuns"),
        "slowStageEvents": delta(current, base, "slowStageEvents"),
        "slowStageMaxMs": delta(current, base, "slowStageMaxMs"),
        "scheduleLagMaxMs": delta(current, base, "scheduleLagMaxMs"),
    }


def compare_conclusion(
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    deltas: dict[str, Any],
) -> dict[str, Any]:
    base = summary_brief(baseline, None)
    current = summary_brief(candidate, None)
    regression_rows = regressions(deltas)
    status = compare_status(base, current, regression_rows)
    return {
        "status": status,
        "nextAction": compare_next_action(status),
        "reason": compare_reason(status),
        "improvements": improvements(deltas),
        "regressions": regression_rows,
        "remainingMechanisms": remaining_mechanisms(current),
        "plannerPenaltySafe": False,
        "qualityPenaltySafe": False,
    }


def compare_status(
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    regression_rows: list[dict[str, Any]],
) -> str:
    if candidate["status"] == "clean" and regression_rows:
        return "candidate-clean-with-observe-only-regressions"
    if candidate["status"] == "clean":
        return "candidate-clean"
    if (
        baseline["status"] == "stage-pressure-with-schedule-lag"
        and candidate["status"] == "outbound-stage-pressure"
    ):
        return "schedule-lag-separated-outbound-stage-remains"
    if baseline["terminalCount"] > 0 and candidate["terminalCount"] == 0:
        return "packet-terminal-cleared-stage-remains"
    if baseline["status"] != candidate["status"]:
        return "mechanism-shifted"
    return "mechanism-unchanged"


def compare_next_action(status: str) -> str:
    actions = {
        "candidate-clean": "return-to-mainline-product-effect",
        "candidate-clean-with-observe-only-regressions": "keep-current-baseline-and-investigate-regressions",
        "schedule-lag-separated-outbound-stage-remains": "harden-outbound-stage-failure-path",
        "packet-terminal-cleared-stage-remains": "inspect-remaining-runtime-stage-failures",
        "mechanism-shifted": "classify-new-runtime-mechanism-before-policy",
    }
    return actions.get(status, "continue-runtime-mechanism-attribution")


def compare_reason(status: str) -> str:
    reasons = {
        "candidate-clean": "candidate comparison is clean; no penalty evidence remains in this comparison",
        "candidate-clean-with-observe-only-regressions": (
            "candidate remains product-clean but regressed against the baseline on observe-only "
            "runtime mechanisms; keep planner and quality penalties disabled and do not promote "
            "this candidate as a default-policy baseline"
        ),
        "schedule-lag-separated-outbound-stage-remains": (
            "schedule lag and packet-terminal pressure are separated from the remaining "
            "outbound-stage failures; treat the candidate artifact as mechanism evidence, "
            "not planner or quality penalty evidence"
        ),
        "packet-terminal-cleared-stage-remains": (
            "packet-terminal pressure cleared while runtime stage failures remain; "
            "continue stage failure hardening before policy changes"
        ),
        "mechanism-shifted": "runtime mechanism changed; classify the new surface before policy changes",
    }
    return reasons.get(
        status,
        "comparison does not prove a stable repeated quality-gap candidate penalty",
    )


def improvements(deltas: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for key in ("workloadSuccess", "terminalCount", "stageFailureCount", "scheduleLagMaxMs"):
        change = int(deltas[key]["delta"])
        if key == "workloadSuccess" and change > 0:
            rows.append({"key": key, "delta": change})
        if key != "workloadSuccess" and change < 0:
            rows.append({"key": key, "delta": change})
    return rows


def regressions(deltas: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for key in (
        "workloadSuccess",
        "workloadFailure",
        "terminalCount",
        "stageFailureCount",
        "recoveredFlowCount",
        "flowRefreshChangedRuns",
        "slowStageEvents",
        "slowStageMaxMs",
        "scheduleLagMaxMs",
    ):
        change = int(deltas[key]["delta"])
        if key == "workloadSuccess" and change < 0:
            rows.append({"key": key, "delta": change})
        if key != "workloadSuccess" and change > 0:
            rows.append({"key": key, "delta": change})
    return rows


def remaining_mechanisms(summary: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    if summary["terminalCount"]:
        rows.append({"key": "packet-terminal", "count": summary["terminalCount"]})
    if summary["stageFailureCount"]:
        rows.append({"key": "runtime-stage-failure", "count": summary["stageFailureCount"]})
    if summary["recoveredFlowCount"]:
        rows.append({"key": "recovered-runtime-stage-pressure", "count": summary["recoveredFlowCount"]})
    if summary["flowRefreshChangedRuns"]:
        rows.append({"key": "flow-refresh-changed-run", "count": summary["flowRefreshChangedRuns"]})
    if summary["scheduleLagMaxMs"]:
        rows.append({"key": "schedule-lag", "maxMs": summary["scheduleLagMaxMs"]})
    return rows


def delta(current: dict[str, Any], baseline: dict[str, Any], key: str) -> dict[str, int]:
    before = int(baseline[key])
    after = int(current[key])
    return {"baseline": before, "candidate": after, "delta": after - before}


def count_keyed(rows: Any) -> int:
    return sum(int(row.get("count") or 0) for row in rows or [] if isinstance(row, dict))


def write_compare_report(output_dir: Path, report: dict[str, Any]) -> None:
    (output_dir / "summary.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    write_compare_markdown(output_dir / "summary.md", report)


def write_compare_markdown(path: Path, report: dict[str, Any]) -> None:
    lines = [
        "# VM Private Runtime Round-Gap Compare",
        "",
        f"- label: `{report['label']}`",
        f"- status: `{report['conclusion']['status']}`",
        f"- next action: `{report['conclusion']['nextAction']}`",
        f"- baseline: `{report['baseline']['label']}` status=`{report['baseline']['status']}`",
        f"- candidate: `{report['candidate']['label']}` status=`{report['candidate']['status']}`",
        f"- baseline flow refresh: `{report['baseline']['flowRefreshClassifications']}`",
        f"- candidate flow refresh: `{report['candidate']['flowRefreshClassifications']}`",
        f"- improvements: `{report['conclusion']['improvements']}`",
        f"- regressions: `{report['conclusion']['regressions']}`",
        f"- remaining mechanisms: `{report['conclusion']['remainingMechanisms']}`",
        f"- policy reason: `{report['policy']['reason']}`",
        "",
        "## Deltas",
        "",
    ]
    for key, value in report["deltas"].items():
        lines.append(
            f"- `{key}` baseline=`{value['baseline']}` "
            f"candidate=`{value['candidate']}` delta=`{value['delta']}`"
        )
    path.write_text("\n".join(lines) + "\n")
