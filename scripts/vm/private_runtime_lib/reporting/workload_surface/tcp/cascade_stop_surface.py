from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from common import Lab, validate_name
from scripts.lib.jsonio import load_summary
from scripts.lib.privacy import empty_privacy_flags


SCHEMA = "dynet-vm-private-runtime-cascade-stop-surface/v1alpha1"
ROUND_GAP_SCHEMA = "dynet-vm-private-runtime-round-gap-batch/v1alpha1"
COUNT_FIELDS = """
roundGapRuns stoppedRows boundExhaustedRows nonBoundRows candidateExhaustedRows
matchedFailedWorkloadRows attemptCount failedAttemptCount retryableFailureCount
missingRequiredFields boundOrderLengthMismatches failedOrderLengthMismatches
retryableOrderLengthMismatches uniqueCandidateCountMismatches
lastCandidateMismatches finalFailureAccountingMismatches exhaustedFlagMismatches
scopeStopMismatches emptyBoundOrderRows
""".split()
REQUIRED_FIELDS = """
stopReason candidateExhausted attemptCount failedAttemptCount retryableFailureCount
candidateCount failureScope errorDisposition failureStageSurface
""".split()
BOUND_EXHAUSTED = "bound-candidates-exhausted"
NON_BOUND = "non-bound-failure"


def command_cascade_stop_surface(_lab: Lab, args: argparse.Namespace) -> None:
    label = validate_name(args.label or "cascade-stop-surface", "label")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = build_cascade_stop_summary(label, output_dir, [Path(item) for item in args.input])
    write_cascade_stop_summary(output_dir, summary)
    print(json.dumps(cascade_stop_print(output_dir, summary), sort_keys=True))


def build_cascade_stop_summary(
    label: str,
    output_dir: Path,
    inputs: list[Path],
) -> dict[str, Any]:
    sources = [cascade_stop_source(path) for path in inputs]
    totals = cascade_stop_totals(sources)
    conclusion = cascade_stop_conclusion(totals)
    return {
        "schema": SCHEMA,
        "label": label,
        "outputDir": str(output_dir),
        "sources": sources,
        "totals": totals,
        "conclusion": conclusion,
        "policy": {
            "plannerPenaltySafe": False,
            "qualityPenaltySafe": False,
            "reason": conclusion["reason"],
        },
        "privacy": empty_privacy_flags(),
    }


def cascade_stop_source(path: Path) -> dict[str, Any]:
    summary = load_summary(path)
    rows = stopped_rows(summary)
    schedule_rows = failed_schedule_rows(summary)
    current = cascade_stop_counts(rows, schedule_rows)
    current["roundGapRuns"] = int_value((summary.get("totals") or {}).get("runs"))
    clean = cascade_stop_clean(current)
    return {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "label": str(summary.get("label") or path.stem),
        "roundGapStatus": str((summary.get("conclusion") or {}).get("status") or ""),
        "clean": clean,
        "classification": "clean" if clean else cascade_stop_classification(current),
        **current,
    }


def stopped_rows(summary: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    rows.extend(cascade_attempt_stopped_rows(summary))
    rows.extend(selection_stopped_rows(summary))
    for run in summary.get("runs") or []:
        if not isinstance(run, dict):
            continue
        cascade = run.get("cascade") or {}
        rows.extend(row for row in cascade.get("stoppedRows") or [] if isinstance(row, dict))
        rows.extend(cascade_attempt_stopped_rows(run))
        rows.extend(selection_stopped_rows(run))
    return rows


def cascade_attempt_stopped_rows(summary: dict[str, Any]) -> list[dict[str, Any]]:
    cascade = summary.get("cascadeAttempts") or {}
    if not isinstance(cascade, dict):
        return []
    return [row for row in cascade.get("stoppedRows") or [] if isinstance(row, dict)]


def selection_stopped_rows(summary: dict[str, Any]) -> list[dict[str, Any]]:
    selection = summary.get("selection") or {}
    if not isinstance(selection, dict):
        return []
    cascade = selection.get("cascadeAttempts") or {}
    if not isinstance(cascade, dict):
        return []
    return [row for row in cascade.get("stoppedRows") or [] if isinstance(row, dict)]


def failed_schedule_rows(summary: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for run in summary.get("runs") or []:
        if not isinstance(run, dict):
            continue
        schedule = run.get("schedule") or {}
        rows.extend(row for row in schedule.get("failedRows") or [] if isinstance(row, dict))
    return rows


def cascade_stop_counts(
    rows: list[dict[str, Any]],
    schedule_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "roundGapRuns": 0,
        "stoppedRows": len(rows),
        "boundExhaustedRows": count_stop_reason(rows, BOUND_EXHAUSTED),
        "nonBoundRows": count_stop_reason(rows, NON_BOUND),
        "candidateExhaustedRows": sum(1 for row in rows if bool(row.get("candidateExhausted"))),
        "matchedFailedWorkloadRows": sum(1 for row in schedule_rows if row.get("cascadeStoppedFlowMatched")),
        "attemptCount": sum_int(rows, "attemptCount"),
        "failedAttemptCount": sum_int(rows, "failedAttemptCount"),
        "retryableFailureCount": sum_int(rows, "retryableFailureCount"),
        **shape_check_counts(rows),
        "stopReasons": aggregate(row.get("stopReason") for row in rows),
        "failureScopes": aggregate(row.get("failureScope") for row in rows),
        "stageSurfaces": aggregate(row.get("failureStageSurface") for row in rows),
        "dispositions": aggregate(row.get("errorDisposition") for row in rows),
        "pendingWaitClasses": aggregate(row.get("pendingWaitClass") for row in rows),
        "failureStagePendingWaitClasses": aggregate(
            row.get("failureStagePendingWaitClass") for row in rows
        ),
        "attemptCountBuckets": aggregate(str(int_value(row.get("attemptCount"))) for row in rows),
        "candidateCountBuckets": aggregate(str(int_value(row.get("candidateCount"))) for row in rows),
    }


def shape_check_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "missingRequiredFields": sum(missing_required(row) for row in rows),
        "boundOrderLengthMismatches": sum(1 for row in rows if bound_order_mismatch(row)),
        "failedOrderLengthMismatches": sum(1 for row in rows if order_mismatch(row, "failedSelectedSequence", "failedAttemptCount")),
        "retryableOrderLengthMismatches": sum(1 for row in rows if order_mismatch(row, "retryableSelectedSequence", "retryableFailureCount")),
        "uniqueCandidateCountMismatches": sum(1 for row in rows if unique_candidate_mismatch(row)),
        "lastCandidateMismatches": sum(1 for row in rows if last_candidate_mismatch(row)),
        "finalFailureAccountingMismatches": sum(1 for row in rows if final_failure_mismatch(row)),
        "exhaustedFlagMismatches": sum(1 for row in rows if exhausted_flag_mismatch(row)),
        "scopeStopMismatches": sum(1 for row in rows if scope_stop_mismatch(row)),
        "emptyBoundOrderRows": sum(1 for row in rows if not row.get("boundSelectedSequence")),
    }


def cascade_stop_totals(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        **{
            field: sum(int(source.get(field) or 0) for source in sources)
            for field in COUNT_FIELDS
            if field != "roundGapRuns"
        },
        "roundGapRuns": sum(round_gap_runs(source) for source in sources),
        "classifications": aggregate(source["classification"] for source in sources),
        "roundGapStatuses": aggregate(source["roundGapStatus"] for source in sources),
        "stopReasons": merge_counts(sources, "stopReasons"),
        "failureScopes": merge_counts(sources, "failureScopes"),
        "stageSurfaces": merge_counts(sources, "stageSurfaces"),
        "dispositions": merge_counts(sources, "dispositions"),
        "pendingWaitClasses": merge_counts(sources, "pendingWaitClasses"),
        "failureStagePendingWaitClasses": merge_counts(
            sources,
            "failureStagePendingWaitClasses",
        ),
        "attemptCountBuckets": merge_counts(sources, "attemptCountBuckets"),
        "candidateCountBuckets": merge_counts(sources, "candidateCountBuckets"),
    }


def cascade_stop_conclusion(totals: dict[str, Any]) -> dict[str, Any]:
    clean = totals["sourceCount"] > 0 and totals["stoppedRows"] > 0 and blockers(totals) == 0
    status = "cascade-stop-shape-clean" if clean else "cascade-stop-shape-needs-evidence"
    if totals["stoppedRows"] == 0:
        status = "no-cascade-stop-evidence"
    return {
        "status": status,
        "nextAction": (
            "continue-stage-hardening-with-sanitized-bound-exhaustion-shape"
            if clean else "inspect-cascade-stop-shape"
        ),
        "reason": conclusion_reason(status),
        "plannerPenaltySafe": False,
        "qualityPenaltySafe": False,
    }


def cascade_stop_clean(counts: dict[str, Any]) -> bool:
    return counts["stoppedRows"] > 0 and all(int(counts[field]) == 0 for field in blocker_fields())


def blocker_fields() -> list[str]:
    return [
        "missingRequiredFields",
        "boundOrderLengthMismatches",
        "failedOrderLengthMismatches",
        "retryableOrderLengthMismatches",
        "uniqueCandidateCountMismatches",
        "lastCandidateMismatches",
        "finalFailureAccountingMismatches",
        "exhaustedFlagMismatches",
        "scopeStopMismatches",
        "emptyBoundOrderRows",
    ]


def blockers(totals: dict[str, Any]) -> int:
    return sum(int(totals[field]) for field in blocker_fields())


def cascade_stop_classification(counts: dict[str, Any]) -> str:
    if counts["stoppedRows"] == 0:
        return "no-cascade-stop-evidence"
    for field, label in [
        ("missingRequiredFields", "cascade-stop-field-missing"),
        ("boundOrderLengthMismatches", "bound-order-length-mismatch"),
        ("failedOrderLengthMismatches", "failed-order-length-mismatch"),
        ("retryableOrderLengthMismatches", "retryable-order-length-mismatch"),
        ("uniqueCandidateCountMismatches", "candidate-count-mismatch"),
        ("lastCandidateMismatches", "last-candidate-mismatch"),
        ("finalFailureAccountingMismatches", "final-failure-accounting-mismatch"),
        ("exhaustedFlagMismatches", "exhausted-flag-mismatch"),
        ("scopeStopMismatches", "scope-stop-mismatch"),
        ("emptyBoundOrderRows", "bound-order-missing"),
    ]:
        if int(counts[field]):
            return label
    return "cascade-stop-shape-incomplete"


def missing_required(row: dict[str, Any]) -> int:
    return sum(1 for field in REQUIRED_FIELDS if row.get(field) in (None, ""))


def bound_order_mismatch(row: dict[str, Any]) -> bool:
    return len(row.get("boundSelectedSequence") or []) != int_value(row.get("attemptCount"))


def order_mismatch(row: dict[str, Any], sequence: str, count_field: str) -> bool:
    return len(row.get(sequence) or []) != int_value(row.get(count_field))


def unique_candidate_mismatch(row: dict[str, Any]) -> bool:
    if not bool(row.get("candidateExhausted")):
        return False
    return len(set(row.get("boundSelectedSequence") or [])) != int_value(row.get("candidateCount"))


def last_candidate_mismatch(row: dict[str, Any]) -> bool:
    order = row.get("boundSelectedSequence") or []
    return bool(order) and row.get("lastBoundSelected") != order[-1]


def final_failure_mismatch(row: dict[str, Any]) -> bool:
    if row.get("stopReason") != BOUND_EXHAUSTED:
        return False
    return int_value(row.get("retryableFailureCount")) + 1 != int_value(row.get("failedAttemptCount"))


def exhausted_flag_mismatch(row: dict[str, Any]) -> bool:
    reason = row.get("stopReason")
    exhausted = bool(row.get("candidateExhausted"))
    return (reason == BOUND_EXHAUSTED and not exhausted) or (exhausted and reason != BOUND_EXHAUSTED)


def scope_stop_mismatch(row: dict[str, Any]) -> bool:
    return row.get("stopReason") == BOUND_EXHAUSTED and row.get("failureScope") != "bound"


def count_stop_reason(rows: list[dict[str, Any]], reason: str) -> int:
    return sum(1 for row in rows if row.get("stopReason") == reason)


def sum_int(rows: list[dict[str, Any]], field: str) -> int:
    return sum(int_value(row.get(field)) for row in rows)


def int_value(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def aggregate(values: Any) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for value in values:
        key = str(value or "unknown")
        counts[key] = counts.get(key, 0) + 1
    return [{"key": key, "count": counts[key]} for key in sorted(counts)]


def merge_counts(sources: list[dict[str, Any]], field: str) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for source in sources:
        for row in source.get(field) or []:
            key = str(row.get("key") or "unknown")
            counts[key] = counts.get(key, 0) + int(row.get("count") or 0)
    return [{"key": key, "count": counts[key]} for key in sorted(counts)]


def round_gap_runs(source: dict[str, Any]) -> int:
    return int(source.get("roundGapRuns") or 0) or int(source.get("stoppedRows") > 0)


def conclusion_reason(status: str) -> str:
    if status == "cascade-stop-shape-clean":
        return "cascade stopped-flow shape is internally consistent and retained as aggregate-only evidence"
    if status == "no-cascade-stop-evidence":
        return "no stopped cascade rows were available to inspect"
    return "cascade stopped-flow shape needs more evidence before policy changes"


def write_cascade_stop_summary(output_dir: Path, summary: dict[str, Any]) -> None:
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    write_cascade_stop_markdown(output_dir / "summary.md", summary)


def write_cascade_stop_markdown(path: Path, summary: dict[str, Any]) -> None:
    totals = summary["totals"]
    lines = [
        "# VM Private Runtime Cascade Stop Surface",
        "",
        f"- label: `{summary['label']}`",
        f"- status: `{summary['conclusion']['status']}`",
        f"- sources: `{totals['sourceCount']}`",
        f"- stopped rows: `{totals['stoppedRows']}`",
        f"- bound exhausted rows: `{totals['boundExhaustedRows']}`",
        f"- stage surfaces: `{totals['stageSurfaces']}`",
        f"- stop reasons: `{totals['stopReasons']}`",
        f"- blockers: `{blockers(totals)}`",
    ]
    path.write_text("\n".join(lines) + "\n")


def cascade_stop_print(output_dir: Path, summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "outputDir": str(output_dir),
        "status": summary["conclusion"]["status"],
        "stoppedRows": summary["totals"]["stoppedRows"],
        "boundExhaustedRows": summary["totals"]["boundExhaustedRows"],
    }
