from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from common import Lab, validate_name
from private_runtime_lib.briefs import fields


FAILURE_SCHEMA = "dynet-vm-private-runtime-outbound-failure-propagation-surface/v1alpha1"
REPEAT_SCHEMA = "dynet-vm-private-runtime-repeat/v1alpha1"
COUNT_FIELDS = """
runs cleanRuns failedRuns eventReports runtimePass events failedStages
failedAttempts failedCascades failedAttemptsWithStage
failedCascadesWithEvidence failedAttemptMissingStage failedCascadeMissingEvidence
failedStageErrorTypeMissing failedStageDispositionMissing
failedAttemptErrorTypeMissing failedAttemptDispositionMissing
failedCascadeErrorTypeMissing failedCascadeDispositionMissing
stageAttemptErrorTypeMismatches stageAttemptDispositionMismatches
cascadeErrorTypeMismatches cascadeDispositionMismatches
cascadeFailureScopeMissing cascadeRetryAllowedMissing
cascadeRetryStopReasonMissing
""".split()
BLOCKERS = """
failedAttemptMissingStage failedCascadeMissingEvidence
failedStageErrorTypeMissing failedStageDispositionMissing
failedAttemptErrorTypeMissing failedAttemptDispositionMissing
failedCascadeErrorTypeMissing failedCascadeDispositionMissing
stageAttemptErrorTypeMismatches stageAttemptDispositionMismatches
cascadeErrorTypeMismatches cascadeDispositionMismatches
cascadeFailureScopeMissing cascadeRetryAllowedMissing
cascadeRetryStopReasonMissing
""".split()


def command_failure_propagation_surface(_lab: Lab, args: argparse.Namespace) -> None:
    label = validate_name(args.label or "failure-propagation-surface", "label")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = build_failure_propagation_summary(
        label,
        output_dir,
        [Path(item) for item in args.input],
    )
    write_failure_propagation_summary(output_dir, summary)
    print(json.dumps(failure_print(output_dir, summary), sort_keys=True))


def build_failure_propagation_summary(
    label: str,
    output_dir: Path,
    inputs: list[Path],
) -> dict[str, Any]:
    rows = [failure_propagation_row(path) for path in expand_inputs(inputs)]
    totals = failure_propagation_totals(rows)
    return {
        "schema": FAILURE_SCHEMA,
        "label": label,
        "outputDir": str(output_dir),
        "runs": rows,
        "totals": totals,
        "conclusion": failure_conclusion(totals),
        "privacy": empty_privacy_flags(),
        "policy": {
            "plannerPenaltySafe": False,
            "qualityPenaltySafe": False,
            "reason": "Failure metadata propagation is observability proof, not penalty proof.",
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


def failure_propagation_row(run_dir: Path) -> dict[str, Any]:
    summary = load_optional_json(run_dir / "summary.json")
    current = failure_counts(load_optional_json(run_dir / "runtime-report.json"))
    clean = failure_clean(current)
    return {
        "label": summary.get("label") or run_dir.name,
        "path": str(run_dir),
        "classification": "clean" if clean else failure_classification(current),
        "clean": clean,
        "current": current,
    }


def failure_counts(report: dict[str, Any]) -> dict[str, Any]:
    raw_events = report.get("events")
    rows = [
        event_row(event, index)
        for index, event in enumerate(raw_events or [])
        if isinstance(event, dict)
    ]
    failed_stages = failed(rows, "outbound-stage-finished")
    failed_attempts = failed(rows, "outbound-attempt-finished")
    failed_cascades = failed(rows, "dialer-cascade-attempt-finished")
    attempt_links = [attempt_link(row, failed_stages) for row in failed_attempts]
    cascade_links = [cascade_link(row, failed_attempts, failed_stages) for row in failed_cascades]
    return {
        "eventReports": 1 if raw_events is not None else 0,
        "runtimePass": 1 if report.get("status") == "pass" else 0,
        "events": len(rows),
        "failedStages": len(failed_stages),
        "failedAttempts": len(failed_attempts),
        "failedCascades": len(failed_cascades),
        **metadata_counts(failed_stages, failed_attempts, failed_cascades),
        **link_counts(attempt_links, cascade_links, failed_cascades),
        "stageFailureProfiles": aggregate(failure_profile("stage", row) for row in failed_stages),
        "attemptFailureProfiles": aggregate(failure_profile("attempt", row) for row in failed_attempts),
        "cascadeFailureProfiles": aggregate(failure_profile("cascade", row) for row in failed_cascades),
    }


def event_row(event: dict[str, Any], index: int) -> dict[str, Any]:
    event_fields = fields(event)
    return {
        "index": index,
        "kind": str(event.get("kind") or ""),
        "reference": event_fields.get("flowId") or event_fields.get("dnsQueryId") or "",
        "outbound": event_fields.get("outbound") or "",
        "adapterKind": event_fields.get("kind") or "",
        "protocol": event_fields.get("protocol") or "",
        "stage": event_fields.get("stage") or "",
        "status": event_fields.get("status") or "",
        "attemptId": event_fields.get("attemptId") or "",
        "errorType": event_fields.get("errorType") or "",
        "errorDisposition": event_fields.get("errorDisposition") or "",
        "failureScope": event_fields.get("failureScope") or "",
        "retryAllowed": event_fields.get("retryAllowed") or "",
        "retryStopReason": event_fields.get("retryStopReason") or "",
    }


def failed(rows: list[dict[str, Any]], kind: str) -> list[dict[str, Any]]:
    return [row for row in rows if row["kind"] == kind and row["status"] == "failed"]


def metadata_counts(
    stages: list[dict[str, Any]],
    attempts: list[dict[str, Any]],
    cascades: list[dict[str, Any]],
) -> dict[str, int]:
    return {
        "failedStageErrorTypeMissing": missing(stages, "errorType"),
        "failedStageDispositionMissing": missing(stages, "errorDisposition"),
        "failedAttemptErrorTypeMissing": missing(attempts, "errorType"),
        "failedAttemptDispositionMissing": missing(attempts, "errorDisposition"),
        "failedCascadeErrorTypeMissing": missing(cascades, "errorType"),
        "failedCascadeDispositionMissing": missing(cascades, "errorDisposition"),
    }


def link_counts(
    attempt_links: list[dict[str, Any]],
    cascade_links: list[dict[str, Any]],
    cascades: list[dict[str, Any]],
) -> dict[str, int]:
    return {
        "failedAttemptsWithStage": sum(1 for row in attempt_links if row["matched"]),
        "failedCascadesWithEvidence": sum(1 for row in cascade_links if row["matched"]),
        "failedAttemptMissingStage": sum(1 for row in attempt_links if not row["matched"]),
        "failedCascadeMissingEvidence": sum(1 for row in cascade_links if not row["matched"]),
        "stageAttemptErrorTypeMismatches": sum(1 for row in attempt_links if row["errorMismatch"]),
        "stageAttemptDispositionMismatches": sum(1 for row in attempt_links if row["dispositionMismatch"]),
        "cascadeErrorTypeMismatches": sum(1 for row in cascade_links if row["errorMismatch"]),
        "cascadeDispositionMismatches": sum(1 for row in cascade_links if row["dispositionMismatch"]),
        "cascadeFailureScopeMissing": missing(cascades, "failureScope"),
        "cascadeRetryAllowedMissing": missing(cascades, "retryAllowed"),
        "cascadeRetryStopReasonMissing": missing(cascades, "retryStopReason"),
    }


def attempt_link(attempt: dict[str, Any], stages: list[dict[str, Any]]) -> dict[str, Any]:
    matches = [
        row for row in stages
        if row["reference"] == attempt["reference"]
        and ((attempt["attemptId"] and row["attemptId"] == attempt["attemptId"]) or not attempt["attemptId"])
    ]
    return match_result(attempt, matches)


def cascade_link(
    cascade: dict[str, Any],
    attempts: list[dict[str, Any]],
    stages: list[dict[str, Any]],
) -> dict[str, Any]:
    matches = [
        row for row in [*attempts, *stages]
        if row["reference"] == cascade["reference"]
    ]
    return match_result(cascade, matches)


def match_result(source: dict[str, Any], matches: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "matched": bool(matches),
        "errorMismatch": bool(matches)
        and source["errorType"]
        and not any(row["errorType"] == source["errorType"] for row in matches),
        "dispositionMismatch": bool(matches)
        and source["errorDisposition"]
        and not any(row["errorDisposition"] == source["errorDisposition"] for row in matches),
    }


def missing(rows: list[dict[str, Any]], field: str) -> int:
    return sum(1 for row in rows if not row[field])


def failure_profile(prefix: str, row: dict[str, Any]) -> str:
    detail = row["stage"] or row["protocol"] or row["adapterKind"] or "unknown"
    scope = row["failureScope"] or "none"
    return (
        f"{prefix}:{detail}:"
        f"{row['errorType'] or 'missing'}:"
        f"{row['errorDisposition'] or 'missing'}:{scope}"
    )


def failure_clean(counts: dict[str, Any]) -> bool:
    return (
        counts["eventReports"] == 1
        and counts["runtimePass"] == 1
        and all(int(counts[key]) == 0 for key in BLOCKERS)
    )


def failure_classification(counts: dict[str, Any]) -> str:
    for key, label in [
        ("failedAttemptMissingStage", "attempt-stage-missing"),
        ("failedCascadeMissingEvidence", "cascade-evidence-missing"),
        ("stageAttemptErrorTypeMismatches", "stage-attempt-error-mismatch"),
        ("stageAttemptDispositionMismatches", "stage-attempt-disposition-mismatch"),
        ("cascadeErrorTypeMismatches", "cascade-error-mismatch"),
        ("cascadeDispositionMismatches", "cascade-disposition-mismatch"),
        ("cascadeFailureScopeMissing", "cascade-scope-missing"),
    ]:
        if int(counts[key]):
            return label
    return "failure-propagation-incomplete"


def failure_propagation_totals(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "runs": len(rows),
        "cleanRuns": sum(1 for row in rows if row["clean"]),
        "failedRuns": sum(1 for row in rows if not row["clean"]),
        "classifications": aggregate(row["classification"] for row in rows),
        **{
            key: sum(int(row["current"].get(key) or 0) for row in rows)
            for key in COUNT_FIELDS
            if key not in {"runs", "cleanRuns", "failedRuns"}
        },
        "stageFailureProfiles": merge_count_rows(row["current"]["stageFailureProfiles"] for row in rows),
        "attemptFailureProfiles": merge_count_rows(row["current"]["attemptFailureProfiles"] for row in rows),
        "cascadeFailureProfiles": merge_count_rows(row["current"]["cascadeFailureProfiles"] for row in rows),
    }


def failure_conclusion(totals: dict[str, Any]) -> dict[str, Any]:
    clean = totals["runs"] > 0 and totals["failedRuns"] == 0
    return {
        "status": "clean" if clean else "failure-propagation-needs-evidence",
        "nextAction": "return-to-runtime-surface" if clean else "inspect-failure-propagation",
        "plannerPenaltySafe": False,
        "qualityPenaltySafe": False,
    }


def write_failure_propagation_summary(output_dir: Path, summary: dict[str, Any]) -> None:
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    totals = summary["totals"]
    lines = [
        "# VM Private Runtime Failure Propagation Surface",
        "",
        f"- label: `{summary['label']}`",
        f"- status: `{summary['conclusion']['status']}`",
        f"- failed stages: `{totals['failedStages']}`",
        f"- failed attempts: `{totals['failedAttempts']}`",
        f"- failed cascades: `{totals['failedCascades']}`",
        f"- attempt missing stage: `{totals['failedAttemptMissingStage']}`",
        f"- cascade missing evidence: `{totals['failedCascadeMissingEvidence']}`",
    ]
    (output_dir / "summary.md").write_text("\n".join(lines) + "\n")


def failure_print(output_dir: Path, summary: dict[str, Any]) -> dict[str, Any]:
    totals = summary["totals"]
    return {
        "outputDir": str(output_dir),
        "status": summary["conclusion"]["status"],
        "runs": totals["runs"],
        "failedAttempts": totals["failedAttempts"],
        "failedCascades": totals["failedCascades"],
    }


def aggregate(values: Any) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for value in values:
        key = str(value or "none")
        counts[key] = counts.get(key, 0) + 1
    return count_rows(counts)


def merge_count_rows(groups: Any) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for group in groups:
        for row in group:
            key = str(row.get("key") or "none")
            counts[key] = counts.get(key, 0) + int(row.get("count") or 0)
    return count_rows(counts)


def count_rows(counts: dict[str, int]) -> list[dict[str, Any]]:
    return [{"key": key, "count": count} for key, count in sorted(counts.items())]


def empty_privacy_flags() -> dict[str, bool]:
    return {
        "rawLogsStored": False,
        "rawPacketsStored": False,
        "rawSecretsStored": False,
        "responseBodiesStored": False,
        "identityInformationSent": False,
    }


def load_optional_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text())
