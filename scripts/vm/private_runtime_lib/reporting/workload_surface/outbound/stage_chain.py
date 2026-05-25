from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from common import Lab, validate_name
from private_runtime_lib.briefs import fields


STAGE_CHAIN_SCHEMA = "dynet-vm-private-runtime-outbound-stage-chain-surface/v1alpha1"
REPEAT_SCHEMA = "dynet-vm-private-runtime-repeat/v1alpha1"
PROFILES = {
    ("tcp-connect", "trojan"): {"tcp-connect", "trojan-tls-handshake", "trojan-request-write", "payload-decode"},
    ("tcp-connect", "vmess"): {"tcp-connect", "payload-decode"},
    ("tcp-connect", "direct"): {"tcp-connect"},
    ("udp-connect", "direct"): {"udp-connect"},
    ("dns-over-tcp", "dialer"): {"dialer-payload-decode"},
}
COUNT_FIELDS = """
runs cleanRuns failedRuns eventReports runtimePass events stageEvents
attempts knownProfileAttempts unknownProfileAttempts successAttempts
failedAttempts successMissingRequiredStages failedMissingFailureStage
stageStatusMissing stageKindMissing stageNameMissing stageReferenceMissing
stageOutboundMissing stageElapsedMissing stageFailureDispositionMissing
stageFailureErrorTypeMissing
""".split()
BLOCKERS = """
unknownProfileAttempts successMissingRequiredStages failedMissingFailureStage
stageStatusMissing stageKindMissing stageNameMissing stageReferenceMissing
stageOutboundMissing stageElapsedMissing stageFailureDispositionMissing
stageFailureErrorTypeMissing
""".split()


def command_stage_chain_surface(_lab: Lab, args: argparse.Namespace) -> None:
    label = validate_name(args.label or "stage-chain-surface", "label")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = build_stage_chain_summary(
        label,
        output_dir,
        [Path(item) for item in args.input],
    )
    write_stage_chain_summary(output_dir, summary)
    print(json.dumps(stage_chain_print(output_dir, summary), sort_keys=True))


def build_stage_chain_summary(
    label: str,
    output_dir: Path,
    inputs: list[Path],
) -> dict[str, Any]:
    rows = [stage_chain_row(path) for path in expand_inputs(inputs)]
    totals = stage_chain_totals(rows)
    return {
        "schema": STAGE_CHAIN_SCHEMA,
        "label": label,
        "outputDir": str(output_dir),
        "runs": rows,
        "totals": totals,
        "conclusion": stage_chain_conclusion(totals),
        "privacy": empty_privacy_flags(),
        "policy": {
            "plannerPenaltySafe": False,
            "qualityPenaltySafe": False,
            "reason": "Protocol stage-chain integrity is observability proof, not penalty proof.",
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


def stage_chain_row(run_dir: Path) -> dict[str, Any]:
    summary = load_optional_json(run_dir / "summary.json")
    current = stage_chain_counts(load_optional_json(run_dir / "runtime-report.json"))
    clean = stage_chain_clean(current)
    return {
        "label": summary.get("label") or run_dir.name,
        "path": str(run_dir),
        "classification": "clean" if clean else stage_chain_classification(current),
        "clean": clean,
        "current": current,
    }


def stage_chain_counts(report: dict[str, Any]) -> dict[str, Any]:
    raw_events = report.get("events")
    rows = [
        event_row(event, index)
        for index, event in enumerate(raw_events or [])
        if isinstance(event, dict)
    ]
    attempts = [row for row in rows if row["kind"] == "outbound-attempt-finished"]
    stage_rows = [row for row in rows if row["kind"] == "outbound-stage-finished"]
    stages_by_attempt = stage_index(stage_rows)
    stages_by_ref = reference_index(stage_rows)
    return {
        "eventReports": 1 if raw_events is not None else 0,
        "runtimePass": 1 if report.get("status") == "pass" else 0,
        "events": len(rows),
        "stageEvents": len(stage_rows),
        **attempt_counts(attempts, stages_by_attempt, stages_by_ref),
        **stage_field_counts(stage_rows),
        "attemptProfiles": aggregate(profile_label(row) for row in attempts),
        "stageProfiles": aggregate(stage_profile(row) for row in stage_rows),
        "missingRequiredStages": missing_required_stage_rows(attempts, stages_by_attempt),
        "failedStageProfiles": aggregate(
            stage_profile(row) for row in stage_rows if row["status"] == "failed"
        ),
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
        "elapsedPresent": bool(event_fields.get("elapsedMs")),
        "errorDispositionPresent": bool(event_fields.get("errorDisposition")),
        "errorTypePresent": bool(event_fields.get("errorType")),
    }


def stage_index(stage_rows: list[dict[str, Any]]) -> dict[tuple[str, str, str], list[dict[str, Any]]]:
    result: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for row in stage_rows:
        result.setdefault(stage_key(row), []).append(row)
    return result


def reference_index(stage_rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {}
    for row in stage_rows:
        result.setdefault(row["reference"], []).append(row)
    return result


def stage_key(row: dict[str, Any]) -> tuple[str, str, str]:
    return (row["reference"], row["outbound"], row["adapterKind"])


def attempt_counts(
    attempts: list[dict[str, Any]],
    stages_by_attempt: dict[tuple[str, str, str], list[dict[str, Any]]],
    stages_by_ref: dict[str, list[dict[str, Any]]],
) -> dict[str, int]:
    known = [row for row in attempts if profile_key(row) in PROFILES]
    return {
        "attempts": len(attempts),
        "knownProfileAttempts": len(known),
        "unknownProfileAttempts": len(attempts) - len(known),
        "successAttempts": sum(1 for row in attempts if row["status"] == "success"),
        "failedAttempts": sum(1 for row in attempts if row["status"] == "failed"),
        "successMissingRequiredStages": sum(
            1 for row in attempts if missing_required_stages(row, stages_by_attempt)
        ),
        "failedMissingFailureStage": sum(
            1 for row in attempts if failed_missing_stage(row, stages_by_attempt, stages_by_ref)
        ),
    }


def stage_field_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "stageStatusMissing": sum(1 for row in rows if not row["status"]),
        "stageKindMissing": sum(1 for row in rows if not row["adapterKind"]),
        "stageNameMissing": sum(1 for row in rows if not row["stage"]),
        "stageReferenceMissing": sum(1 for row in rows if not row["reference"]),
        "stageOutboundMissing": sum(1 for row in rows if not row["outbound"]),
        "stageElapsedMissing": sum(1 for row in rows if not row["elapsedPresent"]),
        "stageFailureDispositionMissing": sum(
            1 for row in rows if row["status"] == "failed" and not row["errorDispositionPresent"]
        ),
        "stageFailureErrorTypeMissing": sum(
            1 for row in rows if row["status"] == "failed" and not row["errorTypePresent"]
        ),
    }


def missing_required_stages(
    attempt: dict[str, Any],
    stages_by_attempt: dict[tuple[str, str, str], list[dict[str, Any]]],
) -> bool:
    if attempt["status"] != "success":
        return False
    required = PROFILES.get(profile_key(attempt))
    if not required:
        return True
    stages = {
        row["stage"]
        for row in stages_by_attempt.get(stage_key(attempt), [])
        if row["status"] == "success"
    }
    return not required.issubset(stages)


def failed_missing_stage(
    attempt: dict[str, Any],
    stages_by_attempt: dict[tuple[str, str, str], list[dict[str, Any]]],
    stages_by_ref: dict[str, list[dict[str, Any]]],
) -> bool:
    if attempt["status"] != "failed":
        return False
    if profile_key(attempt) == ("dns-over-tcp", "dialer"):
        return not any(row["status"] == "failed" for row in stages_by_ref.get(attempt["reference"], []))
    return not any(
        row["status"] == "failed"
        for row in stages_by_attempt.get(stage_key(attempt), [])
    )


def missing_required_stage_rows(
    attempts: list[dict[str, Any]],
    stages_by_attempt: dict[tuple[str, str, str], list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for attempt in attempts:
        required = PROFILES.get(profile_key(attempt))
        if attempt["status"] != "success" or not required:
            continue
        present = {
            row["stage"]
            for row in stages_by_attempt.get(stage_key(attempt), [])
            if row["status"] == "success"
        }
        for stage in sorted(required - present):
            key = f"{profile_label(attempt)}:{stage}"
            counts[key] = counts.get(key, 0) + 1
    return count_rows(counts)


def profile_key(row: dict[str, Any]) -> tuple[str, str]:
    return (row["protocol"], row["adapterKind"])


def profile_label(row: dict[str, Any]) -> str:
    protocol, adapter_kind = profile_key(row)
    return f"{protocol or 'unknown'}:{adapter_kind or 'unknown'}:{row['status'] or 'unknown'}"


def stage_profile(row: dict[str, Any]) -> str:
    return (
        f"{row['adapterKind'] or 'unknown'}:"
        f"{row['stage'] or 'unknown'}:"
        f"{row['status'] or 'unknown'}"
    )


def stage_chain_clean(counts: dict[str, Any]) -> bool:
    return (
        counts["eventReports"] == 1
        and counts["runtimePass"] == 1
        and counts["attempts"] > 0
        and counts["stageEvents"] > 0
        and all(int(counts[key]) == 0 for key in BLOCKERS)
    )


def stage_chain_classification(counts: dict[str, Any]) -> str:
    for key, label in [
        ("unknownProfileAttempts", "unknown-attempt-profile"),
        ("successMissingRequiredStages", "success-required-stage-missing"),
        ("failedMissingFailureStage", "failed-stage-missing"),
        ("stageStatusMissing", "stage-status-missing"),
        ("stageKindMissing", "stage-kind-missing"),
        ("stageNameMissing", "stage-name-missing"),
        ("stageReferenceMissing", "stage-reference-missing"),
        ("stageOutboundMissing", "stage-outbound-missing"),
        ("stageElapsedMissing", "stage-elapsed-missing"),
        ("stageFailureDispositionMissing", "stage-failure-disposition-missing"),
        ("stageFailureErrorTypeMissing", "stage-failure-error-type-missing"),
    ]:
        if int(counts[key]):
            return label
    return "stage-chain-surface-incomplete"


def stage_chain_totals(rows: list[dict[str, Any]]) -> dict[str, Any]:
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
        "attemptProfiles": merge_count_rows(row["current"]["attemptProfiles"] for row in rows),
        "stageProfiles": merge_count_rows(row["current"]["stageProfiles"] for row in rows),
        "missingRequiredStages": merge_count_rows(
            row["current"]["missingRequiredStages"] for row in rows
        ),
        "failedStageProfiles": merge_count_rows(row["current"]["failedStageProfiles"] for row in rows),
    }


def stage_chain_conclusion(totals: dict[str, Any]) -> dict[str, Any]:
    clean = totals["runs"] > 0 and totals["failedRuns"] == 0
    return {
        "status": "clean" if clean else "stage-chain-surface-needs-evidence",
        "nextAction": "return-to-runtime-surface" if clean else "inspect-protocol-stage-chain",
        "plannerPenaltySafe": False,
        "qualityPenaltySafe": False,
    }


def write_stage_chain_summary(output_dir: Path, summary: dict[str, Any]) -> None:
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    write_stage_chain_markdown(output_dir / "summary.md", summary)


def write_stage_chain_markdown(path: Path, summary: dict[str, Any]) -> None:
    totals = summary["totals"]
    lines = [
        "# VM Private Runtime Outbound Stage Chain Surface",
        "",
        f"- label: `{summary['label']}`",
        f"- status: `{summary['conclusion']['status']}`",
        f"- runs: `{totals['runs']}`",
        f"- clean runs: `{totals['cleanRuns']}`",
        f"- attempts: `{totals['attempts']}`",
        f"- stage events: `{totals['stageEvents']}`",
        f"- unknown profiles: `{totals['unknownProfileAttempts']}`",
        f"- missing success stages: `{totals['successMissingRequiredStages']}`",
        f"- failed attempts missing failed stage: `{totals['failedMissingFailureStage']}`",
        "",
        "## Runs",
        "",
    ]
    for row in summary["runs"]:
        current = row["current"]
        lines.append(
            f"- `{row['label']}` clean=`{row['clean']}` "
            f"classification=`{row['classification']}` "
            f"attempts=`{current['attempts']}` stages=`{current['stageEvents']}`"
        )
    path.write_text("\n".join(lines) + "\n")


def stage_chain_print(output_dir: Path, summary: dict[str, Any]) -> dict[str, Any]:
    totals = summary["totals"]
    return {
        "outputDir": str(output_dir),
        "status": summary["conclusion"]["status"],
        "runs": totals["runs"],
        "attempts": totals["attempts"],
        "stageEvents": totals["stageEvents"],
    }


def aggregate(values: Any) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for value in values:
        key = str(value or "unknown")
        counts[key] = counts.get(key, 0) + 1
    return count_rows(counts)


def merge_count_rows(groups: Any) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for group in groups:
        for row in group:
            key = str(row.get("key") or "unknown")
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
