from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from common import Lab, validate_name
from private_runtime_lib.briefs import fields


QUALITY_SCHEMA = "dynet-vm-private-runtime-outbound-candidate-quality-surface/v1alpha1"
REPEAT_SCHEMA = "dynet-vm-private-runtime-repeat/v1alpha1"
SUCCESS_KINDS = {"tcp-session-established", "udp-session-established", "dns-resolve-completed"}
COUNT_FIELDS = """
runs cleanRuns failedRuns eventReports runtimePass events candidateSets
qualityCandidateSets staticCandidateSets candidateRows qualityRows
candidatesWithQuality selectedWithQuality selectedBest selectedBehind
primaryQualityCandidateSets primarySelectedBest primarySelectedBehind
fallbackQualityCandidateSets fallbackSelectedBest fallbackSelectedBehind
recoveredSelectedBehind unrecoveredSelectedBehind jsonParseFailures
missingQuality missingScore missingReason staleQuality missingMatchScope
selectedMissingQuality
""".split()
BLOCKERS = """
jsonParseFailures missingQuality missingScore missingReason staleQuality
missingMatchScope selectedMissingQuality primarySelectedBehind
unrecoveredSelectedBehind
""".split()


def command_candidate_quality_surface(_lab: Lab, args: argparse.Namespace) -> None:
    label = validate_name(args.label or "candidate-quality-surface", "label")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = build_candidate_quality_summary(
        label,
        output_dir,
        [Path(item) for item in args.input],
    )
    write_candidate_quality_summary(output_dir, summary)
    print(json.dumps(quality_print(output_dir, summary), sort_keys=True))


def build_candidate_quality_summary(
    label: str,
    output_dir: Path,
    inputs: list[Path],
) -> dict[str, Any]:
    rows = [candidate_quality_row(path) for path in expand_inputs(inputs)]
    totals = candidate_quality_totals(rows)
    return {
        "schema": QUALITY_SCHEMA,
        "label": label,
        "outputDir": str(output_dir),
        "runs": rows,
        "totals": totals,
        "conclusion": quality_conclusion(totals),
        "privacy": empty_privacy_flags(),
        "policy": {
            "plannerPenaltySafe": False,
            "qualityPenaltySafe": False,
            "reason": "Candidate quality selection is observability proof, not penalty proof.",
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


def candidate_quality_row(run_dir: Path) -> dict[str, Any]:
    summary = load_optional_json(run_dir / "summary.json")
    current = quality_counts(load_optional_json(run_dir / "runtime-report.json"))
    clean = quality_clean(current)
    return {
        "label": summary.get("label") or run_dir.name,
        "path": str(run_dir),
        "classification": "clean" if clean else quality_classification(current),
        "clean": clean,
        "current": current,
    }


def quality_counts(report: dict[str, Any]) -> dict[str, Any]:
    raw_events = report.get("events")
    events = event_rows(raw_events or [])
    candidate_sets = [row for row in events if row["kind"] == "outbound-candidate-set"]
    quality_sets = [row for row in candidate_sets if row["strategyKey"] == "cascade-quality"]
    static_sets = [row for row in candidate_sets if row["strategyKey"] != "cascade-quality"]
    candidate_rows = [candidate for row in quality_sets for candidate in row["candidates"]]
    quality_rows = [row for row in candidate_rows if row["hasQuality"]]
    return {
        "eventReports": 1 if raw_events is not None else 0,
        "runtimePass": 1 if report.get("status") == "pass" else 0,
        "events": len(events),
        "candidateSets": len(candidate_sets),
        "qualityCandidateSets": len(quality_sets),
        "staticCandidateSets": len(static_sets),
        "candidateRows": len(candidate_rows),
        "qualityRows": len(quality_rows),
        **quality_field_counts(quality_sets, candidate_rows, quality_rows),
        **selection_quality_counts(quality_sets, events),
        "qualityReasons": aggregate(row["reason"] for row in quality_rows),
        "qualityVerdicts": aggregate(
            verdict for row in quality_rows for verdict in row["verdicts"]
        ),
        "qualityConfidences": aggregate(
            confidence for row in quality_rows for confidence in row["confidences"]
        ),
        "qualityMatchScopes": aggregate(
            scope for row in quality_rows for scope in row["matchScopes"]
        ),
        "candidateTypes": aggregate(row["type"] for row in candidate_rows),
    }


def event_rows(raw_events: list[Any]) -> list[dict[str, Any]]:
    rows = []
    for index, event in enumerate(raw_events):
        if not isinstance(event, dict):
            continue
        event_fields = fields(event)
        candidate_json = parse_candidates(event_fields.get("candidatesJson") or "")
        rows.append({
            "index": index,
            "kind": str(event.get("kind") or ""),
            "key": event_fields.get("flowId") or event_fields.get("dnsQueryId") or "",
            "status": event_fields.get("status") or "",
            "strategyKey": event_fields.get("strategyKey") or "",
            "selected": event_fields.get("selected") or "",
            "jsonParseFailed": candidate_json["parseFailed"],
            "candidates": candidate_json["rows"],
        })
    return rows


def parse_candidates(value: str) -> dict[str, Any]:
    try:
        rows = json.loads(value)
    except json.JSONDecodeError:
        return {"parseFailed": True, "rows": []}
    if not isinstance(rows, list):
        return {"parseFailed": True, "rows": []}
    return {
        "parseFailed": False,
        "rows": [candidate_quality(row) for row in rows if isinstance(row, dict)],
    }


def candidate_quality(row: dict[str, Any]) -> dict[str, Any]:
    raw_quality = row.get("quality")
    quality = raw_quality if isinstance(raw_quality, dict) else {}
    matches = [item for item in quality.get("matches", []) if isinstance(item, dict)]
    score = parse_score(quality.get("score"))
    reason = str(quality.get("reason") or "")
    stale_present = "stale" in quality
    return {
        "name": str(row.get("to") or ""),
        "type": str(row.get("type") or "unknown"),
        "hasQuality": isinstance(raw_quality, dict),
        "score": score,
        "scorePresent": score is not None,
        "reason": reason,
        "stale": bool_value(quality.get("stale")),
        "stalePresent": stale_present,
        "verdicts": sorted({
            str(item.get("verdict") or "") for item in matches if item.get("verdict")
        }),
        "confidences": sorted({
            str(item.get("confidence") or "") for item in matches if item.get("confidence")
        }),
        "matchScopes": sorted({
            str(item.get("scope") or "") for item in matches if item.get("scope")
        }),
        "matchScopeMissing": match_scope_missing(reason, matches),
    }


def match_scope_missing(reason: str, matches: list[dict[str, Any]]) -> bool:
    if reason == "no-quality-evidence":
        return False
    return not matches or any(not item.get("scope") for item in matches)


def quality_field_counts(
    quality_sets: list[dict[str, Any]],
    candidate_rows: list[dict[str, Any]],
    quality_rows: list[dict[str, Any]],
) -> dict[str, int]:
    return {
        "jsonParseFailures": sum(1 for row in quality_sets if row["jsonParseFailed"]),
        "candidatesWithQuality": len(quality_rows),
        "missingQuality": sum(1 for row in candidate_rows if not row["hasQuality"]),
        "missingScore": sum(1 for row in quality_rows if not row["scorePresent"]),
        "missingReason": sum(1 for row in quality_rows if not row["reason"]),
        "staleQuality": sum(
            1 for row in quality_rows if row["stale"] or not row["stalePresent"]
        ),
        "missingMatchScope": sum(1 for row in quality_rows if row["matchScopeMissing"]),
    }


def selection_quality_counts(
    quality_sets: list[dict[str, Any]],
    events: list[dict[str, Any]],
) -> dict[str, int]:
    selected = [selected_quality(row, events) for row in quality_sets]
    primary = [row for row in selected if not row["fallback"]]
    fallback = [row for row in selected if row["fallback"]]
    return {
        "selectedWithQuality": sum(1 for row in selected if row["selectedHasQuality"]),
        "selectedBest": sum(1 for row in selected if row["selectedBest"]),
        "selectedBehind": sum(1 for row in selected if row["selectedBehind"]),
        "primaryQualityCandidateSets": len(primary),
        "primarySelectedBest": sum(1 for row in primary if row["selectedBest"]),
        "primarySelectedBehind": sum(1 for row in primary if row["selectedBehind"]),
        "fallbackQualityCandidateSets": len(fallback),
        "fallbackSelectedBest": sum(1 for row in fallback if row["selectedBest"]),
        "fallbackSelectedBehind": sum(1 for row in fallback if row["selectedBehind"]),
        "recoveredSelectedBehind": sum(
            1 for row in selected if row["selectedBehind"] and row["recovered"]
        ),
        "unrecoveredSelectedBehind": sum(
            1 for row in selected if row["selectedBehind"] and not row["recovered"]
        ),
        "selectedMissingQuality": sum(1 for row in selected if not row["selectedHasQuality"]),
    }


def selected_quality(row: dict[str, Any], events: list[dict[str, Any]]) -> dict[str, Any]:
    selected = next(
        (candidate for candidate in row["candidates"] if candidate["name"] == row["selected"]),
        {},
    )
    scores = [
        candidate["score"]
        for candidate in row["candidates"]
        if candidate["score"] is not None
    ]
    max_score = max(scores) if scores else None
    selected_score = selected.get("score")
    selected_best = selected_score is not None and max_score is not None and selected_score == max_score
    selected_behind = selected_score is not None and max_score is not None and selected_score < max_score
    fallback = has_prior_failure(row, events)
    return {
        "selectedHasQuality": bool(selected.get("hasQuality")),
        "selectedBest": selected_best,
        "selectedBehind": selected_behind,
        "fallback": fallback,
        "recovered": fallback and selected_behind and has_later_success(row, events),
    }


def has_prior_failure(row: dict[str, Any], events: list[dict[str, Any]]) -> bool:
    return any(
        event["key"] == row["key"]
        and event["index"] < row["index"]
        and event["kind"] == "dialer-cascade-attempt-finished"
        and event["status"] == "failed"
        for event in events
    )


def has_later_success(row: dict[str, Any], events: list[dict[str, Any]]) -> bool:
    return any(
        event["key"] == row["key"]
        and event["index"] > row["index"]
        and event["kind"] in SUCCESS_KINDS
        for event in events
    )


def quality_clean(counts: dict[str, Any]) -> bool:
    return (
        counts["eventReports"] == 1
        and counts["runtimePass"] == 1
        and counts["qualityCandidateSets"] > 0
        and all(int(counts[key]) == 0 for key in BLOCKERS)
    )


def quality_classification(counts: dict[str, Any]) -> str:
    for key, label in [
        ("primarySelectedBehind", "primary-selected-behind"),
        ("unrecoveredSelectedBehind", "unrecovered-selected-behind"),
        ("missingQuality", "quality-missing"),
        ("missingScore", "quality-score-missing"),
        ("missingReason", "quality-reason-missing"),
        ("missingMatchScope", "quality-match-scope-missing"),
        ("jsonParseFailures", "candidate-quality-json-invalid"),
    ]:
        if int(counts[key]):
            return label
    return "candidate-quality-incomplete"


def candidate_quality_totals(rows: list[dict[str, Any]]) -> dict[str, Any]:
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
        "qualityReasons": merge_count_rows(row["current"]["qualityReasons"] for row in rows),
        "qualityVerdicts": merge_count_rows(row["current"]["qualityVerdicts"] for row in rows),
        "qualityConfidences": merge_count_rows(row["current"]["qualityConfidences"] for row in rows),
        "qualityMatchScopes": merge_count_rows(row["current"]["qualityMatchScopes"] for row in rows),
        "candidateTypes": merge_count_rows(row["current"]["candidateTypes"] for row in rows),
    }


def quality_conclusion(totals: dict[str, Any]) -> dict[str, Any]:
    clean = totals["runs"] > 0 and totals["failedRuns"] == 0
    return {
        "status": "clean" if clean else "candidate-quality-needs-evidence",
        "nextAction": "return-to-runtime-surface" if clean else "inspect-candidate-quality-selection",
        "plannerPenaltySafe": False,
        "qualityPenaltySafe": False,
    }


def write_candidate_quality_summary(output_dir: Path, summary: dict[str, Any]) -> None:
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    totals = summary["totals"]
    lines = [
        "# VM Private Runtime Candidate Quality Surface",
        "",
        f"- label: `{summary['label']}`",
        f"- status: `{summary['conclusion']['status']}`",
        f"- quality candidate sets: `{totals['qualityCandidateSets']}`",
        f"- selected best: `{totals['selectedBest']}`",
        f"- selected behind: `{totals['selectedBehind']}`",
        f"- recovered selected behind: `{totals['recoveredSelectedBehind']}`",
        f"- unrecovered selected behind: `{totals['unrecoveredSelectedBehind']}`",
    ]
    (output_dir / "summary.md").write_text("\n".join(lines) + "\n")


def quality_print(output_dir: Path, summary: dict[str, Any]) -> dict[str, Any]:
    totals = summary["totals"]
    return {
        "outputDir": str(output_dir),
        "status": summary["conclusion"]["status"],
        "runs": totals["runs"],
        "qualityCandidateSets": totals["qualityCandidateSets"],
        "selectedBehind": totals["selectedBehind"],
        "recoveredSelectedBehind": totals["recoveredSelectedBehind"],
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


def parse_score(value: Any) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def bool_value(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).lower() == "true"


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
