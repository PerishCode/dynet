from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from common import Lab, validate_name
from private_runtime_lib.briefs import fields


CANDIDATE_SCHEMA = "dynet-vm-private-runtime-outbound-candidate-set-surface/v1alpha1"
REPEAT_SCHEMA = "dynet-vm-private-runtime-repeat/v1alpha1"
VALID_SCOPES = {"tcp-route", "dialer-bound"}
COUNT_FIELDS = """
runs cleanRuns failedRuns eventReports runtimePass events candidateSets
tcpRouteCandidateSets dialerBoundCandidateSets missingScope missingSelected
missingCandidateCount candidateCountMismatches selectedMissingFromList
selectedMissingFromJson jsonCandidateCountMismatches missingStrategyFields
missingPlan missingGraph missingEgress routeCandidateMissingRoute
dialerCandidateMissingCascadeSelected dialerCandidateMissingCascadeAttempt
jsonParseFailures candidatesWithQuality selectedWithQuality
""".split()
BLOCKERS = """
missingScope missingSelected missingCandidateCount candidateCountMismatches
selectedMissingFromList selectedMissingFromJson jsonCandidateCountMismatches
missingStrategyFields missingPlan missingGraph missingEgress
routeCandidateMissingRoute dialerCandidateMissingCascadeSelected
dialerCandidateMissingCascadeAttempt jsonParseFailures
""".split()


def command_candidate_set_surface(_lab: Lab, args: argparse.Namespace) -> None:
    label = validate_name(args.label or "candidate-set-surface", "label")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = build_candidate_set_summary(
        label,
        output_dir,
        [Path(item) for item in args.input],
    )
    write_candidate_set_summary(output_dir, summary)
    print(json.dumps(candidate_print(output_dir, summary), sort_keys=True))


def build_candidate_set_summary(
    label: str,
    output_dir: Path,
    inputs: list[Path],
) -> dict[str, Any]:
    rows = [candidate_set_row(path) for path in expand_inputs(inputs)]
    totals = candidate_set_totals(rows)
    return {
        "schema": CANDIDATE_SCHEMA,
        "label": label,
        "outputDir": str(output_dir),
        "runs": rows,
        "totals": totals,
        "conclusion": candidate_conclusion(totals),
        "privacy": empty_privacy_flags(),
        "policy": {
            "plannerPenaltySafe": False,
            "qualityPenaltySafe": False,
            "reason": "Candidate-set integrity is observability proof, not penalty proof.",
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


def candidate_set_row(run_dir: Path) -> dict[str, Any]:
    summary = load_optional_json(run_dir / "summary.json")
    current = candidate_counts(load_optional_json(run_dir / "runtime-report.json"))
    clean = candidate_clean(current)
    return {
        "label": summary.get("label") or run_dir.name,
        "path": str(run_dir),
        "classification": "clean" if clean else candidate_classification(current),
        "clean": clean,
        "current": current,
    }


def candidate_counts(report: dict[str, Any]) -> dict[str, Any]:
    raw_events = report.get("events")
    events = [
        event_row(event, index)
        for index, event in enumerate(raw_events or [])
        if isinstance(event, dict)
    ]
    candidates = [row for row in events if row["kind"] == "outbound-candidate-set"]
    return {
        "eventReports": 1 if raw_events is not None else 0,
        "runtimePass": 1 if report.get("status") == "pass" else 0,
        "events": len(events),
        "candidateSets": len(candidates),
        "tcpRouteCandidateSets": count_scope(candidates, "tcp-route"),
        "dialerBoundCandidateSets": count_scope(candidates, "dialer-bound"),
        **candidate_field_counts(candidates),
        **candidate_followup_counts(candidates, events),
        "scopes": aggregate(row["scope"] for row in candidates),
        "candidateCounts": aggregate(str(row["candidateCount"]) for row in candidates),
        "candidateTypes": aggregate(item for row in candidates for item in row["candidateTypes"]),
        "strategyKeys": aggregate(row["strategyKey"] for row in candidates),
        "selectors": aggregate(row["selector"] for row in candidates),
    }


def event_row(event: dict[str, Any], index: int) -> dict[str, Any]:
    event_fields = fields(event)
    candidate_json = parse_candidates_json(event_fields.get("candidatesJson") or "")
    return {
        "index": index,
        "kind": str(event.get("kind") or ""),
        "key": event_fields.get("flowId") or event_fields.get("dnsQueryId") or "",
        "scope": event_fields.get("scope") or "",
        "selected": event_fields.get("selected") or "",
        "candidateCount": parse_int(event_fields.get("candidateCount")),
        "candidateList": split_candidates(event_fields.get("candidates") or ""),
        "json": candidate_json,
        "candidateTypes": candidate_json["types"],
        "strategyKey": event_fields.get("strategyKey") or "",
        "strategySource": event_fields.get("strategySource") or "",
        "strategyVersion": event_fields.get("strategyVersion") or "",
        "selector": event_fields.get("selector") or "",
        "selectedEdgeType": event_fields.get("selectedEdgeType") or "",
        "plan": event_fields.get("plan") or "",
    }


def candidate_field_counts(candidates: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "missingScope": sum(1 for row in candidates if row["scope"] not in VALID_SCOPES),
        "missingSelected": sum(1 for row in candidates if not row["selected"]),
        "missingCandidateCount": sum(1 for row in candidates if row["candidateCount"] <= 0),
        "candidateCountMismatches": sum(1 for row in candidates if list_count_mismatch(row)),
        "selectedMissingFromList": sum(1 for row in candidates if not selected_in_list(row)),
        "selectedMissingFromJson": sum(1 for row in candidates if not selected_in_json(row)),
        "jsonCandidateCountMismatches": sum(1 for row in candidates if json_count_mismatch(row)),
        "missingStrategyFields": sum(1 for row in candidates if missing_strategy(row)),
        "missingPlan": sum(1 for row in candidates if not row["plan"]),
        "jsonParseFailures": sum(1 for row in candidates if row["json"]["parseFailed"]),
        "candidatesWithQuality": sum(row["json"]["qualityCount"] for row in candidates),
        "selectedWithQuality": sum(1 for row in candidates if selected_has_quality(row)),
    }


def candidate_followup_counts(
    candidates: list[dict[str, Any]],
    events: list[dict[str, Any]],
) -> dict[str, int]:
    return {
        "missingGraph": sum(
            1 for row in candidates
            if not has_later(events, row, "outbound-graph-selected")
        ),
        "missingEgress": sum(
            1 for row in candidates
            if not has_later(events, row, "outbound-egress-passed")
        ),
        "routeCandidateMissingRoute": sum(
            1 for row in candidates
            if row["scope"] == "tcp-route" and not has_any(events, row, "route-matched")
        ),
        "dialerCandidateMissingCascadeSelected": sum(
            1 for row in candidates
            if row["scope"] == "dialer-bound"
            and not has_later_any_scope(events, row, "dialer-cascade-selected")
        ),
        "dialerCandidateMissingCascadeAttempt": sum(
            1 for row in candidates
            if row["scope"] == "dialer-bound"
            and not has_any(events, row, "dialer-cascade-attempt-started")
        ),
    }


def has_any(events: list[dict[str, Any]], candidate: dict[str, Any], kind: str) -> bool:
    return any(
        row["kind"] == kind
        and row["key"]
        and row["key"] == candidate["key"]
        for row in events
    )


def has_later(events: list[dict[str, Any]], candidate: dict[str, Any], kind: str) -> bool:
    return any(
        row["kind"] == kind
        and row["key"]
        and row["key"] == candidate["key"]
        and row["scope"] == candidate["scope"]
        and row["index"] > candidate["index"]
        for row in events
    )


def has_later_any_scope(
    events: list[dict[str, Any]],
    candidate: dict[str, Any],
    kind: str,
) -> bool:
    return any(
        row["kind"] == kind
        and row["key"]
        and row["key"] == candidate["key"]
        and row["index"] > candidate["index"]
        for row in events
    )


def list_count_mismatch(row: dict[str, Any]) -> bool:
    return row["candidateCount"] > 0 and row["candidateCount"] != len(row["candidateList"])


def json_count_mismatch(row: dict[str, Any]) -> bool:
    return not row["json"]["parseFailed"] and row["candidateCount"] != row["json"]["count"]


def selected_in_list(row: dict[str, Any]) -> bool:
    return bool(row["selected"]) and row["selected"] in row["candidateList"]


def selected_in_json(row: dict[str, Any]) -> bool:
    return bool(row["selected"]) and row["selected"] in row["json"]["names"]


def selected_has_quality(row: dict[str, Any]) -> bool:
    selected = row["selected"]
    return bool(selected) and selected in row["json"]["qualityNames"]


def missing_strategy(row: dict[str, Any]) -> bool:
    return not all([
        row["strategyKey"],
        row["strategySource"],
        row["strategyVersion"],
        row["selector"],
        row["selectedEdgeType"],
    ])


def split_candidates(value: str) -> list[str]:
    return [item for item in value.split(",") if item]


def parse_candidates_json(value: str) -> dict[str, Any]:
    try:
        rows = json.loads(value)
    except json.JSONDecodeError:
        return {"parseFailed": True, "count": 0, "names": set(), "qualityNames": set(), "qualityCount": 0, "types": []}
    if not isinstance(rows, list):
        return {"parseFailed": True, "count": 0, "names": set(), "qualityNames": set(), "qualityCount": 0, "types": []}
    names = {str(row.get("to") or "") for row in rows if isinstance(row, dict)}
    quality_names = {
        str(row.get("to") or "")
        for row in rows
        if isinstance(row, dict) and isinstance(row.get("quality"), dict)
    }
    return {
        "parseFailed": False,
        "count": len(rows),
        "names": {name for name in names if name},
        "qualityNames": {name for name in quality_names if name},
        "qualityCount": len(quality_names),
        "types": sorted({
            str(row.get("type") or "unknown")
            for row in rows
            if isinstance(row, dict)
        }),
    }


def candidate_clean(counts: dict[str, Any]) -> bool:
    return (
        counts["eventReports"] == 1
        and counts["runtimePass"] == 1
        and counts["candidateSets"] > 0
        and all(int(counts[key]) == 0 for key in BLOCKERS)
    )


def candidate_classification(counts: dict[str, Any]) -> str:
    for field, label in [
        ("missingScope", "candidate-scope-missing"),
        ("missingSelected", "candidate-selected-missing"),
        ("candidateCountMismatches", "candidate-count-mismatch"),
        ("selectedMissingFromList", "selected-not-in-candidates"),
        ("missingGraph", "candidate-graph-missing"),
        ("missingEgress", "candidate-egress-missing"),
    ]:
        if int(counts[field]):
            return label
    return "candidate-set-incomplete"


def candidate_set_totals(rows: list[dict[str, Any]]) -> dict[str, Any]:
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
        "scopes": merge_count_rows(row["current"]["scopes"] for row in rows),
        "candidateCounts": merge_count_rows(row["current"]["candidateCounts"] for row in rows),
        "candidateTypes": merge_count_rows(row["current"]["candidateTypes"] for row in rows),
        "strategyKeys": merge_count_rows(row["current"]["strategyKeys"] for row in rows),
        "selectors": merge_count_rows(row["current"]["selectors"] for row in rows),
    }


def candidate_conclusion(totals: dict[str, Any]) -> dict[str, Any]:
    clean = totals["runs"] > 0 and totals["failedRuns"] == 0
    return {
        "status": "clean" if clean else "candidate-set-surface-needs-evidence",
        "nextAction": "return-to-runtime-surface" if clean else "inspect-candidate-set-chain",
        "plannerPenaltySafe": False,
        "qualityPenaltySafe": False,
    }


def write_candidate_set_summary(output_dir: Path, summary: dict[str, Any]) -> None:
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    write_candidate_markdown(output_dir / "summary.md", summary)


def write_candidate_markdown(path: Path, summary: dict[str, Any]) -> None:
    totals = summary["totals"]
    lines = [
        "# VM Private Runtime Outbound Candidate Set Surface",
        "",
        f"- label: `{summary['label']}`",
        f"- status: `{summary['conclusion']['status']}`",
        f"- runs: `{totals['runs']}`",
        f"- candidate sets: `{totals['candidateSets']}`",
        f"- scopes: `{totals['scopes']}`",
        f"- missing graph: `{totals['missingGraph']}`",
        f"- missing egress: `{totals['missingEgress']}`",
        f"- selected missing from list: `{totals['selectedMissingFromList']}`",
    ]
    path.write_text("\n".join(lines) + "\n")


def candidate_print(output_dir: Path, summary: dict[str, Any]) -> dict[str, Any]:
    totals = summary["totals"]
    return {
        "outputDir": str(output_dir),
        "status": summary["conclusion"]["status"],
        "runs": totals["runs"],
        "candidateSets": totals["candidateSets"],
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


def count_scope(rows: list[dict[str, Any]], scope: str) -> int:
    return sum(1 for row in rows if row["scope"] == scope)


def count_rows(counts: dict[str, int]) -> list[dict[str, Any]]:
    return [{"key": key, "count": count} for key, count in sorted(counts.items())]


def parse_int(value: Any) -> int:
    try:
        return int(str(value or "0"))
    except ValueError:
        return 0


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
