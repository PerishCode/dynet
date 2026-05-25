from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from tunnel_private.quality.verify import read_failure_summary


SCHEMA = "dynet-tunnel-private-protocol-followup/v1alpha1"


def command_protocol_followup(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    reports = collect_report_paths(
        [Path(path) for path in args.report or []],
        [Path(path) for path in getattr(args, "report_dir", []) or []],
    )
    summary = protocol_followup_summary(
        Path(args.readiness) if args.readiness else None,
        [Path(path) for path in args.compare or []],
        [Path(path) for path in args.attribution or []],
        reports,
    )
    write_json(output_dir / "summary.json", summary)
    write_markdown(output_dir / "summary.md", summary)
    print(json.dumps(print_summary(output_dir, summary), sort_keys=True))
    return 0 if summary["sourceCount"] else 1


def protocol_followup_summary(
    readiness_path: Path | None,
    compare_paths: list[Path],
    attribution_paths: list[Path],
    report_paths: list[Path],
) -> dict[str, Any]:
    readiness = readiness_source(readiness_path) if readiness_path else {}
    compare = compare_summary(compare_paths)
    attribution = attribution_summary(attribution_paths)
    reports = report_summary(report_paths)
    conclusion = conclusion_summary(readiness, compare, attribution, reports)
    return {
        "schema": SCHEMA,
        "sourceCount": int(bool(readiness)) + len(compare_paths) + len(attribution_paths) + len(report_paths),
        "readiness": readiness,
        "compareEvidence": compare,
        "attributionEvidence": attribution,
        "reportEvidence": reports,
        "conclusion": conclusion,
        "privacy": {"rawSecretsStored": False, "rawLogsStored": False},
    }


def collect_report_paths(paths: list[Path], dirs: list[Path]) -> list[Path]:
    reports = list(paths)
    for directory in dirs:
        if not directory.exists():
            raise SystemExit(f"missing report directory: {directory}")
        if not directory.is_dir():
            raise SystemExit(f"report directory is not a directory: {directory}")
        reports.extend(
            path
            for path in sorted(directory.glob("*.json"))
            if probe_report_path(path)
        )
    return unique_paths(reports)


def probe_report_path(path: Path) -> bool:
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return False
    return str(data.get("schema") or "").startswith("dynet-probe/")


def unique_paths(paths: list[Path]) -> list[Path]:
    unique = []
    seen = set()
    for path in paths:
        key = str(path)
        if key not in seen:
            seen.add(key)
            unique.append(path)
    return unique


def readiness_source(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    summary = load_json(path)
    followup = summary.get("protocolFollowup") or {}
    conclusion = summary.get("conclusion") or {}
    return {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "status": str(summary.get("status") or ""),
        "readyForMainlineAdapterWork": bool(conclusion.get("readyForMainlineAdapterWork")),
        "followupOpen": bool(followup.get("open")),
        "readMarkerCount": int(followup.get("readMarkerCount") or 0),
        "readMarkers": list(followup.get("readMarkers") or []),
        "nextProof": str(followup.get("nextProof") or ""),
    }


def compare_summary(paths: list[Path]) -> dict[str, Any]:
    sources = [compare_source(path) for path in paths]
    return {
        "sourceCount": len(sources),
        "failures": sum(int(source["failures"]) for source in sources),
        "readMarkerCount": sum(int(source["readMarkerCount"]) for source in sources),
        "readMarkers": merge_marker_rows([source["readMarkers"] for source in sources]),
        "signatures": [signature for source in sources for signature in source["signatures"]],
        "sources": sources,
    }


def compare_source(path: Path) -> dict[str, Any]:
    summary = load_json(path)
    signatures = [
        signature
        for signature in summary.get("failureSignatures", [])
        if isinstance(signature, dict)
    ]
    read_signatures = [signature_row(signature) for signature in signatures if signature_read_markers(signature)]
    marker_counts = read_marker_counts(summary.get("markerSummary") or {})
    return {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "failures": int((summary.get("totals") or {}).get("failures") or 0),
        "readMarkerCount": sum(marker_counts.values()),
        "readMarkers": marker_rows(marker_counts),
        "signatures": read_signatures,
    }


def signature_row(signature: dict[str, Any]) -> dict[str, Any]:
    return {
        "label": str(signature.get("label") or ""),
        "protocol": str(signature.get("protocol") or ""),
        "failureScope": str(signature.get("failureScope") or ""),
        "failedStage": str(signature.get("failedStage") or ""),
        "markers": [str(marker) for marker in signature.get("markers", [])],
        "matrixPaths": [str(path) for path in signature.get("matrixPaths", [])],
        "targets": [str(target) for target in signature.get("targets", [])],
    }


def attribution_summary(paths: list[Path]) -> dict[str, Any]:
    sources = [attribution_source(path) for path in paths]
    return {
        "sourceCount": len(sources),
        "readStageCount": sum(int(source["readStageCount"]) for source in sources),
        "readStageFailures": sum(int(source["readStageFailures"]) for source in sources),
        "stages": merge_stage_rows([source["stages"] for source in sources]),
        "sources": sources,
    }


def attribution_source(path: Path) -> dict[str, Any]:
    summary = load_json(path)
    stages = [
        stage
        for stage in summary.get("stageLatencyMs", [])
        if isinstance(stage, dict) and read_marker(str(stage.get("key") or ""))
    ]
    return {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "readStageCount": sum(int(stage.get("count") or 0) for stage in stages),
        "readStageFailures": sum(int(stage.get("failures") or 0) for stage in stages),
        "stages": [
            {
                "key": str(stage.get("key") or ""),
                "count": int(stage.get("count") or 0),
                "failures": int(stage.get("failures") or 0),
                "latencyMs": stage.get("latencyMs") or {},
            }
            for stage in stages
        ],
    }


def report_summary(paths: list[Path]) -> dict[str, Any]:
    sources = [report_source(path) for path in paths]
    read_failures = [
        source["readFailure"]
        for source in sources
        if isinstance(source.get("readFailure"), dict) and source["readFailure"]
    ]
    unclassified = [item for item in read_failures if not classified_read_failure(item)]
    return {
        "sourceCount": len(sources),
        "readStageCount": sum(int(source["readStageCount"]) for source in sources),
        "readStageFailures": sum(int(source["readStageFailures"]) for source in sources),
        "pendingRetriesMax": max((int(source["pendingRetriesMax"]) for source in sources), default=0),
        "readFailureCount": len(read_failures),
        "readFailureClassifiedCount": len(read_failures) - len(unclassified),
        "readFailureUnclassifiedCount": len(unclassified),
        "readFailureMarkers": value_rows(read_failures, "marker"),
        "readFailureContexts": value_rows(read_failures, "context"),
        "readFailureDispositions": value_rows(read_failures, "disposition"),
        "stages": merge_stage_rows([source["stages"] for source in sources]),
        "sources": sources,
    }


def report_source(path: Path) -> dict[str, Any]:
    report = load_json(path)
    read_failure = read_failure_summary(report)
    stages = []
    for event in report.get("events", []):
        if not isinstance(event, dict) or event.get("kind") != "outbound-stage-finished":
            continue
        fields = event.get("fields")
        if not isinstance(fields, dict):
            continue
        key = str(fields.get("stage") or "")
        if not read_marker(key):
            continue
        stages.append({
            "key": key,
            "outbound": str(fields.get("outbound") or ""),
            "count": 1,
            "failures": 1 if str(fields.get("status") or "") == "failed" else 0,
            "pendingRetriesMax": int_or_zero(fields.get("pendingRetries")),
        })
    return {
        "path": str(path),
        "schema": str(report.get("schema") or ""),
        "status": str(report.get("status") or ""),
        "readStageCount": len(stages),
        "readStageFailures": sum(int(stage["failures"]) for stage in stages),
        "pendingRetriesMax": max((int(stage["pendingRetriesMax"]) for stage in stages), default=0),
        "readFailure": read_failure,
        "stages": stages,
    }


def conclusion_summary(
    readiness: dict[str, Any],
    compare: dict[str, Any],
    attribution: dict[str, Any],
    reports: dict[str, Any],
) -> dict[str, Any]:
    followup_open = bool(readiness.get("followupOpen")) or int(compare["readMarkerCount"]) > 0
    current_read_count = int(attribution["readStageCount"]) + int(reports["readStageCount"])
    current_failures = int(attribution["readStageFailures"]) + int(reports["readStageFailures"])
    current_clean = current_read_count > 0 and current_failures == 0
    read_failure_count = int(reports["readFailureCount"])
    read_failure_unclassified = int(reports["readFailureUnclassifiedCount"])
    status = protocol_status(followup_open, current_read_count, current_failures)
    return {
        "status": status,
        "followupOpen": followup_open,
        "currentReadStageCount": current_read_count,
        "currentReadStageFailures": current_failures,
        "currentReadClean": current_clean,
        "readFailureCount": read_failure_count,
        "readFailureUnclassifiedCount": read_failure_unclassified,
        "readFailureClassificationClean": read_failure_unclassified == 0,
        "nextProof": next_proof(status),
    }


def protocol_status(followup_open: bool, current_read_count: int, current_failures: int) -> str:
    if current_failures > 0:
        return "current-read-failure"
    if followup_open and current_read_count > 0:
        return "historical-marker-current-artifacts-clean"
    if followup_open:
        return "needs-current-stage-evidence"
    return "no-followup"


def next_proof(status: str) -> str:
    if status == "current-read-failure":
        return "fix-or-classify-current-runtime-read-failure"
    if status == "historical-marker-current-artifacts-clean":
        return "fresh-repeat-optional-before-closing-followup"
    if status == "needs-current-stage-evidence":
        return "collect-runtime-stage-repeat-for-read-marker"
    return "no-current-protocol-follow-up"


def signature_read_markers(signature: dict[str, Any]) -> list[str]:
    return [str(marker) for marker in signature.get("markers", []) if read_marker(str(marker))]


def read_marker_counts(markers: dict[str, Any]) -> dict[str, int]:
    return {str(key): int(value) for key, value in markers.items() if read_marker(str(key))}


def marker_rows(markers: dict[str, int]) -> list[dict[str, Any]]:
    return [{"key": key, "count": markers[key]} for key in sorted(markers)]


def value_rows(items: list[dict[str, Any]], field: str) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for item in items:
        value = item.get(field)
        if value is None:
            continue
        key = str(value)
        counts[key] = counts.get(key, 0) + 1
    return marker_rows(counts)


def classified_read_failure(item: dict[str, Any]) -> bool:
    return bool(item.get("marker") or item.get("disposition") or item.get("protocolStage"))


def merge_marker_rows(row_sets: list[list[dict[str, Any]]]) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for rows in row_sets:
        for row in rows:
            key = str(row.get("key") or "")
            counts[key] = counts.get(key, 0) + int(row.get("count") or 0)
    return marker_rows(counts)


def merge_stage_rows(row_sets: list[list[dict[str, Any]]]) -> list[dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for row_set in row_sets:
        for row in row_set:
            key = str(row.get("key") or "")
            current = rows.setdefault(key, {"key": key, "count": 0, "failures": 0})
            current["count"] += int(row.get("count") or 0)
            current["failures"] += int(row.get("failures") or 0)
            if row.get("latencyMs"):
                current["latencyMs"] = row["latencyMs"]
            if row.get("pendingRetriesMax") is not None:
                current["pendingRetriesMax"] = max(
                    int(current.get("pendingRetriesMax") or 0),
                    int(row.get("pendingRetriesMax") or 0),
                )
    return [rows[key] for key in sorted(rows)]


def read_marker(key: str) -> bool:
    tokens = ["read", "eof", "response-header", "stream-first-read", "pending", "short"]
    return any(token in key for token in tokens)


def int_or_zero(value: Any) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise SystemExit(f"missing input artifact: {path}")
    return json.loads(path.read_text())


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True))


def print_summary(output_dir: Path, summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "outputDir": str(output_dir),
        "status": summary["conclusion"]["status"],
        "currentReadStageCount": summary["conclusion"]["currentReadStageCount"],
        "currentReadStageFailures": summary["conclusion"]["currentReadStageFailures"],
        "readFailureCount": summary["reportEvidence"]["readFailureCount"],
        "readFailureUnclassified": summary["reportEvidence"]["readFailureUnclassifiedCount"],
        "readMarkerCount": summary["compareEvidence"]["readMarkerCount"],
    }


def write_markdown(path: Path, summary: dict[str, Any]) -> None:
    conclusion = summary["conclusion"]
    lines = [
        "# Tunnel/Private Protocol Follow-Up",
        "",
        f"- status: `{conclusion['status']}`",
        f"- follow-up open: `{conclusion['followupOpen']}`",
        f"- current read stage count: `{conclusion['currentReadStageCount']}`",
        f"- current read stage failures: `{conclusion['currentReadStageFailures']}`",
        f"- current read clean: `{conclusion['currentReadClean']}`",
        f"- read failure classification clean: `{conclusion['readFailureClassificationClean']}`",
        f"- next proof: `{conclusion['nextProof']}`",
        "",
        "## Markers",
        "",
    ]
    for marker in summary["compareEvidence"]["readMarkers"]:
        lines.append(f"- `{marker['key']}` count=`{marker['count']}`")
    lines.extend(["", "## Read Failures", ""])
    for marker in summary["reportEvidence"]["readFailureMarkers"]:
        lines.append(f"- marker `{marker['key']}` count=`{marker['count']}`")
    for context in summary["reportEvidence"].get("readFailureContexts", []):
        lines.append(f"- context `{context['key']}` count=`{context['count']}`")
    for disposition in summary["reportEvidence"]["readFailureDispositions"]:
        lines.append(f"- disposition `{disposition['key']}` count=`{disposition['count']}`")
    lines.extend(["", "## Current Stages", ""])
    for stage in summary["attributionEvidence"]["stages"] + summary["reportEvidence"]["stages"]:
        lines.append(
            f"- `{stage['key']}` count=`{stage['count']}` failures=`{stage['failures']}`"
        )
    path.write_text("\n".join(lines) + "\n")
