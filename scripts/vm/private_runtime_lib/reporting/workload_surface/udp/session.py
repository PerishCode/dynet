from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from common import Lab, validate_name
from private_runtime_lib.briefs import fields


UDP_SESSION_SCHEMA = "dynet-vm-private-runtime-udp-session-surface/v1alpha1"
REPEAT_SCHEMA = "dynet-vm-private-runtime-repeat/v1alpha1"
COUNT_KEYS = [
    "sessions",
    "reportedSessions",
    "startedSessions",
    "attributedSessions",
    "connectingSessions",
    "establishedSessions",
    "payloadSentSessions",
    "payloadReceivedSessions",
    "payloadBidirectionalSessions",
    "closedSessions",
    "closedWithByteTotals",
    "failedSessions",
    "deniedSessions",
    "failedEvents",
    "deniedEvents",
    "sentEvents",
    "receivedEvents",
    "sentBytes",
    "receivedBytes",
    "reportedUpstreamBytes",
    "reportedDownstreamBytes",
    "reportedFailures",
    "reportedDroppedPackets",
]


def command_udp_session_surface(_lab: Lab, args: argparse.Namespace) -> None:
    label = validate_name(args.label or "udp-session-surface", "label")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = build_udp_session_summary(
        label,
        output_dir,
        [Path(item) for item in args.input],
    )
    write_udp_session_summary(output_dir, summary)
    print(json.dumps(udp_session_print(output_dir, summary), sort_keys=True))


def build_udp_session_summary(
    label: str,
    output_dir: Path,
    inputs: list[Path],
) -> dict[str, Any]:
    rows = [udp_session_row(path) for path in expand_inputs(inputs)]
    totals = udp_session_totals(rows)
    return {
        "schema": UDP_SESSION_SCHEMA,
        "label": label,
        "outputDir": str(output_dir),
        "runs": rows,
        "totals": totals,
        "conclusion": udp_session_conclusion(totals),
        "policy": {
            "plannerPenaltySafe": False,
            "qualityPenaltySafe": False,
            "reason": "UDP session surface is execution evidence, not penalty proof.",
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


def udp_session_row(run_dir: Path) -> dict[str, Any]:
    summary = load_optional_json(run_dir / "summary.json")
    current = udp_session_counts(load_optional_json(run_dir / "runtime-report.json"))
    clean = udp_session_clean(current)
    return {
        "label": summary.get("label") or run_dir.name,
        "path": str(run_dir),
        "classification": "clean" if clean else udp_session_classification(current),
        "clean": clean,
        "current": current,
    }


def udp_session_counts(report: dict[str, Any]) -> dict[str, Any]:
    rows, failed_events, denied_events = udp_session_rows(report)
    return {
        "sessions": len(rows),
        "reportedSessions": int(report.get("udpSessions") or 0),
        "startedSessions": count_flag(rows, "started"),
        "attributedSessions": count_flag(rows, "attributed"),
        "connectingSessions": count_flag(rows, "connecting"),
        "establishedSessions": count_flag(rows, "established"),
        "payloadSentSessions": sum(1 for row in rows if row["sentBytes"] > 0),
        "payloadReceivedSessions": sum(1 for row in rows if row["receivedBytes"] > 0),
        "payloadBidirectionalSessions": sum(
            1 for row in rows if row["sentBytes"] > 0 and row["receivedBytes"] > 0
        ),
        "closedSessions": count_flag(rows, "closed"),
        "closedWithByteTotals": sum(1 for row in rows if close_has_totals(row)),
        "failedSessions": count_flag(rows, "failed"),
        "deniedSessions": count_flag(rows, "denied"),
        "failedEvents": failed_events,
        "deniedEvents": denied_events,
        "sentEvents": sum(int(row["sentEvents"]) for row in rows),
        "receivedEvents": sum(int(row["receivedEvents"]) for row in rows),
        "sentBytes": sum(int(row["sentBytes"]) for row in rows),
        "receivedBytes": sum(int(row["receivedBytes"]) for row in rows),
        "reportedUpstreamBytes": int(report.get("udpUpstreamBytes") or 0),
        "reportedDownstreamBytes": int(report.get("udpDownstreamBytes") or 0),
        "reportedFailures": int(report.get("udpSessionFailures") or 0),
        "reportedDroppedPackets": int(report.get("udpDroppedPackets") or 0),
        "closedByReason": aggregate_field(rows, "closeReason"),
        "failedByErrorType": aggregate_field(rows, "failureType"),
        "deniedByErrorType": aggregate_field(rows, "denialType"),
    }


def udp_session_rows(report: dict[str, Any]) -> tuple[list[dict[str, Any]], int, int]:
    sessions: dict[str, dict[str, Any]] = {}
    failed_events = 0
    denied_events = 0
    for event in report.get("events", []):
        if not isinstance(event, dict):
            continue
        kind = str(event.get("kind") or "")
        if not kind.startswith("udp-session-"):
            continue
        event_fields = fields(event)
        flow_id = event_fields.get("flowId")
        if kind == "udp-session-failed":
            failed_events += 1
        if kind == "udp-session-denied":
            denied_events += 1
        if not flow_id or not flow_id.startswith("udp-session-"):
            continue
        observe_udp_session(
            sessions.setdefault(flow_id, new_udp_session(flow_id)),
            kind,
            event_fields,
        )
    return list(sessions.values()), failed_events, denied_events


def observe_udp_session(row: dict[str, Any], kind: str, event_fields: dict[str, str]) -> None:
    if kind == "udp-session-started":
        row["started"] = True
    elif kind == "udp-session-attributed":
        row["attributed"] = True
    elif kind == "udp-session-outbound-connecting":
        row["connecting"] = True
        row["egressSupport"] = event_fields.get("udpEgressSupport") or row["egressSupport"]
    elif kind == "udp-session-established":
        row["established"] = True
    elif kind == "udp-session-payload-sent":
        row["sentEvents"] += 1
        row["sentBytes"] += int_value(event_fields.get("bytes"))
    elif kind == "udp-session-payload-received":
        row["receivedEvents"] += 1
        row["receivedBytes"] += int_value(event_fields.get("bytes"))
    elif kind == "udp-session-closed":
        row["closed"] = True
        row["closeReason"] = event_fields.get("reason") or "unknown"
        row["closeUpstreamBytes"] = optional_int(event_fields.get("upstreamBytes"))
        row["closeDownstreamBytes"] = optional_int(event_fields.get("downstreamBytes"))
    elif kind == "udp-session-failed":
        row["failed"] = True
        row["failureType"] = event_fields.get("errorType") or "unknown"
    elif kind == "udp-session-denied":
        row["denied"] = True
        row["denialType"] = event_fields.get("errorType") or "unknown"


def new_udp_session(flow_id: str) -> dict[str, Any]:
    return {
        "flowId": flow_id,
        "started": False,
        "attributed": False,
        "connecting": False,
        "established": False,
        "closed": False,
        "failed": False,
        "denied": False,
        "sentEvents": 0,
        "receivedEvents": 0,
        "sentBytes": 0,
        "receivedBytes": 0,
        "closeReason": None,
        "failureType": None,
        "denialType": None,
        "closeUpstreamBytes": None,
        "closeDownstreamBytes": None,
        "egressSupport": None,
    }


def udp_session_clean(counts: dict[str, Any]) -> bool:
    sessions = int(counts["sessions"])
    return (
        sessions > 0
        and counts["reportedSessions"] == sessions
        and counts["startedSessions"] == sessions
        and counts["attributedSessions"] == sessions
        and counts["connectingSessions"] == sessions
        and counts["establishedSessions"] == sessions
        and counts["payloadSentSessions"] == sessions
        and counts["payloadReceivedSessions"] == sessions
        and counts["payloadBidirectionalSessions"] == sessions
        and counts["sentBytes"] == counts["reportedUpstreamBytes"]
        and counts["receivedBytes"] == counts["reportedDownstreamBytes"]
        and counts["failedSessions"] == 0
        and counts["deniedSessions"] == 0
        and counts["failedEvents"] == 0
        and counts["deniedEvents"] == 0
        and counts["reportedFailures"] == 0
        and counts["reportedDroppedPackets"] == 0
    )


def udp_session_classification(counts: dict[str, Any]) -> str:
    sessions = int(counts["sessions"])
    if int(counts["failedEvents"]) or int(counts["reportedFailures"]):
        return "udp-session-failure"
    if int(counts["deniedEvents"]):
        return "udp-session-denied"
    if int(counts["reportedDroppedPackets"]):
        return "udp-dropped-packets"
    for field, label in [
        ("startedSessions", "udp-start-missing"),
        ("attributedSessions", "udp-attribution-missing"),
        ("connectingSessions", "udp-connect-missing"),
        ("establishedSessions", "udp-established-missing"),
        ("payloadSentSessions", "udp-payload-sent-missing"),
        ("payloadReceivedSessions", "udp-payload-received-missing"),
    ]:
        if int(counts[field]) < sessions:
            return label
    if counts["sentBytes"] != counts["reportedUpstreamBytes"]:
        return "udp-upstream-byte-mismatch"
    if counts["receivedBytes"] != counts["reportedDownstreamBytes"]:
        return "udp-downstream-byte-mismatch"
    return "udp-session-surface-incomplete"


def udp_session_totals(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "runs": len(rows),
        "cleanRuns": sum(1 for row in rows if row["clean"]),
        "failedRuns": sum(1 for row in rows if not row["clean"]),
        "classifications": aggregate(row["classification"] for row in rows),
        **{
            key: sum(int(row["current"].get(key) or 0) for row in rows)
            for key in COUNT_KEYS
        },
        "closedByReason": merge_count_rows(row["current"]["closedByReason"] for row in rows),
        "failedByErrorType": merge_count_rows(row["current"]["failedByErrorType"] for row in rows),
        "deniedByErrorType": merge_count_rows(row["current"]["deniedByErrorType"] for row in rows),
    }


def udp_session_conclusion(totals: dict[str, Any]) -> dict[str, Any]:
    clean = totals["runs"] > 0 and totals["failedRuns"] == 0
    return {
        "status": "clean" if clean else "udp-session-surface-needs-evidence",
        "nextAction": "return-to-runtime-surface" if clean else "inspect-udp-session-lifecycle",
        "plannerPenaltySafe": False,
        "qualityPenaltySafe": False,
    }


def write_udp_session_summary(output_dir: Path, summary: dict[str, Any]) -> None:
    (output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n"
    )
    write_udp_session_markdown(output_dir / "summary.md", summary)


def write_udp_session_markdown(path: Path, summary: dict[str, Any]) -> None:
    totals = summary["totals"]
    lines = [
        "# VM Private Runtime UDP Session Surface",
        "",
        f"- label: `{summary['label']}`",
        f"- status: `{summary['conclusion']['status']}`",
        f"- runs: `{totals['runs']}`",
        f"- clean runs: `{totals['cleanRuns']}`",
        f"- sessions: `{totals['sessions']}`",
        f"- established sessions: `{totals['establishedSessions']}`",
        f"- sent bytes: `{totals['sentBytes']}`",
        f"- received bytes: `{totals['receivedBytes']}`",
        f"- failed events: `{totals['failedEvents']}`",
        f"- denied events: `{totals['deniedEvents']}`",
        f"- dropped packets: `{totals['reportedDroppedPackets']}`",
        "",
        "## Runs",
        "",
    ]
    for row in summary["runs"]:
        lines.append(
            f"- `{row['label']}` classification=`{row['classification']}` "
            f"clean=`{row['clean']}`"
        )
    path.write_text("\n".join(lines) + "\n")


def udp_session_print(output_dir: Path, summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "outputDir": str(output_dir),
        "runs": summary["totals"]["runs"],
        "cleanRuns": summary["totals"]["cleanRuns"],
        "status": summary["conclusion"]["status"],
    }


def count_flag(rows: list[dict[str, Any]], field: str) -> int:
    return sum(1 for row in rows if row[field])


def close_has_totals(row: dict[str, Any]) -> bool:
    return row["closed"] and row["closeUpstreamBytes"] is not None and row["closeDownstreamBytes"] is not None


def aggregate_field(rows: list[dict[str, Any]], field: str) -> list[dict[str, Any]]:
    return aggregate(row.get(field) for row in rows)


def aggregate(values: Any) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for value in values:
        key = str(value or "")
        if key:
            counts[key] = counts.get(key, 0) + 1
    return [{"key": key, "count": counts[key]} for key in sorted(counts)]


def merge_count_rows(row_sets: Any) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for rows in row_sets:
        for row in rows:
            key = str(row.get("key") or "")
            if key:
                counts[key] = counts.get(key, 0) + int(row.get("count") or 0)
    return [{"key": key, "count": counts[key]} for key in sorted(counts)]


def int_value(value: object) -> int:
    try:
        return int(value or 0)
    except ValueError:
        return 0


def optional_int(value: object) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def load_optional_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text())
