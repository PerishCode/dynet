from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from common import Lab, validate_name
from private_runtime_lib.briefs import fields


TCP_PRESSURE_SCHEMA = "dynet-vm-private-runtime-tcp-pressure-surface/v1alpha1"
REPEAT_SCHEMA = "dynet-vm-private-runtime-repeat/v1alpha1"
COUNT_FIELDS = [
    "runs", "cleanRuns", "failedRuns", "eventReports", "runtimePass", "events",
    "tcpSessions", "tcpClosedSessions", "tcpUnclosedSessions",
    "tcpSessionFailures", "reportedCapacity", "reportedSlotsPerPort",
    "reportedListenPorts", "reportedActiveSlotsMax", "reportedPressureEvents",
    "capacityEvents", "pressureEvents", "capacityMissingForTcpRuns",
    "capacityMissingFields", "capacityMismatches", "capacityFormulaMismatches",
    "pressureCountMismatches", "pressureMissingFields",
    "pressureCapacityMismatches", "pressureActiveOverCapacity",
    "pressureActiveOverReportedMax",
]
BLOCKERS = [
    "tcpUnclosedSessions", "tcpSessionFailures", "capacityMissingForTcpRuns",
    "capacityMissingFields", "capacityMismatches", "capacityFormulaMismatches",
    "pressureCountMismatches", "pressureMissingFields",
    "pressureCapacityMismatches", "pressureActiveOverCapacity",
    "pressureActiveOverReportedMax",
]


def command_tcp_pressure_surface(_lab: Lab, args: argparse.Namespace) -> None:
    label = validate_name(args.label or "tcp-pressure-surface", "label")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = build_tcp_pressure_summary(
        label,
        output_dir,
        [Path(item) for item in args.input],
    )
    write_tcp_pressure_summary(output_dir, summary)
    print(json.dumps(tcp_pressure_print(output_dir, summary), sort_keys=True))


def build_tcp_pressure_summary(
    label: str,
    output_dir: Path,
    inputs: list[Path],
) -> dict[str, Any]:
    rows = [tcp_pressure_row(path) for path in expand_inputs(inputs)]
    totals = tcp_pressure_totals(rows)
    return {
        "schema": TCP_PRESSURE_SCHEMA,
        "label": label,
        "outputDir": str(output_dir),
        "runs": rows,
        "totals": totals,
        "conclusion": tcp_pressure_conclusion(totals),
        "privacy": empty_privacy_flags(),
        "policy": {
            "plannerPenaltySafe": False,
            "qualityPenaltySafe": False,
            "reason": "TCP pressure/capacity signals are observability proof, not penalty proof.",
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


def tcp_pressure_row(run_dir: Path) -> dict[str, Any]:
    summary = load_optional_json(run_dir / "summary.json")
    current = tcp_pressure_counts(load_optional_json(run_dir / "runtime-report.json"))
    clean = tcp_pressure_clean(current)
    return {
        "label": summary.get("label") or run_dir.name,
        "path": str(run_dir),
        "classification": "clean" if clean else tcp_pressure_classification(current),
        "clean": clean,
        "current": current,
    }


def tcp_pressure_counts(report: dict[str, Any]) -> dict[str, Any]:
    raw_events = report.get("events")
    events = [event_row(event) for event in raw_events or [] if isinstance(event, dict)]
    capacity = [event for event in events if event["kind"] == "tcp-forwarder-capacity"]
    pressure = [event for event in events if event["kind"] == "tcp-forwarder-pressure"]
    reported = reported_capacity(report)
    return {
        "eventReports": 1 if raw_events is not None else 0,
        "runtimePass": 1 if report.get("status") == "pass" else 0,
        "events": len(events),
        "tcpSessions": int(report.get("tcpSessions") or 0),
        "tcpClosedSessions": int(report.get("tcpClosedSessions") or 0),
        "tcpUnclosedSessions": tcp_unclosed(report),
        "tcpSessionFailures": int(report.get("tcpSessionFailures") or 0),
        **reported,
        "capacityEvents": len(capacity),
        "pressureEvents": len(pressure),
        "capacityMissingForTcpRuns": capacity_missing_for_tcp(report, capacity),
        **capacity_counts(capacity, reported),
        **pressure_counts(pressure, reported),
    }


def event_row(event: dict[str, Any]) -> dict[str, Any]:
    event_fields = fields(event)
    return {
        "kind": str(event.get("kind") or ""),
        "capacity": parse_int(event_fields.get("capacity")),
        "slotsPerPort": parse_int(event_fields.get("slotsPerPort")),
        "listenPorts": split_csv(event_fields.get("listenPorts")),
        "activeSlots": parse_int(event_fields.get("activeSlots")),
        "pressurePorts": split_csv(event_fields.get("pressurePorts")),
    }


def reported_capacity(report: dict[str, Any]) -> dict[str, int]:
    return {
        "reportedCapacity": int(report.get("tcpListenCapacity") or 0),
        "reportedSlotsPerPort": int(report.get("tcpListenSlotsPerPort") or 0),
        "reportedListenPorts": len(report.get("tcpListenPorts") or []),
        "reportedActiveSlotsMax": int(report.get("tcpActiveSlotsMax") or 0),
        "reportedPressureEvents": int(report.get("tcpSlotPressureEvents") or 0),
    }


def tcp_unclosed(report: dict[str, Any]) -> int:
    sessions = int(report.get("tcpSessions") or 0)
    closed = int(report.get("tcpClosedSessions") or 0)
    return max(0, sessions - closed)


def capacity_missing_for_tcp(report: dict[str, Any], capacity: list[dict[str, Any]]) -> int:
    return 1 if int(report.get("tcpSessions") or 0) > 0 and not capacity else 0


def capacity_counts(
    capacity: list[dict[str, Any]],
    reported: dict[str, int],
) -> dict[str, int]:
    missing = 0
    mismatches = 0
    formula = 0
    for event in capacity:
        if not event["capacity"] or not event["slotsPerPort"] or not event["listenPorts"]:
            missing += 1
            continue
        if (
            event["capacity"] != reported["reportedCapacity"]
            or event["slotsPerPort"] != reported["reportedSlotsPerPort"]
            or len(event["listenPorts"]) != reported["reportedListenPorts"]
        ):
            mismatches += 1
        if event["slotsPerPort"] * len(event["listenPorts"]) != event["capacity"]:
            formula += 1
    return {
        "capacityMissingFields": missing,
        "capacityMismatches": mismatches,
        "capacityFormulaMismatches": formula,
    }


def pressure_counts(
    pressure: list[dict[str, Any]],
    reported: dict[str, int],
) -> dict[str, int]:
    missing = 0
    capacity_mismatch = 0
    over_capacity = 0
    over_reported = 0
    for event in pressure:
        if not event["activeSlots"] or not event["capacity"] or not event["pressurePorts"]:
            missing += 1
            continue
        if event["capacity"] != reported["reportedCapacity"]:
            capacity_mismatch += 1
        if event["activeSlots"] > event["capacity"]:
            over_capacity += 1
        if event["activeSlots"] > reported["reportedActiveSlotsMax"]:
            over_reported += 1
    return {
        "pressureCountMismatches": abs(len(pressure) - reported["reportedPressureEvents"]),
        "pressureMissingFields": missing,
        "pressureCapacityMismatches": capacity_mismatch,
        "pressureActiveOverCapacity": over_capacity,
        "pressureActiveOverReportedMax": over_reported,
    }


def tcp_pressure_clean(counts: dict[str, Any]) -> bool:
    return (
        counts["eventReports"] == 1
        and counts["runtimePass"] == 1
        and counts["events"] > 0
        and all(int(counts[key]) == 0 for key in BLOCKERS)
    )


def tcp_pressure_classification(counts: dict[str, Any]) -> str:
    for key, label in [
        ("tcpUnclosedSessions", "tcp-session-unclosed"),
        ("tcpSessionFailures", "tcp-session-failed"),
        ("capacityMissingForTcpRuns", "capacity-event-missing"),
        ("capacityMissingFields", "capacity-fields-missing"),
        ("capacityMismatches", "capacity-report-mismatch"),
        ("capacityFormulaMismatches", "capacity-formula-mismatch"),
        ("pressureCountMismatches", "pressure-count-mismatch"),
        ("pressureMissingFields", "pressure-fields-missing"),
        ("pressureCapacityMismatches", "pressure-capacity-mismatch"),
        ("pressureActiveOverCapacity", "pressure-active-over-capacity"),
        ("pressureActiveOverReportedMax", "pressure-active-over-reported-max"),
    ]:
        if int(counts[key]):
            return label
    return "tcp-pressure-surface-incomplete"


def tcp_pressure_totals(rows: list[dict[str, Any]]) -> dict[str, Any]:
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
    }


def tcp_pressure_conclusion(totals: dict[str, Any]) -> dict[str, Any]:
    clean = totals["runs"] > 0 and totals["failedRuns"] == 0
    return {
        "status": "clean" if clean else "tcp-pressure-surface-needs-evidence",
        "nextAction": "return-to-runtime-surface" if clean else "inspect-tcp-pressure",
        "plannerPenaltySafe": False,
        "qualityPenaltySafe": False,
    }


def write_tcp_pressure_summary(output_dir: Path, summary: dict[str, Any]) -> None:
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    write_tcp_pressure_markdown(output_dir / "summary.md", summary)


def write_tcp_pressure_markdown(path: Path, summary: dict[str, Any]) -> None:
    totals = summary["totals"]
    lines = [
        "# VM Private Runtime TCP Pressure Surface",
        "",
        f"- label: `{summary['label']}`",
        f"- status: `{summary['conclusion']['status']}`",
        f"- runs: `{totals['runs']}`",
        f"- clean runs: `{totals['cleanRuns']}`",
        f"- capacity events: `{totals['capacityEvents']}`",
        f"- pressure events: `{totals['pressureEvents']}`",
        f"- unclosed TCP sessions: `{totals['tcpUnclosedSessions']}`",
        f"- pressure count mismatches: `{totals['pressureCountMismatches']}`",
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


def tcp_pressure_print(output_dir: Path, summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "outputDir": str(output_dir),
        "runs": summary["totals"]["runs"],
        "cleanRuns": summary["totals"]["cleanRuns"],
        "pressureEvents": summary["totals"]["pressureEvents"],
        "status": summary["conclusion"]["status"],
    }


def parse_int(value: str | None) -> int | None:
    try:
        return int(value or "")
    except ValueError:
        return None


def split_csv(value: str | None) -> list[str]:
    return [item.strip() for item in (value or "").split(",") if item.strip()]


def aggregate(values: Any) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for value in values:
        key = str(value or "")
        if key:
            counts[key] = counts.get(key, 0) + 1
    return [{"key": key, "count": counts[key]} for key in sorted(counts)]


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
