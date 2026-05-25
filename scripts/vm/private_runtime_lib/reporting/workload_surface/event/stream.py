from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from common import Lab, validate_name
from private_runtime_lib.briefs import fields


EVENT_STREAM_SCHEMA = "dynet-vm-private-runtime-event-stream-surface/v1alpha1"
RUNTIME_EVENT_SCHEMA = "dynet-runtime-event/v1alpha1"
REPEAT_SCHEMA = "dynet-vm-private-runtime-repeat/v1alpha1"
REQUIRED_FIELDS = {
    "dialer-cascade-attempt-finished": ["flowId", "status"],
    "dialer-cascade-attempt-started": ["flowId"],
    "dialer-cascade-selected": ["boundSelected", "flowId", "private"],
    "dns-proxy-forward": ["dnsQueryId", "flowId", "kind", "listener", "outbound"],
    "dns-query-received": ["dnsQueryId", "flowId", "listener", "queryBytes"],
    "dns-resolve-failed": ["dnsQueryId", "elapsedMs", "flowId", "listener"],
    "dns-resolve-completed": ["dnsQueryId", "elapsedMs", "flowId", "listener", "proxied"],
    "dns-reverse-record": ["dnsQueryId", "flowId", "ttl"],
    "ip-packet-denied": ["destinationPort", "ipVersion", "protocol", "reason"],
    "outbound-admission-passed": ["gate", "scope", "transport"],
    "outbound-attempt-finished": ["flowId", "protocol", "status"],
    "outbound-attempt-started": ["flowId", "protocol"],
    "outbound-candidate-set": ["candidateCount", "flowId", "scope", "selected", "selector"],
    "outbound-egress-passed": ["gate", "scope", "selected", "transport"],
    "outbound-graph-selected": ["requested", "scope", "selected"],
    "outbound-stage-finished": ["elapsedMs", "flowId", "stage", "status"],
    "plan-bypassed": ["flowId", "outbound", "reason", "rule"],
    "route-matched": ["outbound", "status", "transport"],
    "rule-matched": ["flowId", "outbound", "reason", "rule", "transport"],
    "tcp-forwarder-capacity": ["capacity", "listenPorts", "slotsPerPort"],
    "tcp-forwarder-packet": ["clientPort", "direction", "port", "transport"],
    "tcp-forwarder-preflow": ["clientPort", "port", "state", "transport"],
    "tcp-forwarder-pressure": ["activeSlots", "capacity", "pressurePorts"],
    "tcp-session-attributed": ["flowId", "outbound", "session"],
    "tcp-session-closed": ["downstreamBytes", "flowId", "reason", "session", "upstreamBytes"],
    "tcp-session-established": ["flowId", "outbound", "routeSelected", "session"],
    "tcp-session-outbound-connecting": ["flowId", "kind", "outbound", "routeSelected", "session"],
    "tcp-session-payload-first-write": ["bytes", "flowId", "session"],
    "tcp-session-payload-received": ["bytes", "flowId", "session"],
    "tcp-session-started": ["clientPort", "flowId", "session", "transport"],
    "udp-session-attributed": ["flowId", "outbound", "session"],
    "udp-session-established": ["flowId", "outbound", "session"],
    "udp-session-outbound-connecting": ["flowId", "kind", "outbound", "session"],
    "udp-session-payload-received": ["bytes", "flowId", "session"],
    "udp-session-payload-sent": ["bytes", "flowId", "session"],
    "udp-session-started": ["flowId", "session", "transport"],
}
COUNT_FIELDS = [
    "runs", "cleanRuns", "failedRuns", "eventReports", "runtimePass",
    "events", "eventKinds", "invalidEventObjects", "invalidSchemaEvents",
    "missingKindEvents", "missingFieldsEvents", "missingSequenceEvents",
    "missingTimestampEvents", "duplicateSequences", "sequenceGaps",
    "sequenceStartMismatches", "sequenceEndMismatches", "sequenceOrderViolations",
    "timestampOrderViolations", "unknownEventKinds", "missingRequiredFields",
    "counterMismatches", "byteCounterMismatches",
]
BLOCKER_FIELDS = [
    "invalidEventObjects", "invalidSchemaEvents", "missingKindEvents",
    "missingFieldsEvents", "missingSequenceEvents", "missingTimestampEvents",
    "duplicateSequences", "sequenceGaps", "sequenceStartMismatches",
    "sequenceEndMismatches", "sequenceOrderViolations", "timestampOrderViolations",
    "unknownEventKinds", "missingRequiredFields", "counterMismatches",
    "byteCounterMismatches",
]


def command_event_stream_surface(_lab: Lab, args: argparse.Namespace) -> None:
    label = validate_name(args.label or "event-stream-surface", "label")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = build_event_stream_summary(label, output_dir, [Path(item) for item in args.input])
    write_event_stream_summary(output_dir, summary)
    print(json.dumps(event_stream_print(output_dir, summary), sort_keys=True))


def build_event_stream_summary(label: str, output_dir: Path, inputs: list[Path]) -> dict[str, Any]:
    rows = [event_stream_row(path) for path in expand_inputs(inputs)]
    totals = event_stream_totals(rows)
    return {
        "schema": EVENT_STREAM_SCHEMA,
        "label": label,
        "outputDir": str(output_dir),
        "runs": rows,
        "totals": totals,
        "conclusion": event_stream_conclusion(totals),
        "privacy": empty_privacy_flags(),
        "policy": {
            "plannerPenaltySafe": False,
            "qualityPenaltySafe": False,
            "reason": "Event stream integrity is observability proof, not penalty proof.",
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


def event_stream_row(run_dir: Path) -> dict[str, Any]:
    summary = load_optional_json(run_dir / "summary.json")
    current = event_stream_counts(load_optional_json(run_dir / "runtime-report.json"))
    clean = event_stream_clean(current)
    return {
        "label": summary.get("label") or run_dir.name,
        "path": str(run_dir),
        "classification": "clean" if clean else event_stream_classification(current),
        "clean": clean,
        "current": current,
    }


def event_stream_counts(report: dict[str, Any]) -> dict[str, Any]:
    raw_events = report.get("events")
    events = [event for event in raw_events or [] if isinstance(event, dict)]
    sequences = [int(event["sequence"]) for event in events if integer_like(event.get("sequence"))]
    timestamps = [int(event["emittedAtUnixMs"]) for event in events if integer_like(event.get("emittedAtUnixMs"))]
    missing_fields = missing_required_fields(events)
    counter_mismatches, byte_mismatches = mismatch_names(report, events)
    return {
        "eventReports": 1 if report.get("events") is not None else 0,
        "runtimePass": 1 if report.get("status") == "pass" else 0,
        "events": len(events),
        "eventKinds": len({str(event.get("kind")) for event in events if event.get("kind")}),
        "invalidEventObjects": len(raw_events or []) - len(events) if isinstance(raw_events, list) else 0,
        "invalidSchemaEvents": sum(1 for event in events if event.get("schema") != RUNTIME_EVENT_SCHEMA),
        "missingKindEvents": sum(1 for event in events if not event.get("kind")),
        "missingFieldsEvents": sum(1 for event in events if not isinstance(event.get("fields"), dict)),
        "missingSequenceEvents": len(events) - len(sequences),
        "missingTimestampEvents": len(events) - len(timestamps),
        **sequence_counts(sequences, len(events)),
        "timestampOrderViolations": order_violations(timestamps),
        "unknownEventKinds": sum(1 for event in events if event.get("kind") not in REQUIRED_FIELDS),
        "missingRequiredFields": len(missing_fields),
        "counterMismatches": len(counter_mismatches),
        "byteCounterMismatches": len(byte_mismatches),
        "eventKindCounts": aggregate(event.get("kind") for event in events),
        "missingFieldNames": aggregate(missing_fields),
        "counterMismatchNames": aggregate(counter_mismatches),
        "byteCounterMismatchNames": aggregate(byte_mismatches),
    }


def sequence_counts(sequences: list[int], event_count: int) -> dict[str, int]:
    sequence_set = set(sequences)
    expected = set(range(1, event_count + 1))
    return {
        "duplicateSequences": len(sequences) - len(sequence_set),
        "sequenceGaps": len(expected - sequence_set),
        "sequenceStartMismatches": 1 if event_count and (not sequences or min(sequences) != 1) else 0,
        "sequenceEndMismatches": 1 if event_count and (not sequences or max(sequences) != event_count) else 0,
        "sequenceOrderViolations": order_violations(sequences),
    }


def missing_required_fields(events: list[dict[str, Any]]) -> list[str]:
    missing = []
    for event in events:
        kind = str(event.get("kind") or "")
        required = REQUIRED_FIELDS.get(kind)
        if not required:
            continue
        event_fields = fields(event)
        for name in required:
            if not event_fields.get(name):
                missing.append(f"{kind}.{name}")
    return missing


def mismatch_names(report: dict[str, Any], events: list[dict[str, Any]]) -> tuple[list[str], list[str]]:
    by_kind = {row["key"]: row["count"] for row in aggregate(event.get("kind") for event in events)}
    counters = [
        name for name, kind in {
            "dnsQueries": "dns-query-received",
            "dnsRecords": "dns-reverse-record",
            "routeDecisions": "route-matched",
            "tcpSessions": "tcp-session-started",
            "tcpClosedSessions": "tcp-session-closed",
            "udpSessions": "udp-session-started",
            "ipv6PacketsDenied": "ip-packet-denied",
            "tcpSlotPressureEvents": "tcp-forwarder-pressure",
        }.items()
        if report_count(report, name) != int(by_kind.get(kind) or 0)
    ]
    if report_count(report, "proxiedDnsQueries") != proxied_dns_queries(events):
        counters.append("proxiedDnsQueries")
    byte_counters = [
        name for name, total in {
            "tcpUpstreamBytes": sum_event_bytes(events, "tcp-session-closed", "upstreamBytes"),
            "tcpDownstreamBytes": sum_event_bytes(events, "tcp-session-closed", "downstreamBytes"),
            "udpUpstreamBytes": sum_event_bytes(events, "udp-session-payload-sent", "bytes"),
            "udpDownstreamBytes": sum_event_bytes(events, "udp-session-payload-received", "bytes"),
        }.items()
        if report_count(report, name) != total
    ]
    return counters, byte_counters


def event_stream_clean(counts: dict[str, Any]) -> bool:
    return (
        counts["eventReports"] == 1
        and counts["runtimePass"] == 1
        and counts["events"] > 0
        and all(int(counts[key]) == 0 for key in BLOCKER_FIELDS)
    )


def event_stream_classification(counts: dict[str, Any]) -> str:
    if counts["eventReports"] == 0:
        return "event-report-missing"
    if counts["runtimePass"] == 0:
        return "runtime-not-pass"
    for key, label in [
        ("invalidSchemaEvents", "invalid-event-schema"),
        ("missingSequenceEvents", "event-sequence-missing"),
        ("sequenceGaps", "event-sequence-gap"),
        ("sequenceOrderViolations", "event-sequence-order-invalid"),
        ("timestampOrderViolations", "event-timestamp-order-invalid"),
        ("unknownEventKinds", "unknown-event-kind"),
        ("missingRequiredFields", "required-event-field-missing"),
        ("counterMismatches", "reported-counter-mismatch"),
        ("byteCounterMismatches", "reported-byte-counter-mismatch"),
    ]:
        if int(counts[key]):
            return label
    return "event-stream-incomplete"


def event_stream_totals(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "runs": len(rows),
        "cleanRuns": sum(1 for row in rows if row["clean"]),
        "failedRuns": sum(1 for row in rows if not row["clean"]),
        "classifications": aggregate(row["classification"] for row in rows),
        **{
            key: sum(int(row["current"].get(key) or 0) for row in rows)
            for key in COUNT_FIELDS
            if key not in {"runs", "cleanRuns", "failedRuns", "eventKinds"}
        },
        "eventKindCounts": merge_count_rows(row["current"]["eventKindCounts"] for row in rows),
        "eventKinds": len(merge_count_rows(row["current"]["eventKindCounts"] for row in rows)),
        "missingFieldNames": merge_count_rows(row["current"]["missingFieldNames"] for row in rows),
        "counterMismatchNames": merge_count_rows(row["current"]["counterMismatchNames"] for row in rows),
        "byteCounterMismatchNames": merge_count_rows(row["current"]["byteCounterMismatchNames"] for row in rows),
    }


def event_stream_conclusion(totals: dict[str, Any]) -> dict[str, Any]:
    clean = totals["runs"] > 0 and totals["failedRuns"] == 0
    return {
        "status": "clean" if clean else "event-stream-surface-needs-evidence",
        "nextAction": "return-to-runtime-surface" if clean else "inspect-runtime-event-stream",
        "plannerPenaltySafe": False,
        "qualityPenaltySafe": False,
    }


def write_event_stream_summary(output_dir: Path, summary: dict[str, Any]) -> None:
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    write_event_stream_markdown(output_dir / "summary.md", summary)


def write_event_stream_markdown(path: Path, summary: dict[str, Any]) -> None:
    totals = summary["totals"]
    lines = [
        "# VM Private Runtime Event Stream Surface",
        "",
        f"- label: `{summary['label']}`",
        f"- status: `{summary['conclusion']['status']}`",
        f"- runs: `{totals['runs']}`",
        f"- clean runs: `{totals['cleanRuns']}`",
        f"- events: `{totals['events']}`",
        f"- event kinds: `{totals['eventKinds']}`",
        f"- sequence gaps: `{totals['sequenceGaps']}`",
        f"- order violations: `{totals['sequenceOrderViolations']}`",
        f"- timestamp order violations: `{totals['timestampOrderViolations']}`",
        f"- counter mismatches: `{totals['counterMismatches']}`",
        f"- byte counter mismatches: `{totals['byteCounterMismatches']}`",
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


def event_stream_print(output_dir: Path, summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "outputDir": str(output_dir),
        "runs": summary["totals"]["runs"],
        "cleanRuns": summary["totals"]["cleanRuns"],
        "events": summary["totals"]["events"],
        "status": summary["conclusion"]["status"],
    }


def proxied_dns_queries(events: list[dict[str, Any]]) -> int:
    return sum(
        1 for event in events
        if event.get("kind") == "dns-resolve-completed"
        and fields(event).get("proxied", "").lower() == "true"
    )


def sum_event_bytes(events: list[dict[str, Any]], kind: str, field: str) -> int:
    total = 0
    for event in events:
        if event.get("kind") == kind:
            total += int_value(fields(event).get(field))
    return total


def report_count(report: dict[str, Any], name: str) -> int:
    return int_value(report.get(name))


def integer_like(value: Any) -> bool:
    try:
        int(str(value))
    except (TypeError, ValueError):
        return False
    return True


def int_value(value: Any) -> int:
    if integer_like(value):
        return int(str(value))
    return 0


def order_violations(values: list[int]) -> int:
    return sum(1 for index in range(1, len(values)) if values[index] < values[index - 1])


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
