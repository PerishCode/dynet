from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from common import Lab, validate_name
from private_runtime_lib.briefs import fields


EVENT_CAUSALITY_SCHEMA = "dynet-vm-private-runtime-event-causality-surface/v1alpha1"
REPEAT_SCHEMA = "dynet-vm-private-runtime-repeat/v1alpha1"
TCP_CHAIN = [
    "tcp-session-started",
    "route-matched",
    "tcp-session-attributed",
    "tcp-session-outbound-connecting",
    "tcp-session-established",
    "tcp-session-payload-first-write",
    "tcp-session-payload-received",
    "tcp-session-closed",
]
UDP_CHAIN = [
    "udp-session-started",
    "udp-session-attributed",
    "udp-session-outbound-connecting",
    "udp-session-established",
    "udp-session-payload-sent",
    "udp-session-payload-received",
]
COUNT_FIELDS = [
    "runs", "cleanRuns", "failedRuns", "eventReports", "runtimePass",
    "events", "tcpFlows", "udpFlows", "dnsQueries", "tcpOrderChecked",
    "tcpMissingOrderEvents", "tcpOrderViolations", "tcpTerminalOrderViolations",
    "udpOrderChecked", "udpMissingOrderEvents", "udpOrderViolations",
    "dnsOrderChecked", "dnsMissingTerminalEvents", "dnsOrderViolations",
    "dnsReverseOrderViolations", "outboundAttemptStarts", "outboundAttemptFinishes",
    "unmatchedOutboundAttemptFinishes", "outboundAttemptOrderViolations",
    "outboundAttemptCountMismatches", "cascadeAttemptStarts",
    "cascadeAttemptFinishes", "unmatchedCascadeAttemptFinishes",
    "cascadeAttemptOrderViolations", "cascadeAttemptCountMismatches",
    "egressEvents", "egressMissingAdmission", "egressBeforeAdmission",
    "stageEvents", "stageMissingAttempt", "stageBeforeAttempt",
]
BLOCKERS = [
    "tcpMissingOrderEvents", "tcpOrderViolations", "tcpTerminalOrderViolations",
    "udpMissingOrderEvents", "udpOrderViolations", "dnsMissingTerminalEvents",
    "dnsOrderViolations", "dnsReverseOrderViolations",
    "unmatchedOutboundAttemptFinishes", "outboundAttemptOrderViolations",
    "outboundAttemptCountMismatches", "unmatchedCascadeAttemptFinishes",
    "cascadeAttemptOrderViolations", "cascadeAttemptCountMismatches",
    "egressMissingAdmission", "egressBeforeAdmission", "stageMissingAttempt",
    "stageBeforeAttempt",
]


def command_event_causality_surface(_lab: Lab, args: argparse.Namespace) -> None:
    label = validate_name(args.label or "event-causality-surface", "label")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = build_event_causality_summary(
        label,
        output_dir,
        [Path(item) for item in args.input],
    )
    write_event_causality_summary(output_dir, summary)
    print(json.dumps(event_causality_print(output_dir, summary), sort_keys=True))


def build_event_causality_summary(
    label: str,
    output_dir: Path,
    inputs: list[Path],
) -> dict[str, Any]:
    rows = [event_causality_row(path) for path in expand_inputs(inputs)]
    totals = event_causality_totals(rows)
    return {
        "schema": EVENT_CAUSALITY_SCHEMA,
        "label": label,
        "outputDir": str(output_dir),
        "runs": rows,
        "totals": totals,
        "conclusion": event_causality_conclusion(totals),
        "privacy": empty_privacy_flags(),
        "policy": {
            "plannerPenaltySafe": False,
            "qualityPenaltySafe": False,
            "reason": "Event causality integrity is observability proof, not penalty proof.",
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


def event_causality_row(run_dir: Path) -> dict[str, Any]:
    summary = load_optional_json(run_dir / "summary.json")
    current = event_causality_counts(load_optional_json(run_dir / "runtime-report.json"))
    clean = event_causality_clean(current)
    return {
        "label": summary.get("label") or run_dir.name,
        "path": str(run_dir),
        "classification": "clean" if clean else event_causality_classification(current),
        "clean": clean,
        "current": current,
    }


def event_causality_counts(report: dict[str, Any]) -> dict[str, Any]:
    raw_events = report.get("events")
    events = [event_row(event, index) for index, event in enumerate(raw_events or []) if isinstance(event, dict)]
    flows = flow_indexes(events)
    dns_queries = dns_indexes(events)
    return {
        "eventReports": 1 if report.get("events") is not None else 0,
        "runtimePass": 1 if report.get("status") == "pass" else 0,
        "events": len(events),
        "tcpFlows": len(flows["tcp"]),
        "udpFlows": len(flows["udp"]),
        "dnsQueries": len(dns_queries),
        **chain_counts("tcp", flows["tcp"], TCP_CHAIN),
        **chain_counts("udp", flows["udp"], UDP_CHAIN),
        **dns_causality_counts(dns_queries),
        **attempt_pair_counts(events, "outbound"),
        **attempt_pair_counts(events, "cascade"),
        **egress_causality_counts(events),
        **stage_causality_counts(events),
    }


def event_row(event: dict[str, Any], index: int) -> dict[str, Any]:
    event_fields = fields(event)
    return {
        "index": index,
        "kind": str(event.get("kind") or ""),
        "flowId": event_fields.get("flowId") or "",
        "session": event_fields.get("session") or "",
        "dnsQueryId": event_fields.get("dnsQueryId") or "",
        "scope": event_fields.get("scope") or "",
        "transport": event_fields.get("transport") or "",
    }


def flow_indexes(events: list[dict[str, Any]]) -> dict[str, dict[str, dict[str, list[int]]]]:
    result = {"tcp": {}, "udp": {}}
    for event in events:
        flow_id = event["flowId"]
        if flow_id.startswith("tcp-session-"):
            add_kind_index(result["tcp"], flow_id, event["kind"], event["index"])
        if flow_id.startswith("udp-session-"):
            add_kind_index(result["udp"], flow_id, event["kind"], event["index"])
    return result


def dns_indexes(events: list[dict[str, Any]]) -> dict[str, dict[str, list[int]]]:
    result: dict[str, dict[str, list[int]]] = {}
    for event in events:
        if event["dnsQueryId"]:
            add_kind_index(result, event["dnsQueryId"], event["kind"], event["index"])
    return result


def add_kind_index(
    result: dict[str, dict[str, list[int]]],
    key: str,
    kind: str,
    index: int,
) -> None:
    result.setdefault(key, {}).setdefault(kind, []).append(index)


def chain_counts(
    prefix: str,
    flows: dict[str, dict[str, list[int]]],
    chain: list[str],
) -> dict[str, int]:
    checked = len(flows)
    missing = 0
    order = 0
    terminal = 0
    for row in flows.values():
        indexes = [first(row, kind) for kind in chain]
        missing += sum(1 for value in indexes if value is None)
        present = [value for value in indexes if value is not None]
        order += order_violations(present)
        if indexes[-1] is not None and any(value is not None and value > indexes[-1] for value in indexes[:-1]):
            terminal += 1
    return {
        f"{prefix}OrderChecked": checked,
        f"{prefix}MissingOrderEvents": missing,
        f"{prefix}OrderViolations": order,
        **({f"{prefix}TerminalOrderViolations": terminal} if prefix == "tcp" else {}),
    }


def dns_causality_counts(queries: dict[str, dict[str, list[int]]]) -> dict[str, int]:
    missing = 0
    order = 0
    reverse_order = 0
    for row in queries.values():
        root = first(row, "dns-query-received")
        terminal = first_any(row, ["dns-resolve-completed", "dns-resolve-failed"])
        if terminal is None:
            missing += 1
        if root is not None and terminal is not None and terminal < root:
            order += 1
        if terminal is not None:
            reverse_order += sum(
                1 for index in row.get("dns-reverse-record", []) if index > terminal
            )
    return {
        "dnsOrderChecked": len(queries),
        "dnsMissingTerminalEvents": missing,
        "dnsOrderViolations": order,
        "dnsReverseOrderViolations": reverse_order,
    }


def attempt_pair_counts(events: list[dict[str, Any]], prefix: str) -> dict[str, int]:
    started_kind = f"{prefix}-attempt-started" if prefix == "outbound" else "dialer-cascade-attempt-started"
    finished_kind = f"{prefix}-attempt-finished" if prefix == "outbound" else "dialer-cascade-attempt-finished"
    starts = event_key_indexes(events, started_kind)
    finishes = event_key_indexes(events, finished_kind)
    unmatched = 0
    order = 0
    mismatches = 0
    for key, finish_rows in finishes.items():
        start_rows = starts.get(key, [])
        if len(start_rows) != len(finish_rows):
            mismatches += abs(len(start_rows) - len(finish_rows))
        for index, finish in enumerate(finish_rows):
            if index >= len(start_rows):
                unmatched += 1
            elif finish < start_rows[index]:
                order += 1
    name = "outboundAttempt" if prefix == "outbound" else "cascadeAttempt"
    return {
        f"{name}Starts": sum(len(rows) for rows in starts.values()),
        f"{name}Finishes": sum(len(rows) for rows in finishes.values()),
        f"unmatched{name[0].upper()}{name[1:]}Finishes": unmatched,
        f"{name}OrderViolations": order,
        f"{name}CountMismatches": mismatches,
    }


def event_key_indexes(events: list[dict[str, Any]], kind: str) -> dict[str, list[int]]:
    result: dict[str, list[int]] = {}
    for event in events:
        if event["kind"] == kind:
            result.setdefault(event_key(event), []).append(event["index"])
    return result


def event_key(event: dict[str, Any]) -> str:
    return "|".join([
        event.get("flowId") or "",
        event.get("dnsQueryId") or "",
    ])


def egress_causality_counts(events: list[dict[str, Any]]) -> dict[str, int]:
    admissions = event_key_scope_indexes(events, "outbound-admission-passed")
    egresses = event_key_scope_indexes(events, "outbound-egress-passed")
    missing = 0
    before = 0
    for key, rows in egresses.items():
        admission_rows = admissions.get(key, [])
        for index in rows:
            previous = [candidate for candidate in admission_rows if candidate <= index]
            missing += 0 if previous else 1
            before += 1 if admission_rows and min(admission_rows) > index else 0
    return {
        "egressEvents": sum(len(rows) for rows in egresses.values()),
        "egressMissingAdmission": missing,
        "egressBeforeAdmission": before,
    }


def event_key_scope_indexes(events: list[dict[str, Any]], kind: str) -> dict[str, list[int]]:
    result: dict[str, list[int]] = {}
    for event in events:
        if event["kind"] == kind:
            key = f"{event_key(event)}|{event.get('scope') or ''}"
            result.setdefault(key, []).append(event["index"])
    return result


def stage_causality_counts(events: list[dict[str, Any]]) -> dict[str, int]:
    starts = merge_index_rows(
        event_key_indexes(events, "outbound-attempt-started"),
        event_key_indexes(events, "dialer-cascade-attempt-started"),
    )
    missing = 0
    before = 0
    stages = [event for event in events if event["kind"] == "outbound-stage-finished"]
    for event in stages:
        start_rows = starts.get(event_key(event), [])
        previous = [candidate for candidate in start_rows if candidate <= event["index"]]
        missing += 0 if previous else 1
        before += 1 if start_rows and min(start_rows) > event["index"] else 0
    return {
        "stageEvents": len(stages),
        "stageMissingAttempt": missing,
        "stageBeforeAttempt": before,
    }


def merge_index_rows(*items: dict[str, list[int]]) -> dict[str, list[int]]:
    result: dict[str, list[int]] = {}
    for item in items:
        for key, values in item.items():
            result.setdefault(key, []).extend(values)
    return {key: sorted(values) for key, values in result.items()}


def event_causality_clean(counts: dict[str, Any]) -> bool:
    return (
        counts["eventReports"] == 1
        and counts["runtimePass"] == 1
        and counts["events"] > 0
        and all(int(counts[key]) == 0 for key in BLOCKERS)
    )


def event_causality_classification(counts: dict[str, Any]) -> str:
    if counts["eventReports"] == 0:
        return "event-report-missing"
    for key, label in [
        ("tcpOrderViolations", "tcp-order-invalid"),
        ("udpOrderViolations", "udp-order-invalid"),
        ("dnsOrderViolations", "dns-order-invalid"),
        ("outboundAttemptOrderViolations", "outbound-attempt-order-invalid"),
        ("cascadeAttemptOrderViolations", "cascade-attempt-order-invalid"),
        ("egressMissingAdmission", "egress-admission-missing"),
        ("stageMissingAttempt", "stage-attempt-missing"),
    ]:
        if int(counts[key]):
            return label
    if any(int(counts[key]) for key in BLOCKERS):
        return "event-causality-incomplete"
    return "event-causality-incomplete"


def event_causality_totals(rows: list[dict[str, Any]]) -> dict[str, Any]:
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


def event_causality_conclusion(totals: dict[str, Any]) -> dict[str, Any]:
    clean = totals["runs"] > 0 and totals["failedRuns"] == 0
    return {
        "status": "clean" if clean else "event-causality-surface-needs-evidence",
        "nextAction": "return-to-runtime-surface" if clean else "inspect-runtime-event-causality",
        "plannerPenaltySafe": False,
        "qualityPenaltySafe": False,
    }


def write_event_causality_summary(output_dir: Path, summary: dict[str, Any]) -> None:
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    write_event_causality_markdown(output_dir / "summary.md", summary)


def write_event_causality_markdown(path: Path, summary: dict[str, Any]) -> None:
    totals = summary["totals"]
    lines = [
        "# VM Private Runtime Event Causality Surface",
        "",
        f"- label: `{summary['label']}`",
        f"- status: `{summary['conclusion']['status']}`",
        f"- runs: `{totals['runs']}`",
        f"- clean runs: `{totals['cleanRuns']}`",
        f"- tcp order violations: `{totals['tcpOrderViolations']}`",
        f"- udp order violations: `{totals['udpOrderViolations']}`",
        f"- dns order violations: `{totals['dnsOrderViolations']}`",
        f"- egress missing admission: `{totals['egressMissingAdmission']}`",
        f"- stage missing attempt: `{totals['stageMissingAttempt']}`",
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


def event_causality_print(output_dir: Path, summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "outputDir": str(output_dir),
        "runs": summary["totals"]["runs"],
        "cleanRuns": summary["totals"]["cleanRuns"],
        "events": summary["totals"]["events"],
        "status": summary["conclusion"]["status"],
    }


def first(row: dict[str, list[int]], kind: str) -> int | None:
    values = row.get(kind) or []
    return values[0] if values else None


def first_any(row: dict[str, list[int]], kinds: list[str]) -> int | None:
    values = [value for kind in kinds for value in row.get(kind, [])]
    return min(values) if values else None


def order_violations(values: list[int]) -> int:
    return sum(1 for index in range(1, len(values)) if values[index] < values[index - 1])


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
