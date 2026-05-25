from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from common import Lab, validate_name
from private_runtime_lib.briefs import fields


EVENT_CORRELATION_SCHEMA = "dynet-vm-private-runtime-event-correlation-surface/v1alpha1"
REPEAT_SCHEMA = "dynet-vm-private-runtime-repeat/v1alpha1"
COUNT_FIELDS = [
    "runs", "cleanRuns", "failedRuns", "eventReports", "runtimePass", "events",
    "tcpFlows", "udpFlows", "dnsQueries", "flowIdReferences",
    "dnsQueryReferences", "sessionReferences", "orphanFlowRefs",
    "orphanDnsQueryRefs", "unknownFlowPrefixes", "duplicateTcpRoots",
    "duplicateUdpRoots", "duplicateDnsRoots", "sessionMismatches",
    "missingTcpAttribution", "missingTcpRoute", "missingTcpConnecting",
    "missingTcpEstablished", "missingTcpFirstWrite", "missingTcpPayloadReceived",
    "missingTcpClosed", "duplicateTcpClosed", "missingUdpAttribution",
    "missingUdpConnecting", "missingUdpEstablished", "missingUdpPayloadSent",
    "missingUdpPayloadReceived", "missingDnsTerminal", "duplicateDnsTerminal",
]
BLOCKERS = [
    "orphanFlowRefs", "orphanDnsQueryRefs", "unknownFlowPrefixes",
    "duplicateTcpRoots", "duplicateUdpRoots", "duplicateDnsRoots",
    "sessionMismatches", "missingTcpAttribution", "missingTcpRoute",
    "missingTcpConnecting", "missingTcpEstablished", "missingTcpFirstWrite",
    "missingTcpPayloadReceived", "missingTcpClosed", "duplicateTcpClosed",
    "missingUdpAttribution", "missingUdpConnecting", "missingUdpEstablished",
    "missingUdpPayloadSent", "missingUdpPayloadReceived", "missingDnsTerminal",
    "duplicateDnsTerminal",
]


def command_event_correlation_surface(_lab: Lab, args: argparse.Namespace) -> None:
    label = validate_name(args.label or "event-correlation-surface", "label")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = build_event_correlation_summary(
        label,
        output_dir,
        [Path(item) for item in args.input],
    )
    write_event_correlation_summary(output_dir, summary)
    print(json.dumps(event_correlation_print(output_dir, summary), sort_keys=True))


def build_event_correlation_summary(
    label: str,
    output_dir: Path,
    inputs: list[Path],
) -> dict[str, Any]:
    rows = [event_correlation_row(path) for path in expand_inputs(inputs)]
    totals = event_correlation_totals(rows)
    return {
        "schema": EVENT_CORRELATION_SCHEMA,
        "label": label,
        "outputDir": str(output_dir),
        "runs": rows,
        "totals": totals,
        "conclusion": event_correlation_conclusion(totals),
        "privacy": empty_privacy_flags(),
        "policy": {
            "plannerPenaltySafe": False,
            "qualityPenaltySafe": False,
            "reason": "Event correlation integrity is observability proof, not penalty proof.",
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


def event_correlation_row(run_dir: Path) -> dict[str, Any]:
    summary = load_optional_json(run_dir / "summary.json")
    current = event_correlation_counts(load_optional_json(run_dir / "runtime-report.json"))
    clean = event_correlation_clean(current)
    return {
        "label": summary.get("label") or run_dir.name,
        "path": str(run_dir),
        "classification": "clean" if clean else event_correlation_classification(current),
        "clean": clean,
        "current": current,
    }


def event_correlation_counts(report: dict[str, Any]) -> dict[str, Any]:
    raw_events = report.get("events")
    events = [event for event in raw_events or [] if isinstance(event, dict)]
    index = correlation_index(events)
    roots = root_maps(events)
    issues = correlation_issues(events, roots)
    tcp_completeness = tcp_flow_completeness(index["tcp"], roots["tcp"])
    udp_completeness = udp_flow_completeness(index["udp"], roots["udp"])
    dns_completeness = dns_flow_completeness(index["dns"], roots["dns"])
    return {
        "eventReports": 1 if report.get("events") is not None else 0,
        "runtimePass": 1 if report.get("status") == "pass" else 0,
        "events": len(events),
        "tcpFlows": len(roots["tcp"]),
        "udpFlows": len(roots["udp"]),
        "dnsQueries": len(roots["dns"]),
        "flowIdReferences": issues["flowIdReferences"],
        "dnsQueryReferences": issues["dnsQueryReferences"],
        "sessionReferences": issues["sessionReferences"],
        **duplicate_root_counts(events),
        **issues["counts"],
        **tcp_completeness,
        **udp_completeness,
        **dns_completeness,
        "issueKinds": aggregate(issues["issueKinds"]),
    }


def root_maps(events: list[dict[str, Any]]) -> dict[str, dict[str, str]]:
    roots = {"tcp": {}, "udp": {}, "dns": {}}
    for event in events:
        event_fields = fields(event)
        flow_id = event_fields.get("flowId")
        if event.get("kind") == "tcp-session-started" and flow_id:
            roots["tcp"][flow_id] = event_fields.get("session") or ""
        if event.get("kind") == "udp-session-started" and flow_id:
            roots["udp"][flow_id] = event_fields.get("session") or ""
        if event.get("kind") == "dns-query-received" and event_fields.get("dnsQueryId"):
            roots["dns"][event_fields["dnsQueryId"]] = flow_id or ""
    return roots


def correlation_index(events: list[dict[str, Any]]) -> dict[str, dict[str, list[str]]]:
    result = {"tcp": {}, "udp": {}, "dns": {}}
    for event in events:
        event_fields = fields(event)
        flow_id = event_fields.get("flowId") or ""
        kind = str(event.get("kind") or "")
        if flow_id.startswith("tcp-session-"):
            result["tcp"].setdefault(flow_id, []).append(kind)
        elif flow_id.startswith("udp-session-"):
            result["udp"].setdefault(flow_id, []).append(kind)
        dns_query_id = event_fields.get("dnsQueryId")
        if dns_query_id:
            result["dns"].setdefault(dns_query_id, []).append(kind)
    return result


def correlation_issues(events: list[dict[str, Any]], roots: dict[str, dict[str, str]]) -> dict[str, Any]:
    issue_kinds = []
    counts = {key: 0 for key in [
        "orphanFlowRefs", "orphanDnsQueryRefs", "unknownFlowPrefixes",
        "sessionMismatches",
    ]}
    references = {"flowIdReferences": 0, "dnsQueryReferences": 0, "sessionReferences": 0}
    for event in events:
        event_fields = fields(event)
        flow_id = event_fields.get("flowId")
        if flow_id:
            references["flowIdReferences"] += 1
            check_flow_reference(flow_id, event_fields, roots, counts, issue_kinds)
        if event_fields.get("dnsQueryId"):
            references["dnsQueryReferences"] += 1
            if event_fields["dnsQueryId"] not in roots["dns"]:
                counts["orphanDnsQueryRefs"] += 1
                issue_kinds.append("orphan-dns-query-ref")
        if event_fields.get("session"):
            references["sessionReferences"] += 1
    return {"counts": counts, "issueKinds": issue_kinds, **references}


def check_flow_reference(
    flow_id: str,
    event_fields: dict[str, str],
    roots: dict[str, dict[str, str]],
    counts: dict[str, int],
    issue_kinds: list[str],
) -> None:
    kind = flow_kind(flow_id)
    if not kind:
        counts["unknownFlowPrefixes"] += 1
        issue_kinds.append("unknown-flow-prefix")
        return
    root = roots[kind]
    if flow_id not in root.values() and flow_id not in root:
        counts["orphanFlowRefs"] += 1
        issue_kinds.append(f"orphan-{kind}-flow-ref")
    session = event_fields.get("session")
    if kind in {"tcp", "udp"} and flow_id in root and session and session != root[flow_id]:
        counts["sessionMismatches"] += 1
        issue_kinds.append(f"{kind}-session-mismatch")


def flow_kind(flow_id: str) -> str:
    if flow_id.startswith("tcp-session-"):
        return "tcp"
    if flow_id.startswith("udp-session-"):
        return "udp"
    if flow_id.startswith("dns-query-"):
        return "dns"
    return ""


def duplicate_root_counts(events: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "duplicateTcpRoots": duplicate_count(root_values(events, "tcp-session-started", "flowId")),
        "duplicateUdpRoots": duplicate_count(root_values(events, "udp-session-started", "flowId")),
        "duplicateDnsRoots": duplicate_count(root_values(events, "dns-query-received", "dnsQueryId")),
    }


def root_values(events: list[dict[str, Any]], kind: str, field: str) -> list[str]:
    return [
        fields(event).get(field) or ""
        for event in events
        if event.get("kind") == kind and fields(event).get(field)
    ]


def tcp_flow_completeness(index: dict[str, list[str]], roots: dict[str, str]) -> dict[str, int]:
    return {
        "missingTcpAttribution": missing_kind(index, roots, "tcp-session-attributed"),
        "missingTcpRoute": missing_kind(index, roots, "route-matched"),
        "missingTcpConnecting": missing_kind(index, roots, "tcp-session-outbound-connecting"),
        "missingTcpEstablished": missing_kind(index, roots, "tcp-session-established"),
        "missingTcpFirstWrite": missing_kind(index, roots, "tcp-session-payload-first-write"),
        "missingTcpPayloadReceived": missing_kind(index, roots, "tcp-session-payload-received"),
        "missingTcpClosed": missing_kind(index, roots, "tcp-session-closed"),
        "duplicateTcpClosed": duplicate_terminal(index, roots, "tcp-session-closed"),
    }


def udp_flow_completeness(index: dict[str, list[str]], roots: dict[str, str]) -> dict[str, int]:
    return {
        "missingUdpAttribution": missing_kind(index, roots, "udp-session-attributed"),
        "missingUdpConnecting": missing_kind(index, roots, "udp-session-outbound-connecting"),
        "missingUdpEstablished": missing_kind(index, roots, "udp-session-established"),
        "missingUdpPayloadSent": missing_kind(index, roots, "udp-session-payload-sent"),
        "missingUdpPayloadReceived": missing_kind(index, roots, "udp-session-payload-received"),
    }


def dns_flow_completeness(index: dict[str, list[str]], roots: dict[str, str]) -> dict[str, int]:
    terminal = {"dns-resolve-completed", "dns-resolve-failed"}
    missing = 0
    duplicate = 0
    for query_id in roots:
        count = sum(1 for kind in index.get(query_id, []) if kind in terminal)
        missing += 1 if count == 0 else 0
        duplicate += max(0, count - 1)
    return {"missingDnsTerminal": missing, "duplicateDnsTerminal": duplicate}


def missing_kind(index: dict[str, list[str]], roots: dict[str, str], kind: str) -> int:
    return sum(1 for flow_id in roots if kind not in index.get(flow_id, []))


def duplicate_terminal(index: dict[str, list[str]], roots: dict[str, str], kind: str) -> int:
    return sum(max(0, index.get(flow_id, []).count(kind) - 1) for flow_id in roots)


def event_correlation_clean(counts: dict[str, Any]) -> bool:
    return (
        counts["eventReports"] == 1
        and counts["runtimePass"] == 1
        and counts["events"] > 0
        and all(int(counts[key]) == 0 for key in BLOCKERS)
    )


def event_correlation_classification(counts: dict[str, Any]) -> str:
    if counts["eventReports"] == 0:
        return "event-report-missing"
    if int(counts["orphanFlowRefs"]):
        return "orphan-flow-ref"
    if int(counts["orphanDnsQueryRefs"]):
        return "orphan-dns-query-ref"
    if int(counts["sessionMismatches"]):
        return "session-mismatch"
    for key, label in [
        ("missingTcpClosed", "tcp-terminal-missing"),
        ("missingUdpPayloadReceived", "udp-payload-received-missing"),
        ("missingDnsTerminal", "dns-terminal-missing"),
    ]:
        if int(counts[key]):
            return label
    if any(int(counts[key]) for key in BLOCKERS):
        return "event-correlation-incomplete"
    return "event-correlation-incomplete"


def event_correlation_totals(rows: list[dict[str, Any]]) -> dict[str, Any]:
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
        "issueKinds": merge_count_rows(row["current"]["issueKinds"] for row in rows),
    }


def event_correlation_conclusion(totals: dict[str, Any]) -> dict[str, Any]:
    clean = totals["runs"] > 0 and totals["failedRuns"] == 0
    return {
        "status": "clean" if clean else "event-correlation-surface-needs-evidence",
        "nextAction": "return-to-runtime-surface" if clean else "inspect-runtime-event-correlation",
        "plannerPenaltySafe": False,
        "qualityPenaltySafe": False,
    }


def write_event_correlation_summary(output_dir: Path, summary: dict[str, Any]) -> None:
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    write_event_correlation_markdown(output_dir / "summary.md", summary)


def write_event_correlation_markdown(path: Path, summary: dict[str, Any]) -> None:
    totals = summary["totals"]
    lines = [
        "# VM Private Runtime Event Correlation Surface",
        "",
        f"- label: `{summary['label']}`",
        f"- status: `{summary['conclusion']['status']}`",
        f"- runs: `{totals['runs']}`",
        f"- clean runs: `{totals['cleanRuns']}`",
        f"- tcp flows: `{totals['tcpFlows']}`",
        f"- udp flows: `{totals['udpFlows']}`",
        f"- dns queries: `{totals['dnsQueries']}`",
        f"- orphan flow refs: `{totals['orphanFlowRefs']}`",
        f"- orphan dns query refs: `{totals['orphanDnsQueryRefs']}`",
        f"- session mismatches: `{totals['sessionMismatches']}`",
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


def event_correlation_print(output_dir: Path, summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "outputDir": str(output_dir),
        "runs": summary["totals"]["runs"],
        "cleanRuns": summary["totals"]["cleanRuns"],
        "tcpFlows": summary["totals"]["tcpFlows"],
        "udpFlows": summary["totals"]["udpFlows"],
        "dnsQueries": summary["totals"]["dnsQueries"],
        "status": summary["conclusion"]["status"],
    }


def duplicate_count(values: list[str]) -> int:
    return len(values) - len(set(values))


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
