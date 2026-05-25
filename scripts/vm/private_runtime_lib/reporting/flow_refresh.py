from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from common import Lab, validate_name
from private_runtime_lib.briefs import runtime_brief, tcp_target_identity_brief
from private_runtime_lib.tcp_flow import tcp_flow_brief, workload_flow_brief


FLOW_REFRESH_SCHEMA = "dynet-vm-private-runtime-flow-refresh/v1alpha1"
DNS_REFRESH_SCHEMA = "dynet-vm-private-runtime-dns-refresh/v1alpha1"
TARGET_IDENTITY_REFRESH_SCHEMA = "dynet-vm-private-runtime-target-identity-refresh/v1alpha1"

TCP_KEYS = [
    "failedFlows",
    "stageFailedFlows",
    "lifecycleCompleteFlows",
    "failedByErrorType",
    "failedBySurface",
    "stageFailureByErrorType",
    "stageFailureBySurface",
    "routeFallbackCandidateFlows",
    "routeFallbackAttemptEvents",
    "routeFallbackUsedFlows",
    "routeFallbackEstablishedFlows",
    "routeFallbackFailedFlows",
    "routeFallbackByRouteSelected",
    "routeFallbackByFinalOutbound",
    "routeFallbackByAttemptedOutbound",
]

WORKLOAD_KEYS = [
    "matchedRecoveredFailureEntries",
    "matchedFlowFailedAttempts",
    "matchedFlowStageFailedAttempts",
    "matchedFlowAttempts",
    "matchedEntries",
    "unmatchedEntries",
]

DNS_RUNTIME_KEYS = "dnsQueries dnsRecords proxiedDnsQueries".split()
DNS_EVENT_KEYS = (
    "queryReceivedEvents resolveCompletedEvents reverseRecordEvents "
    "resolveFailedEvents proxiedCompletedEvents routeDecisionCompletedEvents "
    "terminalEvents queriesWithRecords queriesMissingCompletion "
    "completedMissingQuery failedMissingQuery recordsMissingQuery"
).split()

TARGET_IDENTITY_KEYS = [
    "adapterConnectEvents",
    "adapterDomainTargets",
    "adapterSocketTargets",
    "connectingEvents",
    "domainConnectTargets",
    "establishedEvents",
    "socketConnectTargets",
    "targetChainAdapterFlows",
    "targetChainDuplicateAdapterFlows",
    "targetChainFlows",
    "targetChainMatched",
    "targetChainMismatched",
    "targetChainMissingAdapter",
    "targetChainMissingConnect",
    "withAdapterTarget",
    "withConnectTarget",
    "withIdentityDomain",
    "withTargetAddressSource",
]


def command_flow_refresh(_lab: Lab, args: argparse.Namespace) -> None:
    label = validate_name(args.label or "flow-refresh", "label")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = build_flow_refresh_summary(label, output_dir, [Path(item) for item in args.run_dir])
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    write_markdown(output_dir / "summary.md", summary)
    print(json.dumps(refresh_print(output_dir, summary), sort_keys=True))


def command_dns_refresh(_lab: Lab, args: argparse.Namespace) -> None:
    label = validate_name(args.label or "dns-refresh", "label")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = build_dns_refresh_summary(label, output_dir, [Path(item) for item in args.run_dir])
    write_dns_markdown(output_dir / "summary.md", summary)
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(refresh_print(output_dir, summary), sort_keys=True))


def command_target_identity_refresh(_lab: Lab, args: argparse.Namespace) -> None:
    label = validate_name(args.label or "target-identity-refresh", "label")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = build_identity_refresh_summary(
        label,
        output_dir,
        [Path(item) for item in args.run_dir],
    )
    write_target_identity_markdown(output_dir / "summary.md", summary)
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(refresh_print(output_dir, summary), sort_keys=True))


def build_flow_refresh_summary(label: str, output_dir: Path, run_dirs: list[Path]) -> dict[str, Any]:
    rows = [flow_refresh_row(run_dir) for run_dir in run_dirs]
    return {
        "schema": FLOW_REFRESH_SCHEMA,
        "label": label,
        "outputDir": str(output_dir),
        "runs": rows,
        "totals": {
            "runs": len(rows),
            "changedRuns": sum(1 for row in rows if row["changed"]),
            "recoveredStageSeparatedRuns": sum(
                1 for row in rows if row["classification"] == "recovered-stage-separated"
            ),
            "classifications": aggregate(row["classification"] for row in rows),
        },
    }


def refresh_print(output_dir: Path, summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "outputDir": str(output_dir),
        "runs": summary["totals"]["runs"],
        "changedRuns": summary["totals"]["changedRuns"],
    }


def build_dns_refresh_summary(label: str, output_dir: Path, run_dirs: list[Path]) -> dict[str, Any]:
    rows = [dns_refresh_row(run_dir) for run_dir in run_dirs]
    return {
        "schema": DNS_REFRESH_SCHEMA,
        "label": label,
        "outputDir": str(output_dir),
        "runs": rows,
        "totals": dns_totals(rows),
    }


def build_identity_refresh_summary(label: str, output_dir: Path, run_dirs: list[Path]) -> dict[str, Any]:
    rows = [target_identity_refresh_row(run_dir) for run_dir in run_dirs]
    return {
        "schema": TARGET_IDENTITY_REFRESH_SCHEMA,
        "label": label,
        "outputDir": str(output_dir),
        "runs": rows,
        "totals": target_identity_totals(rows),
    }


def dns_refresh_row(run_dir: Path) -> dict[str, Any]:
    previous = load_optional_json(run_dir / "summary.json")
    current_runtime = dns_runtime_counts(dns_runtime_from_run(run_dir))
    current_events = dns_event_brief(load_optional_json(run_dir / "runtime-report.json"))
    previous_runtime = dns_runtime_counts(previous.get("runtime", {}))
    changes = metric_changes(previous_runtime, current_runtime, DNS_RUNTIME_KEYS)
    consistency = dns_consistency(current_runtime, current_events)
    return {
        "label": previous.get("label") or run_dir.name,
        "path": str(run_dir),
        "classification": dns_classification(changes, consistency),
        "changed": bool(changes),
        "changes": changes,
        "consistent": consistency["consistent"],
        "current": {"runtime": current_runtime, "events": current_events},
        "previous": {"runtime": previous_runtime},
    }


def flow_refresh_row(run_dir: Path) -> dict[str, Any]:
    previous = load_optional_json(run_dir / "summary.json")
    _refreshed, refresh = refreshed_flow_summary(run_dir, previous)
    current = refresh["current"]
    previous_tcp = previous.get("tcpFlow", {})
    previous_workload = previous.get("workloadFlow", {})
    return {
        "label": previous.get("label") or run_dir.name,
        "path": str(run_dir),
        "classification": refresh["classification"],
        "changed": refresh["changed"],
        "changes": refresh["changes"],
        "current": current,
        "previous": {
            "tcpFlow": {key: previous_tcp.get(key) for key in TCP_KEYS},
            "workloadFlow": {key: previous_workload.get(key) for key in WORKLOAD_KEYS},
        },
    }


def target_identity_refresh_row(run_dir: Path) -> dict[str, Any]:
    previous = load_optional_json(run_dir / "summary.json")
    current = target_identity_from_run(run_dir)
    previous_identity = target_identity_counts(previous.get("targetIdentity", {}))
    current_identity = target_identity_counts(current)
    changes = metric_changes(previous_identity, current_identity, TARGET_IDENTITY_KEYS)
    return {
        "label": previous.get("label") or run_dir.name,
        "path": str(run_dir),
        "classification": "changed" if changes else "unchanged",
        "changed": bool(changes),
        "changes": changes,
        "current": current_identity,
        "previous": previous_identity,
    }


def refreshed_flow_summary(run_dir: Path, previous: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    runtime_path = run_dir / "runtime-report.json"
    if not run_dir.is_dir() or not runtime_path.exists():
        return previous, empty_refresh(previous)
    runtime_report = load_json(runtime_path)
    workload_report = load_optional_json(run_dir / "workload-probe.json")
    current_tcp = tcp_flow_brief(runtime_report)
    current_workload = workload_flow_brief(runtime_report, workload_report)
    previous_tcp = previous.get("tcpFlow", {})
    previous_workload = previous.get("workloadFlow", {})
    changes = {
        "tcpFlow": metric_changes(previous_tcp, current_tcp, TCP_KEYS),
        "workloadFlow": metric_changes(previous_workload, current_workload, WORKLOAD_KEYS),
    }
    refreshed = {**previous, "tcpFlow": current_tcp, "workloadFlow": current_workload}
    return refreshed, {
        "available": True,
        "classification": classify_refresh(previous_tcp, current_tcp, changes),
        "changed": bool(changes["tcpFlow"] or changes["workloadFlow"]),
        "changes": changes,
        "current": {"tcpFlow": current_tcp, "workloadFlow": current_workload},
    }


def empty_refresh(previous: dict[str, Any]) -> dict[str, Any]:
    return {
        "available": False,
        "classification": "summary-only",
        "changed": False,
        "changes": {"tcpFlow": [], "workloadFlow": []},
        "current": {
            "tcpFlow": previous.get("tcpFlow", {}),
            "workloadFlow": previous.get("workloadFlow", {}),
        },
    }


def dns_runtime_from_run(run_dir: Path) -> dict[str, Any]:
    runtime_path = run_dir / "runtime-report.json"
    if not run_dir.is_dir() or not runtime_path.exists():
        return {}
    return runtime_brief(load_json(runtime_path))


def dns_runtime_counts(runtime: dict[str, Any]) -> dict[str, Any]:
    return {key: runtime.get(key) for key in DNS_RUNTIME_KEYS}


def dns_event_brief(report: dict[str, Any]) -> dict[str, Any]:
    queries: set[str] = set()
    completed: set[str] = set()
    failed: set[str] = set()
    records: set[str] = set()
    with_records: set[str] = set()
    counts = {
        "queryReceivedEvents": 0,
        "resolveCompletedEvents": 0,
        "reverseRecordEvents": 0,
        "resolveFailedEvents": 0,
        "proxiedCompletedEvents": 0,
        "routeDecisionCompletedEvents": 0,
    }
    for event in report.get("events", []):
        if not isinstance(event, dict):
            continue
        event_fields = event.get("fields") or {}
        query_id = str(event_fields.get("dnsQueryId") or "")
        kind = event.get("kind")
        if kind == "dns-query-received":
            counts["queryReceivedEvents"] += 1
            queries.add(query_id)
        if kind == "dns-resolve-completed":
            counts["resolveCompletedEvents"] += 1
            completed.add(query_id)
            if bool_field(event_fields.get("proxied")):
                counts["proxiedCompletedEvents"] += 1
            if bool_field(event_fields.get("routeDecision")):
                counts["routeDecisionCompletedEvents"] += 1
        if kind == "dns-reverse-record":
            counts["reverseRecordEvents"] += 1
            records.add(query_id)
            with_records.add(query_id)
        if kind == "dns-resolve-failed":
            counts["resolveFailedEvents"] += 1
            failed.add(query_id)
    return {
        **counts,
        "terminalEvents": len(completed | failed),
        "queriesWithRecords": len(with_records),
        "queriesMissingCompletion": len(queries - completed - failed),
        "completedMissingQuery": len(completed - queries),
        "failedMissingQuery": len(failed - queries),
        "recordsMissingQuery": len(records - queries),
    }


def dns_consistency(runtime: dict[str, Any], events: dict[str, Any]) -> dict[str, Any]:
    checks = dict(
        queries=int_value(runtime.get("dnsQueries")) == events["queryReceivedEvents"],
        records=int_value(runtime.get("dnsRecords")) == events["reverseRecordEvents"],
        proxied=int_value(runtime.get("proxiedDnsQueries")) == events["proxiedCompletedEvents"],
        terminal=events["terminalEvents"] == events["queryReceivedEvents"],
        recordCoverage=events["queriesWithRecords"] == events["resolveCompletedEvents"],
        links=events["completedMissingQuery"] == 0 and events["failedMissingQuery"] == 0 and events["recordsMissingQuery"] == 0,
        missingCompletion=events["queriesMissingCompletion"] == 0,
    )
    return {**checks, "consistent": all(checks.values())}


def dns_classification(changes: list[dict[str, Any]], consistency: dict[str, Any]) -> str:
    if changes:
        return "changed"
    if not consistency["consistent"]:
        return "inconsistent-events"
    return "unchanged"


def dns_totals(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "runs": len(rows),
        "changedRuns": sum(1 for row in rows if row["changed"]),
        "inconsistentRuns": sum(1 for row in rows if not row["consistent"]),
        "classifications": aggregate(row["classification"] for row in rows),
        **{
            key: sum(int_value(row["current"]["runtime"].get(key)) for row in rows)
            for key in DNS_RUNTIME_KEYS
        },
        **{
            key: sum(int_value(row["current"]["events"].get(key)) for row in rows)
            for key in DNS_EVENT_KEYS
        },
    }


def target_identity_from_run(run_dir: Path) -> dict[str, Any]:
    runtime_path = run_dir / "runtime-report.json"
    if not run_dir.is_dir() or not runtime_path.exists():
        return {}
    return tcp_target_identity_brief(load_json(runtime_path))


def target_identity_counts(identity: dict[str, Any]) -> dict[str, Any]:
    return {key: identity.get(key) for key in TARGET_IDENTITY_KEYS}


def target_identity_totals(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "runs": len(rows),
        "changedRuns": sum(1 for row in rows if row["changed"]),
        "classifications": aggregate(row["classification"] for row in rows),
        **{
            key: sum(int_value(row["current"].get(key)) for row in rows)
            for key in TARGET_IDENTITY_KEYS
        },
    }


def classify_refresh(
    previous_tcp: dict[str, Any],
    current_tcp: dict[str, Any],
    changes: dict[str, list[dict[str, Any]]],
) -> str:
    if not previous_tcp:
        return "computed"
    if not changes["tcpFlow"] and not changes["workloadFlow"]:
        return "unchanged"
    if int_value(previous_tcp.get("failedFlows")) > int_value(current_tcp.get("failedFlows")):
        if int_value(current_tcp.get("stageFailedFlows")) > 0:
            return "recovered-stage-separated"
    return "changed"


def metric_changes(previous: dict[str, Any], current: dict[str, Any], keys: list[str]) -> list[dict[str, Any]]:
    changes = []
    for key in keys:
        if previous.get(key) != current.get(key):
            changes.append({"key": key, "previous": previous.get(key), "current": current.get(key)})
    return changes


def load_json(path: Path) -> dict[str, Any]:
    with path.open() as fh:
        value = json.load(fh)
    return value if isinstance(value, dict) else {}


def load_optional_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return load_json(path)


def aggregate(values: Any) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for value in values:
        key = str(value or "unknown")
        counts[key] = counts.get(key, 0) + 1
    return [{"key": key, "count": counts[key]} for key in sorted(counts)]


def int_value(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def bool_field(value: Any) -> bool:
    return str(value).lower() == "true"


def write_markdown(path: Path, summary: dict[str, Any]) -> None:
    lines = [
        "# VM Private Runtime Flow Refresh",
        "",
        f"- label: `{summary['label']}`",
        f"- runs: `{summary['totals']['runs']}`",
        f"- changed runs: `{summary['totals']['changedRuns']}`",
        f"- recovered stage separated: `{summary['totals']['recoveredStageSeparatedRuns']}`",
        f"- classifications: `{summary['totals']['classifications']}`",
        "",
        "## Runs",
        "",
    ]
    for row in summary["runs"]:
        lines.append(
            f"- `{row['label']}` classification=`{row['classification']}` "
            f"changed=`{row['changed']}` tcpChanges=`{row['changes']['tcpFlow']}` "
            f"workloadChanges=`{row['changes']['workloadFlow']}`"
        )
    path.write_text("\n".join(lines) + "\n")


def write_dns_markdown(path: Path, summary: dict[str, Any]) -> None:
    totals = summary["totals"]
    lines = [
        "# VM Private Runtime DNS Refresh",
        "",
        f"- label: `{summary['label']}`",
        f"- runs: `{totals['runs']}`",
        f"- changed runs: `{totals['changedRuns']}`",
        f"- inconsistent runs: `{totals['inconsistentRuns']}`",
        f"- classifications: `{totals['classifications']}`",
        f"- dns queries: `{totals['dnsQueries']}`",
        f"- reverse records: `{totals['dnsRecords']}`",
        f"- resolve failures: `{totals['resolveFailedEvents']}`",
        "",
        "## Runs",
        "",
    ]
    lines.extend(dns_run_line(row) for row in summary["runs"])
    path.write_text("\n".join(lines) + "\n")


def dns_run_line(row: dict[str, Any]) -> str:
    return (
        f"- `{row['label']}` classification=`{row['classification']}` "
        f"changed=`{row['changed']}` consistent=`{row['consistent']}`"
    )


def write_target_identity_markdown(path: Path, summary: dict[str, Any]) -> None:
    totals = summary["totals"]
    lines = [
        "# VM Private Runtime Target Identity Refresh",
        "",
        f"- label: `{summary['label']}`",
        f"- runs: `{totals['runs']}`",
        f"- changed runs: `{totals['changedRuns']}`",
        f"- classifications: `{totals['classifications']}`",
        f"- target chain matched: `{totals['targetChainMatched']}`",
        f"- target chain mismatched: `{totals['targetChainMismatched']}`",
        f"- target chain missing adapter: `{totals['targetChainMissingAdapter']}`",
        f"- target chain missing connect: `{totals['targetChainMissingConnect']}`",
        "",
        "## Runs",
        "",
    ]
    for row in summary["runs"]:
        lines.append(
            f"- `{row['label']}` classification=`{row['classification']}` "
            f"changed=`{row['changed']}` changes=`{row['changes']}`"
        )
    path.write_text("\n".join(lines) + "\n")
