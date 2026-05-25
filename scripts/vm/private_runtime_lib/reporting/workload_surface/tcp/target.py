from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from common import Lab, validate_name
from private_runtime_lib.briefs import (
    PRIVATE_CONNECT_STAGES,
    connect_host_is_ip,
    fields,
    target_host,
)


TCP_TARGET_SCHEMA = "dynet-vm-private-runtime-tcp-target-surface/v1alpha1"
REPEAT_SCHEMA = "dynet-vm-private-runtime-repeat/v1alpha1"
COUNT_FIELDS = [
    "runs", "cleanRuns", "failedRuns", "eventReports", "runtimePass", "events",
    "connectingEvents", "directConnectEvents", "dialerConnectEvents",
    "unknownKindConnectEvents", "withConnectTarget", "withIdentityDomain",
    "withTargetAddressSource", "domainConnectTargets", "socketConnectTargets",
    "adapterConnectEvents", "adapterMatchedConnects",
    "socketPreservedDirectConnects", "controlledMissingAdapterConnects",
    "uncontrolledMissingAdapterConnects", "adapterMismatchedConnects",
    "adapterDuplicateFlows", "directMissingSocketPreserved",
    "dialerMissingDnsReverse", "coveredConnects",
]
BLOCKERS = [
    "unknownKindConnectEvents", "uncontrolledMissingAdapterConnects",
    "adapterMismatchedConnects", "adapterDuplicateFlows",
    "directMissingSocketPreserved", "dialerMissingDnsReverse",
]


def command_tcp_target_surface(_lab: Lab, args: argparse.Namespace) -> None:
    label = validate_name(args.label or "tcp-target-surface", "label")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = build_tcp_target_summary(
        label,
        output_dir,
        [Path(item) for item in args.input],
    )
    write_tcp_target_summary(output_dir, summary)
    print(json.dumps(tcp_target_print(output_dir, summary), sort_keys=True))


def build_tcp_target_summary(
    label: str,
    output_dir: Path,
    inputs: list[Path],
) -> dict[str, Any]:
    rows = [tcp_target_row(path) for path in expand_inputs(inputs)]
    totals = tcp_target_totals(rows)
    return {
        "schema": TCP_TARGET_SCHEMA,
        "label": label,
        "outputDir": str(output_dir),
        "runs": rows,
        "totals": totals,
        "conclusion": tcp_target_conclusion(totals),
        "privacy": empty_privacy_flags(),
        "policy": {
            "plannerPenaltySafe": False,
            "qualityPenaltySafe": False,
            "reason": "TCP target-chain evidence is observability proof, not penalty proof.",
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


def tcp_target_row(run_dir: Path) -> dict[str, Any]:
    summary = load_optional_json(run_dir / "summary.json")
    current = tcp_target_counts(load_optional_json(run_dir / "runtime-report.json"))
    clean = tcp_target_clean(current)
    return {
        "label": summary.get("label") or run_dir.name,
        "path": str(run_dir),
        "classification": "clean" if clean else tcp_target_classification(current),
        "clean": clean,
        "current": current,
    }


def tcp_target_counts(report: dict[str, Any]) -> dict[str, Any]:
    raw_events = report.get("events")
    events = [
        event_row(index, event)
        for index, event in enumerate(raw_events or [])
        if isinstance(event, dict)
    ]
    connecting = [event for event in events if event["kind"] == "tcp-session-outbound-connecting"]
    adapters = [event for event in events if event["kind"] == "private-connect-target"]
    cascades = [event for event in events if event["kind"] == "failed-cascade"]
    adapter_by_flow = group_by_flow(adapters)
    cascade_by_flow = group_by_flow(cascades)
    coverage = connection_coverage(connecting, adapter_by_flow, cascade_by_flow)
    return {
        "eventReports": 1 if raw_events is not None else 0,
        "runtimePass": 1 if report.get("status") == "pass" else 0,
        "events": len(events),
        "connectingEvents": len(connecting),
        "directConnectEvents": count_connect_kind(connecting, "direct"),
        "dialerConnectEvents": count_connect_kind(connecting, "dialer"),
        "unknownKindConnectEvents": sum(
            1 for row in connecting if row["connectKind"] not in {"direct", "dialer"}
        ),
        "withConnectTarget": sum(1 for row in connecting if row["connectTargetPresent"]),
        "withIdentityDomain": sum(1 for row in connecting if row["identityDomainPresent"]),
        "withTargetAddressSource": sum(1 for row in connecting if row["targetAddressSource"]),
        "domainConnectTargets": sum(1 for row in connecting if row["connectTargetKind"] == "domain"),
        "socketConnectTargets": sum(1 for row in connecting if row["connectTargetKind"] == "socket"),
        "adapterConnectEvents": len(adapters),
        "adapterDuplicateFlows": sum(1 for rows in adapter_by_flow.values() if len(rows) > 1),
        "connectSourceProfiles": aggregate(row["sourceProfile"] for row in connecting),
        "adapterStageProfiles": aggregate(row["stageProfile"] for row in adapters),
        **coverage,
    }


def event_row(index: int, event: dict[str, Any]) -> dict[str, Any]:
    event_fields = fields(event)
    kind = str(event.get("kind") or "")
    if kind == "tcp-session-outbound-connecting":
        return tcp_connecting_row(index, event_fields)
    if kind == "outbound-stage-finished" and event_fields.get("stage") in PRIVATE_CONNECT_STAGES:
        return adapter_row(index, event_fields)
    if kind == "dialer-cascade-attempt-finished" and event_fields.get("status") == "failed":
        return failed_cascade_row(index, event_fields)
    return {"kind": kind, "index": index, "flowId": event_fields.get("flowId")}


def tcp_connecting_row(index: int, event_fields: dict[str, str]) -> dict[str, Any]:
    connect_target = event_fields.get("connectTarget")
    connect_host = target_host(connect_target)
    connect_socket = connect_host_is_ip(connect_host)
    connect_kind = "socket" if connect_socket else "domain" if connect_host else "missing"
    session_kind = event_fields.get("kind") or "unknown"
    source = event_fields.get("targetAddressSource") or "unknown"
    return {
        "kind": "tcp-session-outbound-connecting",
        "index": index,
        "flowId": event_fields.get("flowId"),
        "connectKind": session_kind,
        "connectTarget": connect_target,
        "connectTargetPresent": bool(connect_target),
        "connectTargetKind": connect_kind,
        "identityDomainPresent": bool(event_fields.get("identityDomain")),
        "targetAddressSource": source,
        "sourceProfile": f"{session_kind}:{source}:{connect_kind}",
    }


def adapter_row(index: int, event_fields: dict[str, str]) -> dict[str, Any]:
    adapter_target = event_fields.get("adapterTarget")
    return {
        "kind": "private-connect-target",
        "index": index,
        "flowId": event_fields.get("flowId"),
        "adapterTarget": adapter_target,
        "stageProfile": f"{event_fields.get('kind') or 'unknown'}:{event_fields.get('stage') or 'unknown'}:{event_fields.get('status') or 'unknown'}",
    }


def failed_cascade_row(index: int, event_fields: dict[str, str]) -> dict[str, Any]:
    return {
        "kind": "failed-cascade",
        "index": index,
        "flowId": event_fields.get("flowId"),
        "failureScope": event_fields.get("failureScope") or "unknown",
    }


def group_by_flow(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        flow_id = row.get("flowId")
        if flow_id:
            grouped.setdefault(str(flow_id), []).append(row)
    return grouped


def connection_coverage(
    connecting: list[dict[str, Any]],
    adapter_by_flow: dict[str, list[dict[str, Any]]],
    cascade_by_flow: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    counts = {key: 0 for key in [
        "adapterMatchedConnects", "socketPreservedDirectConnects",
        "controlledMissingAdapterConnects", "uncontrolledMissingAdapterConnects",
        "adapterMismatchedConnects", "directMissingSocketPreserved",
        "dialerMissingDnsReverse",
    ]}
    missing_profiles: list[str] = []
    for row in connecting:
        if row["connectKind"] == "direct":
            cover_direct_connect(row, counts)
            continue
        if row["connectKind"] != "dialer":
            continue
        cover_dialer_connect(row, adapter_by_flow, cascade_by_flow, counts, missing_profiles)
    counts["coveredConnects"] = (
        counts["adapterMatchedConnects"]
        + counts["socketPreservedDirectConnects"]
        + counts["controlledMissingAdapterConnects"]
    )
    counts["missingAdapterProfiles"] = aggregate(missing_profiles)
    return counts


def cover_direct_connect(row: dict[str, Any], counts: dict[str, Any]) -> None:
    if (
        row["connectTargetKind"] == "socket"
        and row["targetAddressSource"] == "socket-ip-direct-preserved"
    ):
        counts["socketPreservedDirectConnects"] += 1
    else:
        counts["directMissingSocketPreserved"] += 1


def cover_dialer_connect(
    row: dict[str, Any],
    adapter_by_flow: dict[str, list[dict[str, Any]]],
    cascade_by_flow: dict[str, list[dict[str, Any]]],
    counts: dict[str, Any],
    missing_profiles: list[str],
) -> None:
    if row["connectTargetKind"] != "domain" or row["targetAddressSource"] != "dns-reverse-rule-domain":
        counts["dialerMissingDnsReverse"] += 1
    flow_id = str(row.get("flowId") or "")
    adapter_targets = [
        adapter.get("adapterTarget")
        for adapter in adapter_by_flow.get(flow_id, [])
        if adapter.get("adapterTarget")
    ]
    if row.get("connectTarget") in adapter_targets:
        counts["adapterMatchedConnects"] += 1
    elif not adapter_targets and cascade_by_flow.get(flow_id):
        counts["controlledMissingAdapterConnects"] += 1
        missing_profiles.append("failed-before-private-connect")
    elif not adapter_targets:
        counts["uncontrolledMissingAdapterConnects"] += 1
        missing_profiles.append("missing-adapter-target")
    else:
        counts["adapterMismatchedConnects"] += 1
        missing_profiles.append("adapter-target-mismatch")


def count_connect_kind(rows: list[dict[str, Any]], kind: str) -> int:
    return sum(1 for row in rows if row["connectKind"] == kind)


def tcp_target_clean(counts: dict[str, Any]) -> bool:
    return (
        counts["eventReports"] == 1
        and counts["runtimePass"] == 1
        and counts["events"] > 0
        and (
            counts["connectingEvents"] == 0
            or (
                counts["withConnectTarget"] == counts["connectingEvents"]
                and counts["withIdentityDomain"] == counts["connectingEvents"]
                and counts["withTargetAddressSource"] == counts["connectingEvents"]
                and counts["coveredConnects"] == counts["connectingEvents"]
            )
        )
        and all(int(counts[key]) == 0 for key in BLOCKERS)
    )


def tcp_target_classification(counts: dict[str, Any]) -> str:
    for key, label in [
        ("eventReports", "runtime-report-missing"),
        ("runtimePass", "runtime-not-pass"),
        ("withConnectTarget", "connect-target-missing"),
        ("withIdentityDomain", "identity-domain-missing"),
        ("withTargetAddressSource", "target-address-source-missing"),
        ("unknownKindConnectEvents", "connect-kind-unknown"),
        ("directMissingSocketPreserved", "direct-target-not-preserved"),
        ("dialerMissingDnsReverse", "dialer-target-not-dns-reverse"),
        ("uncontrolledMissingAdapterConnects", "adapter-target-missing"),
        ("adapterMismatchedConnects", "adapter-target-mismatch"),
        ("adapterDuplicateFlows", "adapter-target-duplicate"),
    ]:
        if classification_triggered(counts, key):
            return label
    if counts["coveredConnects"] != counts["connectingEvents"]:
        return "target-chain-incomplete"
    return "tcp-target-surface-incomplete"


def classification_triggered(counts: dict[str, Any], key: str) -> bool:
    if key == "eventReports":
        return counts[key] != 1
    if key == "runtimePass":
        return counts[key] != 1
    if key == "withConnectTarget":
        return counts[key] != counts["connectingEvents"]
    if key == "withIdentityDomain":
        return counts[key] != counts["connectingEvents"]
    if key == "withTargetAddressSource":
        return counts[key] != counts["connectingEvents"]
    return int(counts.get(key) or 0) > 0


def tcp_target_totals(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "runs": len(rows),
        "cleanRuns": sum(1 for row in rows if row["clean"]),
        "failedRuns": sum(1 for row in rows if not row["clean"]),
        "classifications": aggregate(row["classification"] for row in rows),
        "connectSourceProfiles": aggregate_nested(rows, "connectSourceProfiles"),
        "adapterStageProfiles": aggregate_nested(rows, "adapterStageProfiles"),
        "missingAdapterProfiles": aggregate_nested(rows, "missingAdapterProfiles"),
        **{
            key: sum(int(row["current"].get(key) or 0) for row in rows)
            for key in COUNT_FIELDS
            if key not in {"runs", "cleanRuns", "failedRuns"}
        },
    }


def tcp_target_conclusion(totals: dict[str, Any]) -> dict[str, Any]:
    clean = (
        totals["runs"] > 0
        and totals["failedRuns"] == 0
        and totals["connectingEvents"] > 0
        and totals["directConnectEvents"] > 0
        and totals["dialerConnectEvents"] > 0
    )
    return {
        "status": "clean" if clean else "tcp-target-surface-needs-evidence",
        "nextAction": "return-to-runtime-surface" if clean else "inspect-tcp-target-chain",
        "plannerPenaltySafe": False,
        "qualityPenaltySafe": False,
    }


def write_tcp_target_summary(output_dir: Path, summary: dict[str, Any]) -> None:
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    write_tcp_target_markdown(output_dir / "summary.md", summary)


def write_tcp_target_markdown(path: Path, summary: dict[str, Any]) -> None:
    totals = summary["totals"]
    lines = [
        "# VM Private Runtime TCP Target Surface",
        "",
        f"- label: `{summary['label']}`",
        f"- status: `{summary['conclusion']['status']}`",
        f"- runs: `{totals['runs']}`",
        f"- clean runs: `{totals['cleanRuns']}`",
        f"- connecting events: `{totals['connectingEvents']}`",
        f"- covered connects: `{totals['coveredConnects']}`",
        f"- direct preserved: `{totals['socketPreservedDirectConnects']}`",
        f"- adapter matched: `{totals['adapterMatchedConnects']}`",
        f"- controlled missing adapter: `{totals['controlledMissingAdapterConnects']}`",
        f"- uncontrolled missing adapter: `{totals['uncontrolledMissingAdapterConnects']}`",
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


def tcp_target_print(output_dir: Path, summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "outputDir": str(output_dir),
        "runs": summary["totals"]["runs"],
        "cleanRuns": summary["totals"]["cleanRuns"],
        "connectingEvents": summary["totals"]["connectingEvents"],
        "status": summary["conclusion"]["status"],
    }


def aggregate(values: Any) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for value in values:
        key = str(value or "")
        if key:
            counts[key] = counts.get(key, 0) + 1
    return [{"key": key, "count": counts[key]} for key in sorted(counts)]


def aggregate_nested(rows: list[dict[str, Any]], field: str) -> list[dict[str, Any]]:
    values: list[str] = []
    for row in rows:
        for item in row["current"].get(field, []):
            if isinstance(item, dict) and item.get("key"):
                values.extend([str(item["key"])] * int(item.get("count") or 0))
    return aggregate(values)


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
