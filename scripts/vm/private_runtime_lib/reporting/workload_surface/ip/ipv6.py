from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from common import Lab, validate_name
from private_runtime_lib.briefs import fields
from private_runtime_lib.tcp_flow import tcp_flow_brief


IPV6_DENIAL_SCHEMA = "dynet-vm-private-runtime-ipv6-denial-surface/v1alpha1"
REPEAT_SCHEMA = "dynet-vm-private-runtime-repeat/v1alpha1"
COUNT_KEYS = [
    "denials",
    "reportedIpv6PacketsDenied",
    "ipv6Denials",
    "nonIpv6Denials",
    "missingFieldEvents",
    "flows",
    "startedFlows",
    "establishedFlows",
    "closedFlows",
    "lifecycleCompleteFlows",
    "pathCompleteFlows",
    "payloadBidirectionalFlows",
    "failedFlows",
    "stageFailedFlows",
]
TCP_KEYS = [
    "flows",
    "startedFlows",
    "establishedFlows",
    "closedFlows",
    "lifecycleCompleteFlows",
    "pathCompleteFlows",
    "payloadBidirectionalFlows",
    "failedFlows",
    "stageFailedFlows",
]


def command_ipv6_denial_surface(_lab: Lab, args: argparse.Namespace) -> None:
    label = validate_name(args.label or "ipv6-denial-surface", "label")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = build_ipv6_denial_summary(
        label,
        output_dir,
        [Path(item) for item in args.input],
    )
    write_ipv6_denial_summary(output_dir, summary)
    print(json.dumps(ipv6_denial_print(output_dir, summary), sort_keys=True))


def build_ipv6_denial_summary(
    label: str,
    output_dir: Path,
    inputs: list[Path],
) -> dict[str, Any]:
    rows = [ipv6_denial_row(path) for path in expand_inputs(inputs)]
    totals = ipv6_denial_totals(rows)
    return {
        "schema": IPV6_DENIAL_SCHEMA,
        "label": label,
        "outputDir": str(output_dir),
        "runs": rows,
        "totals": totals,
        "conclusion": ipv6_denial_conclusion(totals),
        "policy": {
            "plannerPenaltySafe": False,
            "qualityPenaltySafe": False,
            "reason": "IPv6 denial surface is execution evidence, not penalty proof.",
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


def ipv6_denial_row(run_dir: Path) -> dict[str, Any]:
    summary = load_optional_json(run_dir / "summary.json")
    report = load_optional_json(run_dir / "runtime-report.json")
    current = ipv6_denial_counts(report)
    clean = ipv6_denial_clean(current)
    return {
        "label": summary.get("label") or run_dir.name,
        "path": str(run_dir),
        "classification": "clean" if clean else ipv6_denial_classification(current),
        "clean": clean,
        "current": current,
    }


def ipv6_denial_counts(report: dict[str, Any]) -> dict[str, Any]:
    denials = denial_rows(report)
    tcp = tcp_counts(tcp_flow_brief(report))
    return {
        "denials": len(denials),
        "reportedIpv6PacketsDenied": int(report.get("ipv6PacketsDenied") or 0),
        "ipv6Denials": sum(1 for row in denials if row["ipVersion"] == "6"),
        "nonIpv6Denials": sum(1 for row in denials if row["ipVersion"] != "6"),
        "missingFieldEvents": sum(1 for row in denials if row["missingFields"]),
        **tcp,
        "byIpVersion": aggregate(row["ipVersion"] for row in denials),
        "byProtocol": aggregate(row["protocol"] for row in denials),
        "byDestinationPort": aggregate(row["destinationPort"] for row in denials),
        "byReasonBucket": aggregate(row["reasonBucket"] for row in denials),
    }


def denial_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for event in report.get("events", []):
        if not isinstance(event, dict) or event.get("kind") != "ip-packet-denied":
            continue
        event_fields = fields(event)
        rows.append({
            "ipVersion": sanitized_value(event_fields.get("ipVersion")),
            "protocol": sanitized_value(event_fields.get("protocol")),
            "destinationPort": sanitized_value(event_fields.get("destinationPort")),
            "reasonBucket": reason_bucket(event_fields.get("reason")),
            "missingFields": missing_denial_fields(event_fields),
        })
    return rows


def tcp_counts(tcp: dict[str, Any]) -> dict[str, int]:
    return {key: int(tcp.get(key) or 0) for key in TCP_KEYS}


def ipv6_denial_clean(counts: dict[str, Any]) -> bool:
    flows = int(counts["flows"])
    return (
        int(counts["denials"]) > 0
        and counts["reportedIpv6PacketsDenied"] == counts["ipv6Denials"]
        and counts["ipv6Denials"] == counts["denials"]
        and counts["nonIpv6Denials"] == 0
        and counts["missingFieldEvents"] == 0
        and flows > 0
        and counts["startedFlows"] == flows
        and counts["establishedFlows"] == flows
        and counts["closedFlows"] == flows
        and counts["lifecycleCompleteFlows"] == flows
        and counts["pathCompleteFlows"] == flows
        and counts["payloadBidirectionalFlows"] == flows
        and counts["failedFlows"] == 0
        and counts["stageFailedFlows"] == 0
    )


def ipv6_denial_classification(counts: dict[str, Any]) -> str:
    if int(counts["denials"]) == 0:
        return "ipv6-denial-missing"
    if counts["reportedIpv6PacketsDenied"] != counts["ipv6Denials"]:
        return "ipv6-denial-counter-mismatch"
    if int(counts["nonIpv6Denials"]):
        return "non-ipv6-denial"
    if int(counts["missingFieldEvents"]):
        return "ipv6-denial-field-missing"
    if int(counts["failedFlows"]) or int(counts["stageFailedFlows"]):
        return "tcp-flow-failure"
    if int(counts["payloadBidirectionalFlows"]) < int(counts["flows"]):
        return "tcp-flow-incomplete"
    return "ipv6-denial-surface-incomplete"


def ipv6_denial_totals(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "runs": len(rows),
        "cleanRuns": sum(1 for row in rows if row["clean"]),
        "failedRuns": sum(1 for row in rows if not row["clean"]),
        "classifications": aggregate(row["classification"] for row in rows),
        **{
            key: sum(int(row["current"].get(key) or 0) for row in rows)
            for key in COUNT_KEYS
        },
        "byIpVersion": merge_count_rows(row["current"]["byIpVersion"] for row in rows),
        "byProtocol": merge_count_rows(row["current"]["byProtocol"] for row in rows),
        "byDestinationPort": merge_count_rows(
            row["current"]["byDestinationPort"] for row in rows
        ),
        "byReasonBucket": merge_count_rows(
            row["current"]["byReasonBucket"] for row in rows
        ),
    }


def ipv6_denial_conclusion(totals: dict[str, Any]) -> dict[str, Any]:
    clean = totals["runs"] > 0 and totals["failedRuns"] == 0
    return {
        "status": "clean" if clean else "ipv6-denial-surface-needs-evidence",
        "nextAction": "return-to-runtime-surface" if clean else "inspect-ip-denials",
        "plannerPenaltySafe": False,
        "qualityPenaltySafe": False,
    }


def write_ipv6_denial_summary(output_dir: Path, summary: dict[str, Any]) -> None:
    (output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n"
    )
    write_ipv6_denial_markdown(output_dir / "summary.md", summary)


def write_ipv6_denial_markdown(path: Path, summary: dict[str, Any]) -> None:
    totals = summary["totals"]
    lines = [
        "# VM Private Runtime IPv6 Denial Surface",
        "",
        f"- label: `{summary['label']}`",
        f"- status: `{summary['conclusion']['status']}`",
        f"- runs: `{totals['runs']}`",
        f"- clean runs: `{totals['cleanRuns']}`",
        f"- denials: `{totals['denials']}`",
        f"- reported IPv6 denied: `{totals['reportedIpv6PacketsDenied']}`",
        f"- non-IPv6 denials: `{totals['nonIpv6Denials']}`",
        f"- TCP flows: `{totals['flows']}`",
        f"- TCP failed flows: `{totals['failedFlows']}`",
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


def ipv6_denial_print(output_dir: Path, summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "outputDir": str(output_dir),
        "runs": summary["totals"]["runs"],
        "cleanRuns": summary["totals"]["cleanRuns"],
        "status": summary["conclusion"]["status"],
    }


def missing_denial_fields(event_fields: dict[str, str]) -> list[str]:
    return [
        key
        for key in ["ipVersion", "protocol", "destinationPort", "reason"]
        if not event_fields.get(key)
    ]


def sanitized_value(value: object) -> str:
    return str(value or "unknown")


def reason_bucket(reason: object) -> str:
    text = str(reason or "").lower()
    if "ipv6" in text and "not implemented" in text:
        return "ipv6-forwarding-not-implemented"
    if "fail closed" in text:
        return "fail-closed"
    return "missing" if not text else "other"


def aggregate(values: Any) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for value in values:
        key = str(value or "unknown")
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


def load_optional_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open() as fh:
        value = json.load(fh)
    return value if isinstance(value, dict) else {}
