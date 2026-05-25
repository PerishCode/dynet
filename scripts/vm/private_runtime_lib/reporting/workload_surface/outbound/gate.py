from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from common import Lab, validate_name
from private_runtime_lib.briefs import fields
from private_runtime_lib.tcp_flow import tcp_flow_brief


OUTBOUND_GATE_SCHEMA = "dynet-vm-private-runtime-outbound-gate-surface/v1alpha1"
REPEAT_SCHEMA = "dynet-vm-private-runtime-repeat/v1alpha1"
SCOPES = {"tcp-route": "route", "dialer-bound": "bound"}
COUNT_KEYS = [
    "flows",
    "startedFlows",
    "closedFlows",
    "failedFlows",
    "lifecycleCompleteFlows",
    "pathCompleteFlows",
    "payloadBidirectionalFlows",
    "admissionEvents",
    "egressEvents",
    "admissionFlows",
    "egressFlows",
    "routeAdmissionEvents",
    "routeAdmissionFlows",
    "routeEgressEvents",
    "routeEgressFlows",
    "routeEgressSelectedFlows",
    "routeEgressMismatches",
    "boundAdmissionEvents",
    "boundAdmissionFlows",
    "boundEgressEvents",
    "boundEgressFlows",
    "boundEgressSelectedFlows",
    "admissionMissingOutboundEvents",
    "egressMissingSelectedEvents",
    "unknownScopeEvents",
    "nonTcpTransportEvents",
]


def command_outbound_gate_surface(_lab: Lab, args: argparse.Namespace) -> None:
    label = validate_name(args.label or "outbound-gate-surface", "label")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = build_outbound_gate_summary(
        label,
        output_dir,
        [Path(item) for item in args.input],
    )
    write_outbound_gate_summary(output_dir, summary)
    print(json.dumps(outbound_gate_print(output_dir, summary), sort_keys=True))


def build_outbound_gate_summary(
    label: str,
    output_dir: Path,
    inputs: list[Path],
) -> dict[str, Any]:
    rows = [outbound_gate_row(path) for path in expand_inputs(inputs)]
    totals = outbound_gate_totals(rows)
    return {
        "schema": OUTBOUND_GATE_SCHEMA,
        "label": label,
        "outputDir": str(output_dir),
        "runs": rows,
        "totals": totals,
        "conclusion": outbound_gate_conclusion(totals),
        "policy": {
            "plannerPenaltySafe": False,
            "qualityPenaltySafe": False,
            "reason": "Outbound admission/egress gates are path evidence, not penalty proof.",
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


def outbound_gate_row(run_dir: Path) -> dict[str, Any]:
    summary = load_optional_json(run_dir / "summary.json")
    current = outbound_gate_counts(load_optional_json(run_dir / "runtime-report.json"))
    clean = outbound_gate_clean(current)
    return {
        "label": summary.get("label") or run_dir.name,
        "path": str(run_dir),
        "classification": "clean" if clean else outbound_gate_classification(current),
        "clean": clean,
        "current": current,
    }


def outbound_gate_counts(report: dict[str, Any]) -> dict[str, Any]:
    flow = tcp_flow_brief(report)
    rows = outbound_gate_rows(report)
    admission = [row for row in rows if row["kind"] == "outbound-admission-passed"]
    egress = [row for row in rows if row["kind"] == "outbound-egress-passed"]
    route_egress = scope_rows(egress, "tcp-route")
    bound_egress = scope_rows(egress, "dialer-bound")
    return {
        "flows": int(flow.get("flows") or 0),
        "startedFlows": int(flow.get("startedFlows") or 0),
        "closedFlows": int(flow.get("closedFlows") or 0),
        "failedFlows": int(flow.get("failedFlows") or 0),
        "lifecycleCompleteFlows": int(flow.get("lifecycleCompleteFlows") or 0),
        "pathCompleteFlows": int(flow.get("pathCompleteFlows") or 0),
        "payloadBidirectionalFlows": int(flow.get("payloadBidirectionalFlows") or 0),
        "admissionEvents": len(admission),
        "egressEvents": len(egress),
        "admissionFlows": count_flows(admission),
        "egressFlows": count_flows(egress),
        **scope_counts(admission, egress),
        "routeEgressSelectedFlows": count_flows(selected_rows(route_egress)),
        "routeEgressMismatches": route_egress_mismatches(route_egress),
        "boundEgressSelectedFlows": count_flows(selected_rows(bound_egress)),
        "admissionMissingOutboundEvents": sum(1 for row in admission if not row["outboundPresent"]),
        "egressMissingSelectedEvents": sum(1 for row in egress if not row["selectedPresent"]),
        "unknownScopeEvents": sum(1 for row in rows if row["scope"] not in SCOPES),
        "nonTcpTransportEvents": sum(1 for row in rows if not row["tcpTransport"]),
        "eventsByScope": aggregate(row["scope"] for row in rows),
    }


def outbound_gate_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for event in report.get("events", []):
        if not isinstance(event, dict):
            continue
        kind = event.get("kind")
        if kind not in {"outbound-admission-passed", "outbound-egress-passed"}:
            continue
        event_fields = fields(event)
        flow_id = event_fields.get("flowId")
        if not flow_id or not flow_id.startswith("tcp-session-"):
            continue
        rows.append(outbound_gate_row_fields(str(kind), event_fields, flow_id))
    return rows


def outbound_gate_row_fields(
    kind: str,
    event_fields: dict[str, str],
    flow_id: str,
) -> dict[str, Any]:
    transport = event_fields.get("transport")
    session_transport = event_fields.get("sessionTransport")
    return {
        "kind": kind,
        "flowId": flow_id,
        "scope": event_fields.get("scope") or "unknown",
        "outboundPresent": bool(event_fields.get("outbound")),
        "requestedPresent": bool(event_fields.get("requested")),
        "selectedPresent": bool(event_fields.get("selected")),
        "requestedSelectedSame": (
            bool(event_fields.get("requested"))
            and event_fields.get("requested") == event_fields.get("selected")
        ),
        "tcpTransport": transport == "tcp" and session_transport == "tcp",
    }


def scope_counts(admission: list[dict[str, Any]], egress: list[dict[str, Any]]) -> dict[str, int]:
    result = {}
    for scope, prefix in SCOPES.items():
        admission_rows = scope_rows(admission, scope)
        egress_rows = scope_rows(egress, scope)
        result[f"{prefix}AdmissionEvents"] = len(admission_rows)
        result[f"{prefix}AdmissionFlows"] = count_flows(admission_rows)
        result[f"{prefix}EgressEvents"] = len(egress_rows)
        result[f"{prefix}EgressFlows"] = count_flows(egress_rows)
    return result


def outbound_gate_clean(counts: dict[str, Any]) -> bool:
    flows = int(counts["flows"])
    return (
        flows > 0
        and counts["startedFlows"] == flows
        and counts["closedFlows"] == flows
        and counts["failedFlows"] == 0
        and counts["lifecycleCompleteFlows"] == flows
        and counts["pathCompleteFlows"] == flows
        and counts["payloadBidirectionalFlows"] == flows
        and counts["routeAdmissionFlows"] == flows
        and counts["routeEgressFlows"] == flows
        and counts["routeEgressSelectedFlows"] == flows
        and counts["boundAdmissionFlows"] == flows
        and counts["boundEgressFlows"] == flows
        and counts["boundEgressSelectedFlows"] == flows
        and counts["routeEgressMismatches"] == 0
        and counts["admissionMissingOutboundEvents"] == 0
        and counts["egressMissingSelectedEvents"] == 0
        and counts["unknownScopeEvents"] == 0
        and counts["nonTcpTransportEvents"] == 0
    )


def outbound_gate_classification(counts: dict[str, Any]) -> str:
    flows = int(counts["flows"])
    if int(counts["failedFlows"]):
        return "flow-failure"
    for field, label in [
        ("routeAdmissionFlows", "route-admission-missing"),
        ("routeEgressFlows", "route-egress-missing"),
        ("boundAdmissionFlows", "bound-admission-missing"),
        ("boundEgressFlows", "bound-egress-missing"),
    ]:
        if int(counts[field]) < flows:
            return label
    if int(counts["routeEgressMismatches"]):
        return "route-egress-mismatch"
    if int(counts["egressMissingSelectedEvents"]):
        return "egress-selected-missing"
    if int(counts["admissionMissingOutboundEvents"]):
        return "admission-outbound-missing"
    if int(counts["unknownScopeEvents"]):
        return "unknown-scope"
    if int(counts["nonTcpTransportEvents"]):
        return "non-tcp-transport"
    if int(counts["lifecycleCompleteFlows"]) < flows or int(counts["pathCompleteFlows"]) < flows:
        return "flow-lifecycle-incomplete"
    return "outbound-gate-surface-incomplete"


def outbound_gate_totals(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "runs": len(rows),
        "cleanRuns": sum(1 for row in rows if row["clean"]),
        "failedRuns": sum(1 for row in rows if not row["clean"]),
        "classifications": aggregate(row["classification"] for row in rows),
        **{
            key: sum(int(row["current"].get(key) or 0) for row in rows)
            for key in COUNT_KEYS
        },
        "eventsByScope": merge_count_rows(row["current"]["eventsByScope"] for row in rows),
    }


def outbound_gate_conclusion(totals: dict[str, Any]) -> dict[str, Any]:
    clean = totals["runs"] > 0 and totals["failedRuns"] == 0
    return {
        "status": "clean" if clean else "outbound-gate-surface-needs-evidence",
        "nextAction": "return-to-runtime-surface" if clean else "inspect-outbound-gate-path",
        "plannerPenaltySafe": False,
        "qualityPenaltySafe": False,
    }


def write_outbound_gate_summary(output_dir: Path, summary: dict[str, Any]) -> None:
    (output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n"
    )
    write_outbound_gate_markdown(output_dir / "summary.md", summary)


def write_outbound_gate_markdown(path: Path, summary: dict[str, Any]) -> None:
    totals = summary["totals"]
    lines = [
        "# VM Private Runtime Outbound Gate Surface",
        "",
        f"- label: `{summary['label']}`",
        f"- status: `{summary['conclusion']['status']}`",
        f"- runs: `{totals['runs']}`",
        f"- clean runs: `{totals['cleanRuns']}`",
        f"- flows: `{totals['flows']}`",
        f"- route admission flows: `{totals['routeAdmissionFlows']}`",
        f"- route egress flows: `{totals['routeEgressFlows']}`",
        f"- bound admission flows: `{totals['boundAdmissionFlows']}`",
        f"- bound egress flows: `{totals['boundEgressFlows']}`",
        f"- route egress mismatches: `{totals['routeEgressMismatches']}`",
        f"- missing selected events: `{totals['egressMissingSelectedEvents']}`",
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


def outbound_gate_print(output_dir: Path, summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "outputDir": str(output_dir),
        "runs": summary["totals"]["runs"],
        "cleanRuns": summary["totals"]["cleanRuns"],
        "status": summary["conclusion"]["status"],
    }


def scope_rows(rows: list[dict[str, Any]], scope: str) -> list[dict[str, Any]]:
    return [row for row in rows if row["scope"] == scope]


def selected_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [row for row in rows if row["selectedPresent"]]


def route_egress_mismatches(rows: list[dict[str, Any]]) -> int:
    return sum(1 for row in rows if not row["requestedSelectedSame"])


def count_flows(rows: list[dict[str, Any]]) -> int:
    return len({str(row["flowId"]) for row in rows if row.get("flowId")})


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


def load_optional_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text())
