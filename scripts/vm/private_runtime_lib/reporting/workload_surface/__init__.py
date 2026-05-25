from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from common import CommandError, Lab, validate_name
from private_runtime_lib.reporting.round_gap import load_run_summary, round_gap_row
from private_runtime_lib.reporting.round_gap_conclusion import cascade_totals
from private_runtime_lib.reporting.workload_surface.conclusion import workload_surface_conclusion
from private_runtime_lib.reporting.workload_surface.markdown import write_workload_surface_markdown


WORKLOAD_SURFACE_SCHEMA = "dynet-vm-private-runtime-workload-surface/v1alpha1"
REPEAT_SCHEMA = "dynet-vm-private-runtime-repeat/v1alpha1"
ROUND_GAP_SCHEMA = "dynet-vm-private-runtime-round-gap-batch/v1alpha1"
EXPANDABLE_SCHEMAS = {REPEAT_SCHEMA, ROUND_GAP_SCHEMA}

FAILED_ROW_FIELDS = """
id domain scheduledOffsetMs scheduleLagMs errorStage errorType errorClass localPortPresent
elapsedMs mechanism failureSurface workloadTcpConnectOk workloadRouteViaDynet workloadTunWitnessed
runtimePreflowMatched runtimePacketMatched runtimePacketTerminalMatched
runtimePacketTerminalReason runtimePacketTerminalHandshakeComplete
runtimePacketTerminalPromotedToSession runtimeIngressSynPackets runtimeEgressSynAckPackets
runtimeFinPackets runtimeRstPackets tunCaptureMatched tunCaptureSynPackets tunCaptureSynAckPackets
flowMatched flowMatchedCount flowFailedCount flowStageFailedCount flowRecoveredFailure
flowId flowIds cascadeStoppedFlowMatched cascadeStoppedFlowStopReason
cascadeStoppedFlowCandidateExhausted cascadeStoppedFlowAttemptCount
cascadeStoppedFlowFailedAttemptCount cascadeStoppedFlowRetryableFailureCount
cascadeStoppedFlowCandidateCount cascadeStoppedFlowFailureScope
cascadeStoppedFlowDisposition cascadeStoppedFlowStageSurface
cascadeStoppedFlowBoundSelectedSequence cascadeStoppedFlowFailedSelectedSequence
cascadeStoppedFlowRetryableSelectedSequence cascadeStoppedFlowLastBoundSelected
runtimePacketTerminalIngressControlPackets runtimePacketTerminalEgressControlPackets
runtimePacketTerminalIngressPayloadPackets runtimePacketTerminalIngressPayloadBytes
runtimePacketTerminalEgressPayloadPackets runtimePacketTerminalEgressPayloadBytes
runtimePacketTerminalFinPackets runtimePacketTerminalRstPackets
runtimePreflowCandidateMatched runtimePreflowCandidateReason
runtimePreflowCandidateIngressPayloadBytes runtimePreflowCandidateEgressPayloadBytes
runtimePreflowCandidateFinPackets runtimePreflowCandidateRstPackets
runtimePreflowMissedMatched runtimePreflowMissedReason runtimePreflowMissedSocketState
runtimePreflowMissedTerminalReason runtimePreflowMissedIngressPayloadBytes
runtimePreflowMissedEgressPayloadBytes runtimePreflowMissedFinPackets runtimePreflowMissedRstPackets
""".split()

DNS_FAILURE_OUTPUT_FIELDS = {
    "runtimeDnsFailureFlowId": "flowId",
    "runtimeDnsFailureElapsedMs": "elapsedMs",
    "runtimeDnsFailureAttemptElapsedMs": "attemptElapsedMs",
    "runtimeDnsFailureType": "errorType",
    "runtimeDnsFailureDisposition": "disposition",
    "runtimeDnsFailureOutbound": "outbound",
    "runtimeDnsFailureUpstream": "upstream",
    "runtimeDnsFailureResponseCode": "failureResponseCode",
    "runtimeDnsFailureResponseBytes": "failureResponseBytes",
}


def command_workload_surface(_lab: Lab, args: argparse.Namespace) -> None:
    label = validate_name(args.label or "workload-surface", "label")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = build_workload_surface_summary(label, output_dir, [Path(item) for item in args.input])
    write_workload_surface_summary(output_dir, summary)
    print(
        json.dumps(
            {
                "outputDir": str(output_dir),
                "status": summary["conclusion"]["status"],
                "runs": summary["totals"]["runs"],
                "failedRows": summary["totals"]["failedRows"],
            },
            sort_keys=True,
        )
    )


def build_workload_surface_summary(
    label: str,
    output_dir: Path,
    inputs: list[Path],
) -> dict[str, Any]:
    run_inputs = expand_run_inputs(inputs)
    rows = [workload_surface_row(path, summary) for path, summary in run_inputs]
    failed_rows = flatten_failed_rows(rows)
    totals = workload_surface_totals(rows, failed_rows)
    return {
        "schema": WORKLOAD_SURFACE_SCHEMA,
        "label": label,
        "outputDir": str(output_dir),
        "runs": rows,
        "failedRows": failed_rows,
        "totals": totals,
        "conclusion": workload_surface_conclusion(totals),
        "policy": {
            "plannerPenaltySafe": False,
            "qualityPenaltySafe": False,
            "productEffectClaimSafe": False,
            "reason": (
                "workload surfaces are observe-only runtime-shape evidence until each "
                "surface is isolated with repeatable runtime-backed stage evidence"
            ),
        },
    }


def expand_run_inputs(inputs: list[Path]) -> list[tuple[Path, dict[str, Any]]]:
    runs: list[tuple[Path, dict[str, Any]]] = []
    for item in inputs:
        summary_path = summary_json_path(item)
        summary = load_json(summary_path)
        if summary.get("schema") in EXPANDABLE_SCHEMAS:
            runs.extend(expand_summary_runs(summary_path, summary))
        else:
            runs.append((item, summary))
    return runs


def summary_json_path(path: Path) -> Path:
    return path / "summary.json" if path.is_dir() else path


def expand_summary_runs(summary_path: Path, summary: dict[str, Any]) -> list[tuple[Path, dict[str, Any]]]:
    expanded: list[tuple[Path, dict[str, Any]]] = []
    for index, row in enumerate(summary.get("runs") or []):
        run_path_value = row.get("path") if isinstance(row, dict) else None
        if not run_path_value:
            raise CommandError(f"{summary_path} run {index + 1} has no path")
        run_path = Path(str(run_path_value))
        if not run_path.is_absolute():
            run_path = summary_path.parent / run_path
        expanded.append((run_path, load_run_summary(run_path)))
    return expanded


def workload_surface_row(run_path: Path, summary: dict[str, Any]) -> dict[str, Any]:
    row = round_gap_row(run_path, summary, include_failed_rows=True)
    runtime_dns_failures = dns_failure_rows(load_optional_runtime_report(run_path, summary))
    return {
        "label": row.get("label") or run_path.name,
        "path": row.get("path") or str(run_path),
        "passed": row["passed"],
        "roundGapClassification": row["classification"],
        "workload": row["workload"],
        "quality": row["quality"],
        "runtime": row["runtime"],
        "cascade": row["cascade"],
        "flowRefresh": row["flowRefresh"],
        "cascadeRefresh": row["cascadeRefresh"],
        "surfaces": row["surfaces"],
        "workloadFlow": row["workloadFlow"],
        "runtimeDnsFailures": runtime_dns_failures,
        "schedule": {
            "lagMaxMs": row["schedule"]["lagMaxMs"],
            "failedRows": row["schedule"]["failedRows"],
        },
        "mechanisms": row["mechanisms"],
    }


def flatten_failed_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    failed_rows = []
    for row in rows:
        dns_failures = rows_by_domain(row["runtimeDnsFailures"])
        for failed in row["schedule"]["failedRows"]:
            dns_failure = first_row(dns_failures.get(str(failed.get("domain") or "")))
            fields = {field: failed.get(field) for field in FAILED_ROW_FIELDS}
            failed_rows.append(
                {
                    "runLabel": row["label"],
                    "runPath": row["path"],
                    "roundGapClassification": row["roundGapClassification"],
                    **fields,
                    "runtimePacketTerminalCloseSignal": packet_terminal_close_signal(fields),
                    **dns_failure_fields(dns_failure),
                }
            )
    return failed_rows


def workload_surface_totals(
    rows: list[dict[str, Any]],
    failed_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "runs": len(rows),
        "cleanRuns": sum(1 for row in rows if row["passed"]),
        "failedRuns": sum(1 for row in rows if not row["passed"]),
        "workloadAttempted": sum(int(row["workload"].get("attempted") or 0) for row in rows),
        "workloadSuccess": sum(int(row["workload"].get("success") or 0) for row in rows),
        "workloadFailure": sum(int(row["workload"].get("failure") or 0) for row in rows),
        "failedRows": len(failed_rows),
        "classifications": aggregate_strings(row["roundGapClassification"] for row in rows),
        "failedBySurface": aggregate_strings(row.get("failureSurface") for row in failed_rows),
        "failedByMechanism": aggregate_strings(row.get("mechanism") for row in failed_rows),
        "failedByMechanismSurface": aggregate_field_tuples(failed_rows, ["mechanism", "failureSurface"]),
        "failedByMechanismStage": aggregate_field_tuples(failed_rows, ["mechanism", "errorStage", "errorType"]),
        "failedByStage": aggregate_strings(row.get("errorStage") for row in failed_rows),
        "failedByErrorType": aggregate_strings(row.get("errorType") for row in failed_rows),
        "failedByDomain": aggregate_strings(row.get("domain") for row in failed_rows),
        "runtimePacketTerminalByReason": aggregate_strings(
            row.get("runtimePacketTerminalReason") for row in failed_rows
        ),
        "preTcpFailures": count_rows(failed_rows, "mechanism", "pre-tcp-workload-failure"),
        "packetTerminalFailures": count_rows(
            failed_rows,
            "mechanism",
            "packet-terminal-before-runtime-session",
        ),
        **packet_terminal_totals(failed_rows),
        "runtimePacketMatchedFailures": sum(
            1 for row in failed_rows if row.get("runtimePacketMatched")
        ),
        "runtimeDnsFailures": sum(len(row["runtimeDnsFailures"]) for row in rows),
        "failedRowsWithRuntimeDnsFailure": sum(
            1 for row in failed_rows if row.get("runtimeDnsFailureMatched")
        ),
        "preTcpFailuresWithRuntimeDnsFailure": sum(
            1
            for row in failed_rows
            if row.get("mechanism") == "pre-tcp-workload-failure"
            and row.get("runtimeDnsFailureMatched")
        ),
        "failedByRuntimeDnsDisposition": aggregate_strings(
            row.get("runtimeDnsFailureDisposition") for row in failed_rows
        ),
        "failedByRuntimeDnsResponseCode": aggregate_strings(
            row.get("runtimeDnsFailureResponseCode") for row in failed_rows
        ),
        **cascade_stopped_flow_totals(failed_rows),
        "tunCaptureMatchedFailures": sum(1 for row in failed_rows if row.get("tunCaptureMatched")),
        "routeViaDynetFailures": sum(1 for row in failed_rows if row.get("workloadRouteViaDynet")),
        "tunWitnessedFailures": sum(1 for row in failed_rows if row.get("workloadTunWitnessed")),
        "tcpConnectedFailures": sum(1 for row in failed_rows if row.get("workloadTcpConnectOk")),
        "scheduleLagMaxMs": max(
            [int_value(row.get("scheduleLagMs")) for row in failed_rows]
            + [int(row["schedule"].get("lagMaxMs") or 0) for row in rows],
            default=0,
        ),
        "qualityCandidateSets": sum(int(row["quality"].get("candidateSets") or 0) for row in rows),
        "qualitySelectedWithQuality": sum(
            int(row["quality"].get("selectedWithQuality") or 0) for row in rows
        ),
        "qualitySelectedBehind": sum(
            int(row["quality"].get("selectedBehind") or 0) for row in rows
        ),
        **cascade_totals(rows),
    }


def write_workload_surface_summary(output_dir: Path, summary: dict[str, Any]) -> None:
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    write_workload_surface_markdown(output_dir / "summary.md", summary)


def load_optional_runtime_report(run_path: Path, summary: dict[str, Any]) -> dict[str, Any]:
    embedded = summary.get("runtimeReport")
    if isinstance(embedded, dict):
        return embedded
    if run_path.is_dir():
        path = run_path / "runtime-report.json"
    else:
        path = run_path.parent / "runtime-report.json"
    if not path.exists():
        return {}
    return load_json(path)


def dns_failure_rows(runtime_report: dict[str, Any]) -> list[dict[str, Any]]:
    events = [event for event in runtime_report.get("events") or [] if isinstance(event, dict)]
    attempts = dns_attempt_failures(events)
    failures = []
    for event in events:
        if event.get("kind") != "dns-resolve-failed":
            continue
        fields = event.get("fields") or {}
        flow_id = str(fields.get("flowId") or "")
        attempt = attempts.get(flow_id, {})
        failures.append(
            {
                "domain": fields.get("query"),
                "flowId": flow_id,
                "dnsQueryId": fields.get("dnsQueryId"),
                "listener": fields.get("listener"),
                "elapsedMs": int_value(fields.get("elapsedMs")),
                "errorType": fields.get("errorType"),
                "disposition": dns_failure_disposition(fields, attempt),
                "outbound": attempt.get("outbound"),
                "upstream": attempt.get("upstream"),
                "attemptElapsedMs": int_value(attempt.get("elapsedMs")),
                "failureResponseCode": fields.get("failureResponseCode"),
                "failureResponseBytes": optional_int(fields.get("failureResponseBytes")),
            }
        )
    return failures


def dns_attempt_failures(events: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    started = {}
    for event in events:
        if event.get("kind") != "outbound-attempt-started":
            continue
        fields = event.get("fields") or {}
        if fields.get("transport") != "dns":
            continue
        flow_id = str(fields.get("flowId") or "")
        if flow_id:
            started[flow_id] = fields
    attempts = {}
    for event in events:
        if event.get("kind") != "outbound-attempt-finished":
            continue
        fields = event.get("fields") or {}
        if fields.get("transport") != "dns" or fields.get("status") != "failed":
            continue
        flow_id = str(fields.get("flowId") or "")
        if flow_id:
            attempts[flow_id] = {**started.get(flow_id, {}), **fields}
    return attempts


def dns_failure_disposition(*field_sets: dict[str, Any]) -> str:
    for fields in field_sets:
        if fields.get("errorDisposition"):
            return str(fields["errorDisposition"])
    text = " ".join(str(fields.get("error") or "") for fields in field_sets).lower()
    if (
        "resource temporarily unavailable" in text
        or "operation would block" in text
        or "would block" in text
    ):
        return "pending-timeout"
    if "timed out" in text or "timeout" in text:
        return "timeout"
    if "eof" in text:
        return "remote-eof"
    return "unknown"


def dns_failure_fields(dns_failure: dict[str, Any] | None) -> dict[str, Any]:
    fields = {
        output: None
        for output in DNS_FAILURE_OUTPUT_FIELDS
    }
    if not dns_failure:
        return {"runtimeDnsFailureMatched": False, **fields}
    fields.update(
        {
            output: dns_failure.get(source)
            for output, source in DNS_FAILURE_OUTPUT_FIELDS.items()
        }
    )
    return {"runtimeDnsFailureMatched": True, **fields}


def rows_by_domain(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(str(row.get("domain") or ""), []).append(row)
    return grouped


def first_row(rows: list[dict[str, Any]] | None) -> dict[str, Any] | None:
    if not rows:
        return None
    return rows[0]


def load_json(path: Path) -> dict[str, Any]:
    with path.open() as fh:
        value = json.load(fh)
    if not isinstance(value, dict):
        raise CommandError(f"{path} does not contain a JSON object")
    return value


def aggregate_strings(values: Any) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for value in values:
        key = str(value or "unknown")
        counts[key] = counts.get(key, 0) + 1
    return [{"key": key, "count": counts[key]} for key in sorted(counts)]


def aggregate_field_tuples(rows: list[dict[str, Any]], fields: list[str]) -> list[dict[str, Any]]:
    counts: dict[tuple[str, ...], int] = {}
    for row in rows:
        key = tuple(str(row.get(field) or "unknown") for field in fields)
        counts[key] = counts.get(key, 0) + 1
    return [
        {**{field: key[index] for index, field in enumerate(fields)}, "count": counts[key]}
        for key in sorted(counts)
    ]


def packet_terminal_totals(failed_rows: list[dict[str, Any]]) -> dict[str, Any]:
    rows = [
        row
        for row in failed_rows
        if row.get("mechanism") == "packet-terminal-before-runtime-session"
    ]
    return {
        "packetTerminalWithIngressPayload": sum(
            1 for row in rows if int_value(row.get("runtimePacketTerminalIngressPayloadBytes")) > 0
        ),
        "packetTerminalIngressPayloadBytes": sum(
            int_value(row.get("runtimePacketTerminalIngressPayloadBytes")) for row in rows
        ),
        "packetTerminalEgressPayloadBytes": sum(
            int_value(row.get("runtimePacketTerminalEgressPayloadBytes")) for row in rows
        ),
        "packetTerminalByCloseSignal": aggregate_strings(
            row.get("runtimePacketTerminalCloseSignal") for row in rows
        ),
        "packetTerminalPreflowCandidates": sum(
            1 for row in rows if row.get("runtimePreflowCandidateMatched")
        ),
        "packetTerminalPreflowCandidateByReason": aggregate_strings(
            row.get("runtimePreflowCandidateReason")
            for row in rows
            if row.get("runtimePreflowCandidateMatched")
        ),
        "packetTerminalPreflowMissed": sum(
            1 for row in rows if row.get("runtimePreflowMissedMatched")
        ),
        "packetTerminalPreflowMissedByReason": aggregate_strings(
            row.get("runtimePreflowMissedReason") for row in rows if row.get("runtimePreflowMissedMatched")
        ),
        "packetTerminalPreflowMissedBySocketState": aggregate_strings(
            row.get("runtimePreflowMissedSocketState")
            for row in rows
            if row.get("runtimePreflowMissedMatched")
        ),
    }


def cascade_stopped_flow_totals(failed_rows: list[dict[str, Any]]) -> dict[str, Any]:
    rows = [row for row in failed_rows if row.get("cascadeStoppedFlowMatched")]
    return {
        "failedRowsWithCascadeStoppedFlow": len(rows),
        "cascadeStoppedFlowCandidateExhaustedFailures": sum(
            1 for row in rows if row.get("cascadeStoppedFlowCandidateExhausted")
        ),
        "failedByCascadeStoppedFlowStopReason": aggregate_strings(
            row.get("cascadeStoppedFlowStopReason") for row in rows
        ),
        "failedByCascadeStoppedFlowStageSurface": aggregate_strings(
            row.get("cascadeStoppedFlowStageSurface") for row in rows
        ),
        "failedByCascadeStoppedFlowLastBoundSelected": aggregate_strings(
            row.get("cascadeStoppedFlowLastBoundSelected") for row in rows
        ),
    }


def packet_terminal_close_signal(row: dict[str, Any]) -> str:
    fin = int_value(row.get("runtimePacketTerminalFinPackets"))
    rst = int_value(row.get("runtimePacketTerminalRstPackets"))
    if fin > 0 and rst > 0:
        return "fin+rst"
    if fin > 0:
        return "fin"
    if rst > 0:
        return "rst"
    return "none"


def count_rows(rows: list[dict[str, Any]], field: str, value: str) -> int:
    return sum(1 for row in rows if row.get(field) == value)


def int_value(value: Any) -> int:
    if value is None:
        return 0
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def optional_int(value: Any) -> int | None:
    if value is None:
        return None
    return int_value(value)
