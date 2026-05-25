from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

from common import Lab, validate_name
from private_runtime_lib.briefs import fields
from private_runtime_lib.reporting.workload_surface.outbound.pairs import pair_counts

OUTBOUND_ATTEMPT_SCHEMA = "dynet-vm-private-runtime-outbound-attempt-surface/v1alpha1"
REPEAT_SCHEMA = "dynet-vm-private-runtime-repeat/v1alpha1"
ATTEMPT_KINDS = {"outbound-attempt-started", "outbound-attempt-finished"}
CASCADE_KINDS = {"dialer-cascade-attempt-started", "dialer-cascade-attempt-finished"}
VALID_ATTEMPT_STATUS = {"success", "failed"}
VALID_CASCADE_STATUS = {"success", "failed"}
VALID_PROTOCOLS = {"tcp-connect", "udp-connect", "dns-over-tcp"}
VALID_TRANSPORTS = {"tcp", "udp", "dns"}
COUNT_FIELDS = """
runs cleanRuns failedRuns eventReports runtimePass events
attemptStarts attemptFinishes attemptPairs finishWithoutStart startWithoutFinish
attemptOrderViolations attemptStatusMissing attemptInvalidStatus
attemptProtocolMissing attemptInvalidProtocol attemptTransportMissing
attemptInvalidTransport attemptReferenceMissing attemptOutboundMissing
attemptFinishElapsedMissing failedAttemptErrorTypeMissing
failedAttemptDispositionMissing successfulAttempts failedAttempts
sessionTcpAttempts sessionTcpAttemptsMissingRoute attemptsWithStage
attemptsMissingStage cascadeStarts cascadeFinishes cascadePairs
cascadeFinishWithoutStart cascadeStartWithoutFinish cascadeOrderViolations
cascadeStatusMissing cascadeInvalidStatus cascadeReferenceMissing
cascadeAttemptMissing cascadeFailureScopeMissing cascadeFailureRetryAllowedMissing
cascadeFailureRetryStopReasonMissing cascadeWithOutboundAttempt
cascadeMissingOutboundAttempt
""".split()
BLOCKERS = """
finishWithoutStart startWithoutFinish attemptOrderViolations
attemptStatusMissing attemptInvalidStatus attemptProtocolMissing
attemptInvalidProtocol attemptTransportMissing attemptInvalidTransport
attemptReferenceMissing attemptOutboundMissing attemptFinishElapsedMissing
failedAttemptErrorTypeMissing failedAttemptDispositionMissing
sessionTcpAttemptsMissingRoute attemptsMissingStage cascadeFinishWithoutStart
cascadeStartWithoutFinish cascadeOrderViolations cascadeStatusMissing
cascadeInvalidStatus cascadeReferenceMissing cascadeAttemptMissing
cascadeFailureScopeMissing cascadeFailureRetryAllowedMissing
cascadeFailureRetryStopReasonMissing cascadeMissingOutboundAttempt
""".split()


def command_outbound_attempt_surface(_lab: Lab, args: argparse.Namespace) -> None:
    label = validate_name(args.label or "outbound-attempt-surface", "label")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = build_outbound_attempt_summary(
        label,
        output_dir,
        [Path(item) for item in args.input],
    )
    write_outbound_attempt_summary(output_dir, summary)
    print(json.dumps(outbound_attempt_print(output_dir, summary), sort_keys=True))


def build_outbound_attempt_summary(
    label: str,
    output_dir: Path,
    inputs: list[Path],
) -> dict[str, Any]:
    rows = [outbound_attempt_row(path) for path in expand_inputs(inputs)]
    totals = outbound_attempt_totals(rows)
    return {
        "schema": OUTBOUND_ATTEMPT_SCHEMA,
        "label": label,
        "outputDir": str(output_dir),
        "runs": rows,
        "totals": totals,
        "conclusion": outbound_attempt_conclusion(totals),
        "privacy": empty_privacy_flags(),
        "policy": {
            "plannerPenaltySafe": False,
            "qualityPenaltySafe": False,
            "reason": "Outbound attempt lifecycle evidence is observability proof, not penalty proof.",
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


def outbound_attempt_row(run_dir: Path) -> dict[str, Any]:
    summary = load_optional_json(run_dir / "summary.json")
    current = outbound_attempt_counts(load_optional_json(run_dir / "runtime-report.json"))
    clean = outbound_attempt_clean(current)
    return {
        "label": summary.get("label") or run_dir.name,
        "path": str(run_dir),
        "classification": "clean" if clean else outbound_attempt_classification(current),
        "clean": clean,
        "current": current,
    }


def outbound_attempt_counts(report: dict[str, Any]) -> dict[str, Any]:
    raw_events = report.get("events")
    rows = [
        event_row(event, index)
        for index, event in enumerate(raw_events or [])
        if isinstance(event, dict)
    ]
    assign_pair_keys(rows, ATTEMPT_KINDS, "attemptPairKey", attempt_base)
    assign_pair_keys(rows, CASCADE_KINDS, "cascadePairKey", cascade_base)
    attempts = [row for row in rows if row["kind"] in ATTEMPT_KINDS]
    attempt_finishes = [row for row in rows if row["kind"] == "outbound-attempt-finished"]
    cascades = [row for row in rows if row["kind"] in CASCADE_KINDS]
    cascade_finishes = [row for row in rows if row["kind"] == "dialer-cascade-attempt-finished"]
    route_refs = route_reference_set(rows)
    stage_counts = Counter(row["reference"] for row in rows if row["kind"] == "outbound-stage-finished")
    attempt_finish_counts = Counter(row["reference"] for row in attempt_finishes)
    tcp_finish_counts = Counter(
        row["reference"] for row in attempt_finishes if row["protocol"] == "tcp-connect"
    )
    cascade_finish_counts = Counter(row["reference"] for row in cascade_finishes)
    return {
        "eventReports": 1 if raw_events is not None else 0,
        "runtimePass": 1 if report.get("status") == "pass" else 0,
        "events": len(rows),
        **attempt_pair_counts(attempts),
        **attempt_field_counts(attempts, attempt_finishes, route_refs, stage_counts),
        **cascade_pair_counts(cascades),
        **cascade_field_counts(cascade_finishes, tcp_finish_counts, cascade_finish_counts),
        "attemptStatuses": aggregate(f"{row['protocol']}:{row['status']}" for row in attempt_finishes),
        "attemptProtocols": aggregate(row["protocol"] for row in attempt_finishes),
        "attemptTransports": aggregate(row["transport"] for row in attempt_finishes),
        "cascadeStatuses": aggregate(
            f"{row['status']}:{row['failureScope'] or 'none'}" for row in cascade_finishes
        ),
    }


def event_row(event: dict[str, Any], index: int) -> dict[str, Any]:
    event_fields = fields(event)
    return {
        "index": index,
        "kind": str(event.get("kind") or ""),
        "reference": event_fields.get("flowId") or event_fields.get("dnsQueryId") or "",
        "flowId": event_fields.get("flowId") or "",
        "dnsQueryId": event_fields.get("dnsQueryId") or "",
        "sessionTransport": event_fields.get("sessionTransport") or "",
        "protocol": event_fields.get("protocol") or "",
        "transport": event_fields.get("transport") or event_fields.get("sessionTransport") or "",
        "status": event_fields.get("status") or "",
        "attempt": event_fields.get("attempt") or "",
        "attemptId": event_fields.get("attemptId") or "",
        "cascadeAttemptId": event_fields.get("cascadeAttemptId") or "",
        "outboundPresent": bool(event_fields.get("outbound")),
        "elapsedPresent": bool(event_fields.get("elapsedMs")),
        "errorTypePresent": bool(event_fields.get("errorType")),
        "errorDispositionPresent": bool(event_fields.get("errorDisposition")),
        "stage": event_fields.get("stage") or "",
        "failureScope": event_fields.get("failureScope") or "",
        "retryAllowed": event_fields.get("retryAllowed") or "",
        "retryStopReason": event_fields.get("retryStopReason") or "",
    }


def assign_pair_keys(
    rows: list[dict[str, Any]],
    kinds: set[str],
    target_key: str,
    base_fn: Any,
) -> None:
    counters: dict[tuple[str, str], int] = {}
    for row in rows:
        if row["kind"] not in kinds:
            continue
        base = base_fn(row)
        identity = row["attemptId"] or row["cascadeAttemptId"] or row["attempt"]
        if not identity:
            counter_key = (row["kind"], base)
            counters[counter_key] = counters.get(counter_key, 0) + 1
            identity = f"ordinal-{counters[counter_key]}"
        row[target_key] = f"{base}:{identity}"


def attempt_base(row: dict[str, Any]) -> str:
    return f"{row['reference']}:{row['protocol']}:{row['transport']}"


def cascade_base(row: dict[str, Any]) -> str:
    return row["reference"]


def attempt_pair_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    return pair_counts(
        rows,
        start_kind="outbound-attempt-started",
        finish_kind="outbound-attempt-finished",
        key_name="attemptPairKey",
        start_field="attemptStarts",
        finish_field="attemptFinishes",
        pair_field="attemptPairs",
        finish_without_field="finishWithoutStart",
        start_without_field="startWithoutFinish",
        order_field="attemptOrderViolations",
    )


def cascade_pair_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    return pair_counts(
        rows,
        start_kind="dialer-cascade-attempt-started",
        finish_kind="dialer-cascade-attempt-finished",
        key_name="cascadePairKey",
        start_field="cascadeStarts",
        finish_field="cascadeFinishes",
        pair_field="cascadePairs",
        finish_without_field="cascadeFinishWithoutStart",
        start_without_field="cascadeStartWithoutFinish",
        order_field="cascadeOrderViolations",
    )


def attempt_field_counts(
    attempts: list[dict[str, Any]],
    finishes: list[dict[str, Any]],
    route_refs: set[str],
    stage_counts: Counter[str],
) -> dict[str, int]:
    session_tcp_finishes = [row for row in finishes if is_session_tcp_attempt(row)]
    finish_counts = Counter(row["reference"] for row in finishes)
    return {
        "attemptStatusMissing": sum(1 for row in finishes if not row["status"]),
        "attemptInvalidStatus": sum(1 for row in finishes if row["status"] not in VALID_ATTEMPT_STATUS),
        "attemptProtocolMissing": sum(1 for row in attempts if not row["protocol"]),
        "attemptInvalidProtocol": sum(
            1 for row in attempts if row["protocol"] and row["protocol"] not in VALID_PROTOCOLS
        ),
        "attemptTransportMissing": sum(1 for row in attempts if not row["transport"]),
        "attemptInvalidTransport": sum(
            1 for row in attempts if row["transport"] and row["transport"] not in VALID_TRANSPORTS
        ),
        "attemptReferenceMissing": sum(1 for row in attempts if not row["reference"]),
        "attemptOutboundMissing": sum(1 for row in attempts if not row["outboundPresent"]),
        "attemptFinishElapsedMissing": sum(1 for row in finishes if not row["elapsedPresent"]),
        "failedAttemptErrorTypeMissing": sum(
            1 for row in finishes if row["status"] == "failed" and not row["errorTypePresent"]
        ),
        "failedAttemptDispositionMissing": sum(
            1 for row in finishes if row["status"] == "failed" and not row["errorDispositionPresent"]
        ),
        "successfulAttempts": sum(1 for row in finishes if row["status"] == "success"),
        "failedAttempts": sum(1 for row in finishes if row["status"] == "failed"),
        "sessionTcpAttempts": len(session_tcp_finishes),
        "sessionTcpAttemptsMissingRoute": sum(
            1 for row in session_tcp_finishes if row["flowId"] not in route_refs
        ),
        "attemptsWithStage": sum(min(finish_counts[ref], stage_counts.get(ref, 0)) for ref in finish_counts),
        "attemptsMissingStage": sum(
            max(0, finish_counts[ref] - stage_counts.get(ref, 0)) for ref in finish_counts
        ),
    }


def cascade_field_counts(
    finishes: list[dict[str, Any]],
    tcp_finish_counts: Counter[str],
    cascade_finish_counts: Counter[str],
) -> dict[str, int]:
    missing_outbound = sum(
        max(0, cascade_finish_counts[ref] - tcp_finish_counts.get(ref, 0))
        for ref in cascade_finish_counts
    )
    return {
        "cascadeStatusMissing": sum(1 for row in finishes if not row["status"]),
        "cascadeInvalidStatus": sum(1 for row in finishes if row["status"] not in VALID_CASCADE_STATUS),
        "cascadeReferenceMissing": sum(1 for row in finishes if not row["reference"]),
        "cascadeAttemptMissing": sum(1 for row in finishes if not row["attempt"]),
        "cascadeFailureScopeMissing": sum(
            1 for row in finishes if row["status"] == "failed" and not row["failureScope"]
        ),
        "cascadeFailureRetryAllowedMissing": sum(
            1 for row in finishes if row["status"] == "failed" and not row["retryAllowed"]
        ),
        "cascadeFailureRetryStopReasonMissing": sum(
            1 for row in finishes if row["status"] == "failed" and not row["retryStopReason"]
        ),
        "cascadeWithOutboundAttempt": len(finishes) - missing_outbound,
        "cascadeMissingOutboundAttempt": missing_outbound,
    }


def route_reference_set(rows: list[dict[str, Any]]) -> set[str]:
    return {
        row["flowId"]
        for row in rows
        if row["kind"] == "route-matched" and row["flowId"]
    }


def is_session_tcp_attempt(row: dict[str, Any]) -> bool:
    return (
        row["protocol"] == "tcp-connect"
        and row["transport"] == "tcp"
        and row["sessionTransport"] == "tcp"
        and row["flowId"].startswith("tcp-session-")
    )


def outbound_attempt_clean(counts: dict[str, Any]) -> bool:
    return (
        counts["eventReports"] == 1
        and counts["runtimePass"] == 1
        and counts["attemptFinishes"] > 0
        and all(int(counts[key]) == 0 for key in BLOCKERS)
    )


def outbound_attempt_classification(counts: dict[str, Any]) -> str:
    for key, label in [
        ("finishWithoutStart", "attempt-finish-without-start"),
        ("startWithoutFinish", "attempt-start-without-finish"),
        ("attemptOrderViolations", "attempt-order-invalid"),
        ("attemptStatusMissing", "attempt-status-missing"),
        ("attemptInvalidStatus", "attempt-status-invalid"),
        ("attemptProtocolMissing", "attempt-protocol-missing"),
        ("attemptInvalidProtocol", "attempt-protocol-invalid"),
        ("attemptTransportMissing", "attempt-transport-missing"),
        ("attemptInvalidTransport", "attempt-transport-invalid"),
        ("attemptReferenceMissing", "attempt-reference-missing"),
        ("attemptOutboundMissing", "attempt-outbound-missing"),
        ("attemptFinishElapsedMissing", "attempt-elapsed-missing"),
        ("failedAttemptErrorTypeMissing", "failed-attempt-error-type-missing"),
        ("failedAttemptDispositionMissing", "failed-attempt-disposition-missing"),
        ("sessionTcpAttemptsMissingRoute", "session-tcp-route-missing"),
        ("attemptsMissingStage", "attempt-stage-missing"),
        ("cascadeFinishWithoutStart", "cascade-finish-without-start"),
        ("cascadeStartWithoutFinish", "cascade-start-without-finish"),
        ("cascadeOrderViolations", "cascade-order-invalid"),
        ("cascadeStatusMissing", "cascade-status-missing"),
        ("cascadeInvalidStatus", "cascade-status-invalid"),
        ("cascadeReferenceMissing", "cascade-reference-missing"),
        ("cascadeAttemptMissing", "cascade-attempt-missing"),
        ("cascadeFailureScopeMissing", "cascade-failure-scope-missing"),
        ("cascadeFailureRetryAllowedMissing", "cascade-retry-allowed-missing"),
        ("cascadeFailureRetryStopReasonMissing", "cascade-retry-stop-reason-missing"),
        ("cascadeMissingOutboundAttempt", "cascade-outbound-attempt-missing"),
    ]:
        if int(counts[key]):
            return label
    return "outbound-attempt-surface-incomplete"


def outbound_attempt_totals(rows: list[dict[str, Any]]) -> dict[str, Any]:
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
        "attemptStatuses": merge_count_rows(row["current"]["attemptStatuses"] for row in rows),
        "attemptProtocols": merge_count_rows(row["current"]["attemptProtocols"] for row in rows),
        "attemptTransports": merge_count_rows(row["current"]["attemptTransports"] for row in rows),
        "cascadeStatuses": merge_count_rows(row["current"]["cascadeStatuses"] for row in rows),
    }


def outbound_attempt_conclusion(totals: dict[str, Any]) -> dict[str, Any]:
    clean = totals["runs"] > 0 and totals["failedRuns"] == 0
    return {
        "status": "clean" if clean else "outbound-attempt-surface-needs-evidence",
        "nextAction": "return-to-runtime-surface" if clean else "inspect-outbound-attempt-lifecycle",
        "plannerPenaltySafe": False,
        "qualityPenaltySafe": False,
    }


def write_outbound_attempt_summary(output_dir: Path, summary: dict[str, Any]) -> None:
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    write_outbound_attempt_markdown(output_dir / "summary.md", summary)


def write_outbound_attempt_markdown(path: Path, summary: dict[str, Any]) -> None:
    totals = summary["totals"]
    lines = [
        "# VM Private Runtime Outbound Attempt Surface",
        "",
        f"- label: `{summary['label']}`",
        f"- status: `{summary['conclusion']['status']}`",
        f"- runs: `{totals['runs']}`",
        f"- clean runs: `{totals['cleanRuns']}`",
        f"- attempt finishes: `{totals['attemptFinishes']}`",
        f"- failed attempts: `{totals['failedAttempts']}`",
        f"- attempt pair gaps: `{totals['finishWithoutStart'] + totals['startWithoutFinish']}`",
        f"- attempts missing stage: `{totals['attemptsMissingStage']}`",
        f"- cascades missing outbound attempt: `{totals['cascadeMissingOutboundAttempt']}`",
        "",
        "## Runs",
        "",
    ]
    for row in summary["runs"]:
        current = row["current"]
        lines.append(
            f"- `{row['label']}` clean=`{row['clean']}` "
            f"classification=`{row['classification']}` "
            f"attempts=`{current['attemptFinishes']}` cascades=`{current['cascadeFinishes']}`"
        )
    path.write_text("\n".join(lines) + "\n")


def outbound_attempt_print(output_dir: Path, summary: dict[str, Any]) -> dict[str, Any]:
    totals = summary["totals"]
    return {
        "outputDir": str(output_dir),
        "status": summary["conclusion"]["status"],
        "runs": totals["runs"],
        "attemptFinishes": totals["attemptFinishes"],
        "failedAttempts": totals["failedAttempts"],
        "cascadeFinishes": totals["cascadeFinishes"],
    }


def aggregate(values: Any) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for value in values:
        key = str(value or "unknown")
        counts[key] = counts.get(key, 0) + 1
    return [{"key": key, "count": count} for key, count in sorted(counts.items())]


def merge_count_rows(groups: Any) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for group in groups:
        for row in group:
            key = str(row.get("key") or "unknown")
            counts[key] = counts.get(key, 0) + int(row.get("count") or 0)
    return [{"key": key, "count": count} for key, count in sorted(counts.items())]


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
