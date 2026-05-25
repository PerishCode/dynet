from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from common import Lab, validate_name
from private_runtime_lib.briefs import fields


OUTBOUND_RETRY_SCHEMA = "dynet-vm-private-runtime-outbound-retry-surface/v1alpha1"
REPEAT_SCHEMA = "dynet-vm-private-runtime-repeat/v1alpha1"
BOUND_RETRY_REASON = "retry-bound-failure-before-replay"
BOUND_EXHAUSTED_REASON = "bound-candidates-exhausted"
NON_BOUND_STOP_REASON = "non-bound-failure"
COUNT_FIELDS = [
    "runs", "cleanRuns", "failedRuns", "eventReports", "runtimePass", "events",
    "cascadeAttempts", "cascadeSuccesses", "cascadeFailures",
    "retryableCascadeFailures", "retryableWithNextAttempt",
    "retryableMissingNextAttempt", "nonRetryableCascadeFailures",
    "nonRetryableWithNextAttempt", "nonRetryableWithoutNextAttempt",
    "boundRetryFailures", "boundRetryMissingStopReason",
    "boundRetryMissingNextAttempt", "boundExhaustedStops",
    "boundExhaustedRecoveredFlows", "boundExhaustedUnrecoveredFlows",
    "nonBoundStops", "nonBoundWithNextAttempt", "failureScopeMissing",
    "retryAllowedMissing", "retryStopReasonMissing", "invalidRetryStopReasons",
    "retryableNonBoundFailures", "successScopeMismatches", "tcpFailureFlows",
    "tcpRecoveredFailureFlows", "tcpUnrecoveredFailureFlows", "dnsFailureQueries",
    "dnsTerminalFailureQueries",
]
BLOCKERS = [
    "retryableMissingNextAttempt", "nonRetryableWithNextAttempt",
    "boundRetryMissingStopReason", "boundRetryMissingNextAttempt",
    "boundExhaustedUnrecoveredFlows", "nonBoundWithNextAttempt",
    "failureScopeMissing", "retryAllowedMissing", "retryStopReasonMissing",
    "invalidRetryStopReasons", "retryableNonBoundFailures", "successScopeMismatches",
    "tcpUnrecoveredFailureFlows",
]


def command_outbound_retry_surface(_lab: Lab, args: argparse.Namespace) -> None:
    label = validate_name(args.label or "outbound-retry-surface", "label")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = build_outbound_retry_summary(
        label,
        output_dir,
        [Path(item) for item in args.input],
    )
    write_outbound_retry_summary(output_dir, summary)
    print(json.dumps(outbound_retry_print(output_dir, summary), sort_keys=True))


def build_outbound_retry_summary(
    label: str,
    output_dir: Path,
    inputs: list[Path],
) -> dict[str, Any]:
    rows = [outbound_retry_row(path) for path in expand_inputs(inputs)]
    totals = outbound_retry_totals(rows)
    return {
        "schema": OUTBOUND_RETRY_SCHEMA,
        "label": label,
        "outputDir": str(output_dir),
        "runs": rows,
        "totals": totals,
        "conclusion": outbound_retry_conclusion(totals),
        "privacy": empty_privacy_flags(),
        "policy": {
            "plannerPenaltySafe": False,
            "qualityPenaltySafe": False,
            "reason": "Outbound retry/stop semantics are observability proof, not penalty proof.",
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


def outbound_retry_row(run_dir: Path) -> dict[str, Any]:
    summary = load_optional_json(run_dir / "summary.json")
    current = outbound_retry_counts(load_optional_json(run_dir / "runtime-report.json"))
    clean = outbound_retry_clean(current)
    return {
        "label": summary.get("label") or run_dir.name,
        "path": str(run_dir),
        "classification": "clean" if clean else outbound_retry_classification(current),
        "clean": clean,
        "current": current,
    }


def outbound_retry_counts(report: dict[str, Any]) -> dict[str, Any]:
    raw_events = report.get("events")
    events = [
        retry_event(event, index)
        for index, event in enumerate(raw_events or [])
        if isinstance(event, dict)
    ]
    cascades = [event for event in events if event["kind"] == "dialer-cascade-attempt-finished"]
    failures = [event for event in cascades if event["status"] == "failed"]
    successes = [event for event in cascades if event["status"] == "success"]
    retryable = [event for event in failures if event["retryAllowed"] is True]
    non_retryable = [event for event in failures if event["retryAllowed"] is False]
    bound_retry = [event for event in retryable if event["failureScope"] == "bound"]
    bound_exhausted = [
        event for event in non_retryable
        if event["failureScope"] == "bound"
        and event["retryStopReason"] == BOUND_EXHAUSTED_REASON
    ]
    non_bound = [
        event for event in non_retryable
        if event["failureScope"] and event["failureScope"] != "bound"
    ]
    terminal_success = terminal_success_indexes(events)
    return {
        "eventReports": 1 if raw_events is not None else 0,
        "runtimePass": 1 if report.get("status") == "pass" else 0,
        "events": len(events),
        "cascadeAttempts": len(cascades),
        "cascadeSuccesses": len(successes),
        "cascadeFailures": len(failures),
        **retryability_counts(events, failures, retryable, non_retryable),
        **failure_reason_counts(failures, successes, retryable, non_retryable, bound_retry),
        **recovery_counts(events, failures, bound_retry, bound_exhausted, non_bound, terminal_success),
    }


def retry_event(event: dict[str, Any], index: int) -> dict[str, Any]:
    event_fields = fields(event)
    return {
        "index": index,
        "kind": str(event.get("kind") or ""),
        "key": event_key(event_fields),
        "status": event_fields.get("status") or "",
        "attempt": parse_int(event_fields.get("attempt")),
        "failureScope": event_fields.get("failureScope") or "",
        "retryAllowed": parse_bool(event_fields.get("retryAllowed")),
        "retryStopReason": event_fields.get("retryStopReason") or "",
    }


def retryability_counts(
    events: list[dict[str, Any]],
    failures: list[dict[str, Any]],
    retryable: list[dict[str, Any]],
    non_retryable: list[dict[str, Any]],
) -> dict[str, int]:
    return {
        "retryableCascadeFailures": len(retryable),
        "retryableWithNextAttempt": sum(1 for event in retryable if has_later_attempt(events, event)),
        "retryableMissingNextAttempt": sum(1 for event in retryable if not has_later_attempt(events, event)),
        "nonRetryableCascadeFailures": len(non_retryable),
        "nonRetryableWithNextAttempt": sum(1 for event in non_retryable if has_later_attempt(events, event)),
        "nonRetryableWithoutNextAttempt": sum(1 for event in non_retryable if not has_later_attempt(events, event)),
        "failureScopeMissing": sum(1 for event in failures if not event["failureScope"]),
        "retryAllowedMissing": sum(1 for event in failures if event["retryAllowed"] is None),
        "retryStopReasonMissing": sum(1 for event in failures if not event["retryStopReason"]),
    }


def failure_reason_counts(
    failures: list[dict[str, Any]],
    successes: list[dict[str, Any]],
    retryable: list[dict[str, Any]],
    non_retryable: list[dict[str, Any]],
    bound_retry: list[dict[str, Any]],
) -> dict[str, int]:
    invalid_reasons = sum(1 for event in failures if not valid_stop_reason(event))
    success_mismatches = sum(
        1 for event in successes
        if event["status"] == "success" and event["failureScope"] != "none"
    )
    return {
        "boundRetryFailures": len(bound_retry),
        "boundRetryMissingStopReason": sum(
            1 for event in bound_retry if event["retryStopReason"] != BOUND_RETRY_REASON
        ),
        "invalidRetryStopReasons": invalid_reasons,
        "successScopeMismatches": success_mismatches,
        "boundExhaustedStops": sum(
            1 for event in non_retryable
            if event["failureScope"] == "bound"
            and event["retryStopReason"] == BOUND_EXHAUSTED_REASON
        ),
        "nonBoundStops": sum(
            1 for event in non_retryable
            if event["failureScope"] and event["failureScope"] != "bound"
        ),
        "retryableNonBoundFailures": sum(
            1 for event in retryable
            if event["failureScope"] and event["failureScope"] != "bound"
        ),
    }


def recovery_counts(
    events: list[dict[str, Any]],
    failures: list[dict[str, Any]],
    bound_retry: list[dict[str, Any]],
    bound_exhausted: list[dict[str, Any]],
    non_bound: list[dict[str, Any]],
    terminal_success: dict[str, list[int]],
) -> dict[str, int]:
    tcp_failure_keys = {event["key"] for event in failures if event["key"].startswith("tcp-session-")}
    recovered_tcp = {
        key for key in tcp_failure_keys
        if has_terminal_success(key, terminal_success)
    }
    dns_failure_keys = {event["key"] for event in failures if event["key"].startswith("dns-query-")}
    return {
        "boundRetryMissingNextAttempt": sum(
            1 for event in bound_retry if not has_later_attempt(events, event)
        ),
        "boundExhaustedRecoveredFlows": sum(
            1 for event in bound_exhausted if has_success_after(events, event, terminal_success)
        ),
        "boundExhaustedUnrecoveredFlows": sum(
            1 for event in bound_exhausted if not has_success_after(events, event, terminal_success)
        ),
        "nonBoundWithNextAttempt": sum(1 for event in non_bound if has_later_attempt(events, event)),
        "tcpFailureFlows": len(tcp_failure_keys),
        "tcpRecoveredFailureFlows": len(recovered_tcp),
        "tcpUnrecoveredFailureFlows": len(tcp_failure_keys - recovered_tcp),
        "dnsFailureQueries": len(dns_failure_keys),
        "dnsTerminalFailureQueries": sum(
            1 for key in dns_failure_keys
            if has_kind_for_key(events, key, "dns-resolve-failed")
        ),
    }


def event_key(event_fields: dict[str, str]) -> str:
    return event_fields.get("flowId") or event_fields.get("dnsQueryId") or ""


def terminal_success_indexes(events: list[dict[str, Any]]) -> dict[str, list[int]]:
    result: dict[str, list[int]] = {}
    for event in events:
        if event["kind"] in {"tcp-session-established", "udp-session-established", "dns-resolve-completed"}:
            result.setdefault(event["key"], []).append(event["index"])
    return result


def has_later_attempt(events: list[dict[str, Any]], failed: dict[str, Any]) -> bool:
    for event in events:
        if event["kind"] != "dialer-cascade-attempt-finished":
            continue
        if event["key"] != failed["key"] or event["index"] <= failed["index"]:
            continue
        if event["attempt"] is None or failed["attempt"] is None:
            return True
        if event["attempt"] > failed["attempt"]:
            return True
    return False


def has_success_after(
    events: list[dict[str, Any]],
    failed: dict[str, Any],
    terminal_success: dict[str, list[int]],
) -> bool:
    if any(index > failed["index"] for index in terminal_success.get(failed["key"], [])):
        return True
    return any(
        event["key"] == failed["key"]
        and event["kind"] == "dialer-cascade-attempt-finished"
        and event["status"] == "success"
        and event["index"] > failed["index"]
        for event in events
    )


def has_terminal_success(key: str, terminal_success: dict[str, list[int]]) -> bool:
    return bool(terminal_success.get(key))


def has_kind_for_key(events: list[dict[str, Any]], key: str, kind: str) -> bool:
    return any(event["key"] == key and event["kind"] == kind for event in events)


def valid_stop_reason(event: dict[str, Any]) -> bool:
    if event["retryAllowed"] is True:
        return event["failureScope"] == "bound" and event["retryStopReason"] == BOUND_RETRY_REASON
    if event["retryAllowed"] is False and event["failureScope"] == "bound":
        return event["retryStopReason"] == BOUND_EXHAUSTED_REASON
    if event["retryAllowed"] is False:
        return event["retryStopReason"] == NON_BOUND_STOP_REASON
    return False


def outbound_retry_clean(counts: dict[str, Any]) -> bool:
    return (
        counts["eventReports"] == 1
        and counts["runtimePass"] == 1
        and counts["events"] > 0
        and counts["cascadeAttempts"] > 0
        and all(int(counts[key]) == 0 for key in BLOCKERS)
    )


def outbound_retry_classification(counts: dict[str, Any]) -> str:
    for key, label in [
        ("retryableMissingNextAttempt", "retryable-replay-missing"),
        ("nonRetryableWithNextAttempt", "non-retryable-continued"),
        ("boundExhaustedUnrecoveredFlows", "bound-exhausted-not-recovered"),
        ("nonBoundWithNextAttempt", "non-bound-stop-continued"),
        ("invalidRetryStopReasons", "invalid-retry-stop-reason"),
        ("failureScopeMissing", "failure-scope-missing"),
        ("retryAllowedMissing", "retry-allowed-missing"),
        ("retryStopReasonMissing", "retry-stop-reason-missing"),
        ("tcpUnrecoveredFailureFlows", "tcp-failure-unrecovered"),
    ]:
        if int(counts[key]):
            return label
    return "outbound-retry-surface-incomplete"


def outbound_retry_totals(rows: list[dict[str, Any]]) -> dict[str, Any]:
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


def outbound_retry_conclusion(totals: dict[str, Any]) -> dict[str, Any]:
    clean = totals["runs"] > 0 and totals["failedRuns"] == 0
    return {
        "status": "clean" if clean else "outbound-retry-surface-needs-evidence",
        "nextAction": "return-to-runtime-surface" if clean else "inspect-outbound-retry-stop",
        "plannerPenaltySafe": False,
        "qualityPenaltySafe": False,
    }


def write_outbound_retry_summary(output_dir: Path, summary: dict[str, Any]) -> None:
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    write_outbound_retry_markdown(output_dir / "summary.md", summary)


def write_outbound_retry_markdown(path: Path, summary: dict[str, Any]) -> None:
    totals = summary["totals"]
    lines = [
        "# VM Private Runtime Outbound Retry Surface",
        "",
        f"- label: `{summary['label']}`",
        f"- status: `{summary['conclusion']['status']}`",
        f"- runs: `{totals['runs']}`",
        f"- clean runs: `{totals['cleanRuns']}`",
        f"- cascade failures: `{totals['cascadeFailures']}`",
        f"- retryable missing next attempt: `{totals['retryableMissingNextAttempt']}`",
        f"- non-retryable continued: `{totals['nonRetryableWithNextAttempt']}`",
        f"- bound exhausted unrecovered: `{totals['boundExhaustedUnrecoveredFlows']}`",
        f"- non-bound continued: `{totals['nonBoundWithNextAttempt']}`",
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


def outbound_retry_print(output_dir: Path, summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "outputDir": str(output_dir),
        "runs": summary["totals"]["runs"],
        "cleanRuns": summary["totals"]["cleanRuns"],
        "cascadeFailures": summary["totals"]["cascadeFailures"],
        "status": summary["conclusion"]["status"],
    }


def parse_bool(value: str | None) -> bool | None:
    if value == "true":
        return True
    if value == "false":
        return False
    return None


def parse_int(value: str | None) -> int | None:
    try:
        return int(value or "")
    except ValueError:
        return None


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
