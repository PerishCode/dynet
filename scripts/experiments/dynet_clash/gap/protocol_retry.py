from __future__ import annotations

import argparse
import datetime as dt
import json
import subprocess
import time
from collections import Counter
from pathlib import Path
from typing import Any

from dynet_clash import attribution
from dynet_clash.gap import drilldown, probe_report


SCHEMA = "dynet-clash-protocol-read-retry-experiment/v1alpha1"
DEFAULT_OUTPUT_DIR = ".task/resources/dynet-clash-protocol-read-retry/latest"
PROTOCOL_READ_PREFIX = "protocol-read-"


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True))


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def command(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = run(args)
    output_dir = Path(args.output_dir)
    write_json(output_dir / "summary.json", report)
    write_markdown(output_dir / "summary.md", report)
    print(json.dumps({
        "outputDir": str(output_dir),
        "rows": report["totals"]["rows"],
        "recovered": report["totals"]["recovered"],
        "recoveredAfterRetry": report["totals"]["recoveredAfterRetry"],
        "unresolvedProtocolRead": report["totals"]["unresolvedProtocolRead"],
    }, sort_keys=True))
    return 0


def run(args: argparse.Namespace) -> dict[str, Any]:
    output_dir = Path(args.output_dir)
    attempts_dir = output_dir / "attempts"
    attempts_dir.mkdir(parents=True, exist_ok=True)
    source = load_json(Path(args.drilldown))
    rows = selected_rows(source, args)
    started = utc_now()
    results = [
        run_row(args, row, index, attempts_dir)
        for index, row in enumerate(rows, start=1)
    ]
    ended = utc_now()
    return {
        "schema": SCHEMA,
        "generatedAt": ended,
        "startedAt": started,
        "endedAt": ended,
        "inputs": {"drilldown": args.drilldown},
        "policy": {
            "name": "retry-on-protocol-read",
            "attempts": args.attempts,
            "retrySleepMs": args.retry_sleep_ms,
            "scope": "experiment-only",
            "readPolicy": configured_read_policy(args),
        },
        "privacy": {
            "rawResultsStored": False,
            "responseBodiesStored": False,
            "sourceAddressesStored": False,
        },
        "totals": totals(results),
        "byDomainProbe": by_domain_probe(results),
        "lastFailureClassifications": counter_rows(
            row.get("lastFailureClassification")
            for row in results
            if not row.get("recovered")
        ),
        "lastProtocolReadSurfaces": counter_rows(
            protocol_read_key(row.get("lastProtocolRead"))
            for row in results
            if not row.get("recovered") and row.get("lastProtocolRead")
        ),
        "rows": results,
    }


def selected_rows(report: dict[str, Any], args: argparse.Namespace) -> list[dict[str, Any]]:
    rows = []
    domains = set(args.domain or [])
    probes = set(args.probe_type or [])
    for row in report.get("rows", []):
        if not isinstance(row, dict):
            continue
        if not str(row.get("classification") or "").startswith(PROTOCOL_READ_PREFIX):
            continue
        if domains and row.get("domain") not in domains:
            continue
        if probes and row.get("probe") not in probes:
            continue
        rows.append(row)
        if args.limit and len(rows) >= args.limit:
            break
    return rows


def run_row(
    args: argparse.Namespace,
    row: dict[str, Any],
    index: int,
    attempts_dir: Path,
) -> dict[str, Any]:
    attempts = []
    first_pass = None
    for attempt in range(1, args.attempts + 1):
        if attempt > 1 and args.retry_sleep_ms > 0:
            time.sleep(args.retry_sleep_ms / 1000)
        result = run_attempt(args, row, index, attempt, attempts_dir)
        attempts.append(result)
        if attempt_recovered(result):
            first_pass = attempt
            break
    recovered = first_pass is not None
    last = attempts[-1] if attempts else {}
    last_classification = None if recovered else last.get("classification")
    return {
        "id": row.get("id"),
        "window": row.get("window"),
        "domain": row.get("domain"),
        "probe": row.get("probe"),
        "originalOutcome": row.get("outcome"),
        "originalClassification": row.get("classification"),
        "originalReadSurface": original_read_surface(row),
        "expectedSelectedOutbound": probe_report.expected_selected_outbound(row),
        "recovered": recovered,
        "firstPassAttempt": first_pass,
        "attemptsUsed": len(attempts),
        "lastStatus": last.get("status"),
        "lastFailureClassification": last_classification,
        "lastProtocolRead": None if recovered else last.get("protocolRead"),
        "attempts": attempts,
    }


def run_attempt(
    args: argparse.Namespace,
    row: dict[str, Any],
    index: int,
    attempt: int,
    attempts_dir: Path,
) -> dict[str, Any]:
    domain = str(row.get("domain"))
    protocol = str(row.get("probe") or "tls-handshake")
    report_path = attempts_dir / f"{index:04d}-attempt-{attempt}-{probe_report.safe_name(domain)}.json"
    completed = subprocess.run(
        dynet_command(args, domain, protocol),
        text=True,
        capture_output=True,
        check=False,
    )
    report = probe_report.parse(completed.stdout)
    write_json(report_path, report)
    item = dynet_item(row, report, str(report_path), completed.returncode)
    evidence = drilldown.event_evidence(report)
    missing = [] if item["status"] == "pass" else drilldown.missing_evidence(item, evidence)
    attempt_class = probe_attempt_classification(report)
    classification = attempt_class or drilldown.classify(item, evidence)
    expected_outbound = probe_report.expected_selected_outbound(row)
    outbound_matches = probe_report.selected_outbound_matches(
        expected_outbound,
        item["selectedOutbound"],
    )
    if not outbound_matches:
        classification = "selected-outbound-drift"
    protocol_read = protocol_read_surface(report, evidence)
    return {
        "attempt": attempt,
        "exitCode": completed.returncode,
        "status": item["status"],
        "reasonMarker": item["reasonMarker"],
        "failedStage": item["failedStage"],
        "failureScope": item["failureScope"],
        "selectedOutbound": item["selectedOutbound"],
        "boundSelectedOutbound": probe_report.bound_selected_outbound(report),
        "expectedSelectedOutbound": expected_outbound,
        "selectedOutboundMatchesExpected": outbound_matches,
        "classification": classification,
        "probeAttemptClassification": attempt_class,
        "missingEvidence": missing,
        "readPolicy": report.get("readPolicy"),
        "protocolRead": protocol_read,
        "readSurface": protocol_read,
        "reportPath": str(report_path),
    }


def dynet_command(args: argparse.Namespace, domain: str, protocol: str) -> list[str]:
    command = []
    if args.sudo:
        command.append("sudo")
    command.extend([
        args.dynet_bin,
        "probe",
        "--config",
        args.config,
        "--url",
        f"https://{domain}/",
        "--protocol",
        protocol,
        "--format",
        "json",
    ])
    if args.read_budget_ms is not None:
        command.extend(["--probe-read-pending-budget-ms", str(args.read_budget_ms)])
    if args.read_poll_ms is not None:
        command.extend(["--probe-read-poll-timeout-ms", str(args.read_poll_ms)])
    if args.read_sleep_ms is not None:
        command.extend(["--probe-read-pending-sleep-ms", str(args.read_sleep_ms)])
    if args.inbound:
        command.extend(["--inbound", args.inbound])
    if args.quality_state:
        command.extend(["--quality-state", args.quality_state])
    return command


def dynet_item(
    row: dict[str, Any],
    report: dict[str, Any],
    report_path: str,
    exit_code: int,
) -> dict[str, Any]:
    return {
        "id": row.get("id"),
        "bucket": "github-proof",
        "domain": row.get("domain"),
        "sourceProbe": row.get("probe"),
        "status": report.get("status"),
        "failedStage": probe_report.failed_stage(report),
        "failureScope": report.get("failureScope"),
        "selectedOutbound": probe_report.selected_outbound(report),
        "reasonMarker": attribution.reason_marker(report.get("reason")),
        "reason": report.get("reason"),
        "reportPath": report_path,
        "exitCode": exit_code,
    }


def attempt_recovered(attempt: dict[str, Any]) -> bool:
    return (
        attempt.get("status") == "pass"
        and attempt.get("selectedOutboundMatchesExpected") is not False
    )


def probe_attempt_classification(report: dict[str, Any]) -> str | None:
    for event in reversed(report.get("events", [])):
        fields = probe_report.fields(event)
        if event.get("kind") == "probe-attempt-finished" and fields.get("classification"):
            return fields["classification"]
    return None


def protocol_read_surface(report: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    attempt = probe_report.latest_attempt_fields(report)
    return {
        "marker": attempt.get("protocolReadMarker") or drilldown.read_marker(evidence),
        "stage": attempt.get("protocolReadStage"),
        "context": attempt.get("protocolReadContext") or drilldown.read_context(evidence),
        "disposition": (
            attempt.get("protocolReadDisposition") or drilldown.read_disposition(evidence)
        ),
    }


def original_read_surface(row: dict[str, Any]) -> dict[str, Any]:
    evidence = row.get("evidence", {})
    return {
        "marker": drilldown.read_marker(evidence),
        "context": drilldown.read_context(evidence),
        "disposition": drilldown.read_disposition(evidence),
    }


def configured_read_policy(args: argparse.Namespace) -> dict[str, int | None]:
    return {
        "pollTimeoutMs": args.read_poll_ms,
        "pendingBudgetMs": args.read_budget_ms,
        "pendingSleepMs": args.read_sleep_ms,
    }


def totals(rows: list[dict[str, Any]]) -> dict[str, Any]:
    recovered = sum(1 for row in rows if row.get("recovered"))
    after_retry = sum(
        1 for row in rows
        if row.get("firstPassAttempt") and int(row["firstPassAttempt"]) > 1
    )
    unresolved = len(rows) - recovered
    unresolved_protocol = sum(
        1 for row in rows
        if not row.get("recovered")
        and str(row.get("lastFailureClassification") or "").startswith(PROTOCOL_READ_PREFIX)
    )
    drift_rows = sum(
        1 for row in rows
        if any(
            attempt.get("selectedOutboundMatchesExpected") is False
            for attempt in row.get("attempts", [])
        )
    )
    return {
        "rows": len(rows),
        "recovered": recovered,
        "recoveredOnFirstAttempt": recovered - after_retry,
        "recoveredAfterRetry": after_retry,
        "unresolved": unresolved,
        "unresolvedProtocolRead": unresolved_protocol,
        "changedSurface": unresolved - unresolved_protocol,
        "selectedOutboundDriftRows": drift_rows,
        "attempts": sum(int(row.get("attemptsUsed") or 0) for row in rows),
        "missingEvidenceRows": sum(
            1 for row in rows
            if any(attempt.get("missingEvidence") for attempt in row.get("attempts", []))
        ),
    }


def by_domain_probe(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], Counter[str]] = {}
    for row in rows:
        key = (str(row.get("domain")), str(row.get("probe")))
        counter = grouped.setdefault(key, Counter())
        counter["rows"] += 1
        counter["recovered"] += int(bool(row.get("recovered")))
        counter["recoveredAfterRetry"] += int(
            bool(row.get("firstPassAttempt") and int(row["firstPassAttempt"]) > 1)
        )
        counter["unresolvedProtocolRead"] += int(
            not row.get("recovered")
            and str(row.get("lastFailureClassification") or "").startswith(PROTOCOL_READ_PREFIX)
        )
    return [
        {
            "domain": domain,
            "probe": probe,
            "rows": counts["rows"],
            "recovered": counts["recovered"],
            "recoveredAfterRetry": counts["recoveredAfterRetry"],
            "unresolvedProtocolRead": counts["unresolvedProtocolRead"],
        }
        for (domain, probe), counts in sorted(grouped.items())
    ]


def counter_rows(values: Any) -> list[dict[str, Any]]:
    counts = Counter(str(value or "unknown") for value in values)
    return [{"key": key, "count": count} for key, count in counts.most_common()]


def protocol_read_key(surface: Any) -> str | None:
    if not isinstance(surface, dict):
        return None
    marker = surface.get("marker") or "unknown"
    context = surface.get("context") or "unknown"
    disposition = surface.get("disposition") or "unknown"
    return f"{context}|{marker}|{disposition}"


def retry_recovered(
    summary: dict[str, Any],
    expected_rows: int,
) -> bool:
    totals = summary.get("totals", {})
    return (
        expected_rows > 0
        and int(totals.get("rows") or 0) == expected_rows
        and int(totals.get("recovered") or 0) == expected_rows
        and int(totals.get("selectedOutboundDriftRows") or 0) == 0
        and int(totals.get("unresolvedProtocolRead") or 0) == 0
    )


def protocol_retry_brief(summary: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(summary, dict):
        return {"present": False}
    totals = summary.get("totals", {})
    policy = summary.get("policy", {})
    return {
        "present": True,
        "rows": int(totals.get("rows") or 0),
        "recovered": int(totals.get("recovered") or 0),
        "recoveredOnFirstAttempt": int(totals.get("recoveredOnFirstAttempt") or 0),
        "recoveredAfterRetry": int(totals.get("recoveredAfterRetry") or 0),
        "unresolvedProtocolRead": int(totals.get("unresolvedProtocolRead") or 0),
        "selectedOutboundDriftRows": int(totals.get("selectedOutboundDriftRows") or 0),
        "attempts": int(totals.get("attempts") or 0),
        "readPolicy": policy.get("readPolicy", {}),
    }


def write_markdown(path: Path, report: dict[str, Any]) -> None:
    totals_row = report["totals"]
    lines = [
        "# Dynet Protocol Read Retry Experiment",
        "",
        f"- Rows: `{totals_row['rows']}`",
        f"- Recovered: `{totals_row['recovered']}`",
        f"- Recovered after retry: `{totals_row['recoveredAfterRetry']}`",
        f"- Unresolved protocol read: `{totals_row['unresolvedProtocolRead']}`",
        f"- Changed surface: `{totals_row['changedSurface']}`",
        f"- Selected outbound drift rows: `{totals_row['selectedOutboundDriftRows']}`",
        f"- Attempts: `{totals_row['attempts']}`",
        f"- Missing evidence rows: `{totals_row['missingEvidenceRows']}`",
        "",
        "## Domain Probe",
        "",
    ]
    for row in report["byDomainProbe"]:
        lines.append(
            f"- `{row['domain']}` probe=`{row['probe']}` rows=`{row['rows']}` "
            f"recovered=`{row['recovered']}` retry=`{row['recoveredAfterRetry']}` "
            f"unresolvedProtocolRead=`{row['unresolvedProtocolRead']}`"
        )
    if report["lastFailureClassifications"]:
        lines.extend(["", "## Last Failure Classifications", ""])
        for row in report["lastFailureClassifications"]:
            lines.append(f"- `{row['key']}` count=`{row['count']}`")
    if report["lastProtocolReadSurfaces"]:
        lines.extend(["", "## Last Protocol Read Surfaces", ""])
        for row in report["lastProtocolReadSurfaces"]:
            lines.append(f"- `{row['key']}` count=`{row['count']}`")
    path.write_text("\n".join(lines) + "\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Retry retained protocol-read probe failures as an experiment-only policy."
    )
    parser.add_argument("--drilldown", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--dynet-bin", default="dynet")
    parser.add_argument("--sudo", action="store_true")
    parser.add_argument("--inbound")
    parser.add_argument("--quality-state")
    parser.add_argument("--attempts", type=probe_report.positive_int, default=3)
    parser.add_argument("--retry-sleep-ms", type=probe_report.non_negative_int, default=250)
    parser.add_argument("--probe-read-poll-timeout-ms", dest="read_poll_ms", type=probe_report.positive_int)
    parser.add_argument("--probe-read-pending-budget-ms", dest="read_budget_ms", type=probe_report.non_negative_int)
    parser.add_argument("--probe-read-pending-sleep-ms", dest="read_sleep_ms", type=probe_report.non_negative_int)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--domain", action="append")
    parser.add_argument("--probe-type", action="append")
    return parser
