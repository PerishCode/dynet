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
from dynet_clash.gap import drilldown


SCHEMA = "dynet-clash-direct-tls-retry-experiment/v1alpha1"
DEFAULT_OUTPUT_DIR = ".task/resources/dynet-clash-direct-tls-retry/latest"
DIRECT_TLS_EOF = "direct-tls-eof-after-path-complete"


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
        "unresolved": report["totals"]["unresolved"],
    }, sort_keys=True))
    return 0


def run(args: argparse.Namespace) -> dict[str, Any]:
    output_dir = Path(args.output_dir)
    attempts_dir = output_dir / "attempts"
    attempts_dir.mkdir(parents=True, exist_ok=True)
    drilldown_report = load_json(Path(args.drilldown))
    rows = selected_rows(drilldown_report, args)
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
            "name": "retry-on-direct-tls-eof",
            "attempts": args.attempts,
            "retrySleepMs": args.retry_sleep_ms,
            "scope": "experiment-only",
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
        "rows": results,
    }


def selected_rows(report: dict[str, Any], args: argparse.Namespace) -> list[dict[str, Any]]:
    rows = []
    domains = set(args.domain or [])
    probes = set(args.probe_type or [])
    for row in report.get("rows", []):
        if not isinstance(row, dict):
            continue
        if row.get("classification") != DIRECT_TLS_EOF:
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
        if result["status"] == "pass":
            first_pass = attempt
            break
    recovered = first_pass is not None
    last = attempts[-1] if attempts else {}
    return {
        "id": row.get("id"),
        "window": row.get("window"),
        "domain": row.get("domain"),
        "probe": row.get("probe"),
        "originalOutcome": row.get("outcome"),
        "recovered": recovered,
        "firstPassAttempt": first_pass,
        "attemptsUsed": len(attempts),
        "lastStatus": last.get("status"),
        "lastFailureClassification": (
            None if recovered else last.get("classification")
        ),
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
    report_path = attempts_dir / f"{index:04d}-attempt-{attempt}-{safe_name(domain)}.json"
    completed = subprocess.run(
        dynet_command(args, domain, protocol),
        text=True,
        capture_output=True,
        check=False,
    )
    report = parse_report(completed.stdout)
    write_json(report_path, report)
    item = dynet_item(row, report, str(report_path), completed.returncode)
    evidence = drilldown.event_evidence(report)
    missing = [] if item["status"] == "pass" else drilldown.missing_evidence(item, evidence)
    return {
        "attempt": attempt,
        "exitCode": completed.returncode,
        "status": item["status"],
        "reasonMarker": item["reasonMarker"],
        "failedStage": item["failedStage"],
        "failureScope": item["failureScope"],
        "selectedOutbound": item["selectedOutbound"],
        "classification": drilldown.classify(item, evidence),
        "missingEvidence": missing,
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
        "failedStage": failed_stage(report),
        "failureScope": report.get("failureScope"),
        "selectedOutbound": selected_outbound(report),
        "reasonMarker": attribution.reason_marker(report.get("reason")),
        "reason": report.get("reason"),
        "reportPath": report_path,
        "exitCode": exit_code,
    }


def parse_report(stdout: str) -> dict[str, Any]:
    try:
        report = json.loads(stdout)
    except json.JSONDecodeError as error:
        return {
            "schema": "dynet-probe/invalid-output",
            "status": "deny",
            "reason": f"failed to parse dynet probe JSON: {error}",
            "events": [],
        }
    return report if isinstance(report, dict) else {
        "schema": "dynet-probe/invalid-output",
        "status": "deny",
        "reason": "dynet probe JSON root was not an object",
        "events": [],
    }


def selected_outbound(report: dict[str, Any]) -> str | None:
    for event in report.get("events", []):
        if event.get("kind") == "outbound-graph-selected":
            return event_fields(event).get("selected")
    for event in report.get("events", []):
        if event.get("kind") == "route-matched":
            return event_fields(event).get("outbound")
    return None


def failed_stage(report: dict[str, Any]) -> str | None:
    for event in report.get("events", []):
        fields = event_fields(event)
        if (
            event.get("kind") == "outbound-stage-finished"
            and fields.get("status") == "failed"
        ):
            return fields.get("stage")
    return None


def event_fields(event: dict[str, Any]) -> dict[str, str]:
    fields = event.get("fields", {})
    if not isinstance(fields, dict):
        return {}
    return {str(key): str(value) for key, value in fields.items()}


def totals(rows: list[dict[str, Any]]) -> dict[str, Any]:
    recovered = sum(1 for row in rows if row.get("recovered"))
    after_retry = sum(
        1 for row in rows
        if row.get("firstPassAttempt") and int(row["firstPassAttempt"]) > 1
    )
    attempts = sum(int(row.get("attemptsUsed") or 0) for row in rows)
    return {
        "rows": len(rows),
        "recovered": recovered,
        "recoveredOnFirstAttempt": recovered - after_retry,
        "recoveredAfterRetry": after_retry,
        "unresolved": len(rows) - recovered,
        "attempts": attempts,
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
        counter["unresolved"] += int(not row.get("recovered"))
    return [
        {
            "domain": domain,
            "probe": probe,
            "rows": counts["rows"],
            "recovered": counts["recovered"],
            "recoveredAfterRetry": counts["recoveredAfterRetry"],
            "unresolved": counts["unresolved"],
        }
        for (domain, probe), counts in sorted(grouped.items())
    ]


def counter_rows(values: Any) -> list[dict[str, Any]]:
    counts = Counter(str(value or "unknown") for value in values)
    return [
        {"key": key, "count": count}
        for key, count in counts.most_common()
    ]


def safe_name(value: str) -> str:
    return "".join(char if char.isalnum() or char in ".-" else "_" for char in value)[:80]


def write_markdown(path: Path, report: dict[str, Any]) -> None:
    totals_row = report["totals"]
    lines = [
        "# Dynet Direct TLS Retry Experiment",
        "",
        f"- Rows: `{totals_row['rows']}`",
        f"- Recovered: `{totals_row['recovered']}`",
        f"- Recovered after retry: `{totals_row['recoveredAfterRetry']}`",
        f"- Unresolved: `{totals_row['unresolved']}`",
        f"- Attempts: `{totals_row['attempts']}`",
        "",
        "## Domain Probe",
        "",
    ]
    for row in report["byDomainProbe"]:
        lines.append(
            f"- `{row['domain']}` probe=`{row['probe']}` rows=`{row['rows']}` "
            f"recovered=`{row['recovered']}` retry=`{row['recoveredAfterRetry']}` "
            f"unresolved=`{row['unresolved']}`"
        )
    if report["lastFailureClassifications"]:
        lines.extend(["", "## Last Failure Classifications", ""])
        for row in report["lastFailureClassifications"]:
            lines.append(f"- `{row['key']}` count=`{row['count']}`")
    path.write_text("\n".join(lines) + "\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Retry retained direct TLS EOF probe failures as an experiment-only policy."
    )
    parser.add_argument("--drilldown", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--dynet-bin", default="dynet")
    parser.add_argument("--sudo", action="store_true")
    parser.add_argument("--inbound")
    parser.add_argument("--quality-state")
    parser.add_argument("--attempts", type=int, default=3)
    parser.add_argument("--retry-sleep-ms", type=int, default=250)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--domain", action="append")
    parser.add_argument("--probe-type", action="append")
    return parser
