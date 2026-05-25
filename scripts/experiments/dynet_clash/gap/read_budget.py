from __future__ import annotations

import argparse
import datetime as dt
import json
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any

from dynet_clash import attribution
from dynet_clash.gap import drilldown, probe_report


SCHEMA = "dynet-clash-protocol-read-budget-experiment/v1alpha1"
DEFAULT_OUTPUT_DIR = ".task/resources/dynet-clash-protocol-read-budget/latest"
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
        "passed": report["totals"]["passed"],
        "stillProtocolRead": report["totals"]["stillProtocolRead"],
        "changedSurface": report["totals"]["changedSurface"],
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
            "name": "protocol-read-budget",
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
        "lastClassifications": counter_rows(
            row.get("classification")
            for row in results
            if not row_passed(row)
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
    domain = str(row.get("domain"))
    protocol = str(row.get("probe") or "tls-handshake")
    report_path = attempts_dir / f"{index:04d}-{probe_report.safe_name(domain)}.json"
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
    classification = drilldown.classify(item, evidence)
    expected_outbound = probe_report.expected_selected_outbound(row)
    outbound_matches = probe_report.selected_outbound_matches(
        expected_outbound,
        item["selectedOutbound"],
    )
    if not outbound_matches:
        classification = "selected-outbound-drift"
    return {
        "id": row.get("id"),
        "window": row.get("window"),
        "domain": row.get("domain"),
        "probe": row.get("probe"),
        "originalOutcome": row.get("outcome"),
        "originalClassification": row.get("classification"),
        "originalReadSurface": original_read_surface(row),
        "exitCode": completed.returncode,
        "status": item["status"],
        "reasonMarker": item["reasonMarker"],
        "failedStage": item["failedStage"],
        "failureScope": item["failureScope"],
        "selectedOutbound": item["selectedOutbound"],
        "expectedSelectedOutbound": expected_outbound,
        "selectedOutboundMatchesExpected": outbound_matches,
        "classification": classification,
        "missingEvidence": missing,
        "readPolicy": report.get("readPolicy"),
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
        "--probe-read-pending-budget-ms",
        str(args.read_budget_ms),
    ])
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
    passed = sum(1 for row in rows if row_passed(row))
    still_read = sum(
        1 for row in rows
        if str(row.get("classification") or "").startswith(PROTOCOL_READ_PREFIX)
    )
    return {
        "rows": len(rows),
        "passed": passed,
        "failed": len(rows) - passed,
        "stillProtocolRead": still_read,
        "changedSurface": len(rows) - passed - still_read,
        "selectedOutboundDriftRows": sum(
            1 for row in rows
            if row.get("selectedOutboundMatchesExpected") is False
        ),
        "missingEvidenceRows": sum(1 for row in rows if row.get("missingEvidence")),
    }


def by_domain_probe(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], Counter[str]] = {}
    for row in rows:
        key = (str(row.get("domain")), str(row.get("probe")))
        counter = grouped.setdefault(key, Counter())
        counter["rows"] += 1
        counter["passed"] += int(row_passed(row))
        counter["stillProtocolRead"] += int(
            str(row.get("classification") or "").startswith(PROTOCOL_READ_PREFIX)
        )
    return [
        {
            "domain": domain,
            "probe": probe,
            "rows": counts["rows"],
            "passed": counts["passed"],
            "stillProtocolRead": counts["stillProtocolRead"],
            "changedSurface": counts["rows"] - counts["passed"] - counts["stillProtocolRead"],
        }
        for (domain, probe), counts in sorted(grouped.items())
    ]


def counter_rows(values: Any) -> list[dict[str, Any]]:
    counts = Counter(str(value or "unknown") for value in values)
    return [
        {"key": key, "count": count}
        for key, count in counts.most_common()
    ]


def row_passed(row: dict[str, Any]) -> bool:
    return (
        row.get("status") == "pass"
        and row.get("selectedOutboundMatchesExpected") is not False
    )


def write_markdown(path: Path, report: dict[str, Any]) -> None:
    totals_row = report["totals"]
    policy = report["policy"]["readPolicy"]
    lines = [
        "# Dynet Protocol Read Budget Experiment",
        "",
        f"- Rows: `{totals_row['rows']}`",
        f"- Passed: `{totals_row['passed']}`",
        f"- Still protocol read: `{totals_row['stillProtocolRead']}`",
        f"- Changed surface: `{totals_row['changedSurface']}`",
        f"- Selected outbound drift rows: `{totals_row['selectedOutboundDriftRows']}`",
        f"- Missing evidence rows: `{totals_row['missingEvidenceRows']}`",
        f"- Read policy: pollTimeoutMs=`{policy.get('pollTimeoutMs')}` "
        f"pendingBudgetMs=`{policy.get('pendingBudgetMs')}` "
        f"pendingSleepMs=`{policy.get('pendingSleepMs')}`",
        "",
        "## Domain Probe",
        "",
    ]
    for row in report["byDomainProbe"]:
        lines.append(
            f"- `{row['domain']}` probe=`{row['probe']}` rows=`{row['rows']}` "
            f"passed=`{row['passed']}` stillProtocolRead=`{row['stillProtocolRead']}` "
            f"changedSurface=`{row['changedSurface']}`"
        )
    if report["lastClassifications"]:
        lines.extend(["", "## Last Classifications", ""])
        for row in report["lastClassifications"]:
            lines.append(f"- `{row['key']}` count=`{row['count']}`")
    path.write_text("\n".join(lines) + "\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Rerun retained protocol-read failures with a scoped probe read budget."
    )
    parser.add_argument("--drilldown", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--dynet-bin", default="dynet")
    parser.add_argument("--sudo", action="store_true")
    parser.add_argument("--inbound")
    parser.add_argument("--quality-state")
    parser.add_argument("--probe-read-poll-timeout-ms", dest="read_poll_ms", type=probe_report.positive_int)
    parser.add_argument(
        "--probe-read-pending-budget-ms",
        dest="read_budget_ms",
        type=probe_report.non_negative_int,
        required=True,
    )
    parser.add_argument("--probe-read-pending-sleep-ms", dest="read_sleep_ms", type=probe_report.non_negative_int)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--domain", action="append")
    parser.add_argument("--probe-type", action="append")
    return parser
