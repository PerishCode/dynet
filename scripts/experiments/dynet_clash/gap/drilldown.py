from __future__ import annotations

import argparse
import datetime as dt
import json
from collections import Counter
from pathlib import Path
from typing import Any

from dynet_clash import attribution


SCHEMA = "dynet-clash-product-effect-drilldown/v1alpha1"
DEFAULT_OUTPUT_JSON = ".task/resources/dynet-clash-product-effect-drilldown.json"
DEFAULT_OUTPUT_MD = ".task/resources/dynet-clash-product-effect-drilldown.md"
RETAINED_OUTCOMES = {"dynet-only-failure", "both-failure"}


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True))


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def build(args: argparse.Namespace) -> dict[str, Any]:
    paths = [Path(path) for path in args.comparison]
    reports = [load_json(path) for path in paths]
    return build_from_reports(reports, args, paths)


def build_from_reports(
    reports: list[dict[str, Any]],
    args: argparse.Namespace,
    paths: list[Path] | None = None,
) -> dict[str, Any]:
    input_paths = paths or [
        Path(f"comparison-{index + 1}.json") for index in range(len(reports))
    ]
    rows = []
    for index, (path, report) in enumerate(zip(input_paths, reports), start=1):
        rows.extend(window_rows(index, path, report, args))
    return {
        "schema": SCHEMA,
        "generatedAt": utc_now(),
        "inputs": [str(path) for path in input_paths],
        "thresholds": {
            "primaryBucket": args.primary_bucket,
            "retainedOutcomes": sorted(RETAINED_OUTCOMES),
        },
        "privacy": {
            "rawResultsStored": False,
            "responseBodiesStored": False,
            "sourceAddressesStored": False,
        },
        "totals": totals(rows),
        "classificationCounts": counter_rows(
            row.get("classification") for row in rows
        ),
        "missingEvidenceCounts": missing_evidence_counts(rows),
        "surfaceCounts": surface_counts(rows),
        "protocolReadSurfaceCounts": protocol_read_surface_counts(rows),
        "rows": rows,
    }


def window_rows(
    index: int,
    path: Path,
    comparison: dict[str, Any],
    args: argparse.Namespace,
) -> list[dict[str, Any]]:
    inputs = comparison.get("inputs", {})
    dynet_summary = load_optional(inputs.get("dynetSummary"))
    pairs = load_optional(infer_pairs_path(inputs.get("dynetSummary")))
    items = {
        str(item.get("id")): item
        for item in dynet_summary.get("items", [])
        if isinstance(item, dict)
    }
    rows = []
    for pair in pairs.get("items", []):
        if not retained_pair(pair, args.primary_bucket):
            continue
        dynet_item = items.get(str(pair.get("id")), {})
        report_path = dynet_item.get("reportPath")
        probe_report = load_optional(report_path)
        evidence = event_evidence(probe_report)
        rows.append({
            "window": index,
            "comparison": str(path),
            "id": pair.get("id"),
            "domain": pair.get("domain"),
            "probe": pair.get("probe"),
            "outcome": outcome_key(pair),
            "clashOk": bool(pair.get("clashOk")),
            "dynetStatus": pair.get("dynetStatus"),
            "dynetReportPath": report_path,
            "dynetSummary": dynet_brief(dynet_item),
            "evidence": evidence,
            "classification": classify(dynet_item, evidence),
            "missingEvidence": missing_evidence(dynet_item, evidence),
        })
    return rows


def retained_pair(pair: Any, primary_bucket: str) -> bool:
    return (
        isinstance(pair, dict)
        and pair.get("bucket") == primary_bucket
        and outcome_key(pair) in RETAINED_OUTCOMES
    )


def load_optional(path: Any) -> dict[str, Any]:
    if not path:
        return {}
    raw = Path(str(path))
    if not raw.exists():
        return {}
    return load_json(raw)


def infer_pairs_path(dynet_summary_path: Any) -> str | None:
    if not dynet_summary_path:
        return None
    raw = Path(str(dynet_summary_path))
    if raw.name != "summary.json":
        return None
    return str(raw.parent.parent / "pairs.json")


def outcome_key(item: dict[str, Any]) -> str:
    clash_failed = not bool(item.get("clashOk"))
    dynet_failed = item.get("dynetStatus") != "pass"
    if clash_failed and dynet_failed:
        return "both-failure"
    if clash_failed:
        return "clash-only-failure"
    if dynet_failed:
        return "dynet-only-failure"
    return "both-pass"


def dynet_brief(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": item.get("status"),
        "failedStage": item.get("failedStage"),
        "failureScope": item.get("failureScope"),
        "selectedOutbound": item.get("selectedOutbound"),
        "reasonMarker": attribution.reason_marker(item.get("reason")),
    }


def event_evidence(report: dict[str, Any]) -> dict[str, Any]:
    events = report.get("events", [])
    route = first_event(events, "route-matched")
    graph = first_event(events, "outbound-graph-selected")
    tcp = stage_event(events, "tcp-connect")
    write = stage_event(events, "stream-first-write")
    read = stage_event(events, "stream-first-read")
    failed = failed_stage(events)
    completed = first_event(events, "probe-completed")
    return {
        "reportPresent": bool(report),
        "target": target(report),
        "route": fields(route),
        "graph": fields(graph),
        "tcpConnect": stage_brief(tcp),
        "streamFirstWrite": stage_brief(write),
        "streamFirstRead": stage_brief(read),
        "failedStage": stage_brief(failed),
        "probeCompleted": fields(completed),
    }


def first_event(events: Any, kind: str) -> dict[str, Any]:
    return next(
        (event for event in events if isinstance(event, dict) and event.get("kind") == kind),
        {},
    )


def stage_event(events: Any, stage: str) -> dict[str, Any]:
    return next(
        (
            event
            for event in events
            if isinstance(event, dict)
            and event.get("kind") == "outbound-stage-finished"
            and event.get("fields", {}).get("stage") == stage
        ),
        {},
    )


def failed_stage(events: Any) -> dict[str, Any]:
    return next(
        (
            event
            for event in events
            if isinstance(event, dict)
            and event.get("kind") == "outbound-stage-finished"
            and event.get("fields", {}).get("status") == "failed"
        ),
        {},
    )


def fields(event: dict[str, Any]) -> dict[str, Any]:
    raw = event.get("fields", {}) if isinstance(event, dict) else {}
    return raw if isinstance(raw, dict) else {}


def stage_brief(event: dict[str, Any]) -> dict[str, Any]:
    data = fields(event)
    return {
        "present": bool(data),
        "status": data.get("status"),
        "stage": data.get("stage"),
        "elapsedMs": int_or_none(data.get("elapsedMs")),
        "bytes": int_or_none(data.get("bytes")),
        "pendingRetries": int_or_none(data.get("pendingRetries")),
        "pendingBudgetMs": int_or_none(data.get("pendingBudgetMs")),
        "errorType": data.get("errorType"),
        "errorMarker": attribution.reason_marker(data.get("error")),
        "protocolReadMarker": data.get("protocolReadMarker"),
        "protocolReadStage": data.get("protocolReadStage"),
        "protocolReadContext": protocol_read_context(data),
        "protocolReadDisposition": data.get("protocolReadDisposition"),
    }


def target(report: dict[str, Any]) -> dict[str, Any]:
    raw = report.get("target", {})
    if not isinstance(raw, dict):
        return {}
    return {"host": raw.get("host"), "port": raw.get("port")}


def int_or_none(value: Any) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def protocol_read_context(data: dict[str, Any]) -> str | None:
    explicit = data.get("protocolReadContext")
    if explicit:
        return str(explicit)
    error = str(data.get("error") or "")
    if "Shadowsocks response salt" in error:
        return "shadowsocks-response-salt"
    if "Shadowsocks chunk length" in error:
        return "shadowsocks-chunk-length"
    if "Shadowsocks chunk payload" in error:
        return "shadowsocks-chunk-payload"
    if "VMess response header length" in error:
        return "vmess-response-header-length"
    return None


def classify(item: dict[str, Any], evidence: dict[str, Any]) -> str:
    if not evidence.get("reportPresent"):
        return "missing-dynet-report"
    if direct_tls_eof(item, evidence):
        return "direct-tls-eof-after-path-complete"
    read_class = protocol_read_classification(item, evidence)
    if read_class:
        return read_class
    if item.get("status") != "pass":
        return "dynet-failure-with-partial-evidence"
    return "not-dynet-failure"


def protocol_read_classification(
    item: dict[str, Any],
    evidence: dict[str, Any],
) -> str | None:
    if item.get("status") == "pass":
        return None
    marker = read_marker(evidence)
    if not marker:
        return None
    return f"protocol-read-{protocol_read_detail(marker, read_disposition(evidence))}"


def read_marker(evidence: dict[str, Any]) -> str | None:
    for key in ["failedStage", "streamFirstRead"]:
        marker = evidence.get(key, {}).get("protocolReadMarker")
        if marker:
            return str(marker)
    return None


def read_disposition(evidence: dict[str, Any]) -> str | None:
    for key in ["failedStage", "streamFirstRead"]:
        value = evidence.get(key, {}).get("protocolReadDisposition")
        if value:
            return str(value)
    return None


def read_context(evidence: dict[str, Any]) -> str | None:
    for key in ["failedStage", "streamFirstRead"]:
        value = evidence.get(key, {}).get("protocolReadContext")
        if value:
            return str(value)
    return None


def protocol_read_detail(marker: str, disposition: str | None) -> str:
    if marker == "vmess-response-header-length-pending" and disposition:
        return f"vmess-response-header-length-{disposition}"
    return marker


def direct_tls_eof(item: dict[str, Any], evidence: dict[str, Any]) -> bool:
    return (
        item.get("failureScope") == "direct"
        and item.get("failedStage") == "tls-handshake"
        and item.get("selectedOutbound") == "direct"
        and item.get("status") != "pass"
        and evidence.get("route", {}).get("outbound") == "direct"
        and evidence.get("tcpConnect", {}).get("status") == "success"
        and evidence.get("streamFirstWrite", {}).get("status") == "success"
        and evidence.get("streamFirstRead", {}).get("status") == "success"
        and evidence.get("streamFirstRead", {}).get("bytes") == 0
        and evidence.get("failedStage", {}).get("stage") == "tls-handshake"
        and evidence.get("failedStage", {}).get("errorMarker") == "tls-eof"
    )


def missing_evidence(item: dict[str, Any], evidence: dict[str, Any]) -> list[str]:
    missing = []
    if not evidence.get("reportPresent"):
        return ["dynet-report-present"]
    if not evidence.get("route"):
        missing.append("route-matched")
    if evidence.get("tcpConnect", {}).get("status") != "success":
        missing.append("tcp-connect-success")
    if evidence.get("streamFirstWrite", {}).get("status") != "success":
        missing.append("stream-first-write-success")
    if (
        evidence.get("streamFirstRead", {}).get("status") != "success"
        and not protocol_read_classification(item, evidence)
    ):
        missing.append("stream-first-read-success")
    if not evidence.get("failedStage", {}).get("present"):
        missing.append("failed-stage")
    if item.get("selectedOutbound") and not evidence.get("graph"):
        missing.append("outbound-graph-selected")
    return missing


def totals(rows: list[dict[str, Any]]) -> dict[str, Any]:
    outcomes = Counter(row.get("outcome") for row in rows)
    return {
        "rows": len(rows),
        "dynetOnlyFailure": outcomes["dynet-only-failure"],
        "bothFailure": outcomes["both-failure"],
        "rowsWithMissingEvidence": sum(
            1 for row in rows if row.get("missingEvidence")
        ),
    }


def counter_rows(values: Any) -> list[dict[str, Any]]:
    counts = Counter(str(value or "unknown") for value in values)
    return [{"key": key, "count": count} for key, count in counts.most_common()]


def missing_evidence_counts(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return counter_rows(
        item
        for row in rows
        for item in row.get("missingEvidence", [])
    )


def surface_counts(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: Counter[tuple[str, str, str, str]] = Counter()
    for row in rows:
        brief = row.get("dynetSummary", {})
        counts[(
            str(row.get("domain") or "unknown"),
            str(row.get("probe") or "unknown"),
            str(brief.get("failedStage") or "unknown"),
            str(brief.get("reasonMarker") or "unknown"),
        )] += 1
    return [
        {
            "domain": domain,
            "probe": probe,
            "stage": stage,
            "reasonMarker": reason,
            "count": count,
        }
        for (domain, probe, stage, reason), count in counts.most_common()
    ]


def protocol_read_surface_counts(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: Counter[tuple[str, str, str, str, str, str, str]] = Counter()
    for row in rows:
        evidence = row.get("evidence", {})
        marker = read_marker(evidence)
        if not marker:
            continue
        summary = row.get("dynetSummary", {})
        counts[(
            str(row.get("domain") or "unknown"),
            str(row.get("probe") or "unknown"),
            str(summary.get("failureScope") or "unknown"),
            str(summary.get("selectedOutbound") or "unknown"),
            marker,
            str(read_context(evidence) or "unknown"),
            str(read_disposition(evidence) or "unknown"),
        )] += 1
    return [
        {
            "domain": domain,
            "probe": probe,
            "failureScope": scope,
            "selectedOutbound": outbound,
            "protocolReadMarker": marker,
            "protocolReadContext": context,
            "protocolReadDisposition": disposition,
            "count": count,
        }
        for (domain, probe, scope, outbound, marker, context, disposition), count in counts.most_common()
    ]


def write_markdown(path: Path, report: dict[str, Any]) -> None:
    lines = [
        "# Dynet vs Clash Product-Effect Drilldown",
        "",
        f"- Rows: `{report['totals']['rows']}`",
        f"- Dynet-only failures: `{report['totals']['dynetOnlyFailure']}`",
        f"- Both failures: `{report['totals']['bothFailure']}`",
        f"- Rows with missing evidence: `{report['totals']['rowsWithMissingEvidence']}`",
        "",
        "## Classifications",
        "",
    ]
    for item in report["classificationCounts"]:
        lines.append(f"- `{item['key']}` count=`{item['count']}`")
    lines.extend(["", "## Surfaces", ""])
    for item in report["surfaceCounts"][:12]:
        lines.append(
            f"- `{item['domain']}` probe=`{item['probe']}` "
            f"stage=`{item['stage']}` reason=`{item['reasonMarker']}` "
            f"count=`{item['count']}`"
        )
    lines.extend(["", "## Protocol Read Surfaces", ""])
    for item in report["protocolReadSurfaceCounts"][:12]:
        lines.append(
            f"- `{item['domain']}` probe=`{item['probe']}` "
            f"scope=`{item['failureScope']}` outbound=`{item['selectedOutbound']}` "
            f"marker=`{item['protocolReadMarker']}` "
            f"context=`{item.get('protocolReadContext')}` "
            f"disposition=`{item['protocolReadDisposition']}` count=`{item['count']}`"
        )
    path.write_text("\n".join(lines) + "\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Drill retained dynet product-effect failures into probe events."
    )
    parser.add_argument("--comparison", action="append", required=True)
    parser.add_argument("--output-json", default=DEFAULT_OUTPUT_JSON)
    parser.add_argument("--output-md", default=DEFAULT_OUTPUT_MD)
    parser.add_argument("--primary-bucket", default="github-proof")
    return parser


def command(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = build(args)
    output_json = Path(args.output_json)
    output_md = Path(args.output_md)
    write_json(output_json, report)
    write_markdown(output_md, report)
    print(json.dumps({
        "outputJson": str(output_json),
        "outputMd": str(output_md),
        "rows": report["totals"]["rows"],
        "classifications": report["classificationCounts"],
    }, sort_keys=True))
    return 0
