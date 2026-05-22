from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from dynet_trace.common import event_fields, event_kind, int_field, latency_summary, top


PROBE_ATTRIBUTION_SCHEMA = "dynet-probe-attribution/v1alpha1"
DEFAULT_PROBE_ATTRIBUTION_JSON = ".task/resources/dynet-probe-attribution.json"
DEFAULT_PROBE_ATTRIBUTION_MD = ".task/resources/dynet-probe-attribution.md"
CONTROL_BUCKETS = {"control-global", "work-direct"}


def build_probe_attribution(summary_path: Path) -> dict[str, Any]:
    summary = load_json(summary_path)
    items = [item for item in summary.get("items", []) if isinstance(item, dict)]
    evidence = [item_evidence(item, summary_path) for item in items]
    guardrails_clean = all(
        item.get("status") == "pass"
        for item in items
        if item.get("bucket") in CONTROL_BUCKETS
    )
    for row in evidence:
        row["classification"] = classify(row, guardrails_clean)
    return {
        "schema": PROBE_ATTRIBUTION_SCHEMA,
        "inputSummary": str(summary_path),
        "replay": summary.get("replay", {}),
        "totals": totals(evidence),
        "evidenceCompleteness": evidence_completeness(evidence),
        "byBucket": grouped(evidence, "bucket"),
        "byDomain": grouped(evidence, "domain"),
        "bySelectedOutbound": grouped(evidence, "selectedOutbound"),
        "byClassification": top(Counter(row["classification"] for row in evidence)),
        "stageLatencyMs": stage_latencies(evidence),
        "failures": [row for row in evidence if row["status"] != "pass"],
    }


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def item_evidence(item: dict[str, Any], summary_path: Path) -> dict[str, Any]:
    report_path = resolve_report_path(item, summary_path)
    report = load_report(report_path)
    events = [event for event in report.get("events", []) if isinstance(event, dict)]
    route = first_event(events, "route-matched")
    graph = first_event(events, "outbound-graph-selected")
    attempts = event_list(events, "outbound-attempt-finished")
    stages = stage_evidence(events)
    failures = failed_events(events)
    missing = missing_evidence(route, graph, attempts, stages, item)
    route_fields = event_fields(route or {})
    graph_fields = event_fields(graph or {})
    return {
        "id": item.get("id"),
        "bucket": item.get("bucket"),
        "domain": item.get("domain"),
        "sourceProbe": item.get("sourceProbe"),
        "dynetProtocol": item.get("dynetProtocol"),
        "scheduledOffsetMs": item.get("scheduledOffsetMs"),
        "actualStartOffsetMs": item.get("actualStartOffsetMs"),
        "status": item.get("status"),
        "selectedOutbound": item.get("selectedOutbound") or graph_fields.get("selected"),
        "routeStatus": route_fields.get("status"),
        "routeOutbound": route_fields.get("outbound"),
        "routeReason": route_fields.get("reason"),
        "graphSelected": graph_fields.get("selected"),
        "hopTags": graph_fields.get("hopTags"),
        "hopKinds": graph_fields.get("hopKinds"),
        "planDecisionCount": int_field(graph_fields, "decisions"),
        "candidateSets": candidate_sets(events),
        "attempts": attempt_summary(attempts),
        "stages": stages,
        "failedStage": item.get("failedStage") or first_failure_field(failures, "stage"),
        "errorType": first_failure_field(failures, "errorType"),
        "reason": item.get("reason"),
        "missingEvidence": missing,
        "reportPath": str(report_path) if report_path else item.get("reportPath"),
    }


def resolve_report_path(item: dict[str, Any], summary_path: Path) -> Path | None:
    raw = item.get("reportPath")
    if not isinstance(raw, str) or not raw:
        return None
    path = Path(raw)
    if path.is_absolute() or path.exists():
        return path
    return summary_path.parent / path


def load_report(path: Path | None) -> dict[str, Any]:
    if path is None or not path.exists():
        return {"events": []}
    try:
        return load_json(path)
    except json.JSONDecodeError:
        return {"events": []}


def first_event(events: list[dict[str, Any]], kind: str) -> dict[str, Any] | None:
    return next((event for event in events if event_kind(event) == kind), None)


def event_list(events: list[dict[str, Any]], kind: str) -> list[dict[str, Any]]:
    return [event for event in events if event_kind(event) == kind]


def candidate_sets(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for event in event_list(events, "outbound-candidate-set"):
        fields = event_fields(event)
        rows.append({
            "plan": fields.get("plan"),
            "selected": fields.get("selected"),
            "candidateCount": int_field(fields, "candidateCount"),
            "candidates": split_csv(fields.get("candidates")),
            "selectedEdgeType": fields.get("selectedEdgeType"),
        })
    return rows


def split_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [item for item in value.split(",") if item]


def attempt_summary(attempts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for event in attempts:
        fields = event_fields(event)
        rows.append({
            "protocol": fields.get("protocol"),
            "outbound": fields.get("outbound"),
            "status": fields.get("status"),
            "elapsedMs": int_field(fields, "elapsedMs"),
            "errorType": fields.get("errorType"),
        })
    return rows


def stage_evidence(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for event in event_list(events, "outbound-stage-finished"):
        fields = event_fields(event)
        rows.append({
            "stage": fields.get("stage"),
            "status": fields.get("status"),
            "outbound": fields.get("outbound"),
            "protocol": fields.get("protocol"),
            "elapsedMs": int_field(fields, "elapsedMs"),
            "errorType": fields.get("errorType"),
        })
    return rows


def failed_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        event
        for event in events
        if event_fields(event).get("status") == "failed"
        or event_kind(event) == "dns-resolve-failed"
    ]


def first_failure_field(events: list[dict[str, Any]], key: str) -> str | None:
    for event in events:
        value = event_fields(event).get(key)
        if value:
            return value
    return None


def missing_evidence(
    route: dict[str, Any] | None,
    graph: dict[str, Any] | None,
    attempts: list[dict[str, Any]],
    stages: list[dict[str, Any]],
    item: dict[str, Any],
) -> list[str]:
    missing = []
    if route is None:
        missing.append("route-matched")
    if graph is None:
        missing.append("outbound-graph-selected")
    if not attempts:
        missing.append("outbound-attempt-finished")
    if not stages:
        missing.append("outbound-stage-finished")
    if item.get("status") != "pass" and not item.get("failedStage"):
        missing.append("failed-stage")
    return missing


def classify(row: dict[str, Any], guardrails_clean: bool) -> str:
    if row["status"] == "pass":
        return "healthy"
    if row["missingEvidence"]:
        return "unknown"
    if row["bucket"] in CONTROL_BUCKETS:
        if row["selectedOutbound"] == "direct":
            return "dynet-infra-suspect"
        return "node-suspect"
    if row["planDecisionCount"] and row["candidateSets"] and not row["graphSelected"]:
        return "plan-suspect"
    if row["selectedOutbound"] and row["selectedOutbound"] != "direct":
        return "node-suspect"
    if row["bucket"] == "github-proof" and guardrails_clean:
        return "target-or-probe-suspect"
    return "unknown"


def totals(rows: list[dict[str, Any]]) -> dict[str, Any]:
    failed = [row for row in rows if row["status"] != "pass"]
    return {
        "items": len(rows),
        "passed": len(rows) - len(failed),
        "failed": len(failed),
        "unknown": sum(1 for row in rows if row["classification"] == "unknown"),
        "withMissingEvidence": sum(1 for row in rows if row["missingEvidence"]),
    }


def evidence_completeness(rows: list[dict[str, Any]]) -> dict[str, Any]:
    required = [
        "route-matched",
        "outbound-graph-selected",
        "outbound-attempt-finished",
        "outbound-stage-finished",
    ]
    missing = Counter(field for row in rows for field in row["missingEvidence"])
    return {
        key: {
            "present": len(rows) - missing.get(key, 0),
            "missing": missing.get(key, 0),
        }
        for key in required
    }


def grouped(rows: list[dict[str, Any]], field: str) -> list[dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[str(row.get(field) or "unknown")].append(row)
    output = []
    for key, items in sorted(groups.items()):
        failures = [item for item in items if item["status"] != "pass"]
        output.append({
            "key": key,
            "items": len(items),
            "failures": len(failures),
            "classifications": top(Counter(item["classification"] for item in items)),
        })
    return output


def stage_latencies(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped_values: dict[str, list[int]] = defaultdict(list)
    failures: Counter[str] = Counter()
    for row in rows:
        for stage in row["stages"]:
            name = str(stage.get("stage") or "unknown")
            if isinstance(stage.get("elapsedMs"), int):
                grouped_values[name].append(stage["elapsedMs"])
            if stage.get("status") == "failed":
                failures[name] += 1
    output = []
    for key in sorted(grouped_values):
        output.append({
            "key": key,
            "count": len(grouped_values[key]),
            "failures": failures.get(key, 0),
            "latencyMs": latency_summary(grouped_values[key]),
        })
    return output


def write_probe_attribution_report(path: Path, report: dict[str, Any]) -> None:
    lines = [
        "# Dynet Probe Attribution",
        "",
        f"- Items: `{report['totals']['items']}`",
        f"- Failed: `{report['totals']['failed']}`",
        f"- Unknown: `{report['totals']['unknown']}`",
        f"- Missing evidence: `{report['totals']['withMissingEvidence']}`",
        "",
        "## Classification",
        "",
    ]
    for item in report["byClassification"]:
        lines.append(f"- `{item['key']}`: {item['count']}")
    lines.extend(["", "## Buckets", ""])
    for item in report["byBucket"]:
        lines.append(f"- `{item['key']}` failures={item['failures']}/{item['items']}")
    lines.extend(["", "## Stage Latency", ""])
    for item in report["stageLatencyMs"]:
        lines.append(
            f"- `{item['key']}` count={item['count']} failures={item['failures']} "
            f"p95={item['latencyMs']['p95']}ms"
        )
    if report["failures"]:
        lines.extend(["", "## Failures", ""])
        for item in report["failures"]:
            lines.append(
                f"- `{item['id']}` {item['domain']} bucket=`{item['bucket']}` "
                f"outbound=`{item['selectedOutbound']}` stage=`{item['failedStage']}` "
                f"class=`{item['classification']}`"
            )
    path.write_text("\n".join(lines) + "\n")
