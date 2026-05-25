from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from common import Lab, validate_name
from private_runtime_lib.briefs import fields


ROUTE_DECISION_SCHEMA = "dynet-vm-private-runtime-route-decision-surface/v1alpha1"
REPEAT_SCHEMA = "dynet-vm-private-runtime-repeat/v1alpha1"
ROUTE_SCOPES = {"tcp-route", "udp-route"}
GRAPH_SCOPES = {"tcp-route", "udp-route", "plan-candidate"}
COUNT_FIELDS = [
    "runs", "cleanRuns", "failedRuns", "eventReports", "runtimePass", "events",
    "reportedRouteDecisions", "routeMatchedEvents",
    "routeDecisionCounterMismatches", "tcpRouteMatched", "udpRouteMatched",
    "unknownTransportRouteMatched", "routeMatchedMissingStatus",
    "routeMatchedMissingOutbound", "routeMatchedMissingTransport",
    "tcpRouteMissingFlowId", "tcpRouteMissingSession",
    "tcpRouteGraphSelected", "tcpRouteMissingGraph",
    "tcpRouteGraphWithoutRoute", "udpRouteGraphSelected",
    "udpRouteGraphMismatches", "routeGraphMissingSelected",
    "routeGraphMissingRequested", "planBypassedEvents",
    "planCandidateGraphSelected", "planBypassMissingGraph",
    "planGraphWithoutBypass", "routeCandidateSets",
    "routeCandidateMissingGraph", "routeCandidateMissingSelected",
    "routeCandidateMissingCount",
]
BLOCKERS = [
    "routeDecisionCounterMismatches", "unknownTransportRouteMatched",
    "routeMatchedMissingStatus", "routeMatchedMissingOutbound",
    "routeMatchedMissingTransport", "tcpRouteMissingFlowId",
    "tcpRouteMissingSession", "tcpRouteMissingGraph",
    "tcpRouteGraphWithoutRoute", "udpRouteGraphMismatches",
    "routeGraphMissingSelected", "routeGraphMissingRequested",
    "planBypassMissingGraph", "planGraphWithoutBypass",
    "routeCandidateMissingGraph", "routeCandidateMissingSelected",
    "routeCandidateMissingCount",
]


def command_route_decision_surface(_lab: Lab, args: argparse.Namespace) -> None:
    label = validate_name(args.label or "route-decision-surface", "label")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = build_route_decision_summary(
        label,
        output_dir,
        [Path(item) for item in args.input],
    )
    write_route_decision_summary(output_dir, summary)
    print(json.dumps(route_decision_print(output_dir, summary), sort_keys=True))


def build_route_decision_summary(
    label: str,
    output_dir: Path,
    inputs: list[Path],
) -> dict[str, Any]:
    rows = [route_decision_row(path) for path in expand_inputs(inputs)]
    totals = route_decision_totals(rows)
    return {
        "schema": ROUTE_DECISION_SCHEMA,
        "label": label,
        "outputDir": str(output_dir),
        "runs": rows,
        "totals": totals,
        "conclusion": route_decision_conclusion(totals),
        "privacy": empty_privacy_flags(),
        "policy": {
            "plannerPenaltySafe": False,
            "qualityPenaltySafe": False,
            "reason": "Route decision integrity is observability proof, not policy proof.",
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


def route_decision_row(run_dir: Path) -> dict[str, Any]:
    summary = load_optional_json(run_dir / "summary.json")
    current = route_decision_counts(load_optional_json(run_dir / "runtime-report.json"))
    clean = route_decision_clean(current)
    return {
        "label": summary.get("label") or run_dir.name,
        "path": str(run_dir),
        "classification": "clean" if clean else route_decision_classification(current),
        "clean": clean,
        "current": current,
    }


def route_decision_counts(report: dict[str, Any]) -> dict[str, Any]:
    raw_events = report.get("events")
    rows = [
        event_row(event, index)
        for index, event in enumerate(raw_events or [])
        if isinstance(event, dict)
    ]
    routes = [row for row in rows if row["kind"] == "route-matched"]
    graphs = [row for row in rows if row["kind"] == "outbound-graph-selected"]
    candidates = [row for row in rows if row["kind"] == "outbound-candidate-set"]
    plan_bypasses = [row for row in rows if row["kind"] == "plan-bypassed"]
    route_graphs = [row for row in graphs if row["scope"] in ROUTE_SCOPES]
    route_candidates = [row for row in candidates if row["scope"] in ROUTE_SCOPES]
    reported = int(report.get("routeDecisions") or 0)
    return {
        "eventReports": 1 if raw_events is not None else 0,
        "runtimePass": 1 if report.get("status") == "pass" else 0,
        "events": len(rows),
        "reportedRouteDecisions": reported,
        "routeMatchedEvents": len(routes),
        "routeDecisionCounterMismatches": abs(reported - len(routes)),
        **route_field_counts(routes),
        **route_graph_counts(routes, route_graphs),
        **plan_bypass_counts(plan_bypasses, graphs),
        **route_candidate_counts(route_candidates, route_graphs),
        "decisionPaths": aggregate(row["scope"] for row in graphs if row["scope"] in GRAPH_SCOPES),
    }


def event_row(event: dict[str, Any], index: int) -> dict[str, Any]:
    event_fields = fields(event)
    return {
        "index": index,
        "kind": str(event.get("kind") or ""),
        "key": event_fields.get("flowId") or event_fields.get("dnsQueryId") or "",
        "scope": event_fields.get("scope") or "",
        "transport": event_fields.get("transport") or event_fields.get("sessionTransport") or "",
        "status": bool(event_fields.get("status")),
        "outbound": bool(event_fields.get("outbound")),
        "selected": bool(event_fields.get("selected")),
        "requested": bool(event_fields.get("requested")),
        "candidateCount": parse_int(event_fields.get("candidateCount")),
        "hasFlowId": bool(event_fields.get("flowId")),
        "hasSession": bool(event_fields.get("session")),
    }


def route_field_counts(routes: list[dict[str, Any]]) -> dict[str, int]:
    tcp_routes = [row for row in routes if row["transport"] == "tcp"]
    udp_routes = [row for row in routes if row["transport"] == "udp"]
    return {
        "tcpRouteMatched": len(tcp_routes),
        "udpRouteMatched": len(udp_routes),
        "unknownTransportRouteMatched": sum(
            1 for row in routes if row["transport"] not in {"tcp", "udp"}
        ),
        "routeMatchedMissingStatus": sum(1 for row in routes if not row["status"]),
        "routeMatchedMissingOutbound": sum(1 for row in routes if not row["outbound"]),
        "routeMatchedMissingTransport": sum(1 for row in routes if not row["transport"]),
        "tcpRouteMissingFlowId": sum(1 for row in tcp_routes if not row["hasFlowId"]),
        "tcpRouteMissingSession": sum(1 for row in tcp_routes if not row["hasSession"]),
    }


def route_graph_counts(
    routes: list[dict[str, Any]],
    route_graphs: list[dict[str, Any]],
) -> dict[str, int]:
    tcp_routes = {row["key"] for row in routes if row["transport"] == "tcp" and row["key"]}
    tcp_graphs = {row["key"] for row in route_graphs if row["scope"] == "tcp-route" and row["key"]}
    udp_routes = [row for row in routes if row["transport"] == "udp"]
    udp_graphs = [row for row in route_graphs if row["scope"] == "udp-route"]
    return {
        "tcpRouteGraphSelected": len(tcp_graphs),
        "tcpRouteMissingGraph": len(tcp_routes - tcp_graphs),
        "tcpRouteGraphWithoutRoute": len(tcp_graphs - tcp_routes),
        "udpRouteGraphSelected": len(udp_graphs),
        "udpRouteGraphMismatches": abs(len(udp_routes) - len(udp_graphs)),
        "routeGraphMissingSelected": sum(1 for row in route_graphs if not row["selected"]),
        "routeGraphMissingRequested": sum(1 for row in route_graphs if not row["requested"]),
    }


def plan_bypass_counts(
    plan_bypasses: list[dict[str, Any]],
    graphs: list[dict[str, Any]],
) -> dict[str, int]:
    bypass_keys = {row["key"] for row in plan_bypasses if row["key"]}
    plan_graph_keys = {
        row["key"] for row in graphs
        if row["scope"] == "plan-candidate" and row["key"]
    }
    return {
        "planBypassedEvents": len(plan_bypasses),
        "planCandidateGraphSelected": len(plan_graph_keys),
        "planBypassMissingGraph": len(bypass_keys - plan_graph_keys),
        "planGraphWithoutBypass": len(plan_graph_keys - bypass_keys),
    }


def route_candidate_counts(
    route_candidates: list[dict[str, Any]],
    route_graphs: list[dict[str, Any]],
) -> dict[str, int]:
    graph_keys = {
        scoped_key(row) for row in route_graphs if row["key"] and row["scope"] in ROUTE_SCOPES
    }
    return {
        "routeCandidateSets": len(route_candidates),
        "routeCandidateMissingGraph": sum(
            1 for row in route_candidates
            if row["key"] and scoped_key(row) not in graph_keys
        ),
        "routeCandidateMissingSelected": sum(
            1 for row in route_candidates if not row["selected"]
        ),
        "routeCandidateMissingCount": sum(
            1 for row in route_candidates if not row["candidateCount"]
        ),
    }


def scoped_key(row: dict[str, Any]) -> str:
    return f"{row['scope']}:{row['key']}"


def route_decision_clean(counts: dict[str, Any]) -> bool:
    has_decision = counts["routeMatchedEvents"] > 0 or counts["planBypassedEvents"] > 0
    return (
        counts["eventReports"] == 1
        and counts["runtimePass"] == 1
        and has_decision
        and all(int(counts[key]) == 0 for key in BLOCKERS)
    )


def route_decision_classification(counts: dict[str, Any]) -> str:
    for key, label in [
        ("routeDecisionCounterMismatches", "route-counter-mismatch"),
        ("unknownTransportRouteMatched", "route-transport-unknown"),
        ("routeMatchedMissingStatus", "route-status-missing"),
        ("routeMatchedMissingOutbound", "route-outbound-missing"),
        ("routeMatchedMissingTransport", "route-transport-missing"),
        ("tcpRouteMissingFlowId", "tcp-route-flow-missing"),
        ("tcpRouteMissingSession", "tcp-route-session-missing"),
        ("tcpRouteMissingGraph", "tcp-route-graph-missing"),
        ("tcpRouteGraphWithoutRoute", "tcp-route-graph-orphan"),
        ("udpRouteGraphMismatches", "udp-route-graph-mismatch"),
        ("routeGraphMissingSelected", "route-graph-selected-missing"),
        ("routeGraphMissingRequested", "route-graph-requested-missing"),
        ("planBypassMissingGraph", "plan-bypass-graph-missing"),
        ("planGraphWithoutBypass", "plan-graph-orphan"),
        ("routeCandidateMissingGraph", "route-candidate-graph-missing"),
        ("routeCandidateMissingSelected", "route-candidate-selected-missing"),
        ("routeCandidateMissingCount", "route-candidate-count-missing"),
    ]:
        if int(counts[key]):
            return label
    return "route-decision-surface-incomplete"


def route_decision_totals(rows: list[dict[str, Any]]) -> dict[str, Any]:
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
        "decisionPaths": merge_count_rows(row["current"]["decisionPaths"] for row in rows),
    }


def route_decision_conclusion(totals: dict[str, Any]) -> dict[str, Any]:
    clean = totals["runs"] > 0 and totals["failedRuns"] == 0
    return {
        "status": "clean" if clean else "route-decision-surface-needs-evidence",
        "nextAction": "return-to-runtime-surface" if clean else "inspect-route-decision-chain",
        "plannerPenaltySafe": False,
        "qualityPenaltySafe": False,
    }


def write_route_decision_summary(output_dir: Path, summary: dict[str, Any]) -> None:
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    write_route_decision_markdown(output_dir / "summary.md", summary)


def write_route_decision_markdown(path: Path, summary: dict[str, Any]) -> None:
    totals = summary["totals"]
    lines = [
        "# VM Private Runtime Route Decision Surface",
        "",
        f"- label: `{summary['label']}`",
        f"- status: `{summary['conclusion']['status']}`",
        f"- runs: `{totals['runs']}`",
        f"- clean runs: `{totals['cleanRuns']}`",
        f"- route decisions: `{totals['routeMatchedEvents']}`",
        f"- plan bypasses: `{totals['planBypassedEvents']}`",
        f"- route counter mismatches: `{totals['routeDecisionCounterMismatches']}`",
        f"- tcp graph missing: `{totals['tcpRouteMissingGraph']}`",
        f"- udp graph mismatches: `{totals['udpRouteGraphMismatches']}`",
        f"- plan bypass graph missing: `{totals['planBypassMissingGraph']}`",
        "",
        "## Runs",
        "",
    ]
    for row in summary["runs"]:
        lines.append(
            f"- `{row['label']}` clean=`{row['clean']}` "
            f"classification=`{row['classification']}` "
            f"route=`{row['current']['routeMatchedEvents']}` "
            f"bypass=`{row['current']['planBypassedEvents']}`"
        )
    path.write_text("\n".join(lines) + "\n")


def route_decision_print(output_dir: Path, summary: dict[str, Any]) -> dict[str, Any]:
    totals = summary["totals"]
    return {
        "outputDir": str(output_dir),
        "status": summary["conclusion"]["status"],
        "runs": totals["runs"],
        "routeMatchedEvents": totals["routeMatchedEvents"],
        "planBypassedEvents": totals["planBypassedEvents"],
        "routeDecisionCounterMismatches": totals["routeDecisionCounterMismatches"],
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


def parse_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def load_optional_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text())
