from __future__ import annotations

from collections import Counter
from typing import Any


SCHEMA = "dynet-clash-runtime-workload-gate/v1alpha1"


def build(summary: dict[str, Any], source: str | None = None) -> dict[str, Any]:
    totals = normalized_totals(summary)
    checks = gate_checks(totals)
    failed = [item["name"] for item in checks if not item["passed"]]
    return {
        "schema": SCHEMA,
        "source": source,
        "present": True,
        "clean": not failed,
        "failedChecks": failed,
        "checks": checks,
        "totals": totals,
        "surfaces": surfaces(summary, totals),
        "classification": classification(failed, totals),
    }


def missing() -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "source": None,
        "present": False,
        "clean": False,
        "failedChecks": ["runtime-summary-present"],
        "checks": [
            {
                "name": "runtime-summary-present",
                "passed": False,
                "value": False,
                "required": True,
            }
        ],
        "totals": {},
        "surfaces": {},
        "classification": "missing-runtime-evidence",
    }


def markdown_lines(gate: dict[str, Any]) -> list[str]:
    totals = gate.get("totals", {})
    lines = [
        "",
        "## Dynet Runtime Gate",
        "",
        f"- clean=`{gate.get('clean')}` classification=`{gate.get('classification')}` "
        f"workload=`{totals.get('workloadSuccess')}/{totals.get('workloadAttempted')}` "
        f"flowMatched=`{totals.get('tcpAttemptedCoveredEntries')}/{totals.get('tcpAttemptedEntries')}`",
    ]
    if totals.get("qualityStateUsed"):
        lines.append(
            f"- qualityBound=`{totals.get('qualityBoundSelectedWithQuality')}/"
            f"{totals.get('qualityBoundCandidateSets')}` "
            f"selectedBehind=`{totals.get('qualityBoundSelectedBehind')}`"
        )
        lines.append(
            f"- routePlan=`{totals.get('tcpFlowRouteGraphSelected')}/"
            f"{totals.get('tcpAttemptedEntries')}` "
            f"routeMatched=`{totals.get('tcpFlowRouteMatched')}` "
            f"ruleMatched=`{totals.get('tcpFlowRuleMatched')}` "
            f"planBypassed=`{totals.get('tcpFlowPlanBypassed')}`"
        )
        if int(totals.get("tcpFlowRouteFallbackUsed") or 0):
            lines.append(
                f"- routeFallback=`{totals.get('tcpFlowRouteFallbackUsed')}` "
                f"attempts=`{totals.get('tcpFlowRouteFallbackAttempts')}` "
                f"established=`{totals.get('tcpFlowRouteFallbackEstablished')}` "
                f"failed=`{totals.get('tcpFlowRouteFallbackFailed')}`"
            )
    for item in gate.get("checks", []):
        if item.get("passed") is False:
            lines.append(
                f"- failed `{item['name']}` value=`{item.get('value')}` "
                f"required=`{item.get('required')}`"
            )
    surfaces = gate.get("surfaces", {})
    for key in [
        "workloadFailedBySurface",
        "workloadFlowFailureSurfaces",
        "tcpFlowFailedBySurface",
    ]:
        if surfaces.get(key):
            lines.append(f"- {key}: `{surfaces[key]}`")
    return lines


def normalized_totals(summary: dict[str, Any]) -> dict[str, Any]:
    if isinstance(summary.get("totals"), dict) and "workloadAttempted" in summary["totals"]:
        return repeat_totals(summary)
    return single_totals(summary)


def repeat_totals(summary: dict[str, Any]) -> dict[str, Any]:
    raw = summary.get("totals", {})
    runs = list_value(summary.get("runs"))
    tcp_attempted = int_value(raw, "workloadFlowTcpAttemptedEntries")
    return {
        "qualityStateUsed": bool(summary.get("qualityStateUsed")),
        "runs": int_value(raw, "runs"),
        "failedRuns": int_value(raw, "failedRuns"),
        "workloadAttempted": int_value(raw, "workloadAttempted"),
        "workloadSuccess": int_value(raw, "workloadSuccess"),
        "workloadFailure": int_value(raw, "workloadFailure"),
        "workloadStrictFailedRuns": int_value(raw, "workloadStrictFailedRuns"),
        "workloadErrors": list_value(raw.get("workloadErrors")),
        "workloadFlowEntries": int_value(raw, "workloadFlowEntries"),
        "tcpAttemptedEntries": tcp_attempted,
        "tcpAttemptedCoveredEntries": int_value(raw, "workloadFlowTcpAttemptedCoveredEntries"),
        "runtimePreflowMatchedEntries": int_value(raw, "workloadFlowRuntimePreflowMatchedEntries"),
        "runtimePacketHandshakeEntries": int_value(raw, "workloadFlowRuntimePacketHandshakeEntries"),
        "tunCaptureMatchedEntries": int_value(raw, "workloadFlowTunCaptureMatchedEntries"),
        "unmatchedEntries": int_value(raw, "workloadFlowUnmatchedEntries"),
        "runtimePacketTerminalEntries": int_value(raw, "workloadFlowRuntimePacketTerminalEntries"),
        "tcpFlowFailed": int_value(raw, "tcpFlowFailed"),
        "tcpFlowFailedAfterPathComplete": int_value(raw, "tcpFlowFailedAfterPathComplete"),
        "tcpFlowFailedAfterUpstreamOnly": int_value(raw, "tcpFlowFailedAfterUpstreamOnly"),
        "tcpSlotPressureEvents": int_value(raw, "tcpSlotPressureEvents"),
        "tcpActiveSlotsMax": int_value(raw, "tcpActiveSlotsMax"),
        "qualityBoundCandidateSets": repeat_int(raw, runs, "qualityBoundCandidateSets", "boundSelection", "candidateSets"),
        "qualityBoundSelectedWithQuality": repeat_int(raw, runs, "qualityBoundSelectedWithQuality", "boundSelection", "selectedWithQuality"),
        "qualityBoundSelectedBehind": repeat_int(raw, runs, "qualityBoundSelectedBehind", "boundSelection", "selectedBehind"),
        "tcpFlowRouteMatched": repeat_int(raw, runs, "tcpFlowRouteMatched", "tcpFlow", "routeMatchedFlows"),
        "tcpFlowRouteGraphSelected": repeat_int(raw, runs, "tcpFlowRouteGraphSelected", "tcpFlow", "routeGraphSelectedFlows"),
        "tcpFlowRuleMatched": repeat_int(raw, runs, "tcpFlowRuleMatched", "tcpFlow", "ruleMatchedFlows"),
        "tcpFlowPlanBypassed": repeat_int(raw, runs, "tcpFlowPlanBypassed", "tcpFlow", "planBypassedFlows"),
        "tcpFlowRouteCandidateSet": repeat_int(raw, runs, "tcpFlowRouteCandidateSet", "tcpFlow", "routeCandidateSetFlows"),
        "tcpFlowRouteFallbackCandidate": repeat_int(raw, runs, "tcpFlowRouteFallbackCandidate", "tcpFlow", "routeFallbackCandidateFlows"),
        "tcpFlowRouteFallbackAttempts": repeat_int(raw, runs, "tcpFlowRouteFallbackAttempts", "tcpFlow", "routeFallbackAttemptEvents"),
        "tcpFlowRouteFallbackUsed": repeat_int(raw, runs, "tcpFlowRouteFallbackUsed", "tcpFlow", "routeFallbackUsedFlows"),
        "tcpFlowRouteFallbackEstablished": repeat_int(raw, runs, "tcpFlowRouteFallbackEstablished", "tcpFlow", "routeFallbackEstablishedFlows"),
        "tcpFlowRouteFallbackFailed": repeat_int(raw, runs, "tcpFlowRouteFallbackFailed", "tcpFlow", "routeFallbackFailedFlows"),
        "tcpFlowRouteFallbackByRouteSelected": repeat_list(raw, runs, "tcpFlowRouteFallbackByRouteSelected", "tcpFlow", "routeFallbackByRouteSelected"),
        "tcpFlowRouteFallbackByFinalOutbound": repeat_list(raw, runs, "tcpFlowRouteFallbackByFinalOutbound", "tcpFlow", "routeFallbackByFinalOutbound"),
        "tcpFlowRouteFallbackByAttemptedOutbound": repeat_list(raw, runs, "tcpFlowRouteFallbackByAttemptedOutbound", "tcpFlow", "routeFallbackByAttemptedOutbound"),
        "tcpFlowFailedBySurface": list_value(raw.get("tcpFlowFailedBySurface")),
        "workloadFlowFailureSurfaces": list_value(raw.get("workloadFlowFailureSurfaces")),
        "workloadFailedBySurface": list_value(raw.get("workloadFailedBySurface")),
        "workloadFailedByStage": list_value(raw.get("workloadFailedByStage")),
        "workloadFailedByProbe": list_value(raw.get("workloadFailedByProbe")),
    }


def single_totals(summary: dict[str, Any]) -> dict[str, Any]:
    workload = summary.get("workloadProbe", {}).get("totals", {})
    flow = summary.get("workloadFlow", {})
    runtime = summary.get("runtime", {})
    bound = summary.get("selection", {}).get("boundSelection", {})
    tcp_flow = summary.get("tcpFlow", {})
    tcp_attempted = int_value(flow, "tcpAttemptedEntries", int_value(flow, "entries"))
    return {
        "qualityStateUsed": bool(summary.get("qualityStateUsed")),
        "runs": 1,
        "failedRuns": 1 if int_value(summary.get("totals", {}), "failed") else 0,
        "workloadAttempted": int_value(workload, "count"),
        "workloadSuccess": int_value(workload, "success"),
        "workloadFailure": int_value(workload, "failure"),
        "workloadStrictFailedRuns": 1 if int_value(workload, "failure") else 0,
        "workloadErrors": list_value(summary.get("workloadProbe", {}).get("errors")),
        "workloadFlowEntries": int_value(flow, "entries"),
        "tcpAttemptedEntries": tcp_attempted,
        "tcpAttemptedCoveredEntries": int_value(flow, "tcpAttemptedCoveredEntries"),
        "runtimePreflowMatchedEntries": int_value(flow, "runtimePreflowMatchedEntries"),
        "runtimePacketHandshakeEntries": int_value(flow, "runtimePacketHandshakeEntries"),
        "tunCaptureMatchedEntries": int_value(flow, "tunCaptureMatchedEntries"),
        "unmatchedEntries": int_value(flow, "unmatchedEntries"),
        "runtimePacketTerminalEntries": int_value(flow, "runtimePacketTerminalEntries"),
        "tcpFlowFailed": int_value(flow, "matchedFlowFailed"),
        "tcpFlowFailedAfterPathComplete": 0,
        "tcpFlowFailedAfterUpstreamOnly": 0,
        "tcpSlotPressureEvents": int_value(runtime, "tcpSlotPressureEvents"),
        "tcpActiveSlotsMax": int_value(runtime, "tcpActiveSlotsMax"),
        "qualityBoundCandidateSets": int_value(bound, "candidateSets"),
        "qualityBoundSelectedWithQuality": int_value(bound, "selectedWithQuality"),
        "qualityBoundSelectedBehind": int_value(bound, "selectedBehind"),
        "tcpFlowRouteMatched": int_value(tcp_flow, "routeMatchedFlows"),
        "tcpFlowRouteGraphSelected": int_value(tcp_flow, "routeGraphSelectedFlows"),
        "tcpFlowRuleMatched": int_value(tcp_flow, "ruleMatchedFlows"),
        "tcpFlowPlanBypassed": int_value(tcp_flow, "planBypassedFlows"),
        "tcpFlowRouteCandidateSet": int_value(tcp_flow, "routeCandidateSetFlows"),
        "tcpFlowRouteFallbackCandidate": int_value(tcp_flow, "routeFallbackCandidateFlows"),
        "tcpFlowRouteFallbackAttempts": int_value(tcp_flow, "routeFallbackAttemptEvents"),
        "tcpFlowRouteFallbackUsed": int_value(tcp_flow, "routeFallbackUsedFlows"),
        "tcpFlowRouteFallbackEstablished": int_value(tcp_flow, "routeFallbackEstablishedFlows"),
        "tcpFlowRouteFallbackFailed": int_value(tcp_flow, "routeFallbackFailedFlows"),
        "tcpFlowRouteFallbackByRouteSelected": list_value(tcp_flow.get("routeFallbackByRouteSelected")),
        "tcpFlowRouteFallbackByFinalOutbound": list_value(tcp_flow.get("routeFallbackByFinalOutbound")),
        "tcpFlowRouteFallbackByAttemptedOutbound": list_value(tcp_flow.get("routeFallbackByAttemptedOutbound")),
        "tcpFlowFailedBySurface": [],
        "workloadFlowFailureSurfaces": list_value(flow.get("failureSurfaces")),
        "workloadFailedBySurface": list_value(summary.get("workloadProbe", {}).get("bySurface")),
        "workloadFailedByStage": list_value(summary.get("workloadProbe", {}).get("byStage")),
        "workloadFailedByProbe": list_value(summary.get("workloadProbe", {}).get("byProbe")),
    }


def gate_checks(totals: dict[str, Any]) -> list[dict[str, Any]]:
    attempted = int(totals.get("workloadAttempted") or 0)
    tcp_attempted = int(totals.get("tcpAttemptedEntries") or 0)
    checks = [
        check("workload-attempted", attempted > 0, attempted, "> 0"),
        check("workload-all-success", int(totals.get("workloadFailure") or 0) == 0, totals.get("workloadFailure"), 0),
        check("workload-errors-clean", not totals.get("workloadErrors"), totals.get("workloadErrors"), []),
        check(
            "workload-strict-runs-clean",
            int(totals.get("workloadStrictFailedRuns") or 0) == 0,
            totals.get("workloadStrictFailedRuns"),
            0,
        ),
        check(
            "workload-flow-entries",
            int(totals.get("workloadFlowEntries") or 0) >= attempted,
            totals.get("workloadFlowEntries"),
            f">= workloadAttempted ({attempted})",
        ),
        check("workload-flow-covered", totals.get("tcpAttemptedCoveredEntries") == tcp_attempted, totals.get("tcpAttemptedCoveredEntries"), tcp_attempted),
        check("workload-flow-preflow", totals.get("runtimePreflowMatchedEntries") == tcp_attempted, totals.get("runtimePreflowMatchedEntries"), tcp_attempted),
        check("workload-flow-packet-handshake", totals.get("runtimePacketHandshakeEntries") == tcp_attempted, totals.get("runtimePacketHandshakeEntries"), tcp_attempted),
        check("workload-flow-tun-capture", totals.get("tunCaptureMatchedEntries") == tcp_attempted, totals.get("tunCaptureMatchedEntries"), tcp_attempted),
        check("workload-flow-unmatched-clean", int(totals.get("unmatchedEntries") or 0) == 0, totals.get("unmatchedEntries"), 0),
        check("workload-flow-terminal-clean", int(totals.get("runtimePacketTerminalEntries") or 0) == 0, totals.get("runtimePacketTerminalEntries"), 0),
        check("tcp-flow-failures-clean", int(totals.get("tcpFlowFailed") or 0) == 0, totals.get("tcpFlowFailed"), 0),
        check("tcp-flow-path-failures-clean", int(totals.get("tcpFlowFailedAfterPathComplete") or 0) == 0, totals.get("tcpFlowFailedAfterPathComplete"), 0),
        check("tcp-flow-upstream-only-failures-clean", int(totals.get("tcpFlowFailedAfterUpstreamOnly") or 0) == 0, totals.get("tcpFlowFailedAfterUpstreamOnly"), 0),
        check("tcp-slot-pressure-clean", int(totals.get("tcpSlotPressureEvents") or 0) == 0, totals.get("tcpSlotPressureEvents"), 0),
    ]
    if totals.get("qualityStateUsed"):
        quality_sets = int(totals.get("qualityBoundCandidateSets") or 0)
        route_selected = int(totals.get("tcpFlowRouteGraphSelected") or 0)
        checks.extend(
            [
                check("quality-bound-present", quality_sets > 0, quality_sets, "> 0"),
                check(
                    "quality-bound-covered",
                    int(totals.get("qualityBoundSelectedWithQuality") or 0) == quality_sets,
                    totals.get("qualityBoundSelectedWithQuality"),
                    quality_sets,
                ),
                check("quality-bound-not-behind", int(totals.get("qualityBoundSelectedBehind") or 0) == 0, totals.get("qualityBoundSelectedBehind"), 0),
                check("route-plan-present", route_selected > 0, route_selected, "> 0"),
                check("route-plan-covered", route_selected == tcp_attempted, route_selected, tcp_attempted),
                check("route-plan-not-bypassed", int(totals.get("tcpFlowPlanBypassed") or 0) == 0, totals.get("tcpFlowPlanBypassed"), 0),
                check("hard-rule-bypass-clean", int(totals.get("tcpFlowRuleMatched") or 0) == 0, totals.get("tcpFlowRuleMatched"), 0),
            ]
        )
    return checks


def check(name: str, passed: bool, value: Any, required: Any) -> dict[str, Any]:
    return {"name": name, "passed": passed, "value": value, "required": required}


def surfaces(summary: dict[str, Any], totals: dict[str, Any]) -> dict[str, Any]:
    return {
        "workloadFailedBySurface": list_value(totals.get("workloadFailedBySurface")),
        "workloadFailedByStage": list_value(totals.get("workloadFailedByStage")),
        "workloadFailedByProbe": list_value(totals.get("workloadFailedByProbe")),
        "workloadFlowFailureSurfaces": list_value(totals.get("workloadFlowFailureSurfaces")),
        "tcpFlowFailedBySurface": list_value(totals.get("tcpFlowFailedBySurface")),
        "tcpFlowFailedByErrorType": list_value(
            (summary.get("totals") or {}).get("tcpFlowFailedByErrorType")
        ),
    }


def classification(failed: list[str], totals: dict[str, Any]) -> str:
    if not failed:
        if totals.get("qualityStateUsed"):
            return "runtime-route-plan-quality-clean"
        return "runtime-workload-clean"
    if any(
        item.startswith("quality-bound-")
        or item.startswith("route-plan-")
        or item == "hard-rule-bypass-clean"
        for item in failed
    ):
        return "runtime-route-plan-quality-suspect"
    if int(totals.get("unmatchedEntries") or 0):
        return "runtime-correlation-suspect"
    if int(totals.get("runtimePacketTerminalEntries") or 0):
        return "runtime-packet-terminal-suspect"
    if int(totals.get("tcpSlotPressureEvents") or 0):
        return "runtime-capacity-suspect"
    if int(totals.get("tcpFlowFailed") or 0):
        return "runtime-flow-suspect"
    if int(totals.get("workloadFailure") or 0):
        return "target-or-probe-suspect"
    return "runtime-gate-incomplete"


def int_value(data: dict[str, Any], key: str, default: int = 0) -> int:
    try:
        return int(data.get(key, default) or 0)
    except (TypeError, ValueError):
        return default


def repeat_int(
    raw: dict[str, Any],
    runs: list[Any],
    total_key: str,
    section: str,
    run_key: str,
) -> int:
    if total_key in raw:
        return int_value(raw, total_key)
    return sum(
        int_value(run.get(section, {}), run_key)
        for run in runs
        if isinstance(run, dict)
    )


def repeat_list(
    raw: dict[str, Any],
    runs: list[Any],
    total_key: str,
    section: str,
    run_key: str,
) -> list[dict[str, Any]]:
    if total_key in raw:
        return list_value(raw.get(total_key))
    counter: Counter[str] = Counter()
    for run in runs:
        if not isinstance(run, dict):
            continue
        for item in list_value(run.get(section, {}).get(run_key)):
            if isinstance(item, dict):
                counter[str(item.get("key") or "unknown")] += int_value(item, "count")
    return [{"key": key, "count": counter[key]} for key in sorted(counter)]


def list_value(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []
