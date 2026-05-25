from __future__ import annotations

from typing import Any


def workload_surface_conclusion(totals: dict[str, Any]) -> dict[str, Any]:
    status = workload_surface_status(totals)
    return {
        "status": status,
        "nextAction": workload_surface_next_action(status),
        "plannerPenaltySafe": False,
        "qualityPenaltySafe": False,
        "productEffectClaimSafe": False,
        "reason": workload_surface_reason(status),
        "mechanisms": workload_surface_mechanism_conclusions(totals),
    }


def workload_surface_status(totals: dict[str, Any]) -> str:
    if int(totals.get("failedRows") or 0) == 0:
        return "clean"
    mechanisms = {
        str(item.get("key"))
        for item in totals.get("failedByMechanism") or []
        if int(item.get("count") or 0) > 0
    }
    if {"pre-tcp-workload-failure", "packet-terminal-before-runtime-session"} <= mechanisms:
        return "split-pre-tcp-and-packet-terminal"
    if mechanisms == {"pre-tcp-workload-failure"}:
        return "pre-tcp-workload-surface"
    if mechanisms == {"packet-terminal-before-runtime-session"}:
        return "packet-terminal-workload-surface"
    if len(mechanisms) > 1 and runtime_attributed_failures(totals):
        return "mixed-runtime-workload-surface"
    if len(mechanisms) > 1:
        return "mixed-workload-surface"
    return "workload-surface"


def runtime_attributed_failures(totals: dict[str, Any]) -> bool:
    failed = int(totals.get("failedRows") or 0)
    return (
        failed > 0
        and int(totals.get("preTcpFailures") or 0) == 0
        and int(totals.get("routeViaDynetFailures") or 0) == failed
        and int(totals.get("tunWitnessedFailures") or 0) == failed
        and int(totals.get("runtimePacketMatchedFailures") or 0) == failed
    )


def workload_surface_next_action(status: str) -> str:
    return {
        "clean": "return-to-product-effect",
        "split-pre-tcp-and-packet-terminal": "isolate-dns-preflow-and-packet-terminal-separately",
        "pre-tcp-workload-surface": "isolate-dns-preflow-workload-timeout",
        "packet-terminal-workload-surface": "harden-preflow-terminal-to-runtime-session-promotion",
        "mixed-runtime-workload-surface": "split-runtime-stage-terminal-and-protocol-surfaces",
        "mixed-workload-surface": "classify-workload-surface-mechanisms",
    }.get(status, "classify-workload-surface")


def workload_surface_reason(status: str) -> str:
    if status == "clean":
        return "workload surface batch has no failed workload rows"
    if status == "split-pre-tcp-and-packet-terminal":
        return (
            "failed workload rows split into DNS/pre-TCP and packet-terminal surfaces; "
            "treat them as separate runtime-shape questions before policy"
        )
    if status == "pre-tcp-workload-surface":
        return "failed workload rows happen before a TCP/runtime session can be attributed"
    if status == "packet-terminal-workload-surface":
        return "failed workload rows have packet-terminal evidence before runtime session promotion"
    if status == "mixed-runtime-workload-surface":
        return (
            "failed rows are all route/TUN/runtime-packet witnessed; split runtime-stage, "
            "packet-terminal, and post-session protocol surfaces before policy"
        )
    return "failed workload rows require mechanism-specific isolation before planner or quality policy"


def workload_surface_mechanism_conclusions(totals: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for item in totals.get("failedByMechanism") or []:
        mechanism = str(item.get("key") or "unknown")
        rows.append(
            {
                "mechanism": mechanism,
                "count": int_value(item.get("count")),
                "category": mechanism_category(mechanism),
                "nextAction": mechanism_next_action(mechanism, totals),
                "reason": mechanism_reason(mechanism),
                "plannerPenaltySafe": False,
                "qualityPenaltySafe": False,
                "context": mechanism_context(mechanism, totals),
                "surfaces": mechanism_rows(
                    totals.get("failedByMechanismSurface") or [],
                    mechanism,
                    ["failureSurface"],
                ),
                "stages": mechanism_rows(
                    totals.get("failedByMechanismStage") or [],
                    mechanism,
                    ["errorStage", "errorType"],
                ),
            }
        )
    return rows


def mechanism_category(mechanism: str) -> str:
    return {
        "pre-tcp-workload-failure": "pre-tcp",
        "packet-terminal-before-runtime-session": "packet-terminal",
        "failed-workload-with-runtime-stage-failure": "runtime-stage",
        "failed-workload-with-runtime-flow-failure": "runtime-flow",
        "workload-protocol-after-runtime-session": "post-session-protocol",
        "runtime-packet-without-session": "runtime-packet",
        "tun-capture-without-runtime-packet": "tun-capture",
        "workload-connected-without-runtime-evidence": "runtime-attribution-gap",
    }.get(mechanism, "unknown")


def mechanism_next_action(mechanism: str, totals: dict[str, Any]) -> str:
    if (
        mechanism == "packet-terminal-before-runtime-session"
        and int_value(totals.get("packetTerminalWithIngressPayload")) > 0
    ):
        return "inspect-preflow-promotion-after-client-payload"
    return {
        "pre-tcp-workload-failure": "isolate-dns-preflow-workload-timeout",
        "packet-terminal-before-runtime-session": "harden-preflow-terminal-to-runtime-session-promotion",
        "failed-workload-with-runtime-stage-failure": "inspect-runtime-stage-failure-and-cascade-context",
        "failed-workload-with-runtime-flow-failure": "inspect-runtime-flow-failure",
        "workload-protocol-after-runtime-session": "classify-post-session-workload-protocol",
        "runtime-packet-without-session": "inspect-runtime-packet-session-promotion",
        "tun-capture-without-runtime-packet": "inspect-tun-to-runtime-packet-correlation",
        "workload-connected-without-runtime-evidence": "inspect-runtime-attribution-gap",
    }.get(mechanism, "classify-workload-surface")


def mechanism_context(mechanism: str, totals: dict[str, Any]) -> dict[str, Any]:
    if mechanism == "packet-terminal-before-runtime-session":
        return {
            "withIngressPayload": int_value(totals.get("packetTerminalWithIngressPayload")),
            "ingressPayloadBytes": int_value(totals.get("packetTerminalIngressPayloadBytes")),
            "egressPayloadBytes": int_value(totals.get("packetTerminalEgressPayloadBytes")),
            "closeSignals": list(totals.get("packetTerminalByCloseSignal") or []),
            "preflowCandidates": int_value(totals.get("packetTerminalPreflowCandidates")),
            "preflowCandidateByReason": list(
                totals.get("packetTerminalPreflowCandidateByReason") or []
            ),
            "preflowMissed": int_value(totals.get("packetTerminalPreflowMissed")),
            "preflowMissedByReason": list(totals.get("packetTerminalPreflowMissedByReason") or []),
            "preflowMissedBySocketState": list(
                totals.get("packetTerminalPreflowMissedBySocketState") or []
            ),
        }
    if mechanism == "failed-workload-with-runtime-stage-failure":
        return {
            "cascadeFailedAttempts": int_value(totals.get("cascadeFailedAttempts")),
            "cascadeRecoveredFlows": int_value(totals.get("cascadeRecoveredFlows")),
            "cascadeStoppedFlows": int_value(totals.get("cascadeStoppedFlows")),
            "cascadeStoppedBoundExhaustedFlows": int_value(
                totals.get("cascadeStoppedBoundExhaustedFlows")
            ),
            "cascadeFailedByStageSurface": list(totals.get("cascadeFailedByStageSurface") or []),
            "cascadeFailedByStopReason": list(totals.get("cascadeFailedByStopReason") or []),
            "failedRowsWithCascadeStoppedFlow": int_value(
                totals.get("failedRowsWithCascadeStoppedFlow")
            ),
            "cascadeStoppedFlowCandidateExhaustedFailures": int_value(
                totals.get("cascadeStoppedFlowCandidateExhaustedFailures")
            ),
            "failedByCascadeStoppedFlowStopReason": list(
                totals.get("failedByCascadeStoppedFlowStopReason") or []
            ),
            "failedByCascadeStoppedFlowStageSurface": list(
                totals.get("failedByCascadeStoppedFlowStageSurface") or []
            ),
        }
    if mechanism == "pre-tcp-workload-failure":
        return {"runtimeDnsFailures": int_value(totals.get("runtimeDnsFailures"))}
    return {}


def mechanism_reason(mechanism: str) -> str:
    return {
        "pre-tcp-workload-failure": "failure occurs before a TCP/runtime packet path can be attributed",
        "packet-terminal-before-runtime-session": "runtime packet evidence exists but session promotion did not happen",
        "failed-workload-with-runtime-stage-failure": "workload failure joins to a runtime stage failure",
        "failed-workload-with-runtime-flow-failure": "workload failure joins to a terminal runtime flow failure",
        "workload-protocol-after-runtime-session": "runtime session exists and workload fails at client protocol stage",
        "runtime-packet-without-session": "runtime packet evidence exists without a promoted session",
        "tun-capture-without-runtime-packet": "TUN capture exists but dynet runtime packet evidence is missing",
        "workload-connected-without-runtime-evidence": "client connected but dynet runtime attribution is missing",
    }.get(mechanism, "mechanism needs classification before policy")


def mechanism_rows(
    rows: list[dict[str, Any]],
    mechanism: str,
    fields: list[str],
) -> list[dict[str, Any]]:
    selected = []
    for row in rows:
        if row.get("mechanism") != mechanism:
            continue
        selected.append(
            {**{field: row.get(field) for field in fields}, "count": int_value(row.get("count"))}
        )
    return selected


def int_value(value: Any) -> int:
    if value is None:
        return 0
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
