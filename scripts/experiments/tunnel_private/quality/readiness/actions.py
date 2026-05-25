from __future__ import annotations

from typing import Any


def next_actions(
    *,
    status: str,
    not_ready_reasons: list[str],
    product_evidence: bool,
    product_clean: bool,
    runtime_blocked: bool,
    strict_control_open: bool,
    transport_blocked: bool,
    transport: dict[str, Any],
    protocol: dict[str, Any],
) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    if not product_evidence:
        actions.append(action(
            "collect-product-e2e-evidence",
            "product-e2e",
            "required",
            "Adapter claims require sanitized product e2e evidence.",
        ))
    elif not product_clean:
        actions.append(action(
            "fix-product-e2e-gate",
            "product-e2e",
            "required",
            "Existing product evidence has failed required gates.",
        ))
    if transport_blocked:
        actions.append(action(
            "collect-sanitized-product-e2e-pass",
            "transport",
            "required",
            "Transport evidence is blocked until product e2e passes.",
        ))
    elif transport["sourceCount"] and not transport["productE2ePass"]:
        actions.append(action(
            str(transport["nextProof"]),
            "transport",
            "follow-up",
            "Transport evidence is diagnostic until product e2e is present.",
        ))
    if runtime_blocked:
        actions.append(action(
            "collect-clean-runtime-repeat",
            "runtime",
            "required",
            "Runtime repeat evidence exists but is not clean.",
        ))
    if strict_control_open:
        actions.append(action(
            "collect-direct-control-follow-up",
            "direct-control",
            "required",
            "Product evidence is clean but direct control evidence is not clean.",
        ))
    if protocol["open"]:
        actions.append(action(
            str(protocol["nextProof"]),
            "protocol",
            "follow-up",
            "Protocol/read markers need stage-repeat evidence before adapter claims.",
        ))
    if status == "ready":
        actions.append(action(
            "start-mainline-adapter-runtime-work",
            "runtime",
            "allowed",
            "Readiness gates allow this adapter as a mainline runtime work slice.",
        ))
    if not actions:
        actions.append(action(
            "collect-product-e2e-evidence",
            "product-e2e",
            "required",
            "No actionable evidence was provided.",
        ))
    return [with_policy(item, not_ready_reasons) for item in actions]


def action(action_id: str, evidence: str, priority: str, reason: str) -> dict[str, Any]:
    return {
        "id": action_id,
        "evidence": evidence,
        "priority": priority,
        "reason": reason,
    }


def with_policy(item: dict[str, Any], reasons: list[str]) -> dict[str, Any]:
    return {
        **item,
        "notReadyReasons": reasons if item["priority"] == "required" else [],
        "plannerPenaltySafe": False,
    }
