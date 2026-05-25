from __future__ import annotations

import argparse
from typing import Any


PRODUCT_EFFECT = "product-effect"
ATTRIBUTION = "attribution"


def detail(scope: str, category: str, message: str) -> dict[str, str]:
    return {
        "scope": scope,
        "category": category,
        "message": message,
    }


def messages(details: list[dict[str, Any]]) -> list[str]:
    return [str(item.get("message", "")) for item in details]


def legacy_details(limits: list[str]) -> list[dict[str, str]]:
    return [
        detail(legacy_scope(message), legacy_category(message), message)
        for message in limits
    ]


def legacy_scope(message: str) -> str:
    category = legacy_category(message)
    if category == "controller":
        return ATTRIBUTION
    return PRODUCT_EFFECT


def legacy_category(message: str) -> str:
    lowered = message.lower()
    if "guardrail" in lowered:
        return "guardrail"
    if (
        "scheduler" in lowered
        or "schedule lag" in lowered
        or "open-loop" in lowered
        or "pair gap" in lowered
    ):
        return "scheduler"
    if (
        "controller" in lowered
        or "selected-chain" in lowered
        or "black-box" in lowered
    ):
        return "controller"
    if "tls-handshake" in lowered or "diagnostic" in lowered:
        return "protocol"
    if "runtime" in lowered or "workloadflow" in lowered:
        return "runtime"
    return "other"


def runtime_gate(
    gate: dict[str, Any] | None,
    args: argparse.Namespace,
) -> list[str]:
    return messages(runtime_gate_details(gate, args))


def runtime_gate_details(
    gate: dict[str, Any] | None,
    args: argparse.Namespace,
) -> list[dict[str, str]]:
    if gate is None:
        if getattr(args, "require_runtime_gate", False):
            return [
                detail(
                    PRODUCT_EFFECT,
                    "runtime",
                    "dynet runtime workloadFlow gate is required but no runtime summary was supplied",
                )
            ]
        return []
    if gate.get("clean"):
        return []
    failed = ", ".join(gate.get("failedChecks") or ["unknown"])
    classification = gate.get("classification") or "unknown"
    return [
        detail(
            PRODUCT_EFFECT,
            "runtime",
            f"dynet runtime workloadFlow gate failed ({classification}): {failed}",
        )
    ]


def paired_replay(summary: dict[str, Any], args: argparse.Namespace) -> list[str]:
    return messages(paired_replay_details(summary, args))


def paired_replay_details(
    summary: dict[str, Any],
    args: argparse.Namespace,
) -> list[dict[str, str]]:
    replay = summary.get("pairedReplay")
    if not isinstance(replay, dict):
        return []
    limits = []
    controller = replay.get("controllerAttribution", {})
    if isinstance(controller, dict) and controller.get("overlapRisk"):
        limits.append(
            detail(
                ATTRIBUTION,
                "controller",
                "paired replay used overlapping controller captures; selected-chain attribution is observe-only",
            )
        )
    p95 = replay.get("pairGapMs", {}).get("p95")
    if isinstance(p95, int) and p95 > args.max_pair_gap_ms:
        limits.append(
            detail(
                PRODUCT_EFFECT,
                "scheduler",
                "paired replay pair gap exceeded configured budget",
            )
        )
    return limits
