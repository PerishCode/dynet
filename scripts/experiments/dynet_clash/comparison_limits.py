from __future__ import annotations

import argparse
from typing import Any

from dynet_clash import limits as limit_model


def build(
    clash: dict[str, Any],
    dynet: dict[str, Any],
    args: argparse.Namespace,
    runtime: dict[str, Any] | None,
    controller: dict[str, Any],
    clash_buckets: dict[str, dict[str, Any]],
    dynet_buckets: dict[str, dict[str, Any]],
) -> list[dict[str, str]]:
    limits = controller_limits(controller)
    limits.extend(guardrail_limits("Clash", clash_buckets, args))
    limits.extend(guardrail_limits("dynet", dynet_buckets, args))
    limits.extend(schedule_limits("Clash", clash))
    limits.extend(schedule_limits("dynet", dynet))
    limits.extend(limit_model.paired_replay_details(clash, args))
    if not dynet.get("replay", {}).get("schedule"):
        limits.insert(0, protocol_limit(
            "dynet probe manifest is diagnostic and does not replay the original schedule"
        ))
    limits.extend(limit_model.runtime_gate_details(runtime, args))
    if tls_probe_mismatches(dynet):
        limits.insert(1, protocol_limit(
            "some dynet tls-handshake source probes were not replayed as TLS-only probes"
        ))
    return limits


def controller_limits(controller: dict[str, Any]) -> list[dict[str, str]]:
    if not controller["enabled"]:
        return [
            attribution_limit(
                "black-box Clash summary lacks selected-node and candidate-plan evidence"
            )
        ]
    if controller.get("missing"):
        return [
            attribution_limit(
                "some Clash probes lack controller selected-chain observations"
            )
        ]
    return []


def guardrail_limits(
    name: str,
    buckets: dict[str, dict[str, Any]],
    args: argparse.Namespace,
) -> list[dict[str, str]]:
    limits = []
    for key in args.guardrail_bucket or []:
        item = buckets.get(key)
        if item and item["successRate"] < args.min_guardrail_rate:
            limits.append(limit_model.detail(
                limit_model.PRODUCT_EFFECT,
                "guardrail",
                f"{name} guardrail bucket `{key}` is below clean baseline threshold",
            ))
    return limits


def schedule_limits(name: str, summary: dict[str, Any]) -> list[dict[str, str]]:
    scheduled = bool(
        summary.get("schedule", {}).get("scheduled")
        or summary.get("replay", {}).get("schedule")
        or summary.get("workload", {}).get("durationSeconds")
    )
    if not scheduled:
        return []
    scheduler = summary.get("scheduler")
    if not isinstance(scheduler, dict):
        return [scheduler_limit(f"{name} summary lacks replay scheduler metadata")]
    limits = []
    if scheduler.get("mode") not in {"open-loop", "paired-interleaved"}:
        limits.append(scheduler_limit(
            f"{name} replay did not use open-loop or paired scheduler"
        ))
    if scheduler.get("lagExceeded"):
        limits.append(scheduler_limit(f"{name} schedule lag exceeded configured budget"))
    return limits


def tls_probe_mismatches(dynet: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        item
        for item in dynet.get("items", [])
        if item.get("sourceProbe") == "tls-handshake"
        and item.get("dynetProtocol") != "tls-handshake"
    ]


def attribution_limit(message: str) -> dict[str, str]:
    return limit_model.detail(limit_model.ATTRIBUTION, "controller", message)


def protocol_limit(message: str) -> dict[str, str]:
    return limit_model.detail(limit_model.PRODUCT_EFFECT, "protocol", message)


def scheduler_limit(message: str) -> dict[str, str]:
    return limit_model.detail(limit_model.PRODUCT_EFFECT, "scheduler", message)
