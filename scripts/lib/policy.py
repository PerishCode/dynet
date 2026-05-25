from __future__ import annotations

from typing import Any


def planner_penalty_safe(summary: dict[str, Any]) -> bool:
    conclusion = summary.get("conclusion") or {}
    policy = summary.get("policy") or {}
    return (
        bool(summary.get("plannerPenaltySafe"))
        or bool(conclusion.get("plannerPenaltySafe"))
        or bool(policy.get("plannerPenaltySafe"))
    )


def quality_penalty_safe(summary: dict[str, Any]) -> bool:
    conclusion = summary.get("conclusion") or {}
    policy = summary.get("policy") or {}
    return (
        bool(summary.get("qualityPenaltySafe"))
        or bool(conclusion.get("qualityPenaltySafe"))
        or bool(policy.get("qualityPenaltySafe"))
    )


def penalty_flags(summary: dict[str, Any]) -> dict[str, bool]:
    return {
        "plannerPenaltySafe": planner_penalty_safe(summary),
        "qualityPenaltySafe": quality_penalty_safe(summary),
    }
