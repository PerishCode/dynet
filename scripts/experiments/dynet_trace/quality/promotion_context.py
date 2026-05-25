from __future__ import annotations

from pathlib import Path
from typing import Any

from dynet_trace.common import load_json


ADAPTER_MATURITY_SCHEMA = "dynet-tunnel-private-adapter-maturity/v1alpha1"
ADAPTER_PRODUCT_EFFECT_SCHEMA = "dynet-tunnel-private-adapter-product-effect/v1alpha1"


def load_contexts(inputs: list[str]) -> list[dict[str, Any]]:
    contexts = []
    for raw in inputs:
        data = load_json(Path(raw))
        if not isinstance(data, dict):
            continue
        schema = data.get("schema")
        if schema not in {ADAPTER_MATURITY_SCHEMA, ADAPTER_PRODUCT_EFFECT_SCHEMA}:
            continue
        contexts.append({
            "path": str(Path(raw)),
            "schema": schema,
            "status": data.get("status"),
            "actions": context_actions(data),
        })
    return contexts


def observe_only_actions(contexts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return context_action_rows(contexts, "observe")


def policy_actions(contexts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return context_action_rows(contexts, "required")


def markdown_lines(promotion: dict[str, Any]) -> list[str]:
    if not promotion.get("observeOnlyActions") and not promotion.get("policyActions"):
        return []
    lines = ["", "## Promotion Context", ""]
    lines.extend(action_line(item, "observe") for item in promotion.get("observeOnlyActions", []))
    lines.extend(action_line(item, "required") for item in promotion.get("policyActions", []))
    return lines


def context_actions(context: dict[str, Any]) -> list[dict[str, Any]]:
    conclusion = context.get("conclusion")
    if not isinstance(conclusion, dict):
        return []
    return [
        action
        for action in conclusion.get("nextActions", [])
        if isinstance(action, dict) and action.get("id")
    ]


def context_action_rows(
    contexts: list[dict[str, Any]],
    priority: str,
) -> list[dict[str, Any]]:
    rows = []
    seen = set()
    for context in contexts:
        for action in context["actions"]:
            if action.get("priority") != priority:
                continue
            action_id = str(action.get("id"))
            key = (context["path"], action_id)
            if key in seen:
                continue
            seen.add(key)
            rows.append({
                "id": action_id,
                "evidence": action.get("evidence"),
                "plannerPenaltySafe": bool(action.get("plannerPenaltySafe")),
                "source": context["path"],
            })
    return rows


def action_line(item: dict[str, Any], priority: str) -> str:
    return (
        f"- `{item['id']}` priority=`{priority}` "
        f"evidence=`{item.get('evidence')}` "
        f"plannerPenaltySafe=`{item.get('plannerPenaltySafe')}`"
    )
