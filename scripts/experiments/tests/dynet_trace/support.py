from __future__ import annotations

import json


def product_effect_context() -> dict[str, object]:
    return {
        "schema": "dynet-tunnel-private-adapter-product-effect/v1alpha1",
        "status": "product-effect-parity-candidate",
        "conclusion": {
            "nextActions": [
                {
                    "id": "retain-recovered-stage-pressure-observe-only",
                    "evidence": "maturity",
                    "priority": "observe",
                    "plannerPenaltySafe": False,
                },
                {
                    "id": "keep-planner-penalties-disabled",
                    "evidence": "policy",
                    "priority": "required",
                    "plannerPenaltySafe": False,
                },
            ],
        },
    }


def write_product_effect_context(path) -> object:
    path.write_text(json.dumps(product_effect_context()))
    return path


def fallback_report() -> dict[str, object]:
    return {
        "schema": "dynet-runtime-report/v1alpha1",
        "status": "pass",
        "events": [
            cascade_start(1, "dns-query-1", "1", "pre-query", "tunnel-poison-001"),
            cascade_finish(2, "dns-query-1", "1", "tunnel-poison-001", "failed", "bound"),
            cascade_start(3, "dns-query-1", "2", "pre-query", "tunnel-001"),
            cascade_finish(4, "dns-query-1", "2", "tunnel-001", "success", "none"),
            cascade_start(5, "tcp-session-1", "1", "pre-payload", "tunnel-poison-001"),
            cascade_finish(6, "tcp-session-1", "1", "tunnel-poison-001", "failed", "bound"),
            cascade_start(7, "tcp-session-1", "2", "pre-payload", "tunnel-001"),
            cascade_finish(8, "tcp-session-1", "2", "tunnel-001", "success", "none"),
        ],
    }


def non_retry_report() -> dict[str, object]:
    return {
        "schema": "dynet-runtime-report/v1alpha1",
        "status": "deny",
        "events": [
            cascade_start(1, "tcp-session-1", "1", "pre-payload", "tunnel-001"),
            cascade_finish(2, "tcp-session-1", "1", "tunnel-001", "failed", "downstream"),
        ],
    }


def cascade_report(
    stages: list[dict[str, object]],
    failure_scope: str | None = None,
) -> dict[str, object]:
    finished_fields = {
        "attempt": "1",
        "boundSelected": "tunnel-001",
        "status": "failed",
        "error": "attempt failed",
    }
    if failure_scope:
        finished_fields["failureScope"] = failure_scope
    return {
        "schema": "dynet-probe/v1alpha1",
        "status": "deny",
        "target": {"host": "api.chatgpt.com"},
        "events": [
            {"kind": "outbound-attempt-finished", "fields": {"transport": "tcp"}},
            {
                "kind": "dialer-cascade-selected",
                "fields": {
                    "bound": "tunnel",
                    "boundSelected": "tunnel-001",
                    "dialer": "private-via-tunnel",
                    "private": "private",
                },
            },
            {
                "kind": "dialer-cascade-attempt-started",
                "sequence": 10,
                "fields": {"attempt": "1"},
            },
            *stages,
            {
                "kind": "dialer-cascade-attempt-finished",
                "sequence": 13,
                "fields": finished_fields,
            },
        ],
    }


def stage(
    sequence: int,
    outbound: str,
    name: str,
    status: str,
) -> dict[str, object]:
    return {
        "kind": "outbound-stage-finished",
        "sequence": sequence,
        "emittedAtUnixMs": 1000,
        "fields": {"outbound": outbound, "stage": name, "status": status},
    }


def cascade_start(
    sequence: int,
    flow_id: str,
    attempt: str,
    replay_safe: str,
    bound: str,
) -> dict[str, object]:
    return {
        "kind": "dialer-cascade-attempt-started",
        "sequence": sequence,
        "fields": {
            "flowId": flow_id,
            "attempt": attempt,
            "replaySafe": replay_safe,
            "dialer": "private-via-tunnel",
            "boundSelected": bound,
        },
    }


def cascade_finish(
    sequence: int,
    flow_id: str,
    attempt: str,
    bound: str,
    status: str,
    scope: str,
) -> dict[str, object]:
    fields = {
        "flowId": flow_id,
        "attempt": attempt,
        "dialer": "private-via-tunnel",
        "boundSelected": bound,
        "status": status,
        "failureScope": scope,
    }
    if status == "failed":
        fields["errorType"] = "refused"
    return {
        "kind": "dialer-cascade-attempt-finished",
        "sequence": sequence,
        "fields": fields,
    }
