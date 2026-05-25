from __future__ import annotations

from private_runtime_lib.config import (
    POISON_DIALER_TAG,
)
from private_runtime_lib.tcp_flow import tcp_flow_brief

RELAXED_TCP_CHECKS = {
    "tcp-adapter-target-reported",
    "tcp-adapter-domain-target",
    "tcp-target-chain-complete",
    "tcp-target-chain-matched",
}


def direct_fallback_checks(report: dict) -> list[dict]:
    flow = tcp_flow_brief(report)
    selection = report.get("_selectionBrief", {})
    cascade = selection.get("cascadeAttempts", {}) if isinstance(selection, dict) else {}
    used = int(flow.get("routeFallbackUsedFlows") or 0)
    return [
        check(
            "route-direct-fallback-used",
            used > 0 and int(flow.get("routeFallbackAttemptEvents") or 0) >= 2 * used,
        ),
        check(
            "route-direct-fallback-final-direct",
            keyed_count(flow.get("routeFallbackByFinalOutbound"), "direct") > 0
            and int(flow.get("routeFallbackEstablishedFlows") or 0) > 0,
        ),
        check(
            "route-direct-fallback-bound-exhausted",
            int(cascade.get("stoppedBoundExhaustedFlows") or 0) > 0,
        ),
        check(
            "route-direct-fallback-no-final-failure",
            int(flow.get("routeFallbackFailedFlows") or 0) == 0,
        ),
    ]


def non_direct_fallback_checks(report: dict) -> list[dict]:
    flow = tcp_flow_brief(report)
    selection = report.get("_selectionBrief", {})
    cascade = selection.get("cascadeAttempts", {}) if isinstance(selection, dict) else {}
    used = int(flow.get("routeFallbackUsedFlows") or 0)
    attempted = flow.get("routeFallbackByAttemptedOutbound")
    final = flow.get("routeFallbackByFinalOutbound")
    return [
        check(
            "route-non-direct-fallback-used",
            used > 0 and int(flow.get("routeFallbackAttemptEvents") or 0) >= 2 * used,
        ),
        check(
            "route-non-direct-fallback-final-private",
            keyed_count(final, "private-via-tunnel") > 0
            and keyed_count(final, "direct") == 0
            and int(flow.get("routeFallbackEstablishedFlows") or 0) > 0,
        ),
        check(
            "route-non-direct-fallback-attempted-both",
            keyed_count(attempted, POISON_DIALER_TAG) > 0
            and keyed_count(attempted, "private-via-tunnel") > 0,
        ),
        check(
            "route-non-direct-fallback-bound-exhausted",
            int(cascade.get("stoppedBoundExhaustedFlows") or 0) > 0,
        ),
        check(
            "route-non-direct-fallback-no-final-failure",
            int(flow.get("routeFallbackFailedFlows") or 0) == 0,
        ),
    ]


def keyed_count(rows: object, key: str) -> int:
    if not isinstance(rows, list):
        return 0
    for row in rows:
        if isinstance(row, dict) and row.get("key") == key:
            return int(row.get("count") or 0)
    return 0


def check(name: str, passed: bool) -> dict:
    return {"name": name, "passed": bool(passed)}
