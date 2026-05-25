from __future__ import annotations

from argparse import Namespace
from typing import Any


def comparison_status(
    primary_delta: float | None,
    guardrail_failures: list[dict[str, Any]],
    args: Namespace,
) -> str:
    primary_win = primary_delta is not None and primary_delta >= args.min_primary_delta
    primary_parity = primary_delta is not None and primary_delta >= args.min_parity_delta
    if primary_win and not guardrail_failures:
        return "dynet-superior-candidate"
    if primary_parity and not guardrail_failures:
        return "dynet-parity-candidate"
    if primary_win:
        return "github-superior-with-guardrail-regression"
    if primary_parity:
        return "dynet-parity-with-guardrail-regression"
    return "not-superior"


def required_primary_delta(args: Namespace) -> float:
    if args.objective == "parity":
        return args.min_aggregate_parity_delta
    return args.min_aggregate_primary_delta


def window_statuses(args: Namespace) -> set[str]:
    statuses = {"dynet-superior-candidate"}
    if args.objective == "parity":
        statuses.add("dynet-parity-candidate")
    return statuses


def below_status(args: Namespace) -> str:
    return "below-parity" if args.objective == "parity" else "not-superior"


def success_status(args: Namespace) -> str:
    repeated = args.min_windows > 1
    if args.objective == "parity":
        return "dynet-parity-repeated-candidate" if repeated else "dynet-parity-window-candidate"
    return "dynet-superior-repeated-candidate" if repeated else "dynet-superior-window-candidate"
