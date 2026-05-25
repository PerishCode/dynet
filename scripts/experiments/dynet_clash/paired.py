#!/usr/bin/env python3
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import time
from pathlib import Path
from typing import Any

from scripts.cli import dynet_probe_manifest as dynet_manifest
from dynet_clash import paired_retry
from dynet_probe.reports import write_summary as write_dynet_summary
from real_access.aggregate import summarize_run
from real_access.common import load_json, utc_now, write_json
from real_access.controller import add_controller_args, sampler_from_args
from real_access.reports import write_report
from real_access.runner import run_probe as run_clash_probe
from real_access.runner import scheduler_summary as clash_scheduler_summary


DEFAULT_OUTPUT_DIR = ".task/resources/dynet-clash-paired/latest"
DEFAULT_PROBES = {"tls-handshake", "https-head"}
SOURCE_PROTOCOL = dynet_manifest.SOURCE_PROTOCOL


def selected_entries(args: argparse.Namespace) -> list[dict[str, Any]]:
    manifest = load_json(Path(args.manifest))
    entries = manifest.get("entries", [])
    probes = set(args.probe_type or DEFAULT_PROBES)
    rows = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if entry.get("probe") not in probes:
            continue
        if args.bucket and entry.get("bucket") not in args.bucket:
            continue
        if args.domain and entry.get("domain") not in args.domain:
            continue
        if args.behavior and entry.get("behavior") not in args.behavior:
            continue
        if int(entry.get("port") or 443) != 443:
            continue
        rows.append(entry)
        if args.limit and len(rows) >= args.limit:
            break
    return sorted(rows, key=scheduled_offset_ms)


def scheduled_offset_ms(entry: dict[str, Any]) -> int:
    return int(entry.get("scheduledOffsetMs") or 0)


def schedule_base_offset(entries: list[dict[str, Any]]) -> int:
    return scheduled_offset_ms(entries[0]) if entries else 0


def replay_target_ms(
    args: argparse.Namespace,
    entry: dict[str, Any],
    base_offset_ms: int,
) -> int:
    if not args.respect_schedule:
        return 0
    delta = max(0, scheduled_offset_ms(entry) - base_offset_ms)
    return round(delta * args.schedule_scale)


def sleep_until(target_ms: int, started_monotonic: float) -> None:
    elapsed_ms = monotonic_offset_ms(started_monotonic)
    sleep_ms = target_ms - elapsed_ms
    if sleep_ms > 0:
        time.sleep(sleep_ms / 1000)


def monotonic_offset_ms(started_monotonic: float) -> int:
    return round((time.monotonic() - started_monotonic) * 1000)


def pair_order(mode: str, index: int) -> list[str]:
    if mode == "clash-first":
        return ["clash", "dynet"]
    if mode == "dynet-first":
        return ["dynet", "clash"]
    return ["clash", "dynet"] if index % 2 == 0 else ["dynet", "clash"]


def command_run(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir)
    clash_dir = output_dir / "clash"
    dynet_dir = output_dir / "dynet"
    clash_dir.mkdir(parents=True, exist_ok=True)
    dynet_dir.mkdir(parents=True, exist_ok=True)
    manifest = load_json(Path(args.manifest))
    entries = selected_entries(args)
    write_json(output_dir / "manifest.json", {**manifest, "entries": entries})
    started_at = utc_now()
    started = time.monotonic()
    base_offset = schedule_base_offset(entries)
    sampler = sampler_from_args(args)
    pairs = run_pairs(args, entries, started, base_offset, sampler, dynet_dir)
    clash_results = [pair["clash"] for pair in pairs]
    dynet_items = [pair["dynet"] for pair in pairs]
    ended_at = utc_now()
    pair_summary = summarize_pairs(pairs, args)
    write_json(output_dir / "pairs.json", pair_summary)
    clash_summary = summarize_run(
        {**manifest, "entries": entries, "environment": args.clash_environment},
        clash_results,
        started_at,
        ended_at,
    )
    clash_summary["scheduler"] = clash_scheduler_summary(clash_results, args)
    clash_summary["pairedReplay"] = pair_brief(pair_summary)
    write_json(clash_dir / "summary.json", clash_summary)
    write_report(clash_dir / "report.md", clash_summary)
    dynet_summary = write_dynet_summary(dynet_dir, dynet_items, args)
    dynet_summary["pairedReplay"] = pair_brief(pair_summary)
    write_json(dynet_dir / "summary.json", dynet_summary)
    print(json.dumps({
        "outputDir": str(output_dir),
        "clashPassed": clash_summary["totals"]["success"],
        "dynetPassed": dynet_summary["totals"]["passed"],
        "count": len(entries),
    }, sort_keys=True))
    return 0


def run_pairs(
    args: argparse.Namespace,
    entries: list[dict[str, Any]],
    started: float,
    base_offset: int,
    sampler: Any,
    dynet_dir: Path,
) -> list[dict[str, Any]]:
    if args.pair_scheduler == "open-loop" and args.respect_schedule:
        pairs = run_pairs_open_loop(args, entries, started, base_offset, sampler, dynet_dir)
    else:
        pairs = run_pairs_sequential(args, entries, started, base_offset, sampler, dynet_dir)
    return sorted(pairs, key=lambda pair: str(pair.get("id")))


def run_pairs_sequential(
    args: argparse.Namespace,
    entries: list[dict[str, Any]],
    started: float,
    base_offset: int,
    sampler: Any,
    dynet_dir: Path,
) -> list[dict[str, Any]]:
    pairs = []
    for index, entry in enumerate(entries):
        target_ms = replay_target_ms(args, entry, base_offset)
        sleep_until(target_ms, started)
        pairs.append(run_pair(args, entry, index, target_ms, started, sampler, dynet_dir))
        if not args.respect_schedule and args.spacing_ms > 0:
            time.sleep(args.spacing_ms / 1000)
    return pairs


def run_pairs_open_loop(
    args: argparse.Namespace,
    entries: list[dict[str, Any]],
    started: float,
    base_offset: int,
    sampler: Any,
    dynet_dir: Path,
) -> list[dict[str, Any]]:
    pairs = []
    with ThreadPoolExecutor(max_workers=max(args.max_concurrency, 1)) as executor:
        futures = []
        for index, entry in enumerate(entries):
            target_ms = replay_target_ms(args, entry, base_offset)
            sleep_until(target_ms, started)
            futures.append(
                executor.submit(
                    run_pair,
                    args,
                    entry,
                    index,
                    target_ms,
                    started,
                    sampler,
                    dynet_dir,
                )
            )
        for future in as_completed(futures):
            pairs.append(future.result())
    return pairs


def run_pair(
    args: argparse.Namespace,
    entry: dict[str, Any],
    index: int,
    target_ms: int,
    started: float,
    sampler: Any,
    dynet_dir: Path,
) -> dict[str, Any]:
    side_results: dict[str, Any] = {}
    starts: dict[str, int] = {}
    pair_started_ms = monotonic_offset_ms(started)
    pair_lag_ms = max(0, pair_started_ms - target_ms) if args.respect_schedule else None
    sides = pair_order(args.side_order, index)
    if args.side_mode == "parallel":
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = {
                executor.submit(
                    run_side_with_stagger,
                    args,
                    entry,
                    side,
                    side_stagger_ms(args, side, sides),
                    pair_lag_ms,
                    started,
                    sampler,
                    dynet_dir,
                ): side
                for side in sides
            }
            for future in as_completed(futures):
                side = futures[future]
                starts[side], side_results[side] = future.result()
    else:
        for side in sides:
            starts[side], side_results[side] = run_side(
                args,
                entry,
                side,
                pair_lag_ms,
                started,
                sampler,
                dynet_dir,
            )
    return {
        "id": entry.get("id"),
        "bucket": entry.get("bucket"),
        "domain": entry.get("domain"),
        "probe": entry.get("probe"),
        "targetStartOffsetMs": target_ms if args.respect_schedule else None,
        "pairStartedOffsetMs": pair_started_ms if args.respect_schedule else None,
        "pairLagMs": pair_lag_ms,
        "sideMode": args.side_mode,
        "sideOrder": sides,
        "parallelSideStaggerMs": parallel_side_stagger_ms(args),
        "pairGapMs": abs(starts.get("clash", 0) - starts.get("dynet", 0)),
        "clash": side_results["clash"],
        "dynet": side_results["dynet"],
    }


def run_side_with_stagger(
    args: argparse.Namespace,
    entry: dict[str, Any],
    side: str,
    stagger_ms: int,
    pair_lag_ms: int | None,
    started: float,
    sampler: Any,
    dynet_dir: Path,
) -> tuple[int, dict[str, Any]]:
    if stagger_ms > 0:
        time.sleep(stagger_ms / 1000)
    return run_side(args, entry, side, pair_lag_ms, started, sampler, dynet_dir)


def side_stagger_ms(args: argparse.Namespace, side: str, sides: list[str]) -> int:
    if args.side_mode != "parallel":
        return 0
    if not sides or side == sides[0]:
        return 0
    return parallel_side_stagger_ms(args)


def parallel_side_stagger_ms(args: argparse.Namespace) -> int:
    return max(0, int(getattr(args, "parallel_side_stagger_ms", 0) or 0))


def run_side(
    args: argparse.Namespace,
    entry: dict[str, Any],
    side: str,
    pair_lag_ms: int | None,
    started: float,
    sampler: Any,
    dynet_dir: Path,
) -> tuple[int, dict[str, Any]]:
    actual_ms = monotonic_offset_ms(started)
    if side == "clash":
        return actual_ms, run_clash_probe(
            entry,
            args.timeout_seconds,
            pair_lag_ms,
            sampler,
            actual_ms,
    )
    side_target_ms = actual_ms - int(pair_lag_ms or 0)
    return actual_ms, paired_retry.run(
        args,
        entry,
        dynet_dir,
        started,
        actual_start_offset_ms=actual_ms,
        target_start_offset_ms=side_target_ms if args.respect_schedule else None,
    )


def summarize_pairs(pairs: list[dict[str, Any]], args: argparse.Namespace) -> dict[str, Any]:
    gaps = [int(pair.get("pairGapMs", 0)) for pair in pairs]
    lags = [
        int(pair["pairLagMs"])
        for pair in pairs
        if isinstance(pair.get("pairLagMs"), int)
    ]
    return {
        "schema": "dynet-clash-paired-run/v1alpha1",
        "mode": args.replay_mode,
        "pairScheduler": args.pair_scheduler,
        "sideMode": args.side_mode,
        "maxConcurrency": args.max_concurrency if args.pair_scheduler == "open-loop" else 1,
        "sideOrder": args.side_order,
        "parallelSideStaggerMs": parallel_side_stagger_ms(args),
        "dynetRetry": paired_retry.totals(pairs, args),
        "dynetReadPolicy": read_policy_from_args(args),
        "count": len(pairs),
        "controllerAttribution": {
            "enabled": bool(
                getattr(args, "clash_controller_unix_socket", None)
                or getattr(args, "clash_controller_url", None)
            ),
            "isolation": "per-clash-probe-domain-filter",
            "overlapRisk": bool(
                (args.pair_scheduler == "open-loop" and args.max_concurrency > 1)
                or args.side_mode == "parallel"
            ),
        },
        "pairLagMs": {
            "max": max(lags) if lags else None,
            "p50": percentile(lags, 50),
            "p95": percentile(lags, 95),
        },
        "pairGapMs": {
            "max": max(gaps) if gaps else None,
            "p50": percentile(gaps, 50),
            "p95": percentile(gaps, 95),
        },
        "items": [
            {
                "id": pair.get("id"),
                "bucket": pair.get("bucket"),
                "domain": pair.get("domain"),
                "probe": pair.get("probe"),
                "targetStartOffsetMs": pair.get("targetStartOffsetMs"),
                "pairStartedOffsetMs": pair.get("pairStartedOffsetMs"),
                "pairLagMs": pair.get("pairLagMs"),
                "sideMode": pair.get("sideMode"),
                "sideOrder": pair.get("sideOrder"),
                "parallelSideStaggerMs": pair.get("parallelSideStaggerMs"),
                "pairGapMs": pair.get("pairGapMs"),
                "clashOk": bool(pair.get("clash", {}).get("ok")),
                "dynetStatus": pair.get("dynet", {}).get("status"),
                "dynetRetry": pair.get("dynet", {}).get("directTlsRetry"),
                "dynetReadPolicy": pair.get("dynet", {}).get("readPolicy"),
            }
            for pair in pairs
        ],
    }


def pair_brief(summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": summary.get("schema"),
        "mode": summary.get("mode"),
        "pairScheduler": summary.get("pairScheduler"),
        "sideMode": summary.get("sideMode"),
        "maxConcurrency": summary.get("maxConcurrency"),
        "sideOrder": summary.get("sideOrder"),
        "parallelSideStaggerMs": summary.get("parallelSideStaggerMs"),
        "dynetRetry": summary.get("dynetRetry", {}),
        "dynetReadPolicy": summary.get("dynetReadPolicy", {}),
        "count": summary.get("count"),
        "controllerAttribution": summary.get("controllerAttribution", {}),
        "pairLagMs": summary.get("pairLagMs", {}),
        "pairGapMs": summary.get("pairGapMs", {}),
    }


def read_policy_from_args(args: argparse.Namespace) -> dict[str, int]:
    policy = {}
    for attr, key, _flag in dynet_manifest.READ_POLICY_FLAGS:
        value = getattr(args, attr, None)
        if value is not None:
            policy[key] = int(value)
    return policy


def percentile(values: list[int], target: int) -> int | None:
    if not values:
        return None
    ordered = sorted(values)
    index = round((len(ordered) - 1) * (target / 100))
    return ordered[index]


def non_negative_float(value: str) -> float:
    number = float(value)
    if number < 0:
        raise argparse.ArgumentTypeError("must be non-negative")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run near-simultaneous paired Clash and dynet manifest probes."
    )
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--config", required=True)
    parser.add_argument("--dynet-bin", default="dynet")
    parser.add_argument("--sudo", action="store_true")
    parser.add_argument("--inbound")
    parser.add_argument("--quality-state")
    parser.add_argument("--dynet-direct-tls-retry-attempts", type=int, default=1)
    parser.add_argument("--dynet-direct-tls-retry-sleep-ms", type=int, default=250)
    parser.add_argument(
        "--probe-read-poll-timeout-ms",
        dest="read_poll_ms",
        type=dynet_manifest.positive_int,
    )
    parser.add_argument(
        "--probe-read-pending-budget-ms",
        dest="read_budget_ms",
        type=dynet_manifest.non_negative_int,
    )
    parser.add_argument(
        "--probe-read-pending-sleep-ms",
        dest="read_sleep_ms",
        type=dynet_manifest.non_negative_int,
    )
    parser.add_argument("--limit", type=int)
    parser.add_argument("--bucket", action="append")
    parser.add_argument("--domain", action="append")
    parser.add_argument("--behavior", action="append")
    parser.add_argument("--probe-type", action="append")
    parser.add_argument("--timeout-seconds", type=float, default=5)
    parser.add_argument("--spacing-ms", type=int, default=250)
    parser.add_argument("--lag-budget-ms", type=int, default=1000)
    parser.add_argument("--schedule-scale", type=non_negative_float, default=1.0)
    parser.add_argument("--max-concurrency", type=int, default=1)
    parser.add_argument(
        "--pair-scheduler",
        choices=["sequential", "open-loop"],
        default="sequential",
        help="sequential preserves strict pair isolation; open-loop schedules pairs concurrently for burst manifests",
    )
    parser.add_argument("--clash-environment", default="local-clash-paired")
    parser.add_argument("--replay-mode", default="paired-interleaved")
    parser.add_argument("--replay-schedule", action="store_true", default=True)
    parser.add_argument("--no-respect-schedule", action="store_false", dest="respect_schedule")
    parser.add_argument(
        "--side-order",
        choices=["alternate", "clash-first", "dynet-first"],
        default="alternate",
    )
    parser.add_argument(
        "--side-mode",
        choices=["sequential", "parallel"],
        default="sequential",
        help="parallel starts Clash and dynet sides together, but makes controller attribution observe-only",
    )
    parser.add_argument(
        "--parallel-side-stagger-ms",
        type=dynet_manifest.non_negative_int,
        default=0,
        help="delay the second side in side-order when side-mode is parallel",
    )
    parser.add_argument(
        "--dynet-protocol",
        choices=[SOURCE_PROTOCOL, "tcp-connect", "https-head", "tls-handshake"],
        default=SOURCE_PROTOCOL,
    )
    add_controller_args(parser)
    parser.set_defaults(respect_schedule=True)
    parser.set_defaults(handler=command_run)
    return parser


def command(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.handler(args)

def main() -> int:
    return command()


if __name__ == "__main__":
    raise SystemExit(main())
