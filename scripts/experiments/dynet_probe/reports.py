from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


SUMMARY_SCHEMA = "dynet-probe-manifest-run/v1alpha1"


def write_summary(
    output_dir: Path,
    items: list[dict[str, Any]],
    args: argparse.Namespace,
    quality_pipeline: dict[str, Any] | None = None,
) -> dict[str, Any]:
    summary = {
        "schema": SUMMARY_SCHEMA,
        "privacy": {
            "identityInformationSent": False,
            "cookiesSent": False,
            "authorizationSent": False,
            "responseBodiesStored": False,
        },
        "replay": {
            "schedule": bool(args.replay_schedule),
            "scheduleScale": args.schedule_scale,
        },
        "probePolicy": probe_policy(args),
        "scheduler": scheduler_summary(items, args),
        "totals": {
            "attempted": len(items),
            "passed": sum(1 for item in items if item["status"] == "pass"),
            "failed": sum(1 for item in items if item["status"] != "pass"),
        },
        "byBucket": aggregate(items, "bucket"),
        "byBehavior": aggregate(items, "behavior"),
        "bySourceProbe": aggregate(items, "sourceProbe"),
        "bySelectedOutbound": aggregate(items, "selectedOutbound"),
        "items": items,
    }
    if quality_pipeline:
        summary["qualityPipeline"] = quality_pipeline
    write_json(output_dir / "summary.json", summary)
    write_markdown(output_dir / "summary.md", summary)
    return summary


def aggregate(items: list[dict[str, Any]], field: str) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for item in items:
        key = str(item.get(field) or "unknown")
        grouped.setdefault(key, []).append(item)
    output = []
    for key, rows in sorted(grouped.items()):
        attempted = len(rows)
        passed = sum(1 for row in rows if row["status"] == "pass")
        output.append(
            {
                "key": key,
                "attempted": attempted,
                "passed": passed,
                "failed": attempted - passed,
                "successRate": round(passed / attempted, 4) if attempted else 0,
            }
        )
    return output


def write_markdown(path: Path, summary: dict[str, Any]) -> None:
    scheduler = summary.get("scheduler", {})
    lag = scheduler.get("lagMs", {})
    lines = [
        "# Dynet Probe Manifest Run",
        "",
        f"- attempted: `{summary['totals']['attempted']}`",
        f"- passed: `{summary['totals']['passed']}`",
        f"- failed: `{summary['totals']['failed']}`",
        f"- replay mode: `{scheduler.get('mode')}`",
        f"- max concurrency: `{scheduler.get('maxConcurrency')}`",
        f"- lag budget: `{scheduler.get('lagBudgetMs')}` ms",
        f"- lag exceeded: `{scheduler.get('lagExceeded')}`",
        f"- schedule lag p95: `{lag.get('p95')}` ms",
    ]
    append_probe_policy(lines, summary)
    append_quality_pipeline(lines, summary)
    lines.extend(["", "## By Behavior", ""])
    for item in summary["byBehavior"]:
        lines.append(
            f"- `{item['key']}` passed={item['passed']}/{item['attempted']} "
            f"rate={item['successRate']}"
        )
    lines.extend(["", "## By Source Probe", ""])
    for item in summary["bySourceProbe"]:
        lines.append(
            f"- `{item['key']}` passed={item['passed']}/{item['attempted']} "
            f"rate={item['successRate']}"
        )
    lines.extend(["", "## By Selected Outbound", ""])
    for item in summary["bySelectedOutbound"]:
        lines.append(
            f"- `{item['key']}` passed={item['passed']}/{item['attempted']} "
            f"rate={item['successRate']}"
        )
    lines.extend(["", "## Items", ""])
    for item in summary["items"]:
        lines.append(
            f"- `{item['id']}` {item['domain']} status=`{item['status']}` "
            f"behavior=`{item['behavior']}` sourceProbe=`{item['sourceProbe']}` "
            f"dynetProtocol=`{item['dynetProtocol']}` "
            f"outbound=`{item['selectedOutbound']}` "
            f"scheduledOffsetMs=`{item['scheduledOffsetMs']}` "
            f"targetStartOffsetMs=`{item['targetStartOffsetMs']}` "
            f"actualStartOffsetMs=`{item['actualStartOffsetMs']}` "
            f"failedStage=`{item['failedStage']}`"
        )
    path.write_text("\n".join(lines) + "\n")


def append_quality_pipeline(lines: list[str], summary: dict[str, Any]) -> None:
    pipeline = summary.get("qualityPipeline")
    if not isinstance(pipeline, dict):
        return
    lines.extend([
        f"- quality pipeline: `{pipeline.get('status')}`",
        f"- quality state: `{pipeline.get('qualityState')}`",
        f"- previous quality states: `{pipeline.get('previousQualityStates')}`",
        f"- previous attributions: `{pipeline.get('previousAttributions')}`",
    ])


def append_probe_policy(lines: list[str], summary: dict[str, Any]) -> None:
    policy = summary.get("probePolicy")
    if not isinstance(policy, dict):
        return
    lines.extend([
        f"- dynet protocol: `{policy.get('dynetProtocol')}`",
        f"- retry direct TLS EOF attempts: `{policy.get('retryDirectTlsEofAttempts')}`",
    ])
    read_policy = policy.get("readPolicy")
    if isinstance(read_policy, dict):
        lines.append(
            "- read policy: "
            f"pollTimeoutMs=`{read_policy.get('pollTimeoutMs')}` "
            f"pendingBudgetMs=`{read_policy.get('pendingBudgetMs')}` "
            f"pendingSleepMs=`{read_policy.get('pendingSleepMs')}`"
        )


def scheduler_summary(items: list[dict[str, Any]], args: argparse.Namespace) -> dict[str, Any]:
    lags = []
    for item in items:
        scheduled = item.get("targetStartOffsetMs")
        actual = item.get("actualStartOffsetMs")
        if isinstance(scheduled, int) and isinstance(actual, int):
            lags.append(max(0, actual - scheduled))
    p95 = percentile(lags, 95)
    return {
        "mode": args.replay_mode if args.replay_schedule else "sequential",
        "maxConcurrency": args.max_concurrency if args.replay_schedule else 1,
        "lagBudgetMs": args.lag_budget_ms,
        "lagExceeded": bool(p95 is not None and p95 > args.lag_budget_ms),
        "lagMs": {
            "p50": percentile(lags, 50),
            "p95": p95,
            "max": max(lags) if lags else None,
        },
    }


def probe_policy(args: argparse.Namespace) -> dict[str, Any]:
    read_policy = {}
    for attr, key in [
        ("read_poll_ms", "pollTimeoutMs"),
        ("read_budget_ms", "pendingBudgetMs"),
        ("read_sleep_ms", "pendingSleepMs"),
    ]:
        value = getattr(args, attr, None)
        if value is not None:
            read_policy[key] = int(value)
    return {
        "dynetProtocol": getattr(args, "dynet_protocol", None),
        "retryDirectTlsEofAttempts": int(
            getattr(args, "retry_direct_tls_eof_attempts", 1)
        ),
        "retryDirectTlsEofSleepMs": int(
            getattr(args, "retry_direct_tls_eof_sleep_ms", 250)
        ),
        "readPolicy": read_policy or None,
    }


def percentile(values: list[int], target: int) -> int | None:
    if not values:
        return None
    ordered = sorted(values)
    index = round((len(ordered) - 1) * (target / 100))
    return ordered[index]


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True))
