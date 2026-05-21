from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from real_access.common import (
    ATTRIBUTION_TRACE_FIELDS,
    RUN_SCHEMA,
    observer_model,
    percentile,
    privacy_model,
    top,
)


def summarize_run(
    manifest: dict[str, Any],
    results: list[dict[str, Any]],
    started: str,
    ended: str,
) -> dict[str, Any]:
    observer = results[0]["observer"] if results else observer_model(0)
    return {
        "schema": RUN_SCHEMA,
        "startedAt": started,
        "endedAt": ended,
        "environment": manifest["environment"],
        "seed": manifest["seed"],
        "manifestSchema": manifest["schema"],
        "observer": observer,
        "workload": manifest.get("workload", {}),
        "privacy": privacy_model(),
        "totals": aggregate(results),
        "byBucket": aggregate_groups(results, "bucket"),
        "byBehavior": aggregate_groups(results, "behavior"),
        "byProbe": aggregate_groups(results, "probe"),
        "byStage": aggregate_stage_groups(results),
        "byFaultSignal": aggregate_fault_signal_groups(results),
        "byDomain": aggregate_groups(results, "domain"),
        "schedule": schedule_summary(results),
        "errors": top(Counter(row["errorType"] for row in results if row["errorType"])),
        "failureClusters": failure_clusters(results),
        "latencyHotspots": latency_hotspots(results),
        "slowSamples": slow_samples(results),
        "attribution": run_attribution(results),
    }

def aggregate_groups(results: list[dict[str, Any]], field: str) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in results:
        grouped[str(row[field])].append(row)
    return [
        {"key": key, **aggregate(rows)}
        for key, rows in sorted(grouped.items(), key=lambda item: item[0])
    ]

def aggregate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(rows)
    successes = sum(1 for row in rows if row["ok"])
    failures = total - successes
    latencies = [row["elapsedMs"] for row in rows]
    output = {
        "count": total,
        "success": successes,
        "failure": failures,
        "successRate": round(successes / total, 4) if total else 0,
        "latencyMs": {
            "p50": percentile(latencies, 50),
            "p95": percentile(latencies, 95),
            "max": max(latencies) if latencies else None,
        },
    }
    errors = top(Counter(str(row["errorType"]) for row in rows if row.get("errorType")))
    if errors:
        output["errors"] = errors
    return output

def aggregate_stage_groups(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in results:
        for stage in row.get("stages", []):
            grouped[str(stage["name"])].append(stage)
    return [{"key": key, **aggregate(rows)} for key, rows in sorted(grouped.items())]

def aggregate_fault_signal_groups(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in results:
        key = row.get("targetPolicy", {}).get("faultSignal", "unknown")
        grouped[str(key)].append(row)
    return [{"key": key, **aggregate(rows)} for key, rows in sorted(grouped.items())]

def schedule_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    lags = [
        int(row["scheduleLagMs"])
        for row in results
        if isinstance(row.get("scheduleLagMs"), int)
    ]
    offsets = [
        int(row["scheduledOffsetMs"])
        for row in results
        if isinstance(row.get("scheduledOffsetMs"), int)
    ]
    return {
        "scheduled": bool(offsets),
        "lagMs": {
            "p50": percentile(lags, 50),
            "p95": percentile(lags, 95),
            "max": max(lags) if lags else None,
        },
        "offsetMs": {
            "first": min(offsets) if offsets else None,
            "last": max(offsets) if offsets else None,
        },
    }

def failure_clusters(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str, str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in results:
        if row.get("ok"):
            continue
        policy = row.get("targetPolicy", {})
        key = (
            str(row.get("bucket")),
            str(row.get("behavior")),
            str(row.get("domain")),
            str(row.get("probe")),
            str(row.get("errorStage")),
            str(row.get("errorType")),
            str(policy.get("faultSignal", "unknown")),
        )
        grouped[key].append(row)
    output = []
    for (
        bucket,
        behavior,
        domain,
        probe,
        error_stage,
        error_type,
        fault_signal,
    ), rows in sorted(grouped.items()):
        tags = sorted(
            {
                tag
                for row in rows
                for tag in row.get("targetPolicy", {}).get("tags", [])
                if isinstance(tag, str)
            }
        )
        output.append(
            {
                "bucket": bucket,
                "behavior": behavior,
                "domain": domain,
                "probe": probe,
                "errorStage": error_stage,
                "errorType": error_type,
                "faultSignal": fault_signal,
                "count": len(rows),
                "targetTags": tags,
                "canAttributePlanVsNode": False,
            }
        )
    return output

def latency_hotspots(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    rows.extend(hotspots_for_groups("bucket", aggregate_groups(results, "bucket")))
    rows.extend(hotspots_for_groups("behavior", aggregate_groups(results, "behavior")))
    rows.extend(hotspots_for_groups("probe", aggregate_groups(results, "probe")))
    rows.extend(hotspots_for_groups("stage", aggregate_stage_groups(results)))
    return rows

def slow_samples(results: list[dict[str, Any]], limit: int = 20) -> list[dict[str, Any]]:
    ordered = sorted(results, key=lambda row: int(row.get("elapsedMs", 0)), reverse=True)
    output = []
    for row in ordered[:limit]:
        output.append(
            {
                "id": row["id"],
                "bucket": row["bucket"],
                "behavior": row.get("behavior"),
                "groupId": row.get("groupId"),
                "domain": row["domain"],
                "probe": row["probe"],
                "scheduledOffsetMs": row.get("scheduledOffsetMs"),
                "scheduleLagMs": row.get("scheduleLagMs"),
                "ok": row["ok"],
                "elapsedMs": row["elapsedMs"],
                "faultSignal": row.get("targetPolicy", {}).get("faultSignal", "unknown"),
                "stageLatencyMs": {
                    stage["name"]: stage.get("elapsedMs")
                    for stage in row.get("stages", [])
                    if isinstance(stage, dict)
                },
                "errorStage": row.get("errorStage"),
                "errorType": row.get("errorType"),
                "canAttributePlanVsNode": False,
            }
        )
    return output

def hotspots_for_groups(kind: str, groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output = []
    for item in groups:
        p95 = item.get("latencyMs", {}).get("p95")
        if p95 is None:
            continue
        threshold = latency_threshold(kind, str(item["key"]))
        if p95 >= threshold:
            output.append(
                {
                    "kind": kind,
                    "key": item["key"],
                    "p95Ms": p95,
                    "thresholdMs": threshold,
                    "count": item["count"],
                    "successRate": item["successRate"],
                }
            )
    return output

def latency_threshold(kind: str, key: str) -> int:
    if kind == "stage" and key == "dns":
        return 200
    if kind == "stage" and key == "tcp-connect":
        return 500
    if kind == "stage" and key == "tls-handshake":
        return 1000
    if kind == "stage" and key in {"http-head", "http-get"}:
        return 1500
    if kind == "probe" and key in {"dns", "tcp-connect"}:
        return 500
    return 1500

def run_attribution(results: list[dict[str, Any]]) -> dict[str, Any]:
    failures = [row for row in results if not row.get("ok")]
    normal_failures = [
        row for row in failures if row.get("targetPolicy", {}).get("faultSignal") == "normal"
    ]
    weak_failures = [
        row for row in failures if row.get("targetPolicy", {}).get("faultSignal") == "weak"
    ]
    informational_failures = [
        row for row in failures if row.get("targetPolicy", {}).get("faultSignal") == "informational"
    ]
    if normal_failures:
        signal = "actionable-blackbox-failures"
    elif weak_failures:
        signal = "weak-blackbox-failures"
    elif informational_failures:
        signal = "informational-failures-only"
    else:
        signal = "no-failures"
    return {
        "blackboxOnlyCanAttributePlanVsNode": False,
        "failureSignal": signal,
        "failureCounts": {
            "normal": len(normal_failures),
            "weak": len(weak_failures),
            "informational": len(informational_failures),
        },
        "requiresDynetTraceFields": list(ATTRIBUTION_TRACE_FIELDS),
        "canBlamePlan": False,
        "canBlameNode": False,
        "reason": "black-box outcomes do not expose selected outbound, candidate set, cascade attempts, or gate verdicts",
    }
