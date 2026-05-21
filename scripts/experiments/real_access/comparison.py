from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from real_access.common import (
    ATTRIBUTION_TRACE_FIELDS,
    COMPARE_SCHEMA,
    load_json,
    privacy_model,
    top,
    utc_now,
)


def load_summary_spec(spec: str) -> dict[str, Any]:
    if "=" in spec:
        label, path_text = spec.split("=", 1)
    else:
        path_text = spec
        label = ""
    path = Path(path_text)
    summary = load_json(path)
    return {
        "label": label or summary.get("environment") or path.parent.name,
        "path": str(path),
        "summary": summary,
    }

def build_comparison(specs: list[str]) -> dict[str, Any]:
    runs = [load_summary_spec(spec) for spec in specs]
    if not runs:
        raise SystemExit("compare requires at least one run summary")
    baseline = runs[0]["summary"]["totals"]
    stable_failures = stable_failure_clusters(runs)
    changed_failures = changed_failure_clusters(runs)
    return {
        "schema": COMPARE_SCHEMA,
        "generatedAt": utc_now(),
        "privacy": privacy_model(),
        "baseline": runs[0]["label"],
        "runs": [compare_run(run, baseline) for run in runs],
        "byBucket": compare_group(runs, "byBucket"),
        "byBehavior": compare_group(runs, "byBehavior"),
        "byProbe": compare_group(runs, "byProbe"),
        "byStage": compare_group(runs, "byStage"),
        "byFaultSignal": compare_group(runs, "byFaultSignal"),
        "stableFailures": stable_failures,
        "changedFailures": changed_failures,
        "attribution": comparison_attribution(runs, stable_failures, changed_failures),
    }

def compare_run(run: dict[str, Any], baseline: dict[str, Any]) -> dict[str, Any]:
    summary = run["summary"]
    totals = summary["totals"]
    return {
        "label": run["label"],
        "path": run["path"],
        "environment": summary.get("environment"),
        "seed": summary.get("seed"),
        "count": totals["count"],
        "successRate": totals["successRate"],
        "successRateDelta": round(totals["successRate"] - baseline["successRate"], 4),
        "p50Ms": totals["latencyMs"]["p50"],
        "p95Ms": totals["latencyMs"]["p95"],
        "p95DeltaMs": delta(totals["latencyMs"]["p95"], baseline["latencyMs"]["p95"]),
        "errors": summary.get("errors", []),
    }

def compare_group(runs: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    group_keys = sorted(
        {
            item["key"]
            for run in runs
            for item in run["summary"].get(key, [])
        }
    )
    output = []
    for group_key in group_keys:
        row = {"key": group_key, "runs": []}
        baseline = group_item(runs[0]["summary"], key, group_key)
        for run in runs:
            item = group_item(run["summary"], key, group_key)
            if item is None:
                row["runs"].append({"label": run["label"], "count": 0})
                continue
            row["runs"].append(
                {
                    "label": run["label"],
                    "count": item["count"],
                    "successRate": item["successRate"],
                    "successRateDelta": group_delta(item, baseline, "successRate"),
                    "p95Ms": item["latencyMs"]["p95"],
                    "p95DeltaMs": group_latency_delta(item, baseline),
                }
            )
        output.append(row)
    return output

def stable_failure_clusters(runs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not runs:
        return []
    cluster_maps = [cluster_map(run) for run in runs]
    common_keys = set(cluster_maps[0])
    for mapping in cluster_maps[1:]:
        common_keys &= set(mapping)
    return [
        merge_cluster(key, cluster_maps, runs)
        for key in sorted(common_keys)
    ]

def changed_failure_clusters(runs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    cluster_maps = [cluster_map(run) for run in runs]
    all_keys = sorted({key for mapping in cluster_maps for key in mapping})
    changed = []
    for key in all_keys:
        labels = [runs[index]["label"] for index, mapping in enumerate(cluster_maps) if key in mapping]
        if len(labels) == len(runs):
            continue
        item = merge_cluster(key, cluster_maps, runs)
        item["presentIn"] = labels
        changed.append(item)
    return changed

def cluster_map(run: dict[str, Any]) -> dict[tuple[str, str, str, str, str, str, str], dict[str, Any]]:
    return {cluster_key(item): item for item in run["summary"].get("failureClusters", [])}

def cluster_key(item: dict[str, Any]) -> tuple[str, str, str, str, str, str, str]:
    return (
        str(item.get("bucket")),
        str(item.get("behavior")),
        str(item.get("domain")),
        str(item.get("probe")),
        str(item.get("errorStage")),
        str(item.get("errorType")),
        str(item.get("faultSignal")),
    )

def merge_cluster(
    key: tuple[str, str, str, str, str, str, str],
    cluster_maps: list[dict[tuple[str, str, str, str, str, str, str], dict[str, Any]]],
    runs: list[dict[str, Any]],
) -> dict[str, Any]:
    bucket, behavior, domain, probe, error_stage, error_type, fault_signal = key
    counts = []
    tags = set()
    for index, mapping in enumerate(cluster_maps):
        item = mapping.get(key)
        count = int(item.get("count", 0)) if item else 0
        counts.append({"label": runs[index]["label"], "count": count})
        if item:
            tags.update(str(tag) for tag in item.get("targetTags", []))
    return {
        "bucket": bucket,
        "behavior": behavior,
        "domain": domain,
        "probe": probe,
        "errorStage": error_stage,
        "errorType": error_type,
        "faultSignal": fault_signal,
        "targetTags": sorted(tags),
        "runs": counts,
        "canAttributePlanVsNode": False,
    }

def comparison_attribution(
    runs: list[dict[str, Any]],
    stable_failures: list[dict[str, Any]],
    changed_failures: list[dict[str, Any]],
) -> dict[str, Any]:
    signals = Counter(
        run["summary"].get("attribution", {}).get("failureSignal", "unknown")
        for run in runs
    )
    stable_normal = [
        item for item in stable_failures if item.get("faultSignal") == "normal"
    ]
    stable_informational = [
        item for item in stable_failures if item.get("faultSignal") == "informational"
    ]
    if stable_normal:
        conclusion = "stable-actionable-failures-need-dynet-trace"
    elif changed_failures:
        conclusion = "unstable-blackbox-failures-need-repeat-or-dynet-trace"
    elif stable_informational:
        conclusion = "stable-informational-failures-only"
    else:
        conclusion = "no-stable-failures"
    return {
        "blackboxOnlyCanAttributePlanVsNode": False,
        "conclusion": conclusion,
        "runFailureSignals": top(signals),
        "requiresDynetTraceFields": list(ATTRIBUTION_TRACE_FIELDS),
        "reason": "comparison still lacks selected outbound, candidate quality, and cascade attempt evidence",
    }

def group_item(summary: dict[str, Any], group_name: str, key: str) -> dict[str, Any] | None:
    return next((item for item in summary.get(group_name, []) if item["key"] == key), None)

def group_delta(item: dict[str, Any], baseline: dict[str, Any] | None, field: str) -> float | None:
    if baseline is None:
        return None
    return round(item[field] - baseline[field], 4)

def group_latency_delta(item: dict[str, Any], baseline: dict[str, Any] | None) -> int | None:
    if baseline is None:
        return None
    return delta(item["latencyMs"]["p95"], baseline["latencyMs"]["p95"])

def delta(value: int | None, baseline: int | None) -> int | None:
    if value is None or baseline is None:
        return None
    return value - baseline
