from __future__ import annotations

from pathlib import Path
from typing import Any


def write_report(path: Path, summary: dict[str, Any]) -> None:
    lines = [
        "# Real Access Blackbox Report",
        "",
        f"- Environment: `{summary['environment']}`",
        f"- Seed: `{summary['seed']}`",
        f"- Started: `{summary['startedAt']}`",
        f"- Ended: `{summary['endedAt']}`",
        f"- Success rate: `{summary['totals']['successRate']}`",
        f"- Count: `{summary['totals']['count']}`",
        f"- Observer: `{summary['observer']['name']}`",
        f"- Attribution: `{summary['attribution']['failureSignal']}`",
        f"- Workload duration: `{summary['workload'].get('durationSeconds', 0)}` seconds",
        f"- Schedule lag p95: `{summary['schedule']['lagMs']['p95']}` ms",
        "",
        "## Privacy",
        "",
        "- No dynet state/API/events were read.",
        "- No cookies, Authorization headers, browser profiles, or request bodies were used.",
        "- Response bodies, response headers, and resolved IP addresses were not stored.",
    ]
    append_report_groups(lines, summary)
    append_controller(lines, summary.get("controllerAttribution", {}))
    if summary["errors"]:
        lines.extend(["", "## Errors", ""])
        for item in summary["errors"]:
            lines.append(f"- `{item['key']}`: {item['count']}")
    if summary["failureClusters"]:
        lines.extend(["", "## Failure Clusters", ""])
        for item in summary["failureClusters"]:
            lines.append(
                f"- `{item['domain']}` bucket=`{item['bucket']}` behavior=`{item['behavior']}` "
                f"probe=`{item['probe']}` "
                f"stage=`{item['errorStage']}` error=`{item['errorType']}` "
                f"signal=`{item['faultSignal']}` count={item['count']}"
            )
    if summary["latencyHotspots"]:
        lines.extend(["", "## Latency Hotspots", ""])
        for item in summary["latencyHotspots"]:
            lines.append(
                f"- {item['kind']} `{item['key']}` p95={item['p95Ms']}ms "
                f"threshold={item['thresholdMs']}ms count={item['count']}"
            )
    if summary["slowSamples"]:
        lines.extend(["", "## Slow Samples", ""])
        for item in summary["slowSamples"][:10]:
            stages = ", ".join(
                f"{name}={value}ms" for name, value in item["stageLatencyMs"].items()
            )
            lines.append(
                f"- `{item['domain']}` bucket=`{item['bucket']}` behavior=`{item['behavior']}` "
                f"probe=`{item['probe']}` lag={item['scheduleLagMs']}ms "
                f"elapsed={item['elapsedMs']}ms signal=`{item['faultSignal']}` stages: {stages}"
            )
    lines.extend(
        [
            "",
            "## Attribution Boundary",
            "",
            "- Black-box output cannot attribute plan-vs-node by itself.",
            "- Needed dynet trace fields: "
            + ", ".join(f"`{field}`" for field in summary["attribution"]["requiresDynetTraceFields"]),
        ]
    )
    path.write_text("\n".join(lines) + "\n")

def append_controller(lines: list[str], controller: dict[str, Any]) -> None:
    if not controller.get("enabled"):
        return
    lines.extend(["", "## Clash Controller Attribution", ""])
    lines.append(
        f"- observed={controller['observed']}/{controller['items']} "
        f"missing={controller['missing']} rawNodeNamesStored={controller['rawNodeNamesStored']}"
    )
    if controller.get("chainKeys"):
        lines.append("- chain keys:")
        for item in controller["chainKeys"]:
            lines.append(f"  - `{item['key']}`: {item['count']}")
    if controller.get("rules"):
        lines.append("- rules:")
        for item in controller["rules"]:
            lines.append(f"  - `{item['key']}`: {item['count']}")
    if controller.get("missReasons"):
        lines.append("- miss reasons:")
        for item in controller["missReasons"]:
            lines.append(f"  - `{item['key']}`: {item['count']}")
    if controller.get("failureGroups"):
        lines.append("- failure groups:")
        for item in controller["failureGroups"]:
            rules = ", ".join(rule["key"] for rule in item.get("rules", [])) or "none"
            miss = item.get("missReason") or "none"
            lines.append(
                f"  - chain=`{item['chainKey']}` observed={item['observed']} "
                f"missReason=`{miss}` domain=`{item['domain']}` "
                f"probe=`{item['probe']}` "
                f"stage=`{item['errorStage']}` error=`{item['errorType']}` "
                f"count={item['count']} rules=`{rules}`"
            )

def append_report_groups(lines: list[str], summary: dict[str, Any]) -> None:
    for title, key in [
        ("By Bucket", "byBucket"),
        ("By Behavior", "byBehavior"),
        ("By Probe", "byProbe"),
        ("By Stage", "byStage"),
        ("Fault Signals", "byFaultSignal"),
    ]:
        lines.extend(["", f"## {title}", ""])
        for item in summary[key]:
            lines.append(
                f"- `{item['key']}`: success={item['success']}/{item['count']} "
                f"rate={item['successRate']} p95={item['latencyMs']['p95']}ms"
            )

def write_comparison_report(path: Path, comparison: dict[str, Any]) -> None:
    lines = [
        "# Real Access Blackbox Comparison",
        "",
        f"- Baseline: `{comparison['baseline']}`",
        "",
        "## Runs",
        "",
    ]
    for run in comparison["runs"]:
        lines.append(
            f"- `{run['label']}` env=`{run['environment']}` count={run['count']} "
            f"success={run['successRate']} delta={run['successRateDelta']} "
            f"p95={run['p95Ms']}ms delta={run['p95DeltaMs']}ms"
        )
    append_comparison_groups(lines, comparison)
    if comparison["stableFailures"]:
        lines.extend(["", "## Stable Failures", ""])
        for item in comparison["stableFailures"]:
            counts = ", ".join(f"{run['label']}={run['count']}" for run in item["runs"])
            lines.append(
                f"- `{item['domain']}` bucket=`{item['bucket']}` behavior=`{item['behavior']}` "
                f"probe=`{item['probe']}` "
                f"stage=`{item['errorStage']}` error=`{item['errorType']}` "
                f"signal=`{item['faultSignal']}` counts={counts}"
            )
    if comparison["changedFailures"]:
        lines.extend(["", "## Changed Failures", ""])
        for item in comparison["changedFailures"]:
            present = ", ".join(item.get("presentIn", []))
            lines.append(
                f"- `{item['domain']}` bucket=`{item['bucket']}` behavior=`{item['behavior']}` "
                f"probe=`{item['probe']}` "
                f"stage=`{item['errorStage']}` error=`{item['errorType']}` "
                f"presentIn={present}"
            )
    lines.extend(
        [
            "",
            "## Attribution",
            "",
            f"- Conclusion: `{comparison['attribution']['conclusion']}`",
            "- Black-box comparison still cannot attribute plan-vs-node without dynet trace fields.",
        ]
    )
    path.write_text("\n".join(lines) + "\n")

def append_comparison_groups(lines: list[str], comparison: dict[str, Any]) -> None:
    for title, key in [
        ("Buckets", "byBucket"),
        ("Behaviors", "byBehavior"),
        ("Probes", "byProbe"),
        ("Stages", "byStage"),
        ("Fault Signals", "byFaultSignal"),
    ]:
        lines.extend(["", f"## {title}", ""])
        for item in comparison[key]:
            pieces = [comparison_run_piece(run) for run in item["runs"]]
            lines.append(f"- `{item['key']}`: " + "; ".join(pieces))

def comparison_run_piece(run: dict[str, Any]) -> str:
    if run["count"] == 0:
        return f"{run['label']}:none"
    return f"{run['label']}:n={run['count']} sr={run['successRate']} p95={run['p95Ms']}ms"
