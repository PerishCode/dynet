from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from dynet_trace.common import DEFAULT_MIN_REPEAT_RUNS, load_json, top


PROBE_BATCH_SCHEMA = "dynet-probe-attribution-batch/v1alpha1"
DEFAULT_PROBE_BATCH_JSON = ".task/resources/dynet-probe-attribution-batch.json"
DEFAULT_PROBE_BATCH_MD = ".task/resources/dynet-probe-attribution-batch.md"


def build_probe_batch(
    attribution_paths: list[Path],
    min_repeat_runs: int = DEFAULT_MIN_REPEAT_RUNS,
) -> dict[str, Any]:
    runs = [probe_batch_run(path) for path in attribution_paths]
    gaps = [
        {**gap, "runLabel": run["label"], "attributionPath": run["attributionPath"]}
        for run in runs
        for gap in run["qualityGaps"]
    ]
    private_sources = [
        {**item, "runLabel": run["label"], "attributionPath": run["attributionPath"]}
        for run in runs
        for item in run["privateSourcePolicy"]
    ]
    repeated_keys = repeated_gap_keys(gaps, min_repeat_runs)
    repeated = repeated_gap_rows(gaps, repeated_keys)
    repeated_private_keys = repeated_private_source_keys(private_sources, min_repeat_runs)
    return {
        "schema": PROBE_BATCH_SCHEMA,
        "inputs": [str(path) for path in attribution_paths],
        "thresholds": {"minRepeatRuns": min_repeat_runs},
        "totals": probe_batch_totals(
            runs,
            gaps,
            repeated,
            private_sources,
            repeated_private_keys,
        ),
        "runs": [run_summary(run) for run in runs],
        "byClass": top(run_class_counter(runs)),
        "bySuspectComponent": top(run_component_counter(runs)),
        "qualityGapSignals": quality_gap_signals(gaps, repeated_keys),
        "privateSourcePolicySignals": private_source_signals(
            private_sources,
            repeated_private_keys,
        ),
        "repeatedQualityGaps": repeated,
        "gates": probe_batch_gates(runs, repeated, min_repeat_runs),
    }


def probe_batch_run(path: Path) -> dict[str, Any]:
    report = load_json(path)
    quality = report.get("candidateQuality", {})
    gaps = quality.get("gaps", []) if isinstance(quality, dict) else []
    failures = [
        item
        for item in report.get("failures", [])
        if isinstance(item, dict)
    ]
    return {
        "label": path.parent.name,
        "attributionPath": str(path),
        "items": report.get("totals", {}).get("items", 0),
        "failures": report.get("totals", {}).get("failed", 0),
        "unknown": report.get("totals", {}).get("unknown", 0),
        "classes": report.get("byClassification", []),
        "candidateSets": quality.get("candidateSets", 0)
        if isinstance(quality, dict)
        else 0,
        "withQuality": quality.get("withQuality", 0)
        if isinstance(quality, dict)
        else 0,
        "selectedBehind": quality.get("selectedBehind", 0)
        if isinstance(quality, dict)
        else 0,
        "qualityGaps": [gap for gap in gaps if isinstance(gap, dict)],
        "suspectComponents": report.get("bySuspectComponent", []),
        "privateSourcePolicy": [
            private_source_row(item)
            for item in failures
            if item.get("suspectComponent") == "private-source-policy"
        ],
    }


def run_summary(run: dict[str, Any]) -> dict[str, Any]:
    return {
        key: run[key]
        for key in [
            "label",
            "attributionPath",
            "items",
            "failures",
            "unknown",
            "candidateSets",
            "withQuality",
            "selectedBehind",
            "classes",
            "suspectComponents",
        ]
    }


def probe_batch_totals(
    runs: list[dict[str, Any]],
    gaps: list[dict[str, Any]],
    repeated: list[dict[str, Any]],
    private_sources: list[dict[str, Any]],
    repeated_private_keys: set[tuple[str, ...]],
) -> dict[str, Any]:
    return {
        "runs": len(runs),
        "items": sum_int(runs, "items"),
        "failures": sum_int(runs, "failures"),
        "unknown": sum_int(runs, "unknown"),
        "candidateSets": sum_int(runs, "candidateSets"),
        "withQuality": sum_int(runs, "withQuality"),
        "selectedBehind": len(gaps),
        "repeatedQualityGapKeys": len(repeated),
        "repeatedQualityGapItems": sum(item["items"] for item in repeated),
        "privateSourcePolicyItems": len(private_sources),
        "repeatedPrivateSourcePolicyKeys": len(repeated_private_keys),
    }


def sum_int(rows: list[dict[str, Any]], key: str) -> int:
    total = 0
    for row in rows:
        try:
            total += int(row.get(key) or 0)
        except (TypeError, ValueError):
            continue
    return total


def run_class_counter(runs: list[dict[str, Any]]) -> Counter[str]:
    counter: Counter[str] = Counter()
    for run in runs:
        for item in run.get("classes", []):
            try:
                counter[str(item.get("key"))] += int(item.get("count") or 0)
            except (TypeError, ValueError):
                continue
    return counter


def run_component_counter(runs: list[dict[str, Any]]) -> Counter[str]:
    counter: Counter[str] = Counter()
    for run in runs:
        for item in run.get("suspectComponents", []):
            try:
                counter[str(item.get("key"))] += int(item.get("count") or 0)
            except (TypeError, ValueError):
                continue
    return counter


def private_source_row(item: dict[str, Any]) -> dict[str, Any]:
    attempts = [
        attempt
        for attempt in item.get("dialerAttempts", [])
        if isinstance(attempt, dict) and attempt.get("failureScope") == "downstream"
    ]
    return {
        "id": item.get("id"),
        "bucket": item.get("bucket"),
        "domain": item.get("domain"),
        "selectedOutbound": item.get("selectedOutbound"),
        "failedStage": item.get("failedStage"),
        "failureScope": item.get("failureScope"),
        "suspectComponent": item.get("suspectComponent"),
        "dialers": sorted({
            str(attempt.get("dialer"))
            for attempt in attempts
            if attempt.get("dialer")
        }),
        "private": sorted({
            str(attempt.get("private"))
            for attempt in attempts
            if attempt.get("private")
        }),
    }


def repeated_gap_keys(
    gaps: list[dict[str, Any]],
    min_repeat_runs: int,
) -> set[tuple[str, ...]]:
    runs_by_key: dict[tuple[str, ...], set[str]] = defaultdict(set)
    for gap in gaps:
        runs_by_key[quality_gap_key(gap)].add(str(gap.get("runLabel")))
    return {
        key
        for key, run_labels in runs_by_key.items()
        if len(run_labels) >= min_repeat_runs
    }


def quality_gap_key(gap: dict[str, Any]) -> tuple[str, ...]:
    return (
        str(gap.get("bucket") or "<none>"),
        str(gap.get("domain") or "<none>"),
        str(gap.get("scope") or "plan-candidate"),
        str(gap.get("plan") or "<none>"),
        str(gap.get("selected") or "<none>"),
        ",".join(str(item) for item in gap.get("bestCandidates", [])),
    )


def repeated_private_source_keys(
    items: list[dict[str, Any]],
    min_repeat_runs: int,
) -> set[tuple[str, ...]]:
    runs_by_key: dict[tuple[str, ...], set[str]] = defaultdict(set)
    for item in items:
        runs_by_key[private_source_key(item)].add(str(item.get("runLabel")))
    return {
        key
        for key, run_labels in runs_by_key.items()
        if len(run_labels) >= min_repeat_runs
    }


def private_source_key(item: dict[str, Any]) -> tuple[str, ...]:
    return (
        str(item.get("bucket") or "<none>"),
        str(item.get("domain") or "<none>"),
        ",".join(str(value) for value in item.get("dialers", [])),
        ",".join(str(value) for value in item.get("private", [])),
    )


def repeated_gap_rows(
    gaps: list[dict[str, Any]],
    repeated_keys: set[tuple[str, ...]],
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, ...], list[dict[str, Any]]] = defaultdict(list)
    for gap in gaps:
        key = quality_gap_key(gap)
        if key in repeated_keys:
            grouped[key].append(gap)
    return [
        {
            "key": list(key),
            "runs": sorted({str(item.get("runLabel")) for item in items}),
            "items": len(items),
            "maxScoreGap": max(int(item.get("scoreGap") or 0) for item in items),
            "ids": [f"{item.get('runLabel')}:{item.get('id')}" for item in items],
        }
        for key, items in sorted(grouped.items())
    ]


def private_source_signals(
    items: list[dict[str, Any]],
    repeated_keys: set[tuple[str, ...]],
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, ...], list[dict[str, Any]]] = defaultdict(list)
    for item in items:
        grouped[private_source_key(item)].append(item)
    return [
        private_source_signal_row(key, rows, key in repeated_keys)
        for key, rows in sorted(grouped.items())
    ]


def private_source_signal_row(
    key: tuple[str, ...],
    items: list[dict[str, Any]],
    repeated: bool,
) -> dict[str, Any]:
    runs = sorted({str(item.get("runLabel")) for item in items})
    return {
        "key": list(key),
        "runs": runs,
        "items": len(items),
        "failedStages": top(Counter(str(item.get("failedStage")) for item in items)),
        "plannerAction": "observe-private-source-policy",
        "confidence": "repeat-private-source-policy" if repeated else "single-run-source-policy",
    }


def quality_gap_signals(
    gaps: list[dict[str, Any]],
    repeated_keys: set[tuple[str, ...]],
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, ...], list[dict[str, Any]]] = defaultdict(list)
    for gap in gaps:
        grouped[quality_gap_key(gap)].append(gap)
    return [
        quality_gap_signal_row(key, items, key in repeated_keys)
        for key, items in sorted(grouped.items())
    ]


def quality_gap_signal_row(
    key: tuple[str, ...],
    items: list[dict[str, Any]],
    repeated: bool,
) -> dict[str, Any]:
    runs = sorted({str(item.get("runLabel")) for item in items})
    return {
        "key": list(key),
        "runs": runs,
        "items": len(items),
        "maxScoreGap": max(int(item.get("scoreGap") or 0) for item in items),
        "classifications": top(Counter(str(item.get("classification")) for item in items)),
        "plannerAction": "investigate-plan-choice" if repeated else "observe",
        "confidence": "repeat-quality-gap" if repeated else "single-run-gap",
    }


def probe_batch_gates(
    runs: list[dict[str, Any]],
    repeated: list[dict[str, Any]],
    min_repeat_runs: int,
) -> list[dict[str, Any]]:
    return [
        {
            "name": "min-repeat-runs",
            "passed": len(runs) >= min_repeat_runs,
            "value": len(runs),
            "required": min_repeat_runs,
        },
        {
            "name": "quality-gap-repeat-visible",
            "passed": True,
            "value": len(repeated),
            "required": "repeated non-stale quality gaps become planner investigation signals",
        },
    ]


def write_probe_batch_report(path: Path, batch: dict[str, Any]) -> None:
    lines = [
        "# Dynet Probe Attribution Batch",
        "",
        f"- Runs: `{batch['totals']['runs']}`",
        f"- Items: `{batch['totals']['items']}` failures=`{batch['totals']['failures']}`",
        f"- Candidate quality: `{batch['totals']['withQuality']}/"
        f"{batch['totals']['candidateSets']}` sets",
        f"- Selected behind: `{batch['totals']['selectedBehind']}` "
        f"repeatedKeys=`{batch['totals']['repeatedQualityGapKeys']}`",
        f"- Private source policy: `{batch['totals']['privateSourcePolicyItems']}` "
        f"repeatedKeys=`{batch['totals']['repeatedPrivateSourcePolicyKeys']}`",
        "",
        "## Gates",
        "",
    ]
    for gate in batch["gates"]:
        lines.append(
            f"- `{gate['name']}` passed={gate['passed']} "
            f"value=`{gate['value']}` required=`{gate['required']}`"
        )
    lines.extend(["", "## Quality Gap Signals", ""])
    for item in batch["qualityGapSignals"][:30]:
        lines.append(
            f"- key=`{' | '.join(item['key'])}` action=`{item['plannerAction']}` "
            f"confidence=`{item['confidence']}` runs={len(item['runs'])} "
            f"items={item['items']} maxGap={item['maxScoreGap']}"
        )
    if batch["privateSourcePolicySignals"]:
        lines.extend(["", "## Private Source Policy Signals", ""])
        for item in batch["privateSourcePolicySignals"][:30]:
            lines.append(
                f"- key=`{' | '.join(item['key'])}` action=`{item['plannerAction']}` "
                f"confidence=`{item['confidence']}` runs={len(item['runs'])} "
                f"items={item['items']}"
            )
    if batch["repeatedQualityGaps"]:
        lines.extend(["", "## Repeated Quality Gaps", ""])
        for item in batch["repeatedQualityGaps"]:
            lines.append(
                f"- key=`{' | '.join(item['key'])}` runs={','.join(item['runs'])} "
                f"items={item['items']} maxGap={item['maxScoreGap']}"
            )
    path.write_text("\n".join(lines) + "\n")
