from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from dynet_trace.common import BATCH_SCHEMA, int_value, load_json, top


def build_batch(
    summary_paths: list[Path],
    min_repeat_runs: int,
    max_unknown_rate: float,
    max_missing_correlation_rate: float,
) -> dict[str, Any]:
    runs = []
    all_items = []
    for path in summary_paths:
        run, annotated = batch_run(path)
        runs.append(run)
        all_items.extend(annotated)

    failures = [item for item in all_items if item.get("classification") != "healthy"]
    repeated_keys = repeated_evidence_keys(failures, min_repeat_runs)
    missing_repeat = [
        item
        for item in failures
        if "repeat-correlation" in item.get("missingFields", [])
        and item.get("classification") != "node-suspect"
        and evidence_key(item) not in repeated_keys
    ]
    node_missing_repeat = [
        item
        for item in failures
        if item.get("classification") == "node-suspect"
        and "repeat-correlation" in item.get("missingFields", [])
        and evidence_key(item) not in repeated_keys
    ]
    unknown_items = [
        item for item in all_items if item.get("classification") == "unknown"
    ]
    candidate_signals = candidate_batch_signals(
        all_items,
        repeated_keys,
        min_repeat_runs,
    )
    gates = batch_gates(
        runs,
        all_items,
        failures,
        unknown_items,
        missing_repeat,
        node_missing_repeat,
        candidate_signals,
        min_repeat_runs,
        max_unknown_rate,
        max_missing_correlation_rate,
    )
    return {
        "schema": BATCH_SCHEMA,
        "inputs": [str(path) for path in summary_paths],
        "thresholds": {
            "minRepeatRuns": min_repeat_runs,
            "maxUnknownRate": max_unknown_rate,
            "maxMissingCorrelationRate": max_missing_correlation_rate,
        },
        "totals": {
            "runs": len(runs),
            "items": len(all_items),
            "failures": len(failures),
            "healthy": sum(
                1 for item in all_items if item.get("classification") == "healthy"
            ),
            "unknown": len(unknown_items),
            "missingRepeatCorrelation": len(missing_repeat),
            "nodeMissingRepeatCorrelation": len(node_missing_repeat),
        },
        "runs": runs,
        "byClass": top(Counter(str(item.get("classification")) for item in all_items)),
        "missingFields": top(Counter(
            str(field)
            for item in failures
            for field in item.get("missingFields", [])
        )),
        "gates": gates,
        "candidateSignals": candidate_signals,
        "repeatedEvidence": repeated_evidence_rows(failures, repeated_keys),
    }

def batch_run(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    summary = load_json(path)
    workload = summary.get("workloadAttribution", {})
    items = workload.get("items", []) if isinstance(workload, dict) else []
    run_label = path.parent.name
    annotated = [
        {**item, "runLabel": run_label, "summaryPath": str(path)}
        for item in items
        if isinstance(item, dict)
    ]
    run = {
        "label": run_label,
        "summaryPath": str(path),
        "runtimeStatus": summary.get("runtimeStatus"),
        "runtimeReason": summary.get("runtimeReason"),
        "ruleBypassOk": all(
            rule.get("bypassesPlan") is True
            for rule in summary.get("rules", [])
            if isinstance(rule, dict)
        ),
        "dialerSelections": len(summary.get("dialers", [])),
        "items": len(annotated),
        "failures": sum(1 for item in annotated if item.get("classification") != "healthy"),
        "classes": top(Counter(str(item.get("classification")) for item in annotated)),
    }
    return run, annotated

def repeated_evidence_keys(
    failures: list[dict[str, Any]],
    min_repeat_runs: int,
) -> set[tuple[str, ...]]:
    runs_by_key: dict[tuple[str, ...], set[str]] = defaultdict(set)
    for item in failures:
        if not has_runtime_repeat_evidence(item):
            continue
        runs_by_key[evidence_key(item)].add(str(item.get("runLabel")))
    return {
        key
        for key, runs in runs_by_key.items()
        if len(runs) >= min_repeat_runs
    }

def evidence_key(item: dict[str, Any]) -> tuple[str, ...]:
    candidates = ",".join(candidate_names(item))
    runtime_signature = ",".join(runtime_evidence_signatures(item)) or "<no-runtime-evidence>"
    return (
        candidates,
        str(item.get("classification") or "unknown"),
        str(item.get("domain") or "<none>"),
        str(item.get("errorStage") or "<none>"),
        str(item.get("errorType") or "<none>"),
        runtime_signature,
    )

def has_runtime_repeat_evidence(item: dict[str, Any]) -> bool:
    return candidate_names(item) != ["<missing>"] and bool(runtime_evidence_signatures(item))

def candidate_names(item: dict[str, Any]) -> list[str]:
    candidates = {
        candidate
        for session in item.get("sessions", [])
        for candidate in session.get("selectedCandidates", [])
    } | {
        candidate
        for flow in item.get("dnsFlows", [])
        for candidate in flow.get("selectedCandidates", [])
    }
    return sorted(candidates) or ["<missing>"]

def runtime_evidence_signatures(item: dict[str, Any]) -> list[str]:
    stage_signatures = stage_failure_signatures(item)
    if stage_signatures:
        return stage_signatures
    close_reasons = {
        f"close/{reason}"
        for session in item.get("sessions", [])
        for reason in session.get("closeReasons", [])
        if reason
    }
    return sorted(close_reasons)

def stage_failure_signatures(item: dict[str, Any]) -> list[str]:
    failures = []
    for session in item.get("sessions", []):
        failures.extend(session.get("stageFailures", []))
    for flow in item.get("dnsFlows", []):
        failures.extend(flow.get("stageFailures", []))
    return sorted(
        {
            "/".join(
                str(part or "<none>")
                for part in [
                    failure.get("outbound"),
                    failure.get("stage"),
                    failure.get("errorType"),
                ]
            )
            for failure in failures
            if isinstance(failure, dict)
        }
    )

def batch_gates(
    runs: list[dict[str, Any]],
    items: list[dict[str, Any]],
    failures: list[dict[str, Any]],
    unknown_items: list[dict[str, Any]],
    missing_repeat: list[dict[str, Any]],
    node_missing_repeat: list[dict[str, Any]],
    candidate_signals: list[dict[str, Any]],
    min_repeat_runs: int,
    max_unknown_rate: float,
    max_missing_correlation_rate: float,
) -> list[dict[str, Any]]:
    item_count = len(items)
    non_node_failure_count = sum(
        1 for item in failures if item.get("classification") != "node-suspect"
    )
    unknown_rate = round(len(unknown_items) / item_count, 4) if item_count else 0.0
    missing_rate = (
        round(len(missing_repeat) / non_node_failure_count, 4)
        if non_node_failure_count
        else 0.0
    )
    unsafe_planner_signals = [
        signal
        for signal in candidate_signals
        if signal.get("plannerAction") == "penalize-candidate"
        and (
            signal.get("confidence") != "repeat-stage-correlated"
            or int_value(signal.get("repeatedNodeSuspectItems")) in (None, 0)
        )
    ]
    return [
        {
            "name": "min-repeat-runs",
            "passed": len(runs) >= min_repeat_runs,
            "value": len(runs),
            "required": min_repeat_runs,
        },
        {
            "name": "unknown-rate",
            "passed": unknown_rate <= max_unknown_rate,
            "value": unknown_rate,
            "required": max_unknown_rate,
        },
        {
            "name": "non-node-missing-correlation-rate",
            "passed": missing_rate <= max_missing_correlation_rate,
            "value": missing_rate,
            "required": max_missing_correlation_rate,
        },
        {
            "name": "node-repeat-required-before-penalty",
            "passed": True,
            "value": len(node_missing_repeat),
            "required": "node-suspect without repeat remains observe-only",
        },
        {
            "name": "runtime-reports-present",
            "passed": all(run.get("runtimeStatus") is not None for run in runs),
            "value": sum(1 for run in runs if run.get("runtimeStatus") is not None),
            "required": len(runs),
        },
        {
            "name": "planner-signals-repeat-only",
            "passed": not unsafe_planner_signals,
            "value": len(unsafe_planner_signals),
            "required": "candidate penalty requires repeated node-suspect evidence",
        },
        {
            "name": "no-silent-fallback-suspect",
            "passed": not silent_fallback_suspect(runs, failures),
            "value": "checked",
            "required": "user-rule path failures keep selected-candidate evidence",
        },
    ]

def silent_fallback_suspect(
    runs: list[dict[str, Any]],
    failures: list[dict[str, Any]],
) -> bool:
    if any(run.get("ruleBypassOk") is False for run in runs):
        return True
    hard_failures = {
        "node-suspect",
        "dynet-infra-suspect",
        "plan-suspect",
    }
    return any(
        item.get("classification") in hard_failures
        and candidate_names(item) == ["<missing>"]
        for item in failures
    )

def candidate_batch_signals(
    items: list[dict[str, Any]],
    repeated_keys: set[tuple[str, ...]],
    min_repeat_runs: int,
) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in items:
        for candidate in candidate_names(item):
            grouped[candidate].append(item)
    rows = []
    for candidate, candidate_items in sorted(grouped.items()):
        rows.append(candidate_signal_row(candidate, candidate_items, repeated_keys, min_repeat_runs))
    return rows

def candidate_signal_row(
    candidate: str,
    candidate_items: list[dict[str, Any]],
    repeated_keys: set[tuple[str, ...]],
    min_repeat_runs: int,
) -> dict[str, Any]:
    failures = [item for item in candidate_items if item.get("classification") != "healthy"]
    node_suspects = [item for item in failures if item.get("classification") == "node-suspect"]
    repeated_node = [item for item in node_suspects if evidence_key(item) in repeated_keys]
    node_runs = {str(item.get("runLabel")) for item in node_suspects}
    planner_action, confidence = candidate_planner_signal(
        repeated_node, node_runs, node_suspects, min_repeat_runs
    )
    return {
        "candidate": candidate,
        "items": len(candidate_items),
        "failures": len(failures),
        "failureRate": round(len(failures) / len(candidate_items), 4) if candidate_items else 0,
        "classes": top(Counter(str(item.get("classification")) for item in candidate_items)),
        "nodeSuspectItems": len(node_suspects),
        "nodeSuspectRuns": len(node_runs),
        "repeatedNodeSuspectItems": len(repeated_node),
        "stageFailures": top(
            Counter(
                signature
                for item in failures
                for signature in stage_failure_signatures(item)
            )
        ),
        "domains": top(Counter(str(item.get("domain")) for item in failures)),
        "plannerAction": planner_action,
        "confidence": confidence,
    }

def candidate_planner_signal(
    repeated_node: list[dict[str, Any]],
    node_runs: set[str],
    node_suspects: list[dict[str, Any]],
    min_repeat_runs: int,
) -> tuple[str, str]:
    if repeated_node and len(node_runs) >= min_repeat_runs:
        return "penalize-candidate", "repeat-stage-correlated"
    if node_suspects:
        return "observe", "single-run-suspect"
    return "observe", "none"

def repeated_evidence_rows(
    failures: list[dict[str, Any]],
    repeated_keys: set[tuple[str, ...]],
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, ...], list[dict[str, Any]]] = defaultdict(list)
    for item in failures:
        key = evidence_key(item)
        if key in repeated_keys:
            grouped[key].append(item)
    rows = []
    for key, key_items in sorted(grouped.items()):
        rows.append(
            {
                "key": list(key),
                "runs": sorted({str(item.get("runLabel")) for item in key_items}),
                "items": len(key_items),
                "ids": [
                    f"{item.get('runLabel')}:{item.get('id')}"
                    for item in key_items
                ],
            }
        )
    return rows
