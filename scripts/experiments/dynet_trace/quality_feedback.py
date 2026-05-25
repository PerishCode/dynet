from __future__ import annotations

from pathlib import Path
from typing import Any

from dynet_trace.common import load_json
from dynet_trace.quality import promotion_context


PROBE_BATCH_SCHEMA = "dynet-probe-attribution-batch/v1alpha1"
TRACE_BATCH_SCHEMA = "dynet-trace-attribution-batch/v1alpha1"
VM_RUNTIME_REPEAT_SCHEMA = "dynet-vm-private-runtime-repeat/v1alpha1"


def planner_feedback(
    inputs: list[str],
    mode: str,
    now_ms: int,
    promotion_inputs: list[str] | None = None,
    promotion_context_inputs: list[str] | None = None,
    trace_inputs: list[str] | None = None,
) -> dict[str, Any]:
    batches = load_feedback_batches(inputs)
    trace_batches = load_trace_batches(trace_inputs or [])
    promotion = promotion_gate(
        promotion_inputs or [],
        promotion_context_inputs or [],
    )
    effective_mode = effective_feedback_mode(mode, promotion)
    gaps = [
        gap
        for batch in batches
        for gap in batch.get("repeatedQualityGaps", [])
        if isinstance(gap, dict)
    ]
    private_sources = [
        item
        for batch in batches
        for item in batch.get("privateSourcePolicySignals", [])
        if isinstance(item, dict)
    ]
    fallbacks = [
        item
        for batch in trace_batches
        for item in batch.get("fallbackSignals", [])
        if isinstance(item, dict)
    ]
    signals = [feedback_signal(gap, effective_mode) for gap in gaps] + [
        private_source_signal(item) for item in private_sources
    ] + [fallback_signal(item) for item in fallbacks]
    observations = (
        [feedback_observation(gap, now_ms) for gap in gaps]
        if effective_mode == "penalize"
        else []
    )
    return {
        "summary": {
            "mode": effective_mode,
            "requestedMode": mode,
            "probeBatches": len(batches),
            "traceBatches": len(trace_batches),
            "repeatedQualityGaps": len(gaps),
            "privateSourcePolicySignals": len(private_sources),
            "fallbackSignals": len(fallbacks),
            "recoveredFallbackSignals": sum(
                1
                for item in fallbacks
                if item.get("type") == "pre-replay-bound-failure-recovered"
            ),
            "nonRetrySafeFallbackSignals": sum(
                1
                for item in fallbacks
                if item.get("type") == "not-retry-safe-cascade-failure"
            ),
            "penaltyObservations": len(observations),
            "promotion": promotion,
        },
        "signals": signals,
        "observations": observations,
    }


def effective_feedback_mode(mode: str, promotion: dict[str, Any]) -> str:
    if mode == "auto":
        return "penalize" if promotion["eligible"] else "observe"
    return mode


def load_feedback_batches(inputs: list[str]) -> list[dict[str, Any]]:
    batches = []
    for raw in inputs:
        data = load_json(Path(raw))
        if isinstance(data, dict) and data.get("schema") == PROBE_BATCH_SCHEMA:
            batches.append(data)
    return batches


def load_trace_batches(inputs: list[str]) -> list[dict[str, Any]]:
    batches = []
    for raw in inputs:
        data = load_json(Path(raw))
        if isinstance(data, dict) and data.get("schema") == TRACE_BATCH_SCHEMA:
            batches.append(data)
    return batches


def promotion_gate(
    inputs: list[str],
    context_inputs: list[str] | None = None,
) -> dict[str, Any]:
    proofs = load_promotion_proofs(inputs)
    contexts = promotion_context.load_contexts(context_inputs or [])
    totals = promotion_totals(proofs)
    gates = promotion_gates(proofs, totals)
    eligible = bool(proofs) and all(item["passed"] for item in gates)
    return {
        "schema": "dynet-quality-gap-promotion-gate/v1alpha1",
        "eligible": eligible,
        "action": "allow-penalty-feedback" if eligible else "observe-only",
        "proofs": len(proofs),
        "inputs": [str(Path(raw)) for raw in inputs],
        "contexts": len(contexts),
        "contextInputs": [item["path"] for item in contexts],
        "observeOnlyActions": promotion_context.observe_only_actions(contexts),
        "policyActions": promotion_context.policy_actions(contexts),
        "totals": totals,
        "gates": gates,
    }


def load_promotion_proofs(inputs: list[str]) -> list[dict[str, Any]]:
    proofs = []
    for raw in inputs:
        data = load_json(Path(raw))
        if isinstance(data, dict) and data.get("schema") == VM_RUNTIME_REPEAT_SCHEMA:
            proofs.append(data)
    return proofs


def promotion_totals(proofs: list[dict[str, Any]]) -> dict[str, Any]:
    repeat_totals = [proof.get("totals", {}) for proof in proofs]
    runs = [run for proof in proofs for run in proof.get("runs", []) if isinstance(run, dict)]
    workload_exact_present = bool(repeat_totals) and all(
        "workloadFailure" in totals for totals in repeat_totals
    )
    return {
        "runs": sum_int(repeat_totals, "runs"),
        "passedRuns": sum_int(repeat_totals, "passedRuns"),
        "failedRuns": sum_int(repeat_totals, "failedRuns"),
        "workloadFailedRuns": sum_int(repeat_totals, "workloadFailedRuns"),
        "workloadAttempted": sum_int(repeat_totals, "workloadAttempted"),
        "workloadSuccess": sum_int(repeat_totals, "workloadSuccess"),
        "workloadFailure": sum_int(repeat_totals, "workloadFailure"),
        "workloadExactPresent": workload_exact_present,
        "qualityBoundCandidateSets": sum_int(repeat_totals, "qualityBoundCandidateSets"),
        "qualityBoundSelectedWithQuality": sum_int(
            repeat_totals, "qualityBoundSelectedWithQuality"
        ),
        "qualityBoundSelectedBehind": sum_int(repeat_totals, "qualityBoundSelectedBehind"),
        "protocolShortReadErrors": sum_int(repeat_totals, "protocolShortReadErrors"),
        "pendingFrameTimeouts": sum_int(repeat_totals, "pendingFrameTimeouts"),
        "dnsEarlyTimeouts": sum_int(repeat_totals, "dnsEarlyTimeouts"),
        "ipDenials": sum_int(repeat_totals, "ipDenials"),
        "tcpSessions": sum_int(runs, "tcpSessions"),
        "tcpClosedSessions": sum_int(runs, "tcpClosedSessions"),
        "tcpSessionFailures": sum_int(runs, "tcpSessionFailures"),
        "minWorkloadSuccessRate": min_float(runs, "workloadSuccessRate"),
    }


def promotion_gates(
    proofs: list[dict[str, Any]],
    totals: dict[str, Any],
) -> list[dict[str, Any]]:
    quality_sets = int(totals["qualityBoundCandidateSets"])
    workload_rate = totals.get("minWorkloadSuccessRate")
    return [
        gate("runtime-repeat-proof", bool(proofs), len(proofs), ">=1 repeat summary"),
        gate("repeat-runs", totals["runs"] >= 2, totals["runs"], ">=2"),
        gate("no-failed-runs", totals["failedRuns"] == 0, totals["failedRuns"], 0),
        gate(
            "workload-replay-clean",
            totals["workloadFailedRuns"] == 0
            and totals["workloadExactPresent"]
            and totals["workloadFailure"] == 0
            and workload_rate == 1.0,
            {
                "failedRuns": totals["workloadFailedRuns"],
                "failure": totals["workloadFailure"],
                "exactPresent": totals["workloadExactPresent"],
                "minSuccessRate": workload_rate,
            },
            "exact workload failure 0 and min success rate 1.0",
        ),
        gate("quality-bound-present", quality_sets > 0, quality_sets, ">0"),
        gate(
            "quality-bound-covered",
            totals["qualityBoundSelectedWithQuality"] == quality_sets,
            totals["qualityBoundSelectedWithQuality"],
            quality_sets,
        ),
        gate(
            "quality-bound-not-behind",
            totals["qualityBoundSelectedBehind"] == 0,
            totals["qualityBoundSelectedBehind"],
            0,
        ),
        gate("tcp-closed", totals["tcpClosedSessions"] > 0, totals["tcpClosedSessions"], ">0"),
        gate("tcp-no-failures", totals["tcpSessionFailures"] == 0, totals["tcpSessionFailures"], 0),
        gate(
            "runtime-clean-stability",
            all(
                totals[key] == 0
                for key in [
                    "protocolShortReadErrors",
                    "pendingFrameTimeouts",
                    "dnsEarlyTimeouts",
                    "ipDenials",
                ]
            ),
            {
                "protocolShortReadErrors": totals["protocolShortReadErrors"],
                "pendingFrameTimeouts": totals["pendingFrameTimeouts"],
                "dnsEarlyTimeouts": totals["dnsEarlyTimeouts"],
                "ipDenials": totals["ipDenials"],
            },
            "all zero",
        ),
    ]


def gate(name: str, passed: bool, value: Any, required: Any) -> dict[str, Any]:
    return {
        "name": name,
        "passed": passed,
        "value": value,
        "required": required,
    }


def feedback_signal(gap: dict[str, Any], mode: str) -> dict[str, Any]:
    fields = feedback_fields(gap)
    return {
        "type": "repeated-quality-gap",
        "action": mode,
        "outbound": fields["selected"],
        "scope": fields["scope"],
        "targetFamily": target_family(fields["domain"]),
        "domain": fields["domain"],
        "plan": fields["plan"],
        "bestCandidates": fields["best"],
        "runs": gap.get("runs", []),
        "items": gap.get("items", 0),
        "maxScoreGap": gap.get("maxScoreGap", 0),
        "reason": "selected candidate repeatedly scored below best candidate",
    }


def feedback_observation(gap: dict[str, Any], now_ms: int) -> dict[str, Any]:
    fields = feedback_fields(gap)
    return {
        "path": "<probe-batch-feedback>",
        "scope": fields["scope"],
        "observedAtUnixMs": now_ms,
        "outbound": fields["selected"],
        "targetFamily": target_family(fields["domain"]),
        "transport": "tcp",
        "status": "deny",
        "reason": "repeated quality gap selected a lower-scored candidate",
        "cascade": {},
        "stages": [],
    }


def private_source_signal(item: dict[str, Any]) -> dict[str, Any]:
    fields = private_source_fields(item)
    return {
        "type": "private-source-policy",
        "action": "observe",
        "targetFamily": target_family(fields["domain"]),
        "domain": fields["domain"],
        "dialers": fields["dialers"],
        "private": fields["private"],
        "runs": item.get("runs", []),
        "items": item.get("items", 0),
        "confidence": item.get("confidence"),
        "reason": "downstream private failure is attributed to private/source-policy and does not penalize bound candidates",
    }


def fallback_signal(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "cascade-fallback",
        "fallbackType": item.get("type"),
        "action": "observe",
        "plannerAction": "observe",
        "scope": "dialer-bound",
        "dialer": item.get("dialer"),
        "flowId": item.get("flowId"),
        "failedBound": item.get("failedBound") or item.get("boundSelected"),
        "recoveredBound": item.get("recoveredBound"),
        "replaySafe": item.get("replaySafe"),
        "failureScope": item.get("failureScope"),
        "errorType": item.get("errorType"),
        "runLabel": item.get("runLabel"),
        "summaryPath": item.get("summaryPath"),
        "reason": item.get("reason", "cascade fallback evidence is observe-only"),
    }


def private_source_fields(item: dict[str, Any]) -> dict[str, Any]:
    key = item.get("key", [])
    return {
        "bucket": key_item(key, 0),
        "domain": key_item(key, 1),
        "dialers": split_best(key_item(key, 2)),
        "private": split_best(key_item(key, 3)),
    }


def feedback_fields(gap: dict[str, Any]) -> dict[str, Any]:
    key = gap.get("key", [])
    if isinstance(key, list) and len(key) >= 6:
        return {
            "bucket": key_item(key, 0),
            "domain": key_item(key, 1),
            "scope": key_item(key, 2),
            "plan": key_item(key, 3),
            "selected": key_item(key, 4),
            "best": split_best(key_item(key, 5)),
        }
    return {
        "bucket": key_item(key, 0),
        "domain": key_item(key, 1),
        "scope": "dialer-bound",
        "plan": key_item(key, 2),
        "selected": key_item(key, 3),
        "best": split_best(key_item(key, 4)),
    }


def key_item(items: Any, index: int) -> str:
    if isinstance(items, list) and index < len(items):
        return str(items[index])
    return "<none>"


def split_best(value: str) -> list[str]:
    return [item for item in value.split(",") if item]


def target_family(host: str) -> str:
    labels = [item for item in host.lower().strip(".").split(".") if item]
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return labels[0] if labels else "<unknown>"


def sum_int(items: list[dict[str, Any]], key: str) -> int:
    total = 0
    for item in items:
        try:
            total += int(item.get(key) or 0)
        except (TypeError, ValueError):
            continue
    return total


def min_float(items: list[dict[str, Any]], key: str) -> float | None:
    values = []
    for item in items:
        try:
            value = float(item.get(key))
        except (TypeError, ValueError):
            continue
        values.append(value)
    return min(values) if values else None


def write_quality_report(path: Path, state: dict[str, Any]) -> None:
    lines = [
        "# Dynet Probe Quality State",
        "",
        f"- observations: `{state['source']['freshObservations']}` fresh / `{state['source']['observations']}` total",
        f"- feedback observations: `{state['source'].get('feedbackObservations', 0)}`",
        f"- ttl: `{state['ttlSecs']}` seconds",
        f"- window: `{state['windowSecs']}` seconds",
        "",
        "## Outbounds",
        "",
    ]
    for item in state["outbounds"]:
        family = item.get("targetFamily", "*")
        lines.append(
            f"- `{item['outbound']}` scope=`{item.get('scope', '*')}` "
            f"dialer=`{item.get('dialer', '*')}` private=`{item.get('private', '*')}` "
            f"family=`{family}` verdict=`{item['verdict']}` "
            f"attempts={item['attempts']} failures={item['failures']} "
            f"errorRate={item['errorRate']}"
        )
    promotion = state.get("plannerFeedback", {}).get("promotion")
    if isinstance(promotion, dict):
        lines.extend([
            "",
            "## Quality Gap Promotion",
            "",
            f"- action: `{promotion.get('action')}`",
            f"- eligible: `{promotion.get('eligible')}`",
            f"- proofs: `{promotion.get('proofs')}`",
        ])
        for item in promotion.get("gates", []):
            lines.append(
                f"- `{item['name']}` passed=`{item['passed']}` "
                f"value=`{item['value']}` required=`{item['required']}`"
            )
        lines.extend(promotion_context.markdown_lines(promotion))
    if state["signals"]:
        lines.extend(["", "## Signals", ""])
        for item in state["signals"]:
            lines.append(signal_line(item))
    path.write_text("\n".join(lines) + "\n")


def signal_line(item: dict[str, Any]) -> str:
    if item["type"] == "private-source-policy":
        return (
            f"- `{item['type']}` action=`{item.get('action', 'observe')}` "
            f"private=`{','.join(item.get('private', [])) or '*'}` "
            f"family=`{item.get('targetFamily', '*')}`"
        )
    if item["type"] == "cascade-fallback":
        return (
            f"- `{item['type']}` action=`{item.get('action', 'observe')}` "
            f"fallback=`{item.get('fallbackType')}` "
            f"failed=`{item.get('failedBound')}` "
            f"recovered=`{item.get('recoveredBound')}` "
            f"replaySafe=`{item.get('replaySafe')}`"
        )
    return (
        f"- `{item['type']}` action=`{item.get('action', 'observe')}` "
        f"outbound=`{item['outbound']}` scope=`{item.get('scope', '*')}` "
        f"family=`{item.get('targetFamily', '*')}`"
    )
