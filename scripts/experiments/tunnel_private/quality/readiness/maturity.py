from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from tunnel_private_config import write_json
from tunnel_private.quality.readiness import (
    flow_refresh,
    runtime as readiness_runtime,
)
from tunnel_private.quality.readiness.reporting.maturity_markdown import write_markdown
from tunnel_private.quality.readiness.supplemental import cascade_stage


MATURITY_SCHEMA = "dynet-tunnel-private-adapter-maturity/v1alpha1"


def command_adapter_maturity(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = adapter_maturity_summary(
        adapter_type=str(args.adapter_type),
        readiness_path=Path(args.readiness),
        runtime_paths=[Path(path) for path in getattr(args, "runtime_evidence", []) or []],
        flow_refresh_paths=[
            Path(path) for path in getattr(args, "flow_refresh_evidence", []) or []
        ],
        cascade_stage_paths=[
            Path(path) for path in getattr(args, "cascade_stage_evidence", []) or []
        ],
        minimums={
            "productTargets": int(args.min_product_targets),
            "runtimeRuns": int(args.min_runtime_runs),
            "runtimeWorkload": int(args.min_workload_attempted),
            "runtimeTargets": int(args.min_runtime_targets),
            "primaryCandidates": int(args.min_primary_candidates),
        },
    )
    write_json(output_dir / "summary.json", summary)
    write_markdown(output_dir / "summary.md", summary)
    print(json.dumps(print_summary(output_dir, summary), sort_keys=True))
    return 0 if summary["sourceCount"] else 1


def adapter_maturity_summary(
    *,
    adapter_type: str,
    readiness_path: Path,
    runtime_paths: list[Path],
    flow_refresh_paths: list[Path] | None = None,
    cascade_stage_paths: list[Path] | None = None,
    minimums: dict[str, int],
) -> dict[str, Any]:
    readiness = readiness_summary(readiness_path)
    runtime_sources = [runtime_source(path) for path in runtime_paths]
    flow_refresh_sources = [
        flow_refresh.source_summary(path) for path in flow_refresh_paths or []
    ]
    cascade_stage_sources = [
        cascade_stage.source_summary(path) for path in cascade_stage_paths or []
    ]
    runtime = runtime_summary(
        runtime_sources,
        readiness,
        flow_refresh_sources,
        cascade_stage_sources,
    )
    gates = maturity_gates(readiness, runtime, minimums)
    conclusion = maturity_conclusion(gates, runtime)
    return {
        "schema": MATURITY_SCHEMA,
        "adapterType": adapter_type,
        "sourceCount": (
            int(bool(readiness))
            + len(runtime_sources)
            + len(flow_refresh_sources)
            + len(cascade_stage_sources)
        ),
        "status": conclusion["status"],
        "recommendedUse": conclusion["recommendedUse"],
        "plannerPenaltySafe": False,
        "readiness": readiness,
        "runtime": runtime,
        "minimums": minimums,
        "gates": gates,
        "conclusion": conclusion,
        "privacy": privacy_summary(runtime_sources),
        "sources": {
            "readiness": str(readiness_path),
            "runtime": runtime_sources,
            "flowRefresh": flow_refresh_sources,
            "cascadeStage": cascade_stage_sources,
        },
    }


def readiness_summary(path: Path) -> dict[str, Any]:
    summary = load_json(path)
    product = (summary.get("productEvidence") or {}).get("product-e2e") or {}
    runtime = summary.get("runtimeEvidence") or {}
    conclusion = summary.get("conclusion") or {}
    targets = [str(target) for target in product.get("targets", []) if target]
    return {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "status": str(summary.get("status") or "missing"),
        "recommendedUse": str(summary.get("recommendedUse") or ""),
        "readyForMainlineAdapterWork": bool(conclusion.get("readyForMainlineAdapterWork")),
        "productRuns": int(product.get("runs") or 0),
        "productFailed": int(product.get("failed") or 0),
        "productTargets": targets,
        "productTargetHosts": sorted({host_from_url(target) for target in targets if host_from_url(target)}),
        "runtimeClean": bool(runtime.get("clean")),
        "runtimeRuns": int(runtime.get("runs") or 0),
        "runtimeFailedRuns": int(runtime.get("failedRuns") or 0),
    }


def runtime_source(path: Path) -> dict[str, Any]:
    source = readiness_runtime.source_summary(path)
    summary = load_json(path)
    runs = [run for run in summary.get("runs", []) if isinstance(run, dict)]
    return {
        **source,
        "primarySelectedCandidates": selected_counts(runs, role="primary"),
        "attemptSelectedCandidates": selected_counts(runs, role="attempt"),
        "runtimeTargetHosts": sorted(runtime_target_hosts(runs)),
        "maxCandidateCount": max_candidate_count(runs),
    }


def runtime_summary(
    sources: list[dict[str, Any]],
    readiness: dict[str, Any],
    flow_refresh_sources: list[dict[str, Any]] | None = None,
    cascade_stage_sources: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if not sources:
        runtime = flow_refresh.merge_runtime_summary(
            runtime_from_readiness(readiness),
            flow_refresh_sources or [],
        )
        return cascade_stage.merge_runtime_summary(runtime, cascade_stage_sources or [])
    aggregate = readiness_runtime.evidence_summary(sources)
    primary_counts = merge_count_rows([source["primarySelectedCandidates"] for source in sources])
    attempt_counts = merge_count_rows([source["attemptSelectedCandidates"] for source in sources])
    runtime_hosts = sorted({
        host for source in sources for host in source.get("runtimeTargetHosts", []) if host
    })
    runtime = {
        **aggregate,
        "primarySelectedCandidates": count_rows(primary_counts),
        "attemptSelectedCandidates": count_rows(attempt_counts),
        "uniquePrimarySelectedCandidates": len(primary_counts),
        "uniqueAttemptSelectedCandidates": len(attempt_counts),
        "runtimeTargetHosts": runtime_hosts,
        "runtimeTargetHostCount": len(runtime_hosts),
        "maxCandidateCount": max((int(source.get("maxCandidateCount") or 0) for source in sources), default=0),
    }
    runtime = flow_refresh.merge_runtime_summary(runtime, flow_refresh_sources or [])
    return cascade_stage.merge_runtime_summary(runtime, cascade_stage_sources or [])


def runtime_from_readiness(readiness: dict[str, Any]) -> dict[str, Any]:
    return {
        "sourceCount": 0,
        "runs": int(readiness.get("runtimeRuns") or 0),
        "failedRuns": int(readiness.get("runtimeFailedRuns") or 0),
        "clean": bool(readiness.get("runtimeClean")),
        "workloadAttempted": 0,
        "workloadSuccess": 0,
        "workloadFlowMatchedEntries": 0,
        "workloadFlowCoveredEntries": 0,
        "workloadFailedBySurface": [],
        "workloadFailedByStage": [],
        "workloadErrors": [],
        "workloadFlowUnmatchedFailureSurfaces": [],
        "qualityBoundCandidateSets": 0,
        "qualityBoundSelectedWithQuality": 0,
        "qualityBoundSelectedBehind": 0,
        "qualityBoundFallbackCandidateSets": 0,
        "qualityBoundFallbackSelectedBehind": 0,
        "tcpFlowPathComplete": 0,
        "tcpFlowPayloadBidirectional": 0,
        "tcpFlowFailed": 0,
        "tcpFlowStageFailed": 0,
        "workloadFlowMatchedRecoveredFailureEntries": 0,
        "workloadFlowMatchedFlowStageFailedAttempts": 0,
        "tcpSessionFailures": 0,
        "primarySelectedCandidates": [],
        "attemptSelectedCandidates": [],
        "uniquePrimarySelectedCandidates": 0,
        "uniqueAttemptSelectedCandidates": 0,
        "runtimeTargetHosts": [],
        "runtimeTargetHostCount": 0,
        "maxCandidateCount": 0,
    }


def maturity_gates(
    readiness: dict[str, Any],
    runtime: dict[str, Any],
    minimums: dict[str, int],
) -> list[dict[str, Any]]:
    return [
        gate("readiness-ready", "required", readiness["readyForMainlineAdapterWork"], readiness["status"], "ready"),
        gate("runtime-clean", "required", bool(runtime["clean"]), runtime["failedRuns"], 0),
        gate(
            "primary-quality-selection-clean",
            "required",
            runtime["qualityBoundCandidateSets"] > 0
            and runtime["qualityBoundSelectedWithQuality"] == runtime["qualityBoundCandidateSets"]
            and runtime["qualityBoundSelectedBehind"] == 0,
            runtime["qualityBoundSelectedWithQuality"],
            runtime["qualityBoundCandidateSets"],
        ),
        gate(
            "tcp-path-payload-clean",
            "required",
            runtime["tcpFlowFailed"] == 0
            and runtime["tcpSessionFailures"] == 0
            and runtime["tcpFlowPathComplete"] >= runtime["qualityBoundCandidateSets"]
            and runtime["tcpFlowPayloadBidirectional"] >= runtime["qualityBoundCandidateSets"],
            runtime["tcpFlowPayloadBidirectional"],
            runtime["qualityBoundCandidateSets"],
        ),
        gate(
            "product-target-diversity",
            "maturity",
            len(readiness["productTargetHosts"]) >= minimums["productTargets"],
            len(readiness["productTargetHosts"]),
            minimums["productTargets"],
        ),
        gate(
            "runtime-repeat-depth",
            "maturity",
            runtime["runs"] >= minimums["runtimeRuns"],
            runtime["runs"],
            minimums["runtimeRuns"],
        ),
        gate(
            "runtime-workload-depth",
            "maturity",
            runtime["workloadAttempted"] >= minimums["runtimeWorkload"]
            and runtime["workloadSuccess"] == runtime["workloadAttempted"],
            runtime["workloadAttempted"],
            minimums["runtimeWorkload"],
        ),
        gate(
            "runtime-target-diversity",
            "maturity",
            runtime["runtimeTargetHostCount"] >= minimums["runtimeTargets"],
            runtime["runtimeTargetHostCount"],
            minimums["runtimeTargets"],
        ),
        gate(
            "primary-candidate-diversity",
            "maturity",
            runtime["uniquePrimarySelectedCandidates"] >= minimums["primaryCandidates"],
            runtime["uniquePrimarySelectedCandidates"],
            minimums["primaryCandidates"],
        ),
    ]


def maturity_conclusion(gates: list[dict[str, Any]], runtime: dict[str, Any]) -> dict[str, Any]:
    failed_required = [item["id"] for item in gates if item["severity"] == "required" and not item["passed"]]
    failed_maturity = [item["id"] for item in gates if item["severity"] == "maturity" and not item["passed"]]
    status = maturity_status(failed_required, failed_maturity)
    return {
        "status": status,
        "recommendedUse": recommended_use(status),
        "candidateMature": status == "candidate-mature",
        "promotionEvaluationEligible": status == "candidate-mature",
        "plannerPenaltySafe": False,
        "notMatureReasons": failed_required + failed_maturity,
        "recoveredFallbackObserved": int(runtime["qualityBoundFallbackCandidateSets"]) > 0,
        "recoveredStagePressureObserved": recovered_stage_pressure(runtime),
        "cascadeStagePressureObserved": cascade_stage_pressure(runtime),
        "nextActions": next_actions(failed_required, failed_maturity, runtime),
    }


def maturity_status(failed_required: list[str], failed_maturity: list[str]) -> str:
    if failed_required:
        return "blocked"
    if failed_maturity:
        return "observe-more"
    return "candidate-mature"


def recommended_use(status: str) -> str:
    if status == "candidate-mature":
        return "eligible-for-broader-adapter-runtime-promotion-evaluation"
    if status == "observe-more":
        return "continue-mainline-runtime-observe"
    return "do-not-promote-adapter"


def next_actions(
    failed_required: list[str],
    failed_maturity: list[str],
    runtime: dict[str, Any],
) -> list[dict[str, Any]]:
    actions = [action_for_gate(gate_id) for gate_id in failed_required + failed_maturity]
    if int(runtime["qualityBoundFallbackCandidateSets"]) > 0:
        actions.append(action(
            "retain-fallback-recovery-observe-only",
            "runtime",
            "observe",
            "Recovered fallback selections are visible but are not planner penalty evidence.",
        ))
    if recovered_stage_pressure(runtime):
        actions.append(action(
            "retain-recovered-stage-pressure-observe-only",
            "runtime",
            "observe",
            "Recovered outbound-stage pressure is visible but is not planner penalty evidence.",
        ))
    if cascade_stage_pressure(runtime):
        actions.append(action(
            "retain-cascade-stage-pressure-observe-only",
            "runtime",
            "observe",
            "Cascade failure-stage pressure is visible but is not planner penalty evidence.",
        ))
    actions.append(action(
        "keep-planner-penalties-disabled",
        "policy",
        "required",
        "This artifact evaluates adapter maturity, not repeated node failure promotion.",
    ))
    return actions


def recovered_stage_pressure(runtime: dict[str, Any]) -> bool:
    return (
        int(runtime["tcpFlowStageFailed"]) > 0
        or int(runtime["workloadFlowMatchedRecoveredFailureEntries"]) > 0
        or int(runtime["workloadFlowMatchedFlowStageFailedAttempts"]) > 0
    )


def cascade_stage_pressure(runtime: dict[str, Any]) -> bool:
    return (
        int(runtime["cascadeStageFailedAttempts"]) > 0
        or int(runtime["cascadeStageRetryableFailures"]) > 0
        or int(runtime["cascadeStageStoppedFailures"]) > 0
    )


def action_for_gate(gate_id: str) -> dict[str, Any]:
    mapping = {
        "readiness-ready": ("fix-readiness-gate", "readiness", "required"),
        "runtime-clean": ("collect-clean-runtime-repeat", "runtime", "required"),
        "primary-quality-selection-clean": ("fix-primary-quality-selection", "runtime", "required"),
        "tcp-path-payload-clean": ("fix-runtime-tcp-path-payload", "runtime", "required"),
        "product-target-diversity": ("collect-more-product-target-families", "product-e2e", "follow-up"),
        "runtime-repeat-depth": ("collect-more-runtime-repeat-windows", "runtime", "follow-up"),
        "runtime-workload-depth": ("collect-more-runtime-workload-entries", "runtime", "follow-up"),
        "runtime-target-diversity": ("collect-more-runtime-target-families", "runtime", "follow-up"),
        "primary-candidate-diversity": ("collect-more-primary-candidate-diversity", "runtime", "follow-up"),
    }
    action_id, evidence, priority = mapping[gate_id]
    return action(action_id, evidence, priority, f"Gate `{gate_id}` is not satisfied.")


def action(action_id: str, evidence: str, priority: str, reason: str) -> dict[str, Any]:
    return {
        "id": action_id,
        "evidence": evidence,
        "priority": priority,
        "reason": reason,
        "plannerPenaltySafe": False,
    }


def gate(
    gate_id: str,
    severity: str,
    passed: bool,
    actual: Any,
    expected: Any,
) -> dict[str, Any]:
    return {
        "id": gate_id,
        "severity": severity,
        "passed": bool(passed),
        "actual": actual,
        "expected": expected,
    }


def selected_counts(runs: list[dict[str, Any]], *, role: str) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for row in bound_rows(runs):
        selected = str(row.get("selected") or "")
        if not selected:
            continue
        selection_role = str(row.get("selectionRole") or "primary")
        if role == "primary" and selection_role != "primary":
            continue
        counts[selected] = counts.get(selected, 0) + 1
    return count_rows(counts)


def bound_rows(runs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for run in runs:
        bound = run.get("boundSelection")
        if isinstance(bound, dict):
            rows.extend(row for row in bound.get("rows", []) if isinstance(row, dict))
    return rows


def runtime_target_hosts(runs: list[dict[str, Any]]) -> set[str]:
    hosts = set()
    for run in runs:
        workload = run.get("workloadFlow")
        if isinstance(workload, dict):
            hosts.update(str(row.get("domain")) for row in workload.get("rows", []) if row.get("domain"))
        identity = run.get("targetIdentity")
        if isinstance(identity, dict):
            hosts.update(host.split(":", 1)[0] for host in identity.get("domainTargets", []) if host)
    return {host for host in hosts if host}


def max_candidate_count(runs: list[dict[str, Any]]) -> int:
    return max((int(row.get("candidateCount") or 0) for row in bound_rows(runs)), default=0)


def merge_count_rows(count_sets: list[list[dict[str, Any]]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for count_set in count_sets:
        for row in count_set:
            key = str(row.get("key") or "")
            if key:
                counts[key] = counts.get(key, 0) + int(row.get("count") or 0)
    return dict(sorted(counts.items()))


def count_rows(counts: dict[str, int]) -> list[dict[str, Any]]:
    return [{"key": key, "count": count} for key, count in sorted(counts.items())]


def host_from_url(raw: str) -> str:
    parsed = urlparse(raw)
    return parsed.hostname or ""


def privacy_summary(runtime_sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "runtimeSourceCount": len(runtime_sources),
        "rawSecretsStored": False,
        "rawLogsStored": False,
        "identityInformationSent": False,
    }


def print_summary(output_dir: Path, summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "outputDir": str(output_dir),
        "adapterType": summary["adapterType"],
        "status": summary["status"],
        "recommendedUse": summary["recommendedUse"],
        "plannerPenaltySafe": summary["plannerPenaltySafe"],
    }


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text())
