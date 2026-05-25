from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from dynet_mainline.adapter_coverage_sources import BASELINE_CLEAN_FIELDS
from dynet_mainline.runtime_surface.cascade_stop import (
    runtime_cascade_stop_source,
    runtime_cascade_stop_summary,
)
from dynet_mainline.runtime_surface.round_gap import (
    runtime_round_gap_source,
    runtime_round_gap_summary,
)
from dynet_mainline.runtime_surface.round_gap_compare import (
    round_gap_compare_source,
    round_gap_compare_summary,
)
from dynet_mainline.runtime_surface.tcp.stage_pressure import (
    runtime_stage_pressure_source,
    runtime_stage_pressure_summary,
)
from tunnel_private_config import write_json
from scripts.lib.jsonio import load_summary


SCHEMA = "dynet-mainline-runtime-hardening-handoff/v1alpha1"
EXTERNAL_PROVIDER_GAPS = {
    "provider-acquisition-required",
    "current-provider-candidate-missing",
}
BASELINE_REQUIRED = """
runtimeWorkloadFlowClean runtimeWorkloadSurfaceClean runtimePayloadSurfaceClean
runtimeCloseSurfaceClean runtimeStageSurfaceClean runtimeOutboundAttemptClean
runtimeFailurePropagationClean runtimeStageChainClean runtimeStageOrderClean
runtimeFailureAttributionClean runtimeFailureImpactClean runtimeOutboundRetryClean
runtimeTcpTargetClean runtimeCascadeStopClean runtimeStagePressureClean
runtimeRoundGapClean runtimeRoundGapCompareClean
""".split()
STAGE_REMAINS_STATUSES = {
    "packet-terminal-cleared-stage-remains",
    "schedule-lag-separated-outbound-stage-remains",
}


def command_mainline_runtime_handoff(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = runtime_hardening_summary(
        mainline_baseline_paths=paths(args.mainline_baseline),
        adapter_coverage_paths=paths(args.adapter_coverage),
        runtime_stage_pressure_paths=paths(args.runtime_stage_pressure),
        runtime_cascade_stop_paths=paths(args.runtime_cascade_stop),
        runtime_round_gap_paths=paths(args.runtime_round_gap),
        round_gap_compare_paths=paths(args.runtime_round_gap_compare),
    )
    write_json(output_dir / "summary.json", summary)
    write_markdown(output_dir / "summary.md", summary)
    print(json.dumps(print_summary(output_dir, summary), sort_keys=True))
    return 0 if summary["sourceCount"] else 1


def paths(values: list[str]) -> list[Path]:
    return [Path(value) for value in values or []]


def runtime_hardening_summary(
    *,
    mainline_baseline_paths: list[Path],
    adapter_coverage_paths: list[Path],
    runtime_stage_pressure_paths: list[Path],
    runtime_cascade_stop_paths: list[Path],
    runtime_round_gap_paths: list[Path],
    round_gap_compare_paths: list[Path],
) -> dict[str, Any]:
    baseline = baseline_summary([baseline_source(path) for path in mainline_baseline_paths])
    coverage = coverage_summary([coverage_source(path) for path in adapter_coverage_paths])
    stage_pressure = runtime_stage_pressure_summary(
        [runtime_stage_pressure_source(path) for path in runtime_stage_pressure_paths]
    )
    cascade_stop = runtime_cascade_stop_summary(
        [runtime_cascade_stop_source(path) for path in runtime_cascade_stop_paths]
    )
    round_gap = runtime_round_gap_summary(
        [runtime_round_gap_source(path) for path in runtime_round_gap_paths]
    )
    round_gap_compare = round_gap_compare_summary(
        [round_gap_compare_source(path) for path in round_gap_compare_paths]
    )
    evidence = evidence_summary(
        stage_pressure,
        cascade_stop,
        round_gap,
        round_gap_compare,
    )
    target = target_summary(evidence, coverage)
    gates = handoff_gates(baseline, coverage, evidence)
    conclusion = conclusion_summary(gates, target)
    return {
        "schema": SCHEMA,
        "sourceCount": (
            baseline["sourceCount"]
            + coverage["sourceCount"]
            + stage_pressure["sourceCount"]
            + cascade_stop["sourceCount"]
            + round_gap["sourceCount"]
            + round_gap_compare["sourceCount"]
        ),
        "status": conclusion["status"],
        "recommendedUse": conclusion["recommendedUse"],
        "plannerPenaltySafe": False,
        "qualityPenaltySafe": False,
        "mainlineBaseline": baseline,
        "adapterCoverage": coverage,
        "runtimeStagePressure": stage_pressure,
        "runtimeCascadeStop": cascade_stop,
        "runtimeRoundGap": round_gap,
        "runtimeRoundGapCompare": round_gap_compare,
        "evidence": evidence,
        "target": target,
        "gates": gates,
        "conclusion": conclusion,
        "privacy": privacy_summary(evidence),
    }


def baseline_source(path: Path) -> dict[str, Any]:
    summary = load_summary(path)
    conclusion = summary.get("conclusion") or {}
    adapter = summary.get("adapterProductEffect") or {}
    return {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "status": str(summary.get("status") or ""),
        "adapterTypes": sorted(str(item) for item in adapter.get("adapterTypes", []) if item),
        "plannerPenaltySafe": bool(summary.get("plannerPenaltySafe"))
        or bool(conclusion.get("plannerPenaltySafe")),
        "qualityPenaltySafe": bool(summary.get("qualityPenaltySafe"))
        or bool(conclusion.get("qualityPenaltySafe")),
        "cleanFields": {
            field: bool(conclusion.get(field)) for field in BASELINE_CLEAN_FIELDS
        },
    }


def baseline_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    missing = sorted({
        field
        for source in sources
        for field in BASELINE_REQUIRED
        if not source["cleanFields"].get(field)
    })
    return {
        "sourceCount": len(sources),
        "statuses": sorted({source["status"] for source in sources if source["status"]}),
        "adapterTypes": sorted({item for source in sources for item in source["adapterTypes"]}),
        "missingRequiredCleanFields": missing,
        "plannerPenaltySafe": any(source["plannerPenaltySafe"] for source in sources),
        "qualityPenaltySafe": any(source["qualityPenaltySafe"] for source in sources),
        "clean": bool(sources)
        and not missing
        and all(source["status"] == "mainline-baseline-current-clean" for source in sources)
        and not any(source["plannerPenaltySafe"] or source["qualityPenaltySafe"] for source in sources),
        "sources": sources,
    }


def coverage_source(path: Path) -> dict[str, Any]:
    summary = load_summary(path)
    conclusion = summary.get("conclusion") or {}
    adapters = [row for row in summary.get("adapters", []) if isinstance(row, dict)]
    gaps = [row for row in conclusion.get("gaps", []) if isinstance(row, dict)]
    product_controls = sorted(
        str(row.get("adapterType") or "")
        for row in adapters
        if row.get("coverageLevel") == "product-effect-baseline"
    )
    return {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "status": str(summary.get("status") or ""),
        "runtimeWorkUnblocked": bool(conclusion.get("runtimeWorkUnblocked")),
        "coverageComplete": bool(conclusion.get("coverageComplete")),
        "productControls": [item for item in product_controls if item],
        "gapAdapters": sorted(str(row.get("adapterType") or "") for row in gaps),
        "externalProviderGapOnly": external_provider_gap_only(gaps),
        "plannerPenaltySafe": bool(summary.get("plannerPenaltySafe"))
        or bool(conclusion.get("plannerPenaltySafe")),
        "qualityPenaltySafe": bool(summary.get("qualityPenaltySafe"))
        or bool(conclusion.get("qualityPenaltySafe")),
    }


def external_provider_gap_only(gaps: list[dict[str, Any]]) -> bool:
    return bool(gaps) and all(
        row.get("gaps")
        and all(str(gap) in EXTERNAL_PROVIDER_GAPS for gap in row.get("gaps", []))
        for row in gaps
    )


def coverage_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "statuses": sorted({source["status"] for source in sources if source["status"]}),
        "runtimeWorkUnblocked": any(source["runtimeWorkUnblocked"] for source in sources),
        "coverageComplete": any(source["coverageComplete"] for source in sources),
        "externalProviderGapOnly": any(source["externalProviderGapOnly"] for source in sources),
        "productControls": sorted({item for source in sources for item in source["productControls"]}),
        "gapAdapters": sorted({item for source in sources for item in source["gapAdapters"] if item}),
        "plannerPenaltySafe": any(source["plannerPenaltySafe"] for source in sources),
        "qualityPenaltySafe": any(source["qualityPenaltySafe"] for source in sources),
        "clean": bool(sources)
        and any(
            source["coverageComplete"] or source["runtimeWorkUnblocked"]
            for source in sources
        )
        and not any(source["plannerPenaltySafe"] or source["qualityPenaltySafe"] for source in sources),
        "sources": sources,
    }


def evidence_summary(
    stage_pressure: dict[str, Any],
    cascade_stop: dict[str, Any],
    round_gap: dict[str, Any],
    round_gap_compare: dict[str, Any],
) -> dict[str, Any]:
    raw_keys = sorted({
        *stage_pressure.get("rawDetailKeys", []),
        *cascade_stop.get("rawDetailKeys", []),
        *round_gap.get("rawDetailKeys", []),
        *round_gap_compare.get("rawDetailKeys", []),
    })
    penalties = any_source_policy(
        stage_pressure,
        cascade_stop,
        round_gap,
        round_gap_compare,
    )
    return {
        "stageSurfaces": stage_pressure.get("stageSurfaces", []),
        "stageDispositions": stage_pressure.get("stageDispositions", []),
        "cascadeScopes": stage_pressure.get("cascadeScopes", []),
        "cascadeStopReasons": stage_pressure.get("cascadeStopReasons", []),
        "replayScopes": stage_pressure.get("replayScopes", []),
        "pendingWaitClasses": sorted({
            *stage_pressure.get("pendingWaitClasses", []),
            *cascade_stop.get("pendingWaitClasses", []),
            *round_gap.get("pendingWaitClasses", []),
        }),
        "failureStagePendingWaitClasses": cascade_stop.get("failureStagePendingWaitClasses", []),
        "stageFailureEvents": int(stage_pressure.get("stageFailureEvents") or 0),
        "workloadFailure": int(stage_pressure.get("workloadFailure") or 0),
        "recoveredFlowCount": int(stage_pressure.get("recoveredFlowCount") or 0),
        "selectedBehind": int(stage_pressure.get("selectedBehind") or 0),
        "tcpSlotPressureEvents": int(stage_pressure.get("tcpSlotPressureEvents") or 0),
        "cascadeBoundExhaustedRows": int(cascade_stop.get("boundExhaustedRows") or 0),
        "roundGapStatuses": round_gap.get("statuses", []),
        "roundGapCompareStatuses": round_gap_compare.get("statuses", []),
        "remainingMechanisms": round_gap_compare.get("remainingMechanisms", []),
        "rawDetailKeys": raw_keys,
        "plannerPenaltySafe": penalties["plannerPenaltySafe"],
        "qualityPenaltySafe": penalties["qualityPenaltySafe"],
        "clean": (
            stage_pressure.get("clean")
            and cascade_stop.get("clean")
            and round_gap.get("clean")
            and round_gap_compare.get("clean")
            and stage_pressure.get("stageDispositions") == ["pending-timeout"]
            and stage_pressure.get("cascadeScopes") == ["bound"]
            and stage_pressure.get("replayScopes") == ["pre-payload"]
            and int(stage_pressure.get("selectedBehind") or 0) == 0
            and int(stage_pressure.get("tcpSlotPressureEvents") or 0) == 0
            and int(cascade_stop.get("boundExhaustedRows") or 0) > 0
            and any(
                status in STAGE_REMAINS_STATUSES
                for status in round_gap_compare.get("statuses", [])
            )
            and not raw_keys
            and not penalties["plannerPenaltySafe"]
            and not penalties["qualityPenaltySafe"]
        ),
    }


def any_source_policy(*sections: dict[str, Any]) -> dict[str, bool]:
    return {
        "plannerPenaltySafe": any(
            bool(source.get("plannerPenaltySafe"))
            for section in sections
            for source in section.get("sources", [])
        ),
        "qualityPenaltySafe": any(
            bool(source.get("qualityPenaltySafe"))
            for section in sections
            for source in section.get("sources", [])
        ),
    }


def target_summary(evidence: dict[str, Any], coverage: dict[str, Any]) -> dict[str, Any]:
    stage_surface = only(evidence["stageSurfaces"])
    stage_name, adapter_type = split_stage_surface(stage_surface)
    focused = stage_name == "trojan-tls-handshake" and adapter_type == "trojan" and evidence["stageDispositions"] == ["pending-timeout"]
    wait_classes = evidence["pendingWaitClasses"]
    wait_class_focused = wait_classes == ["socket-read-timeout"]
    return {
        "action": (
            "harden-trojan-tls-handshake-pending-timeout-path"
            if focused
            else "separate-trojan-tls-handshake-wait-classes-before-control-change"
            if stage_name == "trojan-tls-handshake" and adapter_type == "trojan" and wait_classes
            else "inspect-runtime-stage-pressure-profile"
        ),
        "adapterType": adapter_type,
        "stage": stage_name,
        "stageSurface": stage_surface,
        "dispositions": evidence["stageDispositions"],
        "pendingWaitClasses": wait_classes,
        "failureStagePendingWaitClasses": evidence["failureStagePendingWaitClasses"],
        "cascadeScope": only(evidence["cascadeScopes"]),
        "replayScope": only(evidence["replayScopes"]),
        "implementationOwner": "crates/dynet-runtime/src/outbound/trojan",
        "productControls": coverage["productControls"],
        "guards": [
            "keep-planner-quality-node-penalties-disabled",
            "preserve-pre-payload-bound-retry-only",
            "do-not-retain-raw-flow-or-candidate-identities",
            "revalidate-mainline-baseline-after-runtime-change",
        ],
        "focused": focused,
        "waitClassFocused": wait_class_focused,
    }


def handoff_gates(
    baseline: dict[str, Any],
    coverage: dict[str, Any],
    evidence: dict[str, Any],
) -> list[dict[str, Any]]:
    return [
        gate("mainline-baseline-clean", baseline["clean"], baseline["statuses"], "clean"),
        gate("adapter-runtime-work-unblocked", coverage["clean"], coverage_status(coverage), "unblocked"),
        gate("target-product-control-present", "trojan" in coverage["productControls"], coverage["productControls"], "trojan"),
        gate("stage-pressure-focused", evidence["clean"], evidence_payload(evidence), "focused-bound-pre-payload"),
        gate("policy-penalties-disabled", not evidence["plannerPenaltySafe"] and not evidence["qualityPenaltySafe"], policy_payload(baseline, coverage, evidence), "false"),
        gate("aggregate-retention-clean", not evidence["rawDetailKeys"], evidence["rawDetailKeys"], []),
    ]


def coverage_status(coverage: dict[str, Any]) -> dict[str, Any]:
    return {
        "statuses": coverage["statuses"],
        "runtimeWorkUnblocked": coverage["runtimeWorkUnblocked"],
        "externalProviderGapOnly": coverage["externalProviderGapOnly"],
        "gapAdapters": coverage["gapAdapters"],
    }


def evidence_payload(evidence: dict[str, Any]) -> dict[str, Any]:
    return {
        "stageSurfaces": evidence["stageSurfaces"],
        "stageDispositions": evidence["stageDispositions"],
        "cascadeScopes": evidence["cascadeScopes"],
        "replayScopes": evidence["replayScopes"],
        "pendingWaitClasses": evidence["pendingWaitClasses"],
        "failureStagePendingWaitClasses": evidence["failureStagePendingWaitClasses"],
        "selectedBehind": evidence["selectedBehind"],
        "tcpSlotPressureEvents": evidence["tcpSlotPressureEvents"],
        "roundGapCompareStatuses": evidence["roundGapCompareStatuses"],
    }


def policy_payload(
    baseline: dict[str, Any],
    coverage: dict[str, Any],
    evidence: dict[str, Any],
) -> dict[str, bool]:
    return {
        "baselinePlannerPenaltySafe": baseline["plannerPenaltySafe"],
        "baselineQualityPenaltySafe": baseline["qualityPenaltySafe"],
        "coveragePlannerPenaltySafe": coverage["plannerPenaltySafe"],
        "coverageQualityPenaltySafe": coverage["qualityPenaltySafe"],
        "evidencePlannerPenaltySafe": evidence["plannerPenaltySafe"],
        "evidenceQualityPenaltySafe": evidence["qualityPenaltySafe"],
    }


def conclusion_summary(gates: list[dict[str, Any]], target: dict[str, Any]) -> dict[str, Any]:
    not_ready = [item["id"] for item in gates if not item["passed"]]
    ready = not not_ready and target["focused"]
    return {
        "status": (
            "runtime-hardening-handoff-ready"
            if ready
            else "runtime-hardening-handoff-needs-evidence"
        ),
        "recommendedUse": (
            "use-to-drive-next-runtime-implementation-slice"
            if ready
            else "collect-focused-runtime-hardening-evidence-first"
        ),
        "nextAction": target["action"],
        "notReadyReasons": not_ready,
        "plannerPenaltySafe": False,
        "qualityPenaltySafe": False,
        "policyChangeSafe": False,
    }


def gate(gate_id: str, passed: bool, actual: Any, expected: Any) -> dict[str, Any]:
    return {
        "id": gate_id,
        "severity": "required",
        "passed": bool(passed),
        "actual": actual,
        "expected": expected,
    }


def split_stage_surface(stage_surface: str) -> tuple[str, str]:
    if ":" not in stage_surface:
        return stage_surface, ""
    stage, adapter_type = stage_surface.split(":", 1)
    return stage, adapter_type


def only(items: list[str]) -> str:
    return items[0] if len(items) == 1 else ""


def privacy_summary(evidence: dict[str, Any]) -> dict[str, bool]:
    return {
        "rawLogsStored": False,
        "rawPacketsStored": False,
        "rawSecretsStored": False,
        "rawResponseBodiesStored": False,
        "rawResponseHeadersStored": False,
        "identityInformationSent": False,
        "cookiesSent": False,
        "authorizationSent": False,
        "accountStateStored": False,
        "rawDetailKeysStored": bool(evidence["rawDetailKeys"]),
    }


def print_summary(output_dir: Path, summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "outputDir": str(output_dir),
        "status": summary["status"],
        "nextAction": summary["conclusion"]["nextAction"],
        "notReadyReasons": summary["conclusion"]["notReadyReasons"],
        "plannerPenaltySafe": summary["plannerPenaltySafe"],
        "qualityPenaltySafe": summary["qualityPenaltySafe"],
    }


def write_markdown(path: Path, summary: dict[str, Any]) -> None:
    target = summary["target"]
    evidence = summary["evidence"]
    lines = [
        "# Dynet Mainline Runtime Hardening Handoff",
        "",
        f"- status: `{summary['status']}`",
        f"- recommended use: `{summary['recommendedUse']}`",
        f"- planner penalty safe: `{summary['plannerPenaltySafe']}`",
        f"- quality penalty safe: `{summary['qualityPenaltySafe']}`",
        "",
        "## Target",
        "",
        f"- action: `{target['action']}`",
        f"- owner: `{target['implementationOwner']}`",
        f"- stage: `{target['stageSurface']}`",
        f"- scope: cascade=`{target['cascadeScope']}` replay=`{target['replayScope']}`",
        f"- pending wait classes: `{target['pendingWaitClasses']}`",
        f"- product controls: `{target['productControls']}`",
        "",
        "## Evidence",
        "",
        f"- stage failures: `{evidence['stageFailureEvents']}` workloadFailure=`{evidence['workloadFailure']}` recoveredFlows=`{evidence['recoveredFlowCount']}`",
        f"- selectedBehind: `{evidence['selectedBehind']}` slotPressure=`{evidence['tcpSlotPressureEvents']}`",
        f"- pending wait classes: `{evidence['pendingWaitClasses']}` failureStage=`{evidence['failureStagePendingWaitClasses']}`",
        f"- round-gap compare: `{evidence['roundGapCompareStatuses']}` remaining=`{evidence['remainingMechanisms']}`",
        f"- raw detail keys: `{evidence['rawDetailKeys']}`",
        "",
        "## Gates",
        "",
    ]
    for item in summary["gates"]:
        lines.append(
            f"- `{item['id']}` passed=`{item['passed']}` "
            f"actual=`{item['actual']}` expected=`{item['expected']}`"
        )
    path.write_text("\n".join(lines) + "\n")
