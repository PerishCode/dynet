from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from tunnel_private_config import write_json
from tunnel_private.quality.readiness import product, runtime as readiness_runtime
from tunnel_private.quality.readiness.product_effect_policy import (
    gate,
    product_effect_conclusion,
)
from tunnel_private.quality.readiness.reporting.product_effect_markdown import (
    write_markdown,
)


PRODUCT_EFFECT_SCHEMA = "dynet-tunnel-private-adapter-product-effect/v1alpha1"
TRANSPORT_EVIDENCE_SCHEMA = "dynet-tunnel-private-transport-evidence/v1alpha1"

def command_adapter_product_effect(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = adapter_product_effect_summary(
        adapter_type=str(args.adapter_type),
        maturity_path=Path(args.maturity),
        dynet_product_paths=[
            Path(path) for path in getattr(args, "dynet_product_evidence", []) or []
        ],
        clash_transport_paths=[
            Path(path) for path in getattr(args, "clash_transport_evidence", []) or []
        ],
        runtime_paths=[Path(path) for path in getattr(args, "runtime_evidence", []) or []],
        paired_paths=[Path(path) for path in getattr(args, "paired_evidence", []) or []],
        minimums={
            "dynetProductTargets": int(args.min_dynet_product_targets),
            "pairedWindows": int(args.min_paired_windows),
            "pairedEntries": int(args.min_paired_entries),
            "runtimeWorkloadEntries": int(args.min_runtime_workload_entries),
        },
    )
    write_json(output_dir / "summary.json", summary)
    write_markdown(output_dir / "summary.md", summary)
    print(json.dumps(print_summary(output_dir, summary), sort_keys=True))
    return 0 if summary["sourceCount"] else 1


def adapter_product_effect_summary(
    *,
    adapter_type: str,
    maturity_path: Path,
    dynet_product_paths: list[Path],
    clash_transport_paths: list[Path],
    runtime_paths: list[Path],
    paired_paths: list[Path],
    minimums: dict[str, int],
) -> dict[str, Any]:
    maturity = maturity_source(maturity_path)
    dynet = dynet_product_summary([
        dynet_product_source(path) for path in dynet_product_paths
    ])
    clash = clash_product_summary([
        clash_product_source(path) for path in clash_transport_paths
    ])
    runtime = runtime_product_summary([runtime_product_source(path) for path in runtime_paths])
    paired = paired_summary([paired_source(path) for path in paired_paths])
    gates = product_effect_gates(maturity, dynet, clash, runtime, paired, minimums)
    conclusion = product_effect_conclusion(gates, dynet, clash, paired, maturity)
    return {
        "schema": PRODUCT_EFFECT_SCHEMA,
        "adapterType": adapter_type,
        "sourceCount": 1 + dynet["sourceCount"] + clash["sourceCount"] + runtime["sourceCount"] + paired["sourceCount"],
        "status": conclusion["status"],
        "recommendedUse": conclusion["recommendedUse"],
        "plannerPenaltySafe": False,
        "minimums": minimums,
        "maturity": maturity,
        "dynetProduct": dynet,
        "clashProduct": clash,
        "dynetRuntimeProduct": runtime,
        "pairedProductEffect": paired,
        "gates": gates,
        "conclusion": conclusion,
        "privacy": privacy_summary(dynet, clash, runtime, paired),
        "sources": {
            "maturity": str(maturity_path),
            "dynetProduct": [source["path"] for source in dynet["sources"]],
            "clashTransport": [source["path"] for source in clash["sources"]],
            "runtime": [source["path"] for source in runtime["sources"]],
            "paired": [source["path"] for source in paired["sources"]],
        },
    }


def maturity_source(path: Path) -> dict[str, Any]:
    summary = load_json(path)
    readiness = summary.get("readiness") or {}
    runtime = summary.get("runtime") or {}
    conclusion = summary.get("conclusion") or {}
    return {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "status": str(summary.get("status") or "missing"),
        "recommendedUse": str(summary.get("recommendedUse") or ""),
        "candidateMature": summary.get("status") == "candidate-mature",
        "plannerPenaltySafe": bool(summary.get("plannerPenaltySafe")),
        "productTargetHosts": sorted(str(host) for host in readiness.get("productTargetHosts", [])),
        "runtimeTargetHosts": sorted(str(host) for host in runtime.get("runtimeTargetHosts", [])),
        "recoveredFallbackObserved": bool(conclusion.get("recoveredFallbackObserved")),
        "recoveredStagePressureObserved": bool(
            conclusion.get("recoveredStagePressureObserved")
        ),
        "cascadeStagePressureObserved": bool(
            conclusion.get("cascadeStagePressureObserved")
        ),
        "flowRefreshChangedRuns": int(runtime.get("flowRefreshChangedRuns") or 0),
        "flowRefreshSourceCount": int(runtime.get("flowRefreshSourceCount") or 0),
        "tcpFlowStageFailed": int(runtime.get("tcpFlowStageFailed") or 0),
        "cascadeStageSourceCount": int(
            runtime.get("cascadeStageSourceCount") or 0
        ),
        "cascadeStageFailedAttempts": int(
            runtime.get("cascadeStageFailedAttempts") or 0
        ),
        "cascadeStageRetryableFailures": int(
            runtime.get("cascadeStageRetryableFailures") or 0
        ),
        "cascadeStageStoppedFailures": int(
            runtime.get("cascadeStageStoppedFailures") or 0
        ),
        "cascadeStageRecoveredFlows": int(
            runtime.get("cascadeStageRecoveredFlows") or 0
        ),
        "cascadeStageNonBoundStopObserved": bool(
            runtime.get("cascadeStageNonBoundStopObserved")
        ),
        "cascadeStageFailedByScope": count_rows_value(
            runtime.get("cascadeStageFailedByScope")
        ),
        "cascadeStageFailedByStageSurface": count_rows_value(
            runtime.get("cascadeStageFailedByStageSurface")
        ),
        "cascadeStageFailedByStageDisposition": count_rows_value(
            runtime.get("cascadeStageFailedByStageDisposition")
        ),
        "cascadeStageFailedByStopReason": count_rows_value(
            runtime.get("cascadeStageFailedByStopReason")
        ),
        "nextActionIds": next_action_ids(conclusion),
    }


def dynet_product_source(path: Path) -> dict[str, Any]:
    source = product.source_summary(path)
    targets = [str(target) for target in source.get("targets", []) if target]
    return {
        **source,
        "targetHosts": sorted({host_from_url(target) for target in targets if host_from_url(target)}),
    }


def dynet_product_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    runs = sum(int(source.get("runs") or 0) for source in sources)
    passed = sum(int(source.get("passed") or 0) for source in sources)
    failed = sum(int(source.get("failed") or 0) for source in sources)
    strict_failed = sum(int(source.get("strictFailed") or 0) for source in sources)
    hosts = sorted({
        host for source in sources for host in source.get("targetHosts", []) if host
    })
    return {
        "sourceCount": len(sources),
        "runs": runs,
        "passed": passed,
        "failed": failed,
        "strictFailed": strict_failed,
        "clean": bool(sources) and runs > 0 and failed == 0 and strict_failed == 0,
        "targetHosts": hosts,
        "targetHostCount": len(hosts),
        "sources": sources,
    }


def clash_product_source(path: Path) -> dict[str, Any]:
    summary = load_json(path)
    schema = str(summary.get("schema") or "")
    if schema == TRANSPORT_EVIDENCE_SCHEMA:
        return clash_transport_evidence_source(path, summary)
    return empty_clash_source(path, schema)


def clash_transport_evidence_source(path: Path, summary: dict[str, Any]) -> dict[str, Any]:
    surface = product_surface(summary.get("surfaces") or [])
    features = surface.get("configFeatureCounts") or {}
    return {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "sourceKind": "transport-evidence",
        "productEvidence": int(surface.get("candidateCount") or 0) > 0,
        "productPass": int(surface.get("passCount") or 0) > 0,
        "candidateCount": int(surface.get("candidateCount") or 0),
        "passCount": int(surface.get("passCount") or 0),
        "failCount": int(surface.get("failCount") or 0),
        "interfaceNameConfigured": int(features.get("interface-name:true") or 0),
        "targetHosts": [],
        "unsafePrivacyFlags": unsafe_privacy_flags(summary.get("privacy")),
    }


def empty_clash_source(path: Path, schema: str) -> dict[str, Any]:
    return {
        "path": str(path),
        "schema": schema,
        "sourceKind": "unsupported",
        "productEvidence": False,
        "productPass": False,
        "candidateCount": 0,
        "passCount": 0,
        "failCount": 0,
        "interfaceNameConfigured": 0,
        "targetHosts": [],
        "unsafePrivacyFlags": [],
    }


def clash_product_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    hosts = sorted({
        host for source in sources for host in source.get("targetHosts", []) if host
    })
    candidate_count = sum(int(source.get("candidateCount") or 0) for source in sources)
    pass_count = sum(int(source.get("passCount") or 0) for source in sources)
    fail_count = sum(int(source.get("failCount") or 0) for source in sources)
    return {
        "sourceCount": len(sources),
        "productEvidence": candidate_count > 0,
        "productPass": pass_count > 0,
        "clean": candidate_count > 0 and fail_count == 0,
        "candidateCount": candidate_count,
        "passCount": pass_count,
        "failCount": fail_count,
        "interfaceNameConfigured": sum(
            int(source.get("interfaceNameConfigured") or 0) for source in sources
        ),
        "targetHosts": hosts,
        "targetHostsKnown": bool(hosts),
        "unsafePrivacyFlags": sorted({
            flag for source in sources for flag in source.get("unsafePrivacyFlags", [])
        }),
        "sources": sources,
    }


def paired_source(path: Path) -> dict[str, Any]:
    summary = load_json(path)
    schema = str(summary.get("schema") or "")
    if schema.endswith("proof-comparison/v1alpha1"):
        return comparison_paired_source(path, summary)
    return {
        "path": str(path),
        "schema": schema,
        "windows": 0,
        "parityCandidate": False,
        "runtimeCarrier": "unknown",
        "targetHosts": [],
    }


def comparison_paired_source(path: Path, summary: dict[str, Any]) -> dict[str, Any]:
    totals = summary.get("totals") or {}
    clash = totals.get("clash") or {}
    dynet = totals.get("dynet") or {}
    clash_count = int(clash.get("count") or 0)
    dynet_count = int(dynet.get("count") or 0)
    parity = (
        clash_count > 0
        and clash_count == dynet_count
        and int(dynet.get("success") or 0) >= int(clash.get("success") or 0)
    )
    return {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "windows": 1,
        "parityCandidate": parity,
        "runtimeCarrier": str(summary.get("runtimeCarrier") or "local-dynet-probe"),
        "targetHosts": paired_target_hosts(summary),
        "pairedEntries": min(clash_count, dynet_count),
        "clashSuccess": int(clash.get("success") or 0),
        "dynetSuccess": int(dynet.get("success") or 0),
    }


def paired_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    hosts = sorted({
        host for source in sources for host in source.get("targetHosts", []) if host
    })
    carriers = sorted({
        str(source.get("runtimeCarrier") or "unknown") for source in sources
    })
    linux_interface_bound = "linux-interface-bound" in carriers
    parity = bool(sources) and all(bool(source.get("parityCandidate")) for source in sources)
    return {
        "sourceCount": len(sources),
        "windows": sum(int(source.get("windows") or 0) for source in sources),
        "pairedEntries": sum(int(source.get("pairedEntries") or 0) for source in sources),
        "parityCandidate": parity,
        "runtimeCarriers": carriers,
        "linuxInterfaceBound": linux_interface_bound,
        "targetHosts": hosts,
        "targetHostsKnown": bool(hosts),
        "sources": sources,
    }


def runtime_product_source(path: Path) -> dict[str, Any]:
    source = readiness_runtime.source_summary(path)
    summary = load_json(path)
    runs = [run for run in summary.get("runs", []) if isinstance(run, dict)]
    return {
        **source,
        "runtimeCarrier": "dynet-run-tun",
        "targetHosts": sorted(runtime_target_hosts(runs)),
    }


def runtime_product_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    hosts = sorted({host for source in sources for host in source.get("targetHosts", []) if host})
    aggregate = readiness_runtime.evidence_summary(sources) if sources else empty_runtime_summary()
    return {
        **aggregate,
        "runtimeCarrier": "dynet-run-tun" if sources else "missing",
        "targetHosts": hosts,
        "targetHostsKnown": bool(hosts),
        "sources": sources,
    }


def empty_runtime_summary() -> dict[str, Any]:
    return {
        "sourceCount": 0,
        "runs": 0,
        "passedRuns": 0,
        "failedRuns": 0,
        "workloadAttempted": 0,
        "workloadSuccess": 0,
        "workloadFailure": 0,
        "workloadFailedBySurface": [],
        "workloadFailedByStage": [],
        "workloadErrors": [],
        "workloadFlowUnmatchedFailureSurfaces": [],
        "qualityBoundCandidateSets": 0,
        "qualityBoundSelectedWithQuality": 0,
        "qualityBoundSelectedBehind": 0,
        "tcpFlowPathComplete": 0,
        "tcpFlowPayloadBidirectional": 0,
        "tcpFlowFailed": 0,
        "tcpFlowStageFailed": 0,
        "workloadFlowMatchedRecoveredFailureEntries": 0,
        "workloadFlowMatchedFlowStageFailedAttempts": 0,
        "tcpSessionFailures": 0,
        "clean": False,
    }


def product_effect_gates(
    maturity: dict[str, Any],
    dynet: dict[str, Any],
    clash: dict[str, Any],
    runtime: dict[str, Any],
    paired: dict[str, Any],
    minimums: dict[str, int],
) -> list[dict[str, Any]]:
    overlap = target_overlap(dynet["targetHosts"], clash["targetHosts"] or paired["targetHosts"])
    runtime_min = minimums.get("runtimeWorkloadEntries", 0)
    runtime_required = runtime_min > 0 or runtime["sourceCount"] > 0
    return [
        gate("adapter-candidate-mature", "required", maturity["candidateMature"], maturity["status"], "candidate-mature"),
        gate("dynet-linux-product-clean", "required", dynet["clean"], f"{dynet['passed']}/{dynet['runs']}", "all-pass"),
        gate("dynet-product-target-diversity", "required", dynet["targetHostCount"] >= minimums["dynetProductTargets"], dynet["targetHostCount"], minimums["dynetProductTargets"]),
        gate("clash-product-surface-present", "required", clash["productPass"], clash["passCount"], ">0"),
        gate("clash-interface-bound-surface-present", "shape", clash["interfaceNameConfigured"] > 0, clash["interfaceNameConfigured"], ">0"),
        gate("linux-interface-bound-paired-window", "product-effect", paired["linuxInterfaceBound"], paired["runtimeCarriers"], "linux-interface-bound"),
        gate("paired-product-effect-parity", "product-effect", paired["parityCandidate"], paired["windows"], ">=1 parity window"),
        gate("paired-window-depth", "product-effect", paired["windows"] >= minimums.get("pairedWindows", 1), paired["windows"], minimums.get("pairedWindows", 1)),
        gate("paired-entry-depth", "product-effect", paired["pairedEntries"] >= minimums.get("pairedEntries", 0), paired["pairedEntries"], minimums.get("pairedEntries", 0)),
        gate("dynet-run-tun-runtime-clean", "product-effect", not runtime_required or runtime["clean"], runtime["runtimeCarrier"], "clean dynet-run-tun runtime"),
        gate("runtime-workload-depth", "product-effect", runtime["workloadAttempted"] >= runtime_min, runtime["workloadAttempted"], runtime_min),
        gate("runtime-target-overlap-known", "product-effect", not runtime_required or bool(target_overlap(dynet["targetHosts"], runtime["targetHosts"])), runtime["targetHosts"], "overlap with dynet product targets"),
        gate("target-family-overlap-known", "product-effect", bool(overlap), overlap, "non-empty overlap"),
    ]


def product_surface(surfaces: list[Any]) -> dict[str, Any]:
    for surface in surfaces:
        if isinstance(surface, dict) and surface.get("surface") == "product-e2e":
            return surface
    return {}


def paired_target_hosts(summary: dict[str, Any]) -> list[str]:
    hosts = {str(value) for value in summary.get("targetHosts", []) or [] if value}
    hosts.update(
        host for value in summary.get("targets", []) or []
        if (host := host_from_url(str(value)))
    )
    return sorted(hosts)


def target_overlap(left: list[str], right: list[str]) -> list[str]:
    return sorted(set(left) & set(right))


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


def host_from_url(raw: str) -> str:
    parsed = urlparse(raw)
    return parsed.hostname or ""


def unsafe_privacy_flags(raw: Any) -> list[str]:
    if not isinstance(raw, dict):
        return []
    flags = raw.get("unsafeFlags")
    if isinstance(flags, list):
        return sorted(str(flag) for flag in flags)
    return sorted(str(key) for key, value in raw.items() if bool(value))


def privacy_summary(
    dynet: dict[str, Any],
    clash: dict[str, Any],
    runtime: dict[str, Any],
    paired: dict[str, Any],
) -> dict[str, Any]:
    return {
        "dynetSourceCount": dynet["sourceCount"],
        "clashSourceCount": clash["sourceCount"],
        "runtimeSourceCount": runtime["sourceCount"],
        "pairedSourceCount": paired["sourceCount"],
        "rawSecretsStored": False,
        "rawLogsStored": False,
        "identityInformationSent": False,
        "unsafeClashPrivacyFlags": clash["unsafePrivacyFlags"],
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


def next_action_ids(conclusion: dict[str, Any]) -> list[str]:
    return [
        str(item.get("id"))
        for item in conclusion.get("nextActions", [])
        if isinstance(item, dict) and item.get("id")
    ]


def count_rows_value(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    return [
        {"key": str(row.get("key")), "count": int(row.get("count") or 0)}
        for row in raw
        if isinstance(row, dict) and row.get("key")
    ]
