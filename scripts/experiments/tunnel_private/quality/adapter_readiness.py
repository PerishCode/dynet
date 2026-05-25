from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from tunnel_private_config import write_json
from tunnel_private.quality import adapter_transport
from tunnel_private.quality.readiness import actions
from tunnel_private.quality.readiness import product as readiness_product
from tunnel_private.quality.readiness import runtime as readiness_runtime

READINESS_SCHEMA = "dynet-tunnel-private-adapter-readiness/v1alpha1"


def command_adapter_readiness(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = adapter_readiness_summary(
        str(args.adapter_type),
        [Path(path) for path in getattr(args, "product_evidence", []) or []],
        [Path(path) for path in getattr(args, "runtime_evidence", []) or []],
        [Path(path) for path in getattr(args, "transport_evidence", []) or []],
    )
    write_json(output_dir / "summary.json", summary)
    write_markdown(output_dir / "summary.md", summary)
    print(json.dumps(print_summary(output_dir, summary), sort_keys=True))
    return 0 if summary["sourceCount"] else 1


def adapter_readiness_summary(
    adapter_type: str,
    product_paths: list[Path],
    runtime_paths: list[Path],
    transport_paths: list[Path],
) -> dict[str, Any]:
    product_sources = [readiness_product.source_summary(path) for path in product_paths]
    runtime_sources = [readiness_runtime.source_summary(path) for path in runtime_paths]
    transport_sources = [adapter_transport.source_summary(path) for path in transport_paths]
    categories = category_summaries(product_sources)
    runtime = readiness_runtime.evidence_summary(runtime_sources)
    transport = adapter_transport.summary(transport_sources)
    protocol = protocol_followup(categories)
    conclusion = readiness_conclusion(categories, runtime, transport, protocol)
    return {
        "schema": READINESS_SCHEMA,
        "adapterType": adapter_type,
        "sourceCount": len(product_sources) + len(runtime_sources) + len(transport_sources),
        "status": conclusion["status"],
        "recommendedUse": conclusion["recommendedUse"],
        "conclusion": conclusion,
        "productEvidence": categories,
        "runtimeEvidence": runtime,
        "transportEvidence": transport,
        "protocolFollowup": protocol,
        "privacy": privacy_summary(product_sources, runtime_sources, transport_sources),
        "sources": {"product": product_sources, "runtime": runtime_sources, "transport": transport_sources},
    }


def category_summaries(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        category: category_summary(category, sources)
        for category in ["product-e2e", "direct-control", "unknown"]
    }


def category_summary(category: str, sources: list[dict[str, Any]]) -> dict[str, Any]:
    selected = [source for source in sources if source["category"] == category]
    return {
        "sourceCount": len(selected),
        "runs": sum(int(source["runs"]) for source in selected),
        "passed": sum(int(source["passed"]) for source in selected),
        "failed": sum(int(source["failed"]) for source in selected),
        "strictPassed": sum(int(source["strictPassed"]) for source in selected),
        "strictFailed": sum(int(source["strictFailed"]) for source in selected),
        "matrixFailures": sum(int(source["matrixFailures"]) for source in selected),
        "selectedBehindMax": max(
            (int(source["selectedBehindMax"]) for source in selected),
            default=0,
        ),
        "targets": sorted({
            target for source in selected for target in source.get("targets", []) if target
        }),
        "candidateOffsets": sorted({
            int(offset) for source in selected for offset in source.get("candidateOffsets", [])
        }),
        "markerSummary": merge_counts([source["markerSummary"] for source in selected]),
        "failureStageSummary": merge_counts([
            source.get("failureStageSummary", {}) for source in selected
        ]),
        "failureScopeSummary": merge_counts([
            source.get("failureScopeSummary", {}) for source in selected
        ]),
        "failureLabelSummary": merge_counts([
            source.get("failureLabelSummary", {}) for source in selected
        ]),
        "requiredGateFailures": [
            failure
            for source in selected
            for failure in source.get("requiredGateFailures", [])
        ],
    }


def readiness_conclusion(
    categories: dict[str, Any],
    runtime: dict[str, Any],
    transport: dict[str, Any],
    protocol: dict[str, Any],
) -> dict[str, Any]:
    product = categories["product-e2e"]
    direct = categories["direct-control"]
    product_evidence = int(product["runs"]) > 0
    direct_evidence = int(direct["runs"]) > 0
    product_clean = (
        product_evidence
        and int(product["failed"]) == 0
        and int(product["selectedBehindMax"]) == 0
        and not product["requiredGateFailures"]
    )
    direct_clean = (
        direct_evidence
        and int(direct["failed"]) == 0
        and int(direct["strictFailed"]) == 0
        and int(direct["selectedBehindMax"]) == 0
        and not direct["requiredGateFailures"]
    )
    transport_blocked = bool(transport["blocked"])
    runtime_blocked = bool(runtime["sourceCount"]) and not bool(runtime["clean"])
    strict_control_open = product_clean and int(product["strictFailed"]) > 0 and not direct_clean

    status = readiness_status(
        product_evidence=product_evidence,
        product_clean=product_clean,
        runtime_blocked=runtime_blocked,
        strict_control_open=strict_control_open,
        transport_blocked=transport_blocked,
    )
    reasons = not_ready_reasons(
        product_evidence=product_evidence,
        product_clean=product_clean,
        runtime_blocked=runtime_blocked,
        strict_control_open=strict_control_open,
        transport_blocked=transport_blocked,
    )
    return {
        "status": status,
        "recommendedUse": recommended_use(status, transport_blocked),
        "productEvidence": product_evidence,
        "productClean": product_clean,
        "directControlEvidence": direct_evidence,
        "directControlClean": direct_clean,
        "runtimeEvidence": bool(runtime["sourceCount"]),
        "runtimeClean": bool(runtime["clean"]),
        "strictControlOpen": strict_control_open,
        "runtimeBlocked": runtime_blocked,
        "transportBlocked": transport_blocked,
        "transportAdapterWorkSignal": str(transport["adapterWorkSignal"]),
        "transportNextProof": transport_next_proof(runtime, transport),
        "protocolFollowupOpen": bool(protocol["open"]),
        "protocolNextProof": str(protocol["nextProof"]),
        "readyForMainlineAdapterWork": status == "ready",
        "notReadyReasons": reasons,
        "nextActions": actions.next_actions(
            status=status,
            not_ready_reasons=reasons,
            product_evidence=product_evidence,
            product_clean=product_clean,
            runtime_blocked=runtime_blocked,
            strict_control_open=strict_control_open,
            transport_blocked=transport_blocked,
            transport=transport,
            protocol=protocol,
        ),
    }


def transport_next_proof(runtime: dict[str, Any], transport: dict[str, Any]) -> str:
    next_proof = str(transport["nextProof"])
    if (
        next_proof == "join-product-baseline-with-dynet-runtime-stage-evidence"
        and int(runtime["sourceCount"]) > 0
        and bool(runtime["clean"])
    ):
        return "runtime-stage-evidence-clean"
    return next_proof


def readiness_status(
    *,
    product_evidence: bool,
    product_clean: bool,
    runtime_blocked: bool,
    strict_control_open: bool,
    transport_blocked: bool,
) -> str:
    if transport_blocked or runtime_blocked:
        return "not-ready"
    if not product_evidence:
        return "needs-evidence"
    if not product_clean:
        return "not-ready"
    if strict_control_open:
        return "needs-control-followup"
    return "ready"


def recommended_use(status: str, transport_blocked: bool) -> str:
    if status == "ready":
        return "use-as-mainline-adapter-runtime-work-slice"
    if transport_blocked:
        return "do-not-use-for-adapter-claims"
    if status == "needs-control-followup":
        return "collect-direct-control-follow-up-before-adapter-claims"
    if status == "needs-evidence":
        return "collect-product-e2e-evidence-before-adapter-work"
    return "fix-product-gate-before-adapter-work"


def not_ready_reasons(
    *,
    product_evidence: bool,
    product_clean: bool,
    runtime_blocked: bool,
    strict_control_open: bool,
    transport_blocked: bool,
) -> list[str]:
    reasons = []
    if transport_blocked:
        reasons.append("transport-product-e2e-failed")
    if runtime_blocked:
        reasons.append("runtime-repeat-proof-not-clean")
    if not product_evidence:
        reasons.append("missing-product-e2e-evidence")
    elif not product_clean:
        reasons.append("product-e2e-gate-not-clean")
    if strict_control_open:
        reasons.append("strict-control-follow-up-missing")
    return reasons


def protocol_followup(categories: dict[str, Any]) -> dict[str, Any]:
    product = categories["product-e2e"]
    direct = categories["direct-control"]
    markers = merge_counts([
        product.get("markerSummary", {}),
        direct.get("markerSummary", {}),
    ])
    read_markers = read_marker_rows(markers)
    strict_failures = int(product["strictFailed"]) + int(direct["strictFailed"])
    return {
        "open": bool(read_markers) or strict_failures > 0,
        "strictFailures": strict_failures,
        "readMarkerCount": sum(int(item["count"]) for item in read_markers),
        "readMarkers": read_markers,
        "nextProof": protocol_next_proof(strict_failures, read_markers),
    }


def read_marker_rows(markers: dict[str, int]) -> list[dict[str, Any]]:
    return [
        {"key": key, "count": int(count)}
        for key, count in sorted(markers.items())
        if read_marker(key)
    ]


def read_marker(key: str) -> bool:
    tokens = [
        "read",
        "eof",
        "response-header",
        "stream-first-read",
        "pending",
        "short",
    ]
    return any(token in key for token in tokens)


def protocol_next_proof(strict_failures: int, read_markers: list[dict[str, Any]]) -> str:
    if read_markers:
        return "collect-runtime-stage-repeat-for-read-marker-before-adapter-claim"
    if strict_failures:
        return "review-strict-control-failure-before-adapter-claim"
    return "no-current-protocol-follow-up"


def privacy_summary(
    product_sources: list[dict[str, Any]],
    runtime_sources: list[dict[str, Any]],
    transport_sources: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "productSourceCount": len(product_sources),
        "runtimeSourceCount": len(runtime_sources),
        "transportSourceCount": len(transport_sources),
        "rawSecretsStored": False,
        "rawLogsStored": False,
        "identityInformationSent": False,
    }


def merge_counts(count_sets: list[dict[str, int]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for count_set in count_sets:
        for key, value in count_set.items():
            counts[key] = counts.get(key, 0) + int(value)
    return dict(sorted(counts.items()))


def print_summary(output_dir: Path, summary: dict[str, Any]) -> dict[str, Any]:
    conclusion = summary["conclusion"]
    product = summary["productEvidence"]["product-e2e"]
    return {
        "outputDir": str(output_dir),
        "adapterType": summary["adapterType"],
        "status": summary["status"],
        "recommendedUse": summary["recommendedUse"],
        "productRuns": product["runs"],
        "readyForMainlineAdapterWork": conclusion["readyForMainlineAdapterWork"],
    }


def write_markdown(path: Path, summary: dict[str, Any]) -> None:
    conclusion = summary["conclusion"]
    lines = [
        "# Tunnel/Private Adapter Readiness",
        "",
        f"- adapter: `{summary['adapterType']}`",
        f"- status: `{summary['status']}`",
        f"- recommended use: `{summary['recommendedUse']}`",
        f"- ready for mainline adapter work: `{conclusion['readyForMainlineAdapterWork']}`",
        "",
        "## Product Evidence",
        "",
    ]
    for category, evidence in summary["productEvidence"].items():
        if evidence["sourceCount"] == 0:
            continue
        lines.append(
            f"- `{category}`: sources=`{evidence['sourceCount']}` "
            f"runs=`{evidence['runs']}` passed=`{evidence['passed']}` "
            f"failed=`{evidence['failed']}` strictFailed=`{evidence['strictFailed']}` "
            f"selectedBehindMax=`{evidence['selectedBehindMax']}`"
        )
        if evidence["failureStageSummary"]:
            lines.append(f"  failureStages=`{compact_counts(evidence['failureStageSummary'])}`")
        if evidence["failureScopeSummary"]:
            lines.append(f"  failureScopes=`{compact_counts(evidence['failureScopeSummary'])}`")
    runtime = summary["runtimeEvidence"]
    lines.extend([
        "",
        "## Runtime Evidence",
        "",
        f"- sources: `{runtime['sourceCount']}` runs=`{runtime['runs']}` "
        f"failedRuns=`{runtime['failedRuns']}` "
        f"selectedBehind=`{runtime['qualityBoundSelectedBehind']}` "
        f"fallbackSelections=`{runtime['qualityBoundFallbackCandidateSets']}` "
        f"workload=`{runtime['workloadSuccess']}/{runtime['workloadAttempted']}` "
        f"tcpPathComplete=`{runtime['tcpFlowPathComplete']}` "
        f"tcpPayloadBidirectional=`{runtime['tcpFlowPayloadBidirectional']}` "
        f"tcpClosedSessions=`{runtime['tcpClosedSessions']}` clean=`{runtime['clean']}`",
        "",
        "## Transport Evidence",
        "",
    ])
    transport = summary["transportEvidence"]
    lines.append(
        f"- sources: `{transport['sourceCount']}` blocked=`{transport['blocked']}` "
        f"controllerContradictions=`{transport['controllerContradictions']}` "
        f"adapterWorkSignal=`{transport['adapterWorkSignal']}`"
    )
    lines.append(f"- next proof: `{conclusion['transportNextProof']}`")
    protocol = summary["protocolFollowup"]
    lines.extend([
        "",
        "## Protocol Follow-Up",
        "",
        f"- open: `{protocol['open']}`",
        f"- strict failures: `{protocol['strictFailures']}`",
        f"- read marker count: `{protocol['readMarkerCount']}`",
        f"- next proof: `{protocol['nextProof']}`",
    ])
    for marker in protocol["readMarkers"]:
        lines.append(f"- marker `{marker['key']}` count=`{marker['count']}`")
    lines.extend(["", "## Next Actions", ""])
    for item in conclusion["nextActions"]:
        lines.append(
            f"- `{item['id']}` evidence=`{item['evidence']}` "
            f"priority=`{item['priority']}` "
            f"plannerPenaltySafe=`{item['plannerPenaltySafe']}`"
        )
    if conclusion["notReadyReasons"]:
        lines.extend(["", "## Not Ready Reasons", ""])
        for reason in conclusion["notReadyReasons"]:
            lines.append(f"- `{reason}`")
    path.write_text("\n".join(lines) + "\n")


def compact_counts(counts: dict[str, int]) -> str:
    return ", ".join(f"{key}:{value}" for key, value in counts.items())
