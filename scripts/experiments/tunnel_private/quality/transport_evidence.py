from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from tunnel_private_config import write_json


EVIDENCE_SCHEMA = "dynet-tunnel-private-transport-evidence/v1alpha1"

SURFACE_BY_CHECK = {
    "clash-delay": "controller-health",
    "mihomo-delay": "controller-health",
    "mihomo-proxy": "product-e2e",
    "trojan-tls": "transport-handshake",
    "go-tls": "transport-handshake",
    "utls": "transport-handshake",
}

SURFACE_RANK = {
    "product-e2e": 3,
    "transport-handshake": 2,
    "controller-health": 1,
    "unknown": 0,
}

SURFACE_STRENGTH = {
    "product-e2e": "strong",
    "transport-handshake": "diagnostic",
    "controller-health": "weak",
    "unknown": "unknown",
}

PRIVACY_KEYS = [
    "rawSecretsStored",
    "serverStored",
    "sniStored",
    "passwordStored",
    "rawNodeNamesStored",
    "controllerSecretStored",
    "delayUrlStored",
    "probeUrlStored",
    "rawLogsStored",
    "rawCurlErrorStored",
]


def command_transport_evidence(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = transport_evidence_summary([Path(path) for path in args.transport_summary])
    write_json(output_dir / "summary.json", summary)
    write_markdown(output_dir / "summary.md", summary)
    print(json.dumps(print_summary(output_dir, summary), sort_keys=True))
    return 0 if summary["sourceCount"] else 1


def transport_evidence_summary(paths: list[Path]) -> dict[str, Any]:
    sources = [source_summary(path) for path in paths]
    surfaces = surface_summaries(sources)
    return {
        "schema": EVIDENCE_SCHEMA,
        "sourceCount": len(sources),
        "surfaces": surfaces,
        "conclusion": evidence_conclusion(surfaces, sources),
        "privacy": aggregate_privacy(sources),
        "sources": sources,
    }


def source_summary(path: Path) -> dict[str, Any]:
    summary = json.loads(path.read_text())
    check = str(summary.get("check") or "unknown")
    surface = surface_for_check(check)
    outcome_counts = normalized_counts(summary.get("outcomeCounts") or {})
    rows = [row for row in summary.get("rows", []) if isinstance(row, dict)]
    candidate_count = int(summary.get("candidateCount") or sum(outcome_counts.values()))
    pass_count = pass_count_for(outcome_counts)
    return {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "check": check,
        "surface": surface,
        "surfaceStrength": SURFACE_STRENGTH[surface],
        "evidenceRank": SURFACE_RANK[surface],
        "candidateCount": candidate_count,
        "passCount": pass_count,
        "failCount": max(0, candidate_count - pass_count),
        "outcomeCounts": outcome_counts,
        "configFeatureCounts": config_feature_counts(rows),
        "failureCategoryCounts": failure_category_counts(rows),
        "stageMarkerCounts": stage_marker_counts(rows),
        "environment": environment_summary(summary.get("environment")),
        "privacy": privacy_flags(summary.get("privacy")),
    }


def surface_for_check(check: str) -> str:
    return SURFACE_BY_CHECK.get(check, "unknown")


def normalized_counts(raw: dict[str, Any]) -> dict[str, int]:
    return {
        str(outcome): int(count)
        for outcome, count in sorted(raw.items(), key=lambda item: str(item[0]))
    }


def pass_count_for(outcome_counts: dict[str, int]) -> int:
    return sum(count for outcome, count in outcome_counts.items() if outcome.endswith("-pass"))


def privacy_flags(raw: Any) -> dict[str, bool]:
    if not isinstance(raw, dict):
        return {}
    return {
        key: bool(raw.get(key))
        for key in PRIVACY_KEYS
        if key in raw
    }


def environment_summary(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        return {}
    return {
        "mergedConfigPresent": bool(raw.get("mergedConfigPresent")),
        "tunEnabled": bool(raw.get("tunEnabled")),
        "tunAutoRoute": bool(raw.get("tunAutoRoute")),
        "dnsEnabled": bool(raw.get("dnsEnabled")),
        "dnsEnhancedMode": str(raw.get("dnsEnhancedMode") or ""),
        "proxyServerNameserverCount": int(raw.get("proxyServerNameserverCount") or 0),
        "snifferEnabled": bool(raw.get("snifferEnabled")),
        "mixedPortPresent": bool(raw.get("mixedPortPresent")),
        "externalControllerUnixPresent": bool(raw.get("externalControllerUnixPresent")),
    }


def surface_summaries(sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
    surfaces = sorted(
        {str(source["surface"]) for source in sources},
        key=lambda surface: (-SURFACE_RANK.get(surface, 0), surface),
    )
    return [surface_summary(surface, sources) for surface in surfaces]


def surface_summary(surface: str, sources: list[dict[str, Any]]) -> dict[str, Any]:
    selected = [source for source in sources if source["surface"] == surface]
    outcome_counts = merge_counts([source["outcomeCounts"] for source in selected])
    config_features = merge_counts([source["configFeatureCounts"] for source in selected])
    failure_categories = merge_counts([
        source["failureCategoryCounts"] for source in selected
    ])
    stage_markers = merge_counts([source["stageMarkerCounts"] for source in selected])
    candidate_count = sum(int(source["candidateCount"]) for source in selected)
    pass_count = sum(int(source["passCount"]) for source in selected)
    return {
        "surface": surface,
        "surfaceStrength": SURFACE_STRENGTH.get(surface, "unknown"),
        "evidenceRank": SURFACE_RANK.get(surface, 0),
        "sourceCount": len(selected),
        "checks": sorted({str(source["check"]) for source in selected}),
        "candidateCount": candidate_count,
        "passCount": pass_count,
        "failCount": max(0, candidate_count - pass_count),
        "passRatio": ratio(pass_count, candidate_count),
        "outcomeCounts": outcome_counts,
        "configFeatureCounts": config_features,
        "failureCategoryCounts": failure_categories,
        "stageMarkerCounts": stage_markers,
    }


def merge_counts(count_sets: list[dict[str, int]]) -> dict[str, int]:
    merged: dict[str, int] = {}
    for counts in count_sets:
        for outcome, count in counts.items():
            merged[outcome] = merged.get(outcome, 0) + count
    return dict(sorted(merged.items()))


def failure_category_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        evidence = row.get("stageEvidence")
        if not isinstance(evidence, dict):
            continue
        category = str(evidence.get("failureCategory") or "")
        if not category:
            continue
        counts[category] = counts.get(category, 0) + 1
    return dict(sorted(counts.items()))


def config_feature_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        features = row.get("configFeatures")
        if not isinstance(features, dict):
            continue
        count_bool_feature(counts, "interface-name", features.get("interfaceNameConfigured"))
        count_bool_feature(counts, "resolved-server-ip", features.get("resolvedServerIpUsed"))
    return dict(sorted(counts.items()))


def count_bool_feature(counts: dict[str, int], name: str, value: Any) -> None:
    key = f"{name}:{str(bool(value)).lower()}"
    counts[key] = counts.get(key, 0) + 1


def stage_marker_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        evidence = row.get("stageEvidence")
        if not isinstance(evidence, dict):
            continue
        markers = evidence.get("stageMarkerCounts")
        if not isinstance(markers, dict):
            continue
        for marker, count in markers.items():
            counts[str(marker)] = counts.get(str(marker), 0) + int(count)
    return dict(sorted(counts.items()))


def ratio(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 0.0
    return round(numerator / denominator, 4)


def evidence_conclusion(
    surfaces: list[dict[str, Any]],
    sources: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    by_surface = {str(surface["surface"]): surface for surface in surfaces}
    controller = by_surface.get("controller-health", empty_surface("controller-health"))
    product = by_surface.get("product-e2e", empty_surface("product-e2e"))
    diagnostic = by_surface.get("transport-handshake", empty_surface("transport-handshake"))

    controller_pass = int(controller["passCount"]) > 0
    product_evidence = int(product["candidateCount"]) > 0
    product_pass = int(product["passCount"]) > 0
    product_all_fail = product_evidence and not product_pass
    diagnostic_evidence = int(diagnostic["candidateCount"]) > 0
    diagnostic_pass = int(diagnostic["passCount"]) > 0
    diagnostic_all_fail = diagnostic_evidence and not diagnostic_pass
    contradiction = controller_pass and product_all_fail
    environment_shape_suspect = contradiction and any(
        bool((source.get("environment") or {}).get("tunEnabled"))
        for source in sources or []
    )

    return {
        "recommendedUse": recommended_use(
            controller_pass=controller_pass,
            product_evidence=product_evidence,
            product_pass=product_pass,
            product_all_fail=product_all_fail,
            diagnostic_all_fail=diagnostic_all_fail,
        ),
        "controllerHealthPass": controller_pass,
        "controllerHealthAsProductProof": False,
        "controllerContradictsProductE2e": contradiction,
        "controllerHealthOnly": (
            controller_pass and not product_evidence and not diagnostic_evidence
        ),
        "experimentShapeSuspect": environment_shape_suspect,
        "environmentNextProof": environment_next_proof(environment_shape_suspect),
        "productE2eEvidence": product_evidence,
        "productE2ePass": product_pass,
        "diagnosticHandshakeEvidence": diagnostic_evidence,
        "diagnosticHandshakePass": diagnostic_pass,
        "plannerPenaltySafe": False,
        "plannerPenaltyReason": (
            "transport evidence is diagnostic; planner penalties require repeated "
            "runtime-backed candidate and stage evidence"
        ),
    }


def environment_next_proof(environment_shape_suspect: bool) -> str:
    if environment_shape_suspect:
        return "rerun-isolated-mihomo-with-running-tun-disabled-or-clean-network-namespace"
    return "no-environment-follow-up-from-this-artifact"


def empty_surface(surface: str) -> dict[str, Any]:
    return {
        "surface": surface,
        "candidateCount": 0,
        "passCount": 0,
        "failCount": 0,
        "outcomeCounts": {},
    }


def recommended_use(
    *,
    controller_pass: bool,
    product_evidence: bool,
    product_pass: bool,
    product_all_fail: bool,
    diagnostic_all_fail: bool,
) -> str:
    if controller_pass and product_all_fail:
        return "controller-health-is-weak-signal-not-product-proof"
    if product_pass:
        return "product-e2e-evidence-can-seed-follow-up"
    if product_all_fail and diagnostic_all_fail:
        return "retain-as-protocol-diagnostic-not-planner-penalty"
    if not product_evidence:
        return "collect-product-e2e-before-planner-or-adapter-claims"
    return "collect-more-evidence"


def aggregate_privacy(sources: list[dict[str, Any]]) -> dict[str, Any]:
    true_flags = sorted({
        flag
        for source in sources
        for flag, enabled in source.get("privacy", {}).items()
        if enabled
    })
    return {
        "sourceCount": len(sources),
        "unsafeFlags": true_flags,
        "rawSecretsStored": "rawSecretsStored" in true_flags,
        "rawLogsStored": "rawLogsStored" in true_flags,
        "rawCurlErrorStored": "rawCurlErrorStored" in true_flags,
    }


def print_summary(output_dir: Path, summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "outputDir": str(output_dir),
        "sourceCount": summary["sourceCount"],
        "recommendedUse": summary["conclusion"]["recommendedUse"],
        "plannerPenaltySafe": summary["conclusion"]["plannerPenaltySafe"],
    }


def write_markdown(path: Path, summary: dict[str, Any]) -> None:
    conclusion = summary["conclusion"]
    lines = [
        "# Tunnel/Private Transport Evidence",
        "",
        f"- sources: `{summary['sourceCount']}`",
        f"- recommended use: `{conclusion['recommendedUse']}`",
        f"- controller health as product proof: `{conclusion['controllerHealthAsProductProof']}`",
        f"- controller contradicts product e2e: `{conclusion['controllerContradictsProductE2e']}`",
        f"- planner penalty safe: `{conclusion['plannerPenaltySafe']}`",
        "",
        "## Surfaces",
        "",
    ]
    for surface in summary["surfaces"]:
        lines.append(
            "- `{surface}` ({strength}): sources=`{sources}` candidates=`{candidates}` "
            "pass=`{passed}` fail=`{failed}`".format(
                surface=surface["surface"],
                strength=surface["surfaceStrength"],
                sources=surface["sourceCount"],
                candidates=surface["candidateCount"],
                passed=surface["passCount"],
                failed=surface["failCount"],
            )
        )
        for outcome, count in surface["outcomeCounts"].items():
            lines.append(f"  - `{outcome}`: `{count}`")
        for feature, count in surface.get("configFeatureCounts", {}).items():
            lines.append(f"  - config feature `{feature}`: `{count}`")
        for category, count in surface.get("failureCategoryCounts", {}).items():
            lines.append(f"  - failure category `{category}`: `{count}`")
        for marker, count in surface.get("stageMarkerCounts", {}).items():
            lines.append(f"  - stage marker `{marker}`: `{count}`")
    lines.extend(["", "## Sources", ""])
    for source in summary["sources"]:
        lines.append(
            f"- `{source['check']}` -> `{source['surface']}`: `{source['path']}`"
        )
    path.write_text("\n".join(lines) + "\n")
