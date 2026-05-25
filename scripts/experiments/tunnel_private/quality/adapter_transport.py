from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def source_summary(path: Path) -> dict[str, Any]:
    summary = json.loads(path.read_text()) if path.exists() else {}
    conclusion = summary.get("conclusion") or {}
    return {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "sourceCount": int(summary.get("sourceCount") or 0),
        "surfaces": [surface_summary(surface) for surface in summary.get("surfaces", [])],
        "recommendedUse": str(conclusion.get("recommendedUse") or ""),
        "productE2eEvidence": bool(conclusion.get("productE2eEvidence")),
        "productE2ePass": bool(conclusion.get("productE2ePass")),
        "controllerHealthPass": bool(conclusion.get("controllerHealthPass")),
        "controllerContradictsProductE2e": bool(
            conclusion.get("controllerContradictsProductE2e")
        ),
        "diagnosticHandshakeEvidence": bool(conclusion.get("diagnosticHandshakeEvidence")),
        "diagnosticHandshakePass": bool(conclusion.get("diagnosticHandshakePass")),
        "experimentShapeSuspect": bool(conclusion.get("experimentShapeSuspect")),
        "environmentNextProof": str(conclusion.get("environmentNextProof") or ""),
        "plannerPenaltySafe": bool(conclusion.get("plannerPenaltySafe")),
    }


def surface_summary(surface: dict[str, Any]) -> dict[str, Any]:
    return {
        "surface": str(surface.get("surface") or "unknown"),
        "surfaceStrength": str(surface.get("surfaceStrength") or "unknown"),
        "evidenceRank": int(surface.get("evidenceRank") or 0),
        "sourceCount": int(surface.get("sourceCount") or 0),
        "checks": sorted(str(check) for check in surface.get("checks", [])),
        "candidateCount": int(surface.get("candidateCount") or 0),
        "passCount": int(surface.get("passCount") or 0),
        "failCount": int(surface.get("failCount") or 0),
        "outcomeCounts": normalized_counts(surface.get("outcomeCounts") or {}),
        "configFeatureCounts": normalized_counts(surface.get("configFeatureCounts") or {}),
        "failureCategoryCounts": normalized_counts(surface.get("failureCategoryCounts") or {}),
        "stageMarkerCounts": normalized_counts(surface.get("stageMarkerCounts") or {}),
    }


def summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    result = {
        "sourceCount": len(sources),
        "productE2eEvidence": any(source["productE2eEvidence"] for source in sources),
        "productE2ePass": any(source["productE2ePass"] for source in sources),
        "blocked": any(blocks_adapter(source) for source in sources),
        "controllerContradictions": sum(
            1 for source in sources if source["controllerContradictsProductE2e"]
        ),
        "controllerHealthPass": any(source["controllerHealthPass"] for source in sources),
        "diagnosticHandshakeEvidence": any(
            source["diagnosticHandshakeEvidence"] for source in sources
        ),
        "diagnosticHandshakePass": any(
            source["diagnosticHandshakePass"] for source in sources
        ),
        "experimentShapeSuspect": any(
            source["experimentShapeSuspect"] for source in sources
        ),
        "environmentNextProofs": sorted({
            source["environmentNextProof"] for source in sources if source["environmentNextProof"]
        }),
        "plannerPenaltySafe": any(source["plannerPenaltySafe"] for source in sources),
        "surfaces": merged_surfaces(sources),
    }
    result["adapterWorkSignal"] = adapter_work_signal(result)
    result["nextProof"] = next_proof(result)
    return result


def blocks_adapter(source: dict[str, Any]) -> bool:
    return bool(source["productE2eEvidence"]) and not bool(source["productE2ePass"])


def adapter_work_signal(summary: dict[str, Any]) -> str:
    if summary["sourceCount"] == 0:
        return "no-transport-evidence"
    if summary["blocked"]:
        return "transport-product-e2e-blocked"
    if summary["productE2ePass"]:
        return "transport-product-e2e-baseline-present"
    if summary["controllerHealthPass"] and not summary["productE2eEvidence"]:
        return "controller-health-only"
    if summary["diagnosticHandshakeEvidence"] and not summary["diagnosticHandshakePass"]:
        return "diagnostic-handshake-blocked"
    return "collect-transport-evidence"


def next_proof(summary: dict[str, Any]) -> str:
    if summary["sourceCount"] == 0:
        return "no-transport-proof-required-for-current-gate"
    if summary["blocked"]:
        return "collect-sanitized-product-e2e-pass-before-adapter-compat-claim"
    if summary["productE2ePass"]:
        return "join-product-baseline-with-dynet-runtime-stage-evidence"
    if not summary["productE2eEvidence"]:
        return "collect-product-e2e-baseline"
    return "collect-repeat-transport-evidence"


def merged_surfaces(sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_surface: dict[str, dict[str, Any]] = {}
    for source in sources:
        for surface in source.get("surfaces", []):
            name = str(surface["surface"])
            current = by_surface.setdefault(name, empty_surface(name))
            merge_surface(current, surface)
    return sorted(
        by_surface.values(),
        key=lambda surface: (-int(surface["evidenceRank"]), str(surface["surface"])),
    )


def merge_surface(current: dict[str, Any], surface: dict[str, Any]) -> None:
    current["sourceCount"] += int(surface["sourceCount"])
    current["candidateCount"] += int(surface["candidateCount"])
    current["passCount"] += int(surface["passCount"])
    current["failCount"] += int(surface["failCount"])
    current["evidenceRank"] = max(int(current["evidenceRank"]), int(surface["evidenceRank"]))
    current["surfaceStrength"] = strongest(current["surfaceStrength"], surface["surfaceStrength"])
    current["checks"] = sorted({*current["checks"], *surface["checks"]})
    current["outcomeCounts"] = merge_counts(
        current["outcomeCounts"],
        surface["outcomeCounts"],
    )
    current["configFeatureCounts"] = merge_counts(
        current["configFeatureCounts"],
        surface["configFeatureCounts"],
    )
    current["failureCategoryCounts"] = merge_counts(
        current["failureCategoryCounts"],
        surface["failureCategoryCounts"],
    )
    current["stageMarkerCounts"] = merge_counts(
        current["stageMarkerCounts"],
        surface["stageMarkerCounts"],
    )


def strongest(left: str, right: str) -> str:
    order = {"unknown": 0, "weak": 1, "diagnostic": 2, "strong": 3}
    return right if order.get(right, 0) > order.get(left, 0) else left


def empty_surface(name: str) -> dict[str, Any]:
    return {
        "surface": name,
        "surfaceStrength": "unknown",
        "evidenceRank": 0,
        "sourceCount": 0,
        "checks": [],
        "candidateCount": 0,
        "passCount": 0,
        "failCount": 0,
        "outcomeCounts": {},
        "configFeatureCounts": {},
        "failureCategoryCounts": {},
        "stageMarkerCounts": {},
    }


def normalized_counts(raw: dict[str, Any]) -> dict[str, int]:
    return {
        str(key): int(value)
        for key, value in sorted(raw.items(), key=lambda item: str(item[0]))
    }


def merge_counts(left: dict[str, int], right: dict[str, int]) -> dict[str, int]:
    merged = dict(left)
    for key, value in right.items():
        merged[key] = merged.get(key, 0) + int(value)
    return dict(sorted(merged.items()))
