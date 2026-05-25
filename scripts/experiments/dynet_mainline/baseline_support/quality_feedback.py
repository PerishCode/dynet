from __future__ import annotations

import json
from pathlib import Path
from typing import Any


QUALITY_STATE_SCHEMA = "dynet-outbound-quality-state/v1alpha1"


def quality_feedback_source(path: Path) -> dict[str, Any]:
    summary = load_json(path)
    feedback = summary.get("plannerFeedback") or {}
    promotion = feedback.get("promotion") or {}
    signals = [
        item for item in summary.get("signals", [])
        if isinstance(item, dict)
    ]
    gates = [
        item for item in promotion.get("gates", [])
        if isinstance(item, dict)
    ]
    source = {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "mode": str(feedback.get("mode") or ""),
        "requestedMode": str(feedback.get("requestedMode") or ""),
        "probeBatches": int(feedback.get("probeBatches") or 0),
        "repeatedQualityGaps": int(feedback.get("repeatedQualityGaps") or 0),
        "penaltyObservations": int(feedback.get("penaltyObservations") or 0),
        "promotionAction": str(promotion.get("action") or ""),
        "promotionEligible": bool(promotion.get("eligible")),
        "promotionProofs": int(promotion.get("proofs") or 0),
        "promotionContexts": int(promotion.get("contexts") or 0),
        "promotionGateFailures": promotion_gate_failures(gates),
        "promotionGateNames": sorted({
            str(item.get("name")) for item in gates if item.get("name")
        }),
        "signalTypes": sorted({
            str(item.get("type")) for item in signals if item.get("type")
        }),
        "signalActions": signal_actions(signals),
        "repeatedQualityGapActions": signal_actions(
            [
                item for item in signals
                if item.get("type") == "repeated-quality-gap"
            ]
        ),
        "privacy": privacy_flags(summary),
    }
    source["category"] = quality_feedback_category(source)
    source["clean"] = quality_feedback_clean(source)
    return source


def quality_feedback_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "clean": bool(sources) and all(source["clean"] for source in sources),
        "categories": sorted({
            source["category"] for source in sources if source["category"]
        }),
        "observeRepeatedGapSources": count_category(
            sources,
            "observe-repeated-gap",
        ),
        "penalizeRepeatedGapSources": count_category(
            sources,
            "penalize-repeated-gap",
        ),
        "autoNoProofObserveOnlySources": count_category(
            sources,
            "auto-no-proof-observe-only",
        ),
        "autoRuntimeProofSources": count_category(
            sources,
            "auto-runtime-proof",
        ),
        "repeatedQualityGaps": sum(
            source["repeatedQualityGaps"] for source in sources
        ),
        "penaltyObservations": sum(
            source["penaltyObservations"] for source in sources
        ),
        "promotionProofs": sum(source["promotionProofs"] for source in sources),
        "promotionGateFailures": sorted({
            item for source in sources for item in source["promotionGateFailures"]
        }),
        "sources": sources,
    }


def quality_feedback_category(source: dict[str, Any]) -> str:
    if auto_runtime_proof(source):
        return "auto-runtime-proof"
    if auto_no_proof_gate(source):
        return "auto-no-proof-observe-only"
    if penalize_repeated_gap(source):
        return "penalize-repeated-gap"
    if observe_repeated_gap(source):
        return "observe-repeated-gap"
    return "unknown"


def quality_feedback_clean(source: dict[str, Any]) -> bool:
    return (
        source["schema"] == QUALITY_STATE_SCHEMA
        and source["category"] != "unknown"
        and not any(source["privacy"].values())
    )


def observe_repeated_gap(source: dict[str, Any]) -> bool:
    return (
        source["mode"] == "observe"
        and source["repeatedQualityGaps"] > 0
        and source["penaltyObservations"] == 0
        and "observe" in source["repeatedQualityGapActions"]
    )


def penalize_repeated_gap(source: dict[str, Any]) -> bool:
    return (
        source["mode"] == "penalize"
        and source["repeatedQualityGaps"] > 0
        and source["penaltyObservations"] > 0
        and "penalize" in source["repeatedQualityGapActions"]
    )


def auto_no_proof_gate(source: dict[str, Any]) -> bool:
    return (
        source["requestedMode"] == "auto"
        and source["mode"] == "observe"
        and source["repeatedQualityGaps"] > 0
        and source["penaltyObservations"] == 0
        and source["promotionAction"] == "observe-only"
        and not source["promotionEligible"]
        and source["promotionProofs"] == 0
        and "runtime-repeat-proof" in source["promotionGateFailures"]
        and "observe" in source["repeatedQualityGapActions"]
    )


def auto_runtime_proof(source: dict[str, Any]) -> bool:
    return (
        source["requestedMode"] == "auto"
        and source["mode"] == "penalize"
        and source["repeatedQualityGaps"] > 0
        and source["penaltyObservations"] > 0
        and source["promotionAction"] == "allow-penalty-feedback"
        and source["promotionEligible"]
        and source["promotionProofs"] > 0
        and not source["promotionGateFailures"]
        and "penalize" in source["repeatedQualityGapActions"]
    )


def count_category(sources: list[dict[str, Any]], category: str) -> int:
    return sum(1 for source in sources if source["category"] == category)


def signal_actions(signals: list[dict[str, Any]]) -> list[str]:
    return sorted({
        str(item.get("action")) for item in signals if item.get("action")
    })


def promotion_gate_failures(gates: list[dict[str, Any]]) -> list[str]:
    return sorted([
        str(item.get("name"))
        for item in gates
        if item.get("name") and item.get("passed") is not True
    ])


def privacy_flags(summary: dict[str, Any]) -> dict[str, bool]:
    privacy = summary.get("privacy") or {}
    return {
        "rawLogsStored": bool(privacy.get("rawLogsStored")),
        "rawPacketsStored": bool(privacy.get("rawPacketsStored")),
        "rawSecretsStored": bool(privacy.get("rawSecretsStored")),
        "responseBodiesStored": bool(privacy.get("responseBodiesStored"))
        or bool(privacy.get("rawResponseBodiesStored")),
        "rawResponseHeadersStored": bool(privacy.get("rawResponseHeadersStored"))
        or bool(privacy.get("responseHeadersStored")),
        "identityInformationSent": bool(privacy.get("identityInformationSent")),
        "cookiesSent": bool(privacy.get("cookiesSent")),
        "authorizationSent": bool(privacy.get("authorizationSent")),
        "accountStateStored": bool(privacy.get("accountStateStored")),
    }


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text())
