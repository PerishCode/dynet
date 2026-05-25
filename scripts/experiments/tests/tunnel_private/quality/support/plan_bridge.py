from __future__ import annotations

from pathlib import Path

from tests.tunnel_private.quality.support.mainline_baseline import write_json


def write_plan_bridges(root: Path, *, include_auto: bool = True) -> list[Path]:
    paths = [write_bridge(root / "trojan", "trojan", include_auto)]
    paths.append(write_bridge(root / "vmess", "vmess", include_auto))
    return paths


def write_bridge(root: Path, adapter: str, include_auto: bool) -> Path:
    root.mkdir()
    observe = write_row(root / "observe", adapter, "observe", "observe")
    rows = [comparison_row(observe)]
    if include_auto:
        auto = write_row(root / "auto", adapter, "penalize", "auto")
        rows.append(comparison_row(auto))
    return write_json(
        root / "compare.json",
        {
            "schema": "dynet-tunnel-private-plan-quality-comparison/v1alpha1",
            "status": "pass",
            "totals": {
                "inspections": len(rows),
                "passed": len(rows),
                "failed": 0,
                "selectedBehind": 0,
                "promotionEligible": 1 if include_auto else 0,
                "penaltyObservations": 0,
            },
            "rows": rows,
            "conclusion": {
                "allSelectedBest": True,
                "selectionChanged": False,
                "penaltyApplied": False,
                "nextLever": "none-current-quality-already-selects-best",
            },
        },
    )


def write_row(root: Path, adapter: str, mode: str, requested: str) -> Path:
    root.mkdir()
    quality = write_json(root / "quality-state.json", quality_state(mode, requested))
    return write_json(
        root / "summary.json",
        {
            "schema": "dynet-tunnel-private-plan-quality-inspection/v1alpha1",
            "status": "pass",
            "inspectionScope": "dialer-bound",
            "qualityState": str(quality),
            "metadata": {"candidates": [{"tag": "tunnel-001", "type": adapter}]},
            "candidateQuality": candidate_quality(adapter),
            "plannerFeedback": {
                "mode": mode,
                "requestedMode": requested,
                "promotionEligible": requested == "auto",
                "penaltyObservations": 0,
            },
            "privacy": {
                "authorizationSent": False,
                "cookiesSent": False,
                "identityInformationSent": False,
                "rawPlanStored": False,
                "rawSecretsStored": False,
            },
        },
    )


def comparison_row(path: Path) -> dict[str, object]:
    return {
        "path": str(path),
        "status": "pass",
        "qualityState": str(path.parent / "quality-state.json"),
        "feedbackMode": "observe" if path.parent.name == "observe" else "penalize",
        "requestedFeedbackMode": path.parent.name,
        "promotionEligible": path.parent.name == "auto",
        "penaltyObservations": 0,
        "selected": "tunnel-001",
        "best": "tunnel-001",
        "selectedBest": True,
        "selectedBehind": 0,
        "selectedHasMatches": True,
        "withQuality": 1,
    }


def quality_state(mode: str, requested: str) -> dict[str, object]:
    return {
        "schema": "dynet-outbound-quality-state/v1alpha1",
        "plannerFeedback": {
            "mode": mode,
            "requestedMode": requested,
            "penaltyObservations": 0,
            "promotion": {"eligible": requested == "auto"},
        },
        "privacy": {
            "authorizationSent": False,
            "cookiesSent": False,
            "identityInformationSent": False,
            "responseBodiesStored": False,
        },
    }


def candidate_quality(adapter: str) -> dict[str, object]:
    selected = {
        "to": "tunnel-001",
        "type": adapter,
        "selected": True,
        "quality": {
            "stale": False,
            "targetFamily": "chatgpt.com",
            "score": 5000,
            "reason": "exact-and-overall-quality",
            "matches": [
                {
                    "scope": "dialer-bound",
                    "targetFamily": "chatgpt.com",
                    "transport": "tcp",
                    "verdict": "healthy",
                    "attempts": 2,
                    "successes": 2,
                    "failures": 0,
                    "confidence": "medium",
                    "weightedScore": 5000,
                }
            ],
        },
    }
    return {
        "withQuality": 1,
        "selectedBest": True,
        "selectedBehind": 0,
        "selectedHasMatches": True,
        "selectedScore": 5000,
        "bestScore": 5000,
        "selected": selected,
        "best": selected,
        "candidates": [selected],
    }
