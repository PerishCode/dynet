from __future__ import annotations

from pathlib import Path

from tests.tunnel_private.quality.support.mainline_baseline import write_json


def write_quality_feedback_sources(
    root: Path,
    *,
    include_auto_proof: bool = True,
) -> list[Path]:
    output = [
        write_json(root / "quality-observe.json", quality_observe()),
        write_json(root / "quality-penalize.json", quality_penalize()),
        write_json(root / "quality-auto-no-proof.json", quality_auto_no_proof()),
    ]
    if include_auto_proof:
        output.append(
            write_json(
                root / "quality-auto-runtime-proof.json",
                quality_auto_runtime_proof(),
            )
        )
    return output


def quality_observe() -> dict[str, object]:
    return quality_state("observe", 0, "observe")


def quality_penalize() -> dict[str, object]:
    return quality_state("penalize", 1, "penalize")


def quality_auto_no_proof() -> dict[str, object]:
    state = quality_state("observe", 0, "observe")
    state["plannerFeedback"]["requestedMode"] = "auto"
    state["plannerFeedback"]["promotion"] = promotion(False, 0)
    return state


def quality_auto_runtime_proof() -> dict[str, object]:
    state = quality_state("penalize", 1, "penalize")
    state["plannerFeedback"]["requestedMode"] = "auto"
    state["plannerFeedback"]["promotion"] = promotion(True, 1)
    return state


def quality_state(
    mode: str,
    penalty_observations: int,
    signal_action: str,
) -> dict[str, object]:
    return {
        "schema": "dynet-outbound-quality-state/v1alpha1",
        "plannerFeedback": {
            "mode": mode,
            "probeBatches": 1,
            "repeatedQualityGaps": 1,
            "penaltyObservations": penalty_observations,
        },
        "signals": [quality_signal(signal_action)],
        "privacy": {
            "authorizationSent": False,
            "cookiesSent": False,
            "identityInformationSent": False,
            "responseBodiesStored": False,
        },
    }


def quality_signal(action: str) -> dict[str, object]:
    return {
        "type": "repeated-quality-gap",
        "action": action,
        "outbound": "private-a",
        "scope": "plan-candidate",
        "targetFamily": "gap.example",
        "domain": "api.gap.example",
        "plan": "auto-static",
        "bestCandidates": ["private-b"],
        "runs": ["run-a", "run-b"],
        "items": 2,
        "maxScoreGap": 9200,
    }


def promotion(eligible: bool, proofs: int) -> dict[str, object]:
    return {
        "schema": "dynet-quality-gap-promotion-gate/v1alpha1",
        "eligible": eligible,
        "action": "allow-penalty-feedback" if eligible else "observe-only",
        "proofs": proofs,
        "gates": promotion_gates(eligible),
    }


def promotion_gates(eligible: bool) -> list[dict[str, object]]:
    return [
        gate("runtime-repeat-proof", eligible, 1 if eligible else 0, ">=1"),
        gate("repeat-runs", eligible, 2 if eligible else 0, ">=2"),
        gate("no-failed-runs", True, 0, 0),
        gate("workload-replay-clean", eligible, 1.0 if eligible else None, 1.0),
        gate("quality-bound-present", eligible, 10 if eligible else 0, ">0"),
        gate("quality-bound-covered", True, 10 if eligible else 0, 10 if eligible else 0),
        gate("quality-bound-not-behind", True, 0, 0),
        gate("tcp-closed", eligible, 6 if eligible else 0, ">0"),
        gate("tcp-no-failures", True, 0, 0),
        gate("runtime-clean-stability", True, {}, "all zero"),
    ]


def gate(
    name: str,
    passed: bool,
    value: object,
    required: object,
) -> dict[str, object]:
    return {
        "name": name,
        "passed": passed,
        "value": value,
        "required": required,
    }
