from __future__ import annotations

from typing import Any


def product_effect_conclusion(
    gates: list[dict[str, Any]],
    dynet: dict[str, Any],
    clash: dict[str, Any],
    paired: dict[str, Any],
    maturity: dict[str, Any] | None = None,
) -> dict[str, Any]:
    failed_required = failed_gate_ids(gates, "required")
    failed_product_effect = failed_gate_ids(gates, "product-effect")
    status = product_effect_status(failed_required, failed_product_effect)
    return {
        "status": status,
        "recommendedUse": recommended_use(status),
        "productEffectParityClaimSafe": status == "product-effect-parity-candidate",
        "plannerPenaltySafe": False,
        "notReadyReasons": failed_required + failed_product_effect,
        "dynetLinuxProductClean": bool(dynet["clean"]),
        "clashProductSurfacePresent": bool(clash["productPass"]),
        "linuxInterfaceBoundPaired": bool(paired["linuxInterfaceBound"]),
        "nextActions": next_actions(
            status,
            failed_required,
            failed_product_effect,
            maturity or {},
        ),
    }


def product_effect_status(
    failed_required: list[str],
    failed_product_effect: list[str],
) -> str:
    if failed_required:
        return "blocked"
    if "linux-interface-bound-paired-window" in failed_product_effect:
        return "needs-vm-side-paired-product-effect"
    if "paired-product-effect-parity" in failed_product_effect:
        return "needs-paired-product-effect-parity"
    if "paired-window-depth" in failed_product_effect:
        return "needs-repeat-paired-product-effect"
    if "paired-entry-depth" in failed_product_effect:
        return "needs-broader-paired-product-effect"
    if (
        "dynet-run-tun-runtime-clean" in failed_product_effect
        or "runtime-workload-depth" in failed_product_effect
        or "runtime-target-overlap-known" in failed_product_effect
    ):
        return "needs-runtime-backed-product-effect"
    if "target-family-overlap-known" in failed_product_effect:
        return "needs-target-overlap-proof"
    return "product-effect-parity-candidate"


def recommended_use(status: str) -> str:
    mapping = {
        "blocked": "fix-input-evidence-before-product-effect-claim",
        "needs-vm-side-paired-product-effect": "build-vm-side-paired-product-effect-runner",
        "needs-paired-product-effect-parity": "collect-clean-paired-product-effect-window",
        "needs-repeat-paired-product-effect": "collect-repeat-paired-product-effect-window",
        "needs-broader-paired-product-effect": "collect-broader-paired-product-effect-window",
        "needs-runtime-backed-product-effect": "collect-clean-dynet-run-tun-product-effect-window",
        "needs-target-overlap-proof": "collect-target-family-overlap-evidence",
        "product-effect-parity-candidate": "eligible-for-product-effect-parity-review",
    }
    return mapping[status]


def next_actions(
    status: str,
    failed_required: list[str],
    failed_product_effect: list[str],
    maturity: dict[str, Any],
) -> list[dict[str, Any]]:
    actions = [action_for_gate(gate_id) for gate_id in failed_required + failed_product_effect]
    if status == "needs-vm-side-paired-product-effect":
        actions.insert(0, action(
            "build-vm-side-paired-product-effect-runner",
            "product-effect",
            "required",
            "Local paired dynet probe does not exercise Linux interface-bound Trojan runtime.",
        ))
    actions.extend(maturity_observe_actions(maturity))
    actions.append(action(
        "keep-planner-penalties-disabled",
        "policy",
        "required",
        "Product-effect shape evidence is not repeated runtime-backed node failure evidence.",
    ))
    return dedupe_actions(actions)


def maturity_observe_actions(maturity: dict[str, Any]) -> list[dict[str, Any]]:
    actions = []
    if bool(maturity.get("recoveredFallbackObserved")):
        actions.append(action(
            "retain-fallback-recovery-observe-only",
            "maturity",
            "observe",
            "Maturity observed recovered fallback selections; product-effect does not turn them into planner penalties.",
        ))
    if bool(maturity.get("recoveredStagePressureObserved")):
        actions.append(action(
            "retain-recovered-stage-pressure-observe-only",
            "maturity",
            "observe",
            "Maturity observed recovered outbound-stage pressure; product-effect does not turn it into planner penalties.",
        ))
    if bool(maturity.get("cascadeStagePressureObserved")):
        actions.append(action(
            "retain-cascade-stage-pressure-observe-only",
            "maturity",
            "observe",
            "Maturity observed cascade failure-stage pressure; product-effect does not turn it into planner penalties.",
        ))
    return actions


def action_for_gate(gate_id: str) -> dict[str, Any]:
    mapping = {
        "adapter-candidate-mature": ("reach-adapter-candidate-maturity", "maturity", "required"),
        "dynet-linux-product-clean": ("collect-clean-dynet-linux-product-evidence", "product-e2e", "required"),
        "dynet-product-target-diversity": ("collect-more-dynet-product-targets", "product-e2e", "required"),
        "clash-product-surface-present": ("collect-clash-product-e2e-surface", "product-e2e", "required"),
        "linux-interface-bound-paired-window": ("build-vm-side-paired-product-effect-runner", "product-effect", "required"),
        "paired-product-effect-parity": ("collect-clean-paired-product-effect-window", "product-effect", "required"),
        "paired-window-depth": ("collect-repeat-paired-product-effect-window", "product-effect", "required"),
        "paired-entry-depth": ("collect-broader-paired-product-effect-window", "product-effect", "required"),
        "dynet-run-tun-runtime-clean": ("collect-clean-dynet-run-tun-product-effect-window", "runtime", "required"),
        "runtime-workload-depth": ("collect-more-dynet-run-tun-workload-entries", "runtime", "required"),
        "runtime-target-overlap-known": ("collect-runtime-target-overlap-evidence", "runtime", "follow-up"),
        "target-family-overlap-known": ("collect-target-family-overlap-evidence", "product-effect", "follow-up"),
    }
    action_id, evidence, priority = mapping.get(
        gate_id,
        ("inspect-product-effect-gate", "product-effect", "follow-up"),
    )
    return action(action_id, evidence, priority, f"Gate `{gate_id}` is not satisfied.")


def action(action_id: str, evidence: str, priority: str, reason: str) -> dict[str, Any]:
    return {
        "id": action_id,
        "evidence": evidence,
        "priority": priority,
        "reason": reason,
        "plannerPenaltySafe": False,
    }


def dedupe_actions(actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    result = []
    for item in actions:
        action_id = str(item.get("id") or "")
        if action_id in seen:
            continue
        seen.add(action_id)
        result.append(item)
    return result


def failed_gate_ids(gates: list[dict[str, Any]], severity: str) -> list[str]:
    return [
        str(gate["id"]) for gate in gates
        if gate.get("severity") == severity and not gate.get("passed")
    ]


def gate(gate_id: str, severity: str, passed: bool, actual: Any, expected: Any) -> dict[str, Any]:
    return {
        "id": gate_id,
        "severity": severity,
        "passed": bool(passed),
        "actual": actual,
        "expected": expected,
    }
