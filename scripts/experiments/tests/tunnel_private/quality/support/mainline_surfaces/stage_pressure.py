from __future__ import annotations

from pathlib import Path

from tests.tunnel_private.quality.support.mainline_baseline import write_json


def write_stage_pressure(
    root: Path,
    failed: bool = False,
    product_clean: bool = False,
) -> Path:
    status = "stage-pressure-profile-needs-evidence"
    if product_clean:
        status = "stage-pressure-product-clean"
    elif not failed:
        status = "stage-pressure-profile-clean"
    return write_json(root / "stage-pressure.json", {
        "schema": "dynet-vm-private-runtime-stage-pressure-profile/v1alpha1",
        "label": "stage-pressure",
        "totals": {
            "sourceCount": 1, "roundGapRuns": 2,
            "cleanControlRuns": 2 if product_clean else 1,
            "failedRuns": 0 if product_clean else 1,
            "stageFailureEvents": 3 if product_clean else 8,
            "workloadFailure": 0 if product_clean else 1,
            "recoveredFlowCount": 2 if product_clean else 7,
            "cascadeFailedAttempts": 5 if product_clean else 11,
            "cascadeRetryableFailures": 5 if product_clean else 10,
            "cascadeStoppedFailures": 0 if product_clean else 1,
            "cascadeStoppedBoundExhaustedFlows": 0 if product_clean else 1,
            "selectedBehind": 1 if failed else 0,
            "tcpSlotPressureEvents": 45 if product_clean else 0,
            "scheduleLagMaxMs": 3568 if product_clean else 5196,
            "profileCount": 1,
            "schemaMismatchSources": 0, "penaltySafeSources": 0,
            "classifications": [{"key": "clean", "count": 1}],
            "stageSurfaces": [{"key": "trojan-tls-handshake:trojan", "count": 1}],
            "stageDispositions": [{"key": "pending-timeout", "count": 1}],
            "cascadeScopes": [{"key": "bound", "count": 1}],
            "cascadeStopReasons": [
                {"key": "retry-bound-failure-before-replay", "count": 1}
                if product_clean else {"key": "bound-candidates-exhausted", "count": 1}
            ],
            "replayScopes": [] if product_clean else [{"key": "pre-payload", "count": 1}],
            "pendingWaitClasses": [{"key": "socket-read-timeout", "count": 1}],
        },
        "conclusion": {
            "status": status,
            "nextAction": (
                "return-to-mainline-product-effect-with-pressure-observe"
                if product_clean else "harden-focused-stage-pressure-without-policy-change"
            ),
            "plannerPenaltySafe": False, "qualityPenaltySafe": False,
        },
        "policy": {"plannerPenaltySafe": False, "qualityPenaltySafe": False},
    })
