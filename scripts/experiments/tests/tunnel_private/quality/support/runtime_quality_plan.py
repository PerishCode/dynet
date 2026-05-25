from __future__ import annotations

from pathlib import Path

from tests.tunnel_private.quality.support.mainline_baseline import write_json


def runtime_quality_plan_repeat(
    adapter_type: str,
    runtime_dns_mode: str = "config-chain",
    selected_behind: int = 0,
) -> dict[str, object]:
    return {
        "schema": "dynet-vm-private-runtime-repeat/v1alpha1",
        "label": f"{adapter_type}-quality-plan-repeat",
        "runtimeDnsMode": runtime_dns_mode,
        "tcpForward": True,
        "qualityStateUsed": True,
        "candidateControl": {
            "forceBoundCandidate": None,
            "forcePrivateDownstreamFailure": False,
            "poisonBoundOnly": False,
            "poisonFirstBoundCandidate": False,
            "tcpRouteDirectFallback": False,
            "tcpRouteNonDirectFallback": False,
        },
        "totals": {
            "runs": 2,
            "passedRuns": 2,
            "failedRuns": 0,
            "workloadAttempted": 8,
            "workloadSuccess": 8,
            "workloadFailure": 0,
            "workloadStrictFailedRuns": 0,
            "qualityBoundCandidateSets": 8,
            "qualityBoundSelectedWithQuality": 8,
            "qualityBoundSelectedBehind": selected_behind,
            "tcpFlowRouteGraphSelected": 8,
            "tcpFlowRouteMatched": 8,
            "tcpFlowRuleMatched": 0,
            "tcpFlowPlanBypassed": 0,
            "tcpFlowStarted": 8,
            "tcpFlowPathComplete": 8,
            "tcpFlowLifecycleComplete": 8,
            "tcpFlowPayloadBidirectional": 8,
            "tcpFlowFailed": 0,
            "tcpFlowFailedAfterPathComplete": 0,
            "tcpFlowFailedAfterUpstreamOnly": 0,
            "tcpFlowStageFailed": 0,
            "workloadFlowEntries": 8,
            "workloadFlowTcpAttemptedEntries": 8,
            "workloadFlowTcpAttemptedCoveredEntries": 8,
            "workloadFlowMatchedEntries": 8,
            "workloadFlowCoveredEntries": 8,
            "workloadFlowRuntimePreflowMatchedEntries": 8,
            "workloadFlowRuntimePacketHandshakeEntries": 8,
            "workloadFlowTunCaptureMatchedEntries": 8,
            "workloadFlowUnmatchedEntries": 0,
            "workloadFlowRuntimePacketTerminalEntries": 0,
            "workloadFlowMatchedFailures": 0,
            "workloadFlowUnmatchedFailures": 0,
            "workloadFlowMatchedFlowFailedAttempts": 0,
            "workloadFlowMatchedFlowStageFailedAttempts": 0,
            "workloadFlowMatchedRecoveredFailureEntries": 0,
        },
    }


def runtime_quality_plan_run(adapter_type: str) -> dict[str, object]:
    return {
        "schema": "dynet-vm-private-runtime-run/v1alpha1",
        "label": f"{adapter_type}-quality-plan-run",
        "metadata": {
            "candidates": [{"tag": "tunnel-001", "type": adapter_type}],
            "privacy": {
                "rawSecretsStored": False,
                "identityInformationSent": False,
            },
        },
        "privacy": {
            "rawSecretsStored": False,
            "identityInformationSent": False,
            "cookiesSent": False,
            "authorizationSent": False,
        },
        "runtime": {
            "tcpSessionFailures": 0,
            "tcpSlotPressureEvents": 0,
        },
        "workloadProbe": {
            "privacy": {
                "identityInformationSent": False,
                "responseBodiesStored": False,
            },
            "tunCapture": {"rawLinesStored": False, "rawPcapStored": False},
        },
        "checks": [
            {"name": "runtime-pass", "passed": True},
            {"name": "route-or-rule", "passed": True},
            {"name": "dialer-selected", "passed": True},
            {"name": "tcp-blackbox-https", "passed": True},
            {"name": "tcp-flow-lifecycle-complete", "passed": True},
            {"name": "tcp-flow-path-complete", "passed": True},
            {"name": "tcp-flow-payload-bidirectional", "passed": True},
            {"name": "workload-all-success", "passed": True},
            {"name": "workload-flow-covered", "passed": True},
            {"name": "quality-bound-candidate-set", "passed": True},
            {"name": "quality-bound-selected", "passed": True},
            {"name": "quality-bound-selected-has-quality", "passed": True},
            {"name": "quality-bound-selected-best", "passed": True},
        ],
    }


def write_quality_plan_repeat(
    root: Path,
    adapter_type: str,
    runtime_dns_mode: str = "config-chain",
    selected_behind: int = 0,
) -> Path:
    repeat_dir = root / f"{adapter_type}-quality-plan-repeat"
    repeat_dir.mkdir()
    repeat = write_json(
        repeat_dir / "summary.json",
        runtime_quality_plan_repeat(
            adapter_type,
            runtime_dns_mode,
            selected_behind,
        ),
    )
    for index in range(1, 3):
        run_dir = repeat_dir / f"run-{index:02d}"
        run_dir.mkdir()
        write_json(run_dir / "summary.json", runtime_quality_plan_run(adapter_type))
    return repeat
