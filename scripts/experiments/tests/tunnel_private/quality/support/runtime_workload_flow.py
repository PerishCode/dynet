from __future__ import annotations

from pathlib import Path

from tests.tunnel_private.quality.support.mainline_baseline import write_json


def runtime_workload_flow_repeat(unmatched: int = 0) -> dict[str, object]:
    matched = 8 - unmatched
    return {
        "schema": "dynet-vm-private-runtime-repeat/v1alpha1",
        "label": "runtime-workload-flow-repeat",
        "qualityStateUsed": False,
        "totals": {
            "runs": 2,
            "failedRuns": 0,
            "workloadAttempted": 8,
            "workloadSuccess": 8,
            "workloadFailure": 0,
            "workloadStrictFailedRuns": 0,
            "workloadErrors": [],
            "workloadFlowEntries": 8,
            "workloadFlowTcpAttemptedEntries": 8,
            "workloadFlowTcpAttemptedCoveredEntries": matched,
            "workloadFlowRuntimePreflowMatchedEntries": matched,
            "workloadFlowRuntimePacketHandshakeEntries": matched,
            "workloadFlowTunCaptureMatchedEntries": matched,
            "workloadFlowUnmatchedEntries": unmatched,
            "workloadFlowRuntimePacketTerminalEntries": 0,
            "tcpFlowFailed": 0,
            "tcpFlowFailedAfterPathComplete": 0,
            "tcpFlowFailedAfterUpstreamOnly": 0,
            "tcpSlotPressureEvents": 0,
        },
    }


def runtime_workload_flow_run() -> dict[str, object]:
    return {
        "schema": "dynet-vm-private-runtime-run/v1alpha1",
        "label": "runtime-workload-flow-run",
        "metadata": {
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
        "workloadProbe": {
            "privacy": {
                "identityInformationSent": False,
                "responseBodiesStored": False,
            },
            "tunCapture": {"rawLinesStored": False, "rawPcapStored": False},
        },
    }


def write_workload_flow_repeat(root: Path, unmatched: int = 0) -> Path:
    repeat_dir = root / "runtime-workload-flow-repeat"
    repeat_dir.mkdir()
    repeat = write_json(
        repeat_dir / "summary.json",
        runtime_workload_flow_repeat(unmatched),
    )
    for index in range(1, 3):
        run_dir = repeat_dir / f"run-{index:02d}"
        run_dir.mkdir()
        write_json(run_dir / "summary.json", runtime_workload_flow_run())
    return repeat
