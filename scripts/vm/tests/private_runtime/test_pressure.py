from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
VM_PATH = ROOT / "scripts" / "vm"
sys.path.insert(0, str(VM_PATH))

from private_runtime_lib.reporting import round_gap_compare
from private_runtime_lib.reporting.workload_surface.ip.ipv6 import (
    build_ipv6_denial_summary,
)
from private_runtime_lib.reporting.workload_surface.artifact.retention import (
    build_retained_artifact_summary,
)
from private_runtime_lib.reporting.workload_surface.lifecycle.exit_limit import (
    build_exit_limit_summary,
)
from private_runtime_lib.reporting.workload_surface.lifecycle.takeover import (
    build_takeover_lifecycle_summary,
)
from tests.private_runtime_fixtures import gap_runtime, round_gap_batch, tcp_identity_report


class RoundGapCompareTest(unittest.TestCase):
    def test_compare(self) -> None:
        baseline = round_gap_batch(
            "baseline",
            [
                gap_runtime(
                    "stage-pressure-lag",
                    2935,
                    workload_success=7,
                    terminal=1,
                    stage_failures=1,
                    lag=8000,
                ),
            ],
        )
        candidate = round_gap_batch(
            "candidate",
            [gap_runtime("outbound-stage", 2935, workload_success=7, stage_failures=1)],
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            report = compare_fixture(Path(temp_dir), baseline, candidate)

        self.assertEqual(
            report["conclusion"]["status"],
            "schedule-lag-separated-outbound-stage-remains",
        )
        self.assertEqual(
            report["conclusion"]["nextAction"],
            "harden-outbound-stage-failure-path",
        )
        self.assertEqual(report["deltas"]["terminalCount"]["delta"], -1)
        self.assertEqual(report["deltas"]["scheduleLagMaxMs"]["delta"], -8000)
        self.assertEqual(
            report["conclusion"]["remainingMechanisms"],
            [
                {"key": "runtime-stage-failure", "count": 1},
                {"key": "recovered-runtime-stage-pressure", "count": 1},
            ],
        )

    def test_clean_regression(self) -> None:
        baseline = clean_compare_summary(
            stage_failures=1,
            recovered_flows=1,
            slow_stage_events=1,
            slow_stage_max_ms=12000,
            schedule_lag_max_ms=4200,
        )
        candidate = clean_compare_summary(
            stage_failures=3,
            recovered_flows=3,
            slow_stage_events=3,
            slow_stage_max_ms=16000,
            schedule_lag_max_ms=9000,
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            report = compare_fixture(Path(temp_dir), baseline, candidate)

        self.assertEqual(
            report["conclusion"]["status"],
            "candidate-clean-with-observe-only-regressions",
        )
        self.assertEqual(
            report["conclusion"]["nextAction"],
            "keep-current-baseline-and-investigate-regressions",
        )
        self.assertEqual(
            report["conclusion"]["regressions"],
            [
                {"key": "stageFailureCount", "delta": 2},
                {"key": "recoveredFlowCount", "delta": 2},
                {"key": "slowStageEvents", "delta": 2},
                {"key": "slowStageMaxMs", "delta": 4000},
                {"key": "scheduleLagMaxMs", "delta": 4800},
            ],
        )


class Ipv6DenialSurfaceTest(unittest.TestCase):
    def test_clean(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = root / "run-01"
            write_run(run, ipv6_denial_report())

            report = build_ipv6_denial_summary("ipv6", root / "out", [run])

        self.assertEqual(report["conclusion"]["status"], "clean")
        self.assertEqual(report["totals"]["denials"], 1)
        self.assertEqual(report["totals"]["reportedIpv6PacketsDenied"], 1)
        self.assertEqual(report["totals"]["byReasonBucket"], [
            {"count": 1, "key": "ipv6-forwarding-not-implemented"},
        ])

    def test_counter_mismatch_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = root / "run-01"
            report = ipv6_denial_report()
            report["ipv6PacketsDenied"] = 0
            write_run(run, report)

            summary = build_ipv6_denial_summary("ipv6", root / "out", [run])

        self.assertEqual(summary["runs"][0]["classification"], "ipv6-denial-counter-mismatch")
        self.assertEqual(summary["conclusion"]["status"], "ipv6-denial-surface-needs-evidence")


class TakeoverLifecycleSurfaceTest(unittest.TestCase):
    def test_clean(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = root / "run-01"
            write_lifecycle_run(run)

            summary = build_takeover_lifecycle_summary("life", root / "out", [run])

        self.assertEqual(summary["conclusion"]["status"], "clean")
        self.assertEqual(summary["totals"]["installReports"], 1)
        self.assertEqual(summary["totals"]["uninstallReports"], 1)
        self.assertEqual(summary["totals"]["uninstallPresentResources"], 0)

    def test_cleanup_resource_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = root / "run-01"
            write_lifecycle_run(run, cleanup_present=True)

            summary = build_takeover_lifecycle_summary("life", root / "out", [run])

        self.assertEqual(summary["runs"][0]["classification"], "cleanup-resource-present")
        self.assertEqual(
            summary["conclusion"]["status"],
            "takeover-lifecycle-surface-needs-evidence",
        )


class RetainedArtifactSurfaceTest(unittest.TestCase):
    def test_clean(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = root / "run-01"
            write_retained_run(run)
            summary = build_retained_artifact_summary("retained", root / "out", [run])
        self.assertEqual(summary["conclusion"]["status"], "clean")
        self.assertEqual(summary["totals"]["requiredJsonMissing"], 0)
        self.assertEqual(summary["totals"]["unsafePrivacyFlags"], 0)
        self.assertEqual(summary["totals"]["pcapFiles"], 0)

    def test_forbidden_file_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = root / "run-01"
            write_retained_run(run)
            (run / "capture.pcap").write_text("not retained by product artifacts")
            summary = build_retained_artifact_summary("retained", root / "out", [run])
        self.assertEqual(summary["runs"][0]["classification"], "forbidden-file-retained")
        self.assertEqual(
            summary["conclusion"]["status"],
            "retained-artifact-surface-needs-evidence",
        )

    def test_privacy_flag_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = root / "run-01"
            write_retained_run(run, raw_secret=True)
            summary = build_retained_artifact_summary("retained", root / "out", [run])
        self.assertEqual(summary["runs"][0]["classification"], "unsafe-privacy-flag")
        self.assertEqual(summary["totals"]["unsafeFlagNames"], [
            {"count": 1, "key": "privacy.rawSecretsStored"},
        ])


class ExitLimitSurfaceTest(unittest.TestCase):
    def test_clean(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = root / "run-01"
            write_run_summary(run, exit_limit_run())
            summary = build_exit_limit_summary("exit", root / "out", [run])
        self.assertEqual(summary["conclusion"]["status"], "clean")
        self.assertEqual(summary["totals"]["limitEvidence"], [
            {"count": 1, "key": "tcp-terminal-limit"},
        ])

    def test_limit_reason_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = root / "run-01"
            summary = exit_limit_run()
            summary["runtime"]["reason"] = "timeout reached"
            write_run_summary(run, summary)
            report = build_exit_limit_summary("exit", root / "out", [run])
        self.assertEqual(report["runs"][0]["classification"], "runtime-limit-reason-missing")
        self.assertEqual(report["conclusion"]["status"], "exit-limit-surface-needs-evidence")


def write_run(path: Path, report: dict[str, object]) -> None:
    path.mkdir()
    write_json(path / "summary.json", run_summary())
    write_json(path / "runtime-report.json", report)


def write_run_summary(path: Path, summary: dict[str, object]) -> None:
    path.mkdir()
    write_json(path / "summary.json", summary)


def write_lifecycle_run(path: Path, cleanup_present: bool = False) -> None:
    path.mkdir()
    write_json(path / "summary.json", lifecycle_run_summary())
    write_json(path / "install-report.json", lifecycle_report("install"))
    write_json(path / "uninstall-report.json", lifecycle_report("uninstall", cleanup_present))
    write_json(path / "stage-report.json", stage_report())


def write_retained_run(path: Path, raw_secret: bool = False) -> None:
    path.mkdir()
    write_json(path / "summary.json", retained_run_summary(raw_secret))
    for name in [
        "runtime-report.json",
        "install-report.json",
        "uninstall-report.json",
        "stage-report.json",
        "workload-probe.json",
        "tcp-probe.json",
        "meta.json",
    ]:
        write_json(path / name, {"schema": name})
    for name in ["runtime-log.txt", "command-stdout.txt", "command-stderr.txt"]:
        (path / name).write_text("diagnostic")


def ipv6_denial_report() -> dict[str, object]:
    report = tcp_identity_report()
    report["ipv6PacketsDenied"] = 1
    report["events"] = [
        {
            "kind": "ip-packet-denied",
            "fields": {
                "destination": "[<redacted-ip>]:443",
                "destinationPort": "443",
                "ipVersion": "6",
                "protocol": "udp",
                "reason": "ipv6 forwarding is not implemented; fail closed",
                "source": "[<redacted-ip>]:34254",
            },
        },
        *report["events"],
    ]
    return report


def lifecycle_run_summary() -> dict[str, object]:
    return {
        "label": "run-01",
        "checks": [
            {"name": "install-apply", "passed": True},
            {"name": "uninstall-cleanup", "passed": True},
        ],
    }


def retained_run_summary(raw_secret: bool = False) -> dict[str, object]:
    return {
        "label": "run-01",
        "privacy": {
            "authorizationSent": False,
            "cookiesSent": False,
            "identityInformationSent": False,
            "rawSecretsStored": raw_secret,
            "remoteSecretConfigCleaned": True,
            "resolvedIpsRedacted": True,
        },
        "metadata": {
            "privacy": {
                "authorizationSent": False,
                "cookiesSent": False,
                "identityInformationSent": False,
                "rawSecretsStored": False,
            },
        },
        "workloadProbe": {
            "privacy": {
                "authorizationSent": False,
                "cookiesSent": False,
                "identityInformationSent": False,
                "resolvedIpAddressesStored": False,
                "responseBodiesStored": False,
                "responseHeadersStored": False,
            },
            "tunCapture": {
                "rawLinesStored": False,
                "rawPcapStored": False,
                "started": True,
            },
        },
    }


def exit_limit_run() -> dict[str, object]:
    return {
        "label": "run-01",
        "commandExitCode": 0,
        "totals": {"failed": 0},
        "runtime": {
            "reason": "runtime limits reached",
            "status": "pass",
            "tcpClosedSessions": 2,
            "udpDownstreamBytes": 0,
            "dnsQueries": 2,
            "tunPackets": 2,
        },
        "tcpProbe": {"results": [{"name": "one"}]},
        "workloadProbe": {
            "totals": {"count": 1},
            "privacy": {
                "authorizationSent": False,
                "cookiesSent": False,
                "identityInformationSent": False,
                "resolvedIpAddressesStored": False,
                "responseBodiesStored": False,
                "responseHeadersStored": False,
            },
        },
        "privacy": {
            "authorizationSent": False,
            "cookiesSent": False,
            "identityInformationSent": False,
            "rawSecretsStored": False,
        },
        "metadata": {"privacy": {"rawSecretsStored": False}},
    }


def lifecycle_report(action: str, cleanup_present: bool = False) -> dict[str, object]:
    checks = install_checks() if action == "install" else uninstall_checks()
    present = action == "install"
    return {
        "action": action,
        "checkOnly": False,
        "checks": [{"name": name, "status": "pass"} for name in checks],
        "resources": [
            {"kind": kind, "owned": True, "present": cleanup_present or present}
            for kind in lifecycle_resource_kinds()
        ],
        "diagnostics": [],
    }


def install_checks() -> list[str]:
    return [
        "apply-engine",
        "apply:preflight",
        "apply:directories",
        "apply:manifest",
        "apply:tun",
        "apply:bypass-route",
        "apply:nftables",
    ]


def uninstall_checks() -> list[str]:
    return [
        "uninstall-engine",
        "uninstall:manifest",
        "uninstall:nft-dropin",
        "uninstall:bypass-route",
        "uninstall:tun",
        "uninstall:state",
    ]


def lifecycle_resource_kinds() -> list[str]:
    return ["nft-dropin", "nft-table", "tun", "route-table", "runtime-dir", "state-dir"]


def stage_report() -> dict[str, object]:
    return {
        "schema": "dynet-vm-private-runtime-stages/v1alpha1",
        "stages": [
            {"name": "run-acceptance", "status": "pass"},
            {"name": "collect-install-report", "status": "pass"},
            {"name": "collect-uninstall-report", "status": "pass"},
            {"name": "cleanup-guest-files", "status": "pass"},
        ],
    }


def run_summary() -> dict[str, object]:
    return {
        "label": "run-01",
        "checks": [{"name": "runtime-pass", "passed": True}],
        "runtime": {"tcpSlotPressureEvents": 2},
        "workloadProbe": {"totals": {"count": 1, "success": 1, "failure": 0}},
        "tcpFlow": {
            "failedFlows": 0,
            "stageFailedFlows": 1,
            "pathCompleteFlows": 1,
            "payloadBidirectionalFlows": 1,
        },
        "cascadeAttempts": {"failedAttempts": 1, "recoveredFlows": 1},
    }


def compare_fixture(root: Path, baseline: dict, candidate: dict) -> dict:
    baseline_path = root / "baseline.json"
    candidate_path = root / "candidate.json"
    baseline_path.write_text(json.dumps(baseline, sort_keys=True))
    candidate_path.write_text(json.dumps(candidate, sort_keys=True))
    return round_gap_compare.build_compare_report(
        "compare",
        root / "out",
        baseline_path,
        candidate_path,
        "baseline",
        "candidate",
    )


def clean_compare_summary(
    *,
    stage_failures: int,
    recovered_flows: int,
    slow_stage_events: int,
    slow_stage_max_ms: int,
    schedule_lag_max_ms: int,
) -> dict:
    return {
        "label": "clean-compare",
        "conclusion": {"status": "clean", "nextAction": "return-to-mainline-product-effect"},
        "totals": {
            "runs": 4,
            "workloadAttempted": 32,
            "workloadSuccess": 32,
            "workloadFailure": 0,
            "terminalByReason": [],
            "stageFailureBySurface": [{"key": "tcp-connect:trojan", "count": stage_failures}],
            "recoveredFlowMechanisms": [
                {
                    "key": "recovered-runtime-stage-failure-before-success",
                    "count": recovered_flows,
                },
            ],
            "flowRefreshChangedRuns": 0,
            "flowRefreshClassifications": [{"key": "unchanged", "count": 4}],
            "slowStageEvents": slow_stage_events,
            "slowStageMaxMs": slow_stage_max_ms,
            "scheduleLagMaxMs": schedule_lag_max_ms,
            "classifications": [{"key": "clean", "count": 4}],
        },
    }


def write_json(path: Path, payload: dict[str, object]) -> None:
    path.write_text(json.dumps(payload))


if __name__ == "__main__":
    unittest.main()
