from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
VM_PATH = ROOT / "scripts" / "vm"
sys.path.insert(0, str(VM_PATH))

from tests.private_runtime.cascade_fixtures import (
    cascade_stage_report,
    stale_cascade_summary,
)
from tests.private_runtime_fixtures import (
    gap_runtime,
    round_gap_batch,
    tcp_event,
    tcp_identity_report,
)
from private_runtime_lib.reporting import round_gap
from private_runtime_lib.reporting.workload_surface.tcp import stage_pressure_profile


class PrivateRuntimeRoundGapTest(unittest.TestCase):
    def test_round_gap_batch(self) -> None:
        summary = round_gap_batch(
            "round-gap",
            [
                gap_runtime("gap2500-a", 2500, workload_success=7, terminal=1),
                gap_runtime("gap2500-b", 2500, workload_success=7, terminal=1),
                gap_runtime(
                    "gap2875",
                    2875,
                    workload_success=5,
                    terminal=3,
                    stage_failures=2,
                    lag=16779,
                ),
                gap_runtime("gap2937-a", 2937),
                gap_runtime("gap2937-b", 2937),
            ],
        )

        self.assert_batch_totals(summary)
        self.assert_gap_summary(summary)
        self.assert_gap_row(summary)

    def test_round_gap_seconds(self) -> None:
        summary = gap_runtime("gap3s", 3000)
        summary["workloadProbe"]["seed"] = "trojan-paired-wide-roundgap3s-v1"
        summary["workloadProbe"]["results"] = []

        batch = round_gap_batch("round-gap", [summary])

        self.assertEqual(batch["runs"][0]["gapMs"], 3000)
        self.assertEqual(batch["byGap"][0]["status"], "single-clean")

    def test_outbound_reason(self) -> None:
        summary = round_gap_batch(
            "round-gap",
            [gap_runtime("stage-pressure", 2935, workload_success=7, stage_failures=1)],
        )

        self.assertEqual(summary["runs"][0]["classification"], "outbound-stage-pressure")
        self.assertEqual(summary["conclusion"]["status"], "outbound-stage-pressure")
        self.assertEqual(
            summary["conclusion"]["nextAction"],
            "harden-outbound-stage-failure-path",
        )
        self.assertEqual(
            summary["policy"]["reason"],
            "round-gap batch is outbound-stage pressure evidence, not repeated runtime-backed quality-gap evidence",
        )

    def test_schedule_reason(self) -> None:
        summary = round_gap_batch(
            "round-gap",
            [gap_runtime("stage-pressure-lag", 2935, workload_success=7, stage_failures=1, lag=8000)],
        )

        self.assertEqual(summary["runs"][0]["classification"], "stage-pressure-with-schedule-lag")
        self.assertEqual(
            summary["conclusion"]["status"],
            "stage-pressure-with-schedule-lag",
        )
        self.assertEqual(
            summary["conclusion"]["nextAction"],
            "separate-schedule-pressure-from-outbound-stage",
        )
        self.assertEqual(
            summary["policy"]["reason"],
            "round-gap batch is schedule-lag pressure evidence, not repeated runtime-backed quality-gap evidence",
        )

    def test_cascade_stop_conclusion(self) -> None:
        run = gap_runtime("cascade-control", 2935)
        run["selection"]["cascadeAttempts"] = {
            "startedAttempts": 2,
            "finishedAttempts": 2,
            "successAttempts": 0,
            "failedAttempts": 2,
            "retryableFailures": 1,
            "stoppedFailures": 1,
            "recoveredFlows": 0,
            "failedByScope": [
                {"key": "bound", "count": 1},
                {"key": "downstream", "count": 1},
            ],
            "failedByDisposition": [
                {"key": "pending-timeout", "count": 1},
                {"key": "protocol-invalid", "count": 1},
            ],
            "failedByStage": [
                {"key": "private-trojan-connect", "count": 1},
                {"key": "trojan-tls-handshake", "count": 1},
            ],
            "failedByStageSurface": [
                {"key": "private-trojan-connect:trojan", "count": 1},
                {"key": "trojan-tls-handshake:trojan", "count": 1},
            ],
            "failedByStageDisposition": [
                {"key": "pending-timeout", "count": 1},
                {"key": "protocol-invalid", "count": 1},
            ],
            "failedByStopReason": [
                {"key": "non-bound-failure", "count": 1},
                {"key": "retry-bound-failure-before-replay", "count": 1},
            ],
            "stoppedFlows": 1,
            "stoppedBoundExhaustedFlows": 0,
            "stoppedFlowByStopReason": [{"key": "non-bound-failure", "count": 1}],
            "stoppedFlowByStageSurface": [
                {"key": "private-trojan-connect:trojan", "count": 1},
            ],
            "stoppedFlowByAttemptCount": [{"key": "2", "count": 1}],
        }

        summary = round_gap_batch("round-gap", [run])

        self.assertEqual(summary["conclusion"]["status"], "clean")
        self.assertEqual(
            summary["conclusion"]["nextAction"],
            "preserve-non-bound-cascade-stop-and-return-to-product-effect",
        )
        self.assertEqual(summary["totals"]["cascadeFailedByStageSurface"], [
            {"count": 1, "key": "private-trojan-connect:trojan"},
            {"count": 1, "key": "trojan-tls-handshake:trojan"},
        ])
        self.assertEqual(
            summary["conclusion"]["cascade"]["status"],
            "non-bound-stop-observed",
        )
        self.assertEqual(
            summary["conclusion"]["cascade"]["nextAction"],
            "preserve-non-bound-cascade-stop",
        )
        self.assertEqual(summary["conclusion"]["cascade"]["stoppedFailures"], 1)
        self.assertEqual(
            summary["policy"]["reason"],
            "batch is clean but contains cascade mechanism evidence; cascade failures are observe-only control evidence, not stable candidate penalties",
        )

    def test_bound_exhaustion(self) -> None:
        run = gap_runtime("cascade-bound-exhausted", 2935)
        run["selection"]["cascadeAttempts"] = {
            "startedAttempts": 4,
            "finishedAttempts": 4,
            "successAttempts": 0,
            "failedAttempts": 4,
            "retryableFailures": 3,
            "stoppedFailures": 1,
            "stoppedFlows": 1,
            "stoppedBoundExhaustedFlows": 1,
            "recoveredFlows": 0,
            "failedByScope": [{"key": "bound", "count": 4}],
            "failedByDisposition": [{"key": "pending-timeout", "count": 4}],
            "failedByStageSurface": [{"key": "trojan-tls-handshake:trojan", "count": 4}],
            "failedByStageDisposition": [{"key": "pending-timeout", "count": 4}],
            "failedByStopReason": [
                {"key": "bound-candidates-exhausted", "count": 1},
                {"key": "retry-bound-failure-before-replay", "count": 3},
            ],
            "stoppedFlowByStopReason": [{"key": "bound-candidates-exhausted", "count": 1}],
            "stoppedFlowByStageSurface": [
                {"key": "trojan-tls-handshake:trojan", "count": 1},
            ],
            "stoppedFlowByAttemptCount": [{"key": "4", "count": 1}],
        }

        summary = round_gap_batch("round-gap", [run])

        self.assertEqual(
            summary["conclusion"]["cascade"]["status"],
            "bound-exhausted-cascade-stop-observed",
        )
        self.assertEqual(
            summary["conclusion"]["cascade"]["nextAction"],
            "inspect-bound-candidate-exhaustion-flow",
        )
        self.assertEqual(summary["totals"]["cascadeStoppedBoundExhaustedFlows"], 1)
        self.assertEqual(
            summary["totals"]["cascadeStoppedFlowByStageSurface"],
            [{"count": 1, "key": "trojan-tls-handshake:trojan"}],
        )

    def test_refreshes_flow(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run_dir = root / "run"
            run_dir.mkdir()
            write_json(run_dir / "runtime-report.json", recovered_stage_report())
            write_json(run_dir / "workload-probe.json", successful_workload_report())
            write_json(run_dir / "summary.json", stale_flow_summary())

            summary = round_gap.build_round_gap_summary("round-gap", root / "out", [run_dir])

        row = summary["runs"][0]
        self.assertEqual(row["flowRefresh"]["classification"], "recovered-stage-separated")
        self.assertTrue(row["flowRefresh"]["changed"])
        self.assertEqual(summary["totals"]["flowRefreshChangedRuns"], 1)
        self.assertEqual(
            summary["totals"]["flowRefreshClassifications"],
            [{"count": 1, "key": "recovered-stage-separated"}],
        )
        self.assertEqual(row["workloadFlow"]["matchedRecoveredFailureEntries"], 1)
        self.assertEqual(row["workloadFlow"]["matchedFlowFailedAttempts"], 0)
        self.assertEqual(row["workloadFlow"]["matchedFlowStageFailedAttempts"], 1)
        self.assertEqual(
            row["surfaces"]["stageFailureBySurface"],
            [{"count": 1, "key": "tcp-connect:trojan"}],
        )

    def test_cascade_stage_refresh(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run_dir = root / "run"
            run_dir.mkdir()
            write_json(run_dir / "runtime-report.json", cascade_stage_report())
            write_json(run_dir / "summary.json", stale_cascade_summary())

            summary = round_gap.build_round_gap_summary("round-gap", root / "out", [run_dir])

        row = summary["runs"][0]
        self.assertTrue(row["cascadeRefresh"]["changed"])
        self.assertEqual(row["cascade"]["failedByStageSurface"], [
            {"count": 1, "key": "private-trojan-connect:trojan"},
            {"count": 1, "key": "trojan-tls-handshake:trojan"},
        ])
        self.assertEqual(summary["totals"]["cascadeFailedByStageDisposition"], [
            {"count": 1, "key": "protocol-invalid"},
            {"count": 1, "key": "reset"},
        ])

    def test_stage_profiles(self) -> None:
        run = gap_runtime("run-01", 2935, stage_failures=2)
        for event in run["runtimeReport"]["events"]:
            fields = event["fields"]
            fields["pendingRetries"] = "7"
            fields["pendingElapsedMs"] = "321"
            fields["pendingBudgetMs"] = "250"
            fields["pendingSleepMs"] = "10"
            fields["pendingWaitClass"] = "poll-budget-exhausted"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            summary_path = root / "round-gap.json"
            write_json(
                summary_path,
                round_gap_batch(
                    "round-gap",
                    [run],
                ),
            )

            summary = stage_pressure_profile.build_stage_pressure_summary(
                "stage-pressure",
                root / "out",
                [summary_path],
            )

        self.assertEqual(summary["totals"]["pressureRunCount"], 1)
        self.assertEqual(summary["totals"]["maxStageFailureEventsInRun"], 2)
        profile = summary["totals"]["runProfiles"][0]
        self.assertEqual(profile["stageFailureEvents"], 2)
        self.assertEqual(profile["cascadeFailedAttempts"], 2)
        self.assertEqual(profile["slowStageMaxMs"], 8000)
        self.assertEqual(profile["pendingRetryEvents"], 2)
        self.assertEqual(profile["pendingRetries"], 14)
        self.assertEqual(profile["pendingRetriesMax"], 7)
        self.assertEqual(profile["pendingElapsedMs"], 642)
        self.assertEqual(profile["pendingElapsedMaxMs"], 321)
        self.assertEqual(profile["pendingBudgetMs"], 250)
        self.assertEqual(profile["pendingSleepMs"], 10)
        self.assertEqual(profile["pendingWaitClasses"], [
            {"count": 2, "key": "poll-budget-exhausted"},
        ])
        self.assertEqual(profile["stageDispositions"], [{"count": 2, "key": "pending-timeout"}])
        self.assertEqual(profile["stageSurfaces"], [{"count": 2, "key": "tcp-connect:trojan"}])

    def assert_batch_totals(self, summary: dict) -> None:
        self.assertFalse(summary["policy"]["plannerPenaltySafe"])
        self.assertFalse(summary["policy"]["qualityPenaltySafe"])
        self.assertEqual(summary["conclusion"]["status"], "mixed-with-clean-controls")
        self.assertEqual(
            summary["conclusion"]["nextAction"],
            "compare-mechanism-deltas-with-clean-controls",
        )
        self.assertEqual(summary["totals"]["runs"], 5)
        self.assertEqual(summary["totals"]["cleanRuns"], 2)
        self.assertEqual(
            summary["totals"]["terminalByReason"],
            [{"count": 5, "key": "closed-before-preflow"}],
        )
        self.assertEqual(
            summary["totals"]["stageFailureBySurface"],
            [{"count": 2, "key": "tcp-connect:trojan"}],
        )
        self.assertEqual(
            summary["totals"]["failedByPhase"],
            [{"count": 2, "key": "session-start"}],
        )
        self.assertEqual(
            summary["totals"]["failedByCleanupAction"],
            [{"count": 2, "key": "socket-abort"}],
        )
        self.assertEqual(
            summary["totals"]["failedByReplaySafe"],
            [{"count": 2, "key": "pre-payload"}],
        )
        self.assertEqual(
            summary["totals"]["failedByFailureStage"],
            [{"count": 2, "key": "tcp-connect"}],
        )
        self.assertEqual(
            summary["totals"]["stageFailureByDisposition"],
            [{"count": 2, "key": "pending-timeout"}],
        )
        self.assertEqual(summary["totals"]["cascadeFailedAttempts"], 2)
        self.assertEqual(summary["totals"]["cascadeRetryableFailures"], 2)
        self.assertEqual(
            summary["totals"]["cascadeFailedByDisposition"],
            [{"count": 2, "key": "pending-timeout"}],
        )
        self.assertEqual(
            summary["totals"]["cascadeFailedByStopReason"],
            [{"count": 2, "key": "retry-bound-failure-before-replay"}],
        )
        self.assertEqual(summary["totals"]["slowStageEvents"], 2)
        self.assertEqual(summary["totals"]["slowFailedStageEvents"], 2)
        self.assertEqual(summary["totals"]["slowStageMaxMs"], 8000)
        self.assertEqual(summary["totals"]["slowStageElapsedMs"], 16000)
        self.assertEqual(
            summary["totals"]["slowStageBySurface"],
            [{"count": 2, "key": "tcp-connect:failed:trojan"}],
        )
        self.assertEqual(
            summary["totals"]["failedWorkloadMechanisms"],
            [{"count": 5, "key": "packet-terminal-before-runtime-session"}],
        )
        self.assertEqual(
            summary["totals"]["recoveredFlowMechanisms"],
            [{"count": 2, "key": "recovered-runtime-stage-failure-before-success"}],
        )
        self.assertEqual(
            summary["totals"]["classifications"],
            [
                {"count": 2, "key": "clean"},
                {"count": 2, "key": "preflow-terminal-before-runtime-session"},
                {"count": 1, "key": "stage-pressure-with-schedule-lag"},
            ],
        )

    def assert_gap_summary(self, summary: dict) -> None:
        self.assertEqual(
            [(item["gapMs"], item["status"]) for item in summary["byGap"]],
            [
                (2500, "repeat-preflow-terminal"),
                (2875, "pressure-transition"),
                (2937, "repeat-clean"),
            ],
        )
        pressure = next(item for item in summary["byGap"] if item["gapMs"] == 2875)
        self.assertEqual(pressure["slowStageEvents"], 2)
        self.assertEqual(pressure["slowStageMaxMs"], 8000)
        self.assertEqual(
            pressure["failedByFailureStage"],
            [{"count": 2, "key": "tcp-connect"}],
        )
        self.assertEqual(
            pressure["stageFailureByDisposition"],
            [{"count": 2, "key": "pending-timeout"}],
        )
        self.assertEqual(pressure["cascadeFailedAttempts"], 2)
        self.assertEqual(
            pressure["cascadeFailedByDisposition"],
            [{"count": 2, "key": "pending-timeout"}],
        )
        self.assertEqual(
            pressure["recoveredFlowMechanisms"],
            [{"count": 2, "key": "recovered-runtime-stage-failure-before-success"}],
        )

    def assert_gap_row(self, summary: dict) -> None:
        row = next(item for item in summary["runs"] if item["label"] == "gap2500-a")
        self.assertEqual(row["schedule"]["failedRowCount"], 1)
        self.assertEqual(row["mechanisms"]["failedWorkloadCount"], 1)
        self.assertEqual(
            row["mechanisms"]["failedWorkloadByMechanism"],
            [{"count": 1, "key": "packet-terminal-before-runtime-session"}],
        )
        encoded = json.dumps(row)
        for key in ("domain", "flowId", "flowIds", "failedWorkloadRows", "recoveredFlowRows", "slowStageRows", "stoppedRows"):
            self.assertNotIn(f'"{key}"', encoded)


def recovered_stage_report() -> dict:
    report = tcp_identity_report()
    report["events"].insert(
        -1,
        tcp_event(
            "outbound-stage-finished",
            {"outbound": "tunnel-003", "stage": "tcp-connect", "status": "failed", "errorType": "trojan"},
        ),
    )
    return report


def successful_workload_report() -> dict:
    return {
        "totals": {"count": 1, "success": 1, "failure": 0, "successRate": 1.0},
        "results": [
            {
                "id": "example-head-1",
                "probe": "https-head",
                "domain": "chatgpt.com",
                "ok": True,
                "localPort": 45678,
                "routeViaDynet": True,
                "tunWitness": {"observed": True},
                "stages": [{"name": "tcp-connect", "ok": True}],
            }
        ],
    }


def stale_flow_summary() -> dict:
    return {
        "label": "stale-flow",
        "totals": {"failed": 0},
        "checks": [],
        "runtime": {"tcpSessionFailures": 0, "tcpActiveSlotsMax": 1, "tcpSlotPressureEvents": 0},
        "selection": {"boundSelection": {}, "cascadeAttempts": {}},
        "stability": {},
        "workloadProbe": successful_workload_report(),
        "tcpFlow": {
            "failedFlows": 1,
            "stageFailedFlows": 1,
            "stageFailureBySurface": [{"key": "tcp-connect:trojan", "count": 1}],
        },
        "workloadFlow": {
            "matchedEntries": 1,
            "unmatchedEntries": 0,
            "coveredEntries": 1,
            "matchedRecoveredFailureEntries": 0,
            "matchedFlowFailedAttempts": 1,
            "matchedFlowStageFailedAttempts": 1,
            "rows": [],
        },
    }


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, sort_keys=True))


if __name__ == "__main__":
    unittest.main()
