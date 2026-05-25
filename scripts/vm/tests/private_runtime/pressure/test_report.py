from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
VM_PATH = ROOT / "scripts" / "vm"
sys.path.insert(0, str(VM_PATH))

from private_runtime_lib.reporting.pressure import pressure_report


class PressureReportTest(unittest.TestCase):
    def test_recovered_pressure(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = root / "run-01"
            write_run(run, runtime_events())
            report = pressure_report("pressure", root / "out", [run])

        self.assertEqual(report["status"], "observe-only-product-clean")
        self.assertTrue(report["conclusion"]["productSurfaceClean"])
        self.assertTrue(report["conclusion"]["allStageFailuresRecovered"])
        self.assertEqual(report["totals"]["stageFailures"], 1)
        self.assertEqual(report["totals"]["stageRecoveredFailures"], 1)
        self.assertEqual(report["totals"]["slotPressureEvents"], 2)
        self.assertEqual(report["totals"]["sourceSlotPressureEvents"], 2)
        self.assertEqual(report["stagePressure"]["byStageDisposition"], [
            {"key": "trojan-tls-handshake:pending-timeout", "count": 1},
        ])
        self.assertNotIn("rows", report["stagePressure"])
        retained = json.dumps(report, sort_keys=True)
        self.assertNotIn("tcp-session-1", retained)
        self.assertNotIn("tunnel-004", retained)
        self.assertNotIn("chatgpt.com", retained)
        self.assertEqual(
            report["runPressure"]["rows"][0]["classification"],
            "product-clean-stage-and-slot-pressure",
        )
        self.assertFalse(report["policy"]["plannerPenaltySafe"])
        self.assertFalse(report["policy"]["qualityPenaltySafe"])
        self.assertFalse(report["policy"]["productEffectClaimSafe"])
        self.assertFalse(report["privacy"]["rawSecretsStored"])

    def test_separated_pressure(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            write_run(root / "run-01", runtime_events(slot=False, slow=True))
            write_run(root / "run-02", runtime_events(stage=False))
            report = pressure_report("pressure", root / "out", [
                root / "run-01",
                root / "run-02",
            ])

        self.assertEqual(report["status"], "observe-only-product-clean")
        self.assertEqual(
            report["conclusion"]["pressureShape"],
            "separated-handshake-wait-and-slot-admission-pressure",
        )
        self.assertEqual(report["totals"]["runsWithStageWithoutSlotPressure"], 1)
        self.assertEqual(report["totals"]["runsWithSlotWithoutStagePressure"], 1)
        self.assertEqual(report["totals"]["slowFailedStageEvents"], 1)
        self.assertEqual(report["totals"]["slotCapacityMissingEvents"], 2)

    def test_terminal_pressure(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = root / "run-01"
            write_run(run, runtime_events(recovered=False))
            report = pressure_report("pressure", root / "out", [run])

        self.assertEqual(report["status"], "needs-runtime-pressure-classification")
        self.assertTrue(report["conclusion"]["productSurfaceClean"])
        self.assertFalse(report["conclusion"]["allStageFailuresRecovered"])
        self.assertEqual(report["totals"]["stageUnrecoveredFailures"], 1)

    def test_repeat_input(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = root / "run-01"
            write_run(run, runtime_events())
            repeat = root / "repeat"
            repeat.mkdir()
            write_json(
                repeat / "summary.json",
                {
                    "schema": "dynet-vm-private-runtime-repeat/v1alpha1",
                    "label": "repeat",
                    "totals": repeat_totals(),
                    "runs": [{"label": "run-01", "path": str(run)}],
                },
            )

            report = pressure_report("pressure", root / "out", [repeat])

        self.assertEqual(report["status"], "observe-only-product-clean")
        self.assertEqual(report["sources"][0]["schema"], "dynet-vm-private-runtime-repeat/v1alpha1")
        self.assertEqual(report["totals"]["runs"], 1)


def write_run(path: Path, report: dict[str, object]) -> None:
    path.mkdir()
    write_json(path / "summary.json", run_summary())
    write_json(path / "runtime-report.json", report)


def runtime_events(
    recovered: bool = True,
    *,
    stage: bool = True,
    slot: bool = True,
    slow: bool = False,
) -> dict[str, object]:
    events = []
    if stage:
        events.append(event("dialer-cascade-attempt-finished", failed_fields(), 10))
    if slow:
        events.append(event("outbound-stage-finished", slow_fields(), 11))
    if slot:
        events.extend([
            event("tcp-forwarder-pressure", {"pressurePorts": "443", "activeSlots": "8"}, 12),
            event("tcp-forwarder-pressure", {"pressurePorts": "443", "activeSlots": "8"}, 13),
        ])
    if stage and recovered:
        events.append(event("dialer-cascade-attempt-finished", recovered_fields(), 20))
    return {"events": events}


def failed_fields() -> dict[str, str]:
    return {
        "flowId": "tcp-session-1",
        "boundSelected": "tunnel-004",
        "status": "failed",
        "attempt": "1",
        "candidateCount": "4",
        "failureStage": "trojan-tls-handshake",
        "failureScope": "bound",
        "failureStageDisposition": "pending-timeout",
        "errorType": "trojan",
        "retryStopReason": "retry-bound-failure-before-replay",
        "retryAllowed": "true",
        "target": "chatgpt.com:443",
    }


def slow_fields() -> dict[str, str]:
    return {
        "stage": "trojan-tls-handshake",
        "status": "failed",
        "errorType": "trojan",
        "elapsedMs": "8200",
    }


def recovered_fields() -> dict[str, str]:
    return {
        "flowId": "tcp-session-1",
        "boundSelected": "tunnel-002",
        "status": "success",
        "failureScope": "none",
        "target": "chatgpt.com:443",
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


def repeat_totals() -> dict[str, object]:
    return {
        "runs": 1,
        "passedRuns": 1,
        "failedRuns": 0,
        "workloadAttempted": 1,
        "workloadSuccess": 1,
        "workloadFailure": 0,
        "tcpFlowFailed": 0,
        "tcpFlowStageFailed": 1,
        "tcpFlowPathComplete": 1,
        "tcpFlowPayloadBidirectional": 1,
        "tcpSlotPressureEvents": 2,
        "cascadeFailedAttempts": 1,
        "cascadeRecoveredFlows": 1,
    }


def event(kind: str, fields: dict[str, str], sequence: int) -> dict[str, object]:
    return {"kind": kind, "fields": fields, "sequence": sequence}


def write_json(path: Path, payload: dict[str, object]) -> None:
    path.write_text(json.dumps(payload))


if __name__ == "__main__":
    unittest.main()
