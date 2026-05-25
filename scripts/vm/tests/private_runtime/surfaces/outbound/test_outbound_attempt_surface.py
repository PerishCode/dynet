from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[6]
VM_PATH = ROOT / "scripts" / "vm"
sys.path.insert(0, str(VM_PATH))

from private_runtime_lib.reporting.workload_surface.outbound.attempt import (
    build_outbound_attempt_summary,
)


class OutboundAttemptSurfaceTest(unittest.TestCase):
    def test_outbound_attempt_clean(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = write_run(root / "run-01", runtime_report())
            summary = build_outbound_attempt_summary("attempt", root / "out", [run])

        self.assertEqual(summary["conclusion"]["status"], "clean")
        self.assertEqual(summary["totals"]["attemptFinishes"], 1)
        self.assertEqual(summary["totals"]["cascadeFinishes"], 1)
        self.assertEqual(summary["totals"]["finishWithoutStart"], 0)
        self.assertEqual(summary["totals"]["sessionTcpAttemptsMissingRoute"], 0)

    def test_missing_finish_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = write_run(root / "run-01", runtime_report(missing_finish=True))
            summary = build_outbound_attempt_summary("attempt", root / "out", [run])

        self.assertEqual(summary["runs"][0]["classification"], "attempt-start-without-finish")
        self.assertEqual(
            summary["conclusion"]["status"],
            "outbound-attempt-surface-needs-evidence",
        )


def runtime_report(missing_finish: bool = False) -> dict[str, object]:
    events = [
        event("route-matched", {
            "flowId": "tcp-session-1",
            "sessionTransport": "tcp",
        }),
        event("outbound-attempt-started", attempt_fields()),
        event("dialer-cascade-attempt-started", cascade_fields()),
        event("outbound-stage-finished", stage_fields()),
        event("dialer-cascade-attempt-finished", cascade_fields(status="success")),
    ]
    if not missing_finish:
        events.append(event("outbound-attempt-finished", attempt_fields(status="success")))
    return {
        "schema": "dynet-runtime-report/v1alpha1",
        "status": "pass",
        "events": events,
    }


def attempt_fields(status: str = "") -> dict[str, str]:
    result = {
        "flowId": "tcp-session-1",
        "sessionTransport": "tcp",
        "transport": "tcp",
        "protocol": "tcp-connect",
        "outbound": "selected",
        "attempt": "1",
        "attemptId": "attempt-1",
    }
    if status:
        result["status"] = status
        result["elapsedMs"] = "10"
    return result


def cascade_fields(status: str = "") -> dict[str, str]:
    result = {
        "flowId": "tcp-session-1",
        "sessionTransport": "tcp",
        "attempt": "1",
    }
    if status:
        result["status"] = status
        result["failureScope"] = "none"
    return result


def stage_fields() -> dict[str, str]:
    return {
        "flowId": "tcp-session-1",
        "sessionTransport": "tcp",
        "status": "success",
        "stage": "private-vmess-connect",
        "elapsedMs": "8",
    }


def event(kind: str, event_fields: dict[str, str]) -> dict[str, object]:
    return {"kind": kind, "fields": event_fields}


def write_run(path: Path, report: dict[str, object]) -> Path:
    path.mkdir()
    (path / "runtime-report.json").write_text(json.dumps(report, sort_keys=True))
    (path / "summary.json").write_text(json.dumps({"label": path.name}))
    return path


if __name__ == "__main__":
    unittest.main()
