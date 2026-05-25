from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[6]
VM_PATH = ROOT / "scripts" / "vm"
sys.path.insert(0, str(VM_PATH))

from private_runtime_lib.reporting.workload_surface.outbound.stage_order import (
    build_stage_order_summary,
)


class StageOrderSurfaceTest(unittest.TestCase):
    def test_ordered_clean(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = write_run(root / "run-01", runtime_report(ordered_stages()))
            summary = build_stage_order_summary("stage-order", root / "out", [run])

        self.assertEqual(summary["conclusion"]["status"], "clean")
        self.assertEqual(summary["totals"]["orderedAttempts"], 1)
        self.assertEqual(summary["totals"]["stageOrderViolations"], 0)

    def test_reversed_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = write_run(root / "run-01", runtime_report(reversed_stages()))
            summary = build_stage_order_summary("stage-order", root / "out", [run])

        self.assertEqual(summary["runs"][0]["classification"], "stage-order-violation")
        self.assertEqual(summary["conclusion"]["status"], "stage-order-surface-needs-evidence")

    def test_after_failure_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = write_run(root / "run-01", runtime_report(after_failure_stages()))
            summary = build_stage_order_summary("stage-order", root / "out", [run])

        self.assertEqual(summary["runs"][0]["classification"], "stage-after-failure")
        self.assertEqual(summary["totals"]["stageAfterFailure"], 1)


def runtime_report(stages: list[dict[str, str]]) -> dict[str, object]:
    events = [stage_event(row) for row in stages]
    events.append(event("outbound-attempt-finished", {**base_fields(), "status": "success"}))
    return {
        "schema": "dynet-runtime-report/v1alpha1",
        "status": "pass",
        "events": events,
    }


def ordered_stages() -> list[dict[str, str]]:
    return [
        {"stage": "payload-decode", "status": "success"},
        {"stage": "tcp-connect", "status": "success"},
        {"stage": "trojan-tls-handshake", "status": "success"},
        {"stage": "trojan-request-write", "status": "success"},
    ]


def reversed_stages() -> list[dict[str, str]]:
    return [
        {"stage": "tcp-connect", "status": "success"},
        {"stage": "payload-decode", "status": "success"},
    ]


def after_failure_stages() -> list[dict[str, str]]:
    return [
        {"stage": "payload-decode", "status": "success"},
        {"stage": "tcp-connect", "status": "failed"},
        {"stage": "trojan-tls-handshake", "status": "success"},
    ]


def base_fields() -> dict[str, str]:
    return {
        "flowId": "tcp-session-1",
        "outbound": "tunnel-001",
        "kind": "trojan",
        "protocol": "tcp-connect",
        "attemptId": "attempt-1",
    }


def stage_event(row: dict[str, str]) -> dict[str, object]:
    return event("outbound-stage-finished", {**base_fields(), **row})


def event(kind: str, event_fields: dict[str, str]) -> dict[str, object]:
    return {"kind": kind, "fields": event_fields}


def write_run(path: Path, report: dict[str, object]) -> Path:
    path.mkdir()
    (path / "runtime-report.json").write_text(json.dumps(report, sort_keys=True))
    (path / "summary.json").write_text(json.dumps({"label": path.name}))
    return path


if __name__ == "__main__":
    unittest.main()
