from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[6]
VM_PATH = ROOT / "scripts" / "vm"
sys.path.insert(0, str(VM_PATH))

from private_runtime_lib.reporting.workload_surface.outbound.failure.propagation import (
    build_failure_propagation_summary,
)


class FailurePropagationSurfaceTest(unittest.TestCase):
    def test_failure_chain_clean(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = write_run(root / "run-01", runtime_report())
            summary = build_failure_propagation_summary("failure", root / "out", [run])

        self.assertEqual(summary["conclusion"]["status"], "clean")
        self.assertEqual(summary["totals"]["failedAttemptsWithStage"], 1)
        self.assertEqual(summary["totals"]["failedCascadesWithEvidence"], 1)

    def test_stage_mismatch_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = write_run(root / "run-01", runtime_report(stage_error="tls"))
            summary = build_failure_propagation_summary("failure", root / "out", [run])

        self.assertEqual(summary["runs"][0]["classification"], "stage-attempt-error-mismatch")
        self.assertEqual(summary["conclusion"]["status"], "failure-propagation-needs-evidence")

    def test_scope_missing_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = write_run(root / "run-01", runtime_report(scope=""))
            summary = build_failure_propagation_summary("failure", root / "out", [run])

        self.assertEqual(summary["runs"][0]["classification"], "cascade-scope-missing")
        self.assertEqual(summary["totals"]["cascadeFailureScopeMissing"], 1)


def runtime_report(stage_error: str = "trojan", scope: str = "bound") -> dict[str, object]:
    events = [
        event("outbound-stage-finished", {
            **base_fields(),
            "stage": "trojan-tls-handshake",
            "status": "failed",
            "errorType": stage_error,
            "errorDisposition": "reset",
        }),
        event("outbound-attempt-finished", {
            **base_fields(),
            "protocol": "tcp-connect",
            "status": "failed",
            "errorType": "trojan",
            "errorDisposition": "reset",
        }),
        event("dialer-cascade-attempt-finished", {
            "flowId": "tcp-session-1",
            "status": "failed",
            "errorType": "trojan",
            "errorDisposition": "reset",
            "failureScope": scope,
            "retryAllowed": "true",
            "retryStopReason": "retry-bound-failure-before-replay",
        }),
    ]
    return {"schema": "dynet-runtime-report/v1alpha1", "status": "pass", "events": events}


def base_fields() -> dict[str, str]:
    return {
        "flowId": "tcp-session-1",
        "outbound": "tunnel-001",
        "kind": "trojan",
        "attemptId": "attempt-1",
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
