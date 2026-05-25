from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[5]
VM_PATH = ROOT / "scripts" / "vm"
sys.path.insert(0, str(VM_PATH))

from private_runtime_lib.reporting.workload_surface.event.failure import (
    build_failure_attribution_summary,
)


class FailureAttributionSurfaceTest(unittest.TestCase):
    def test_failure_attribution_clean(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            clean_run = write_run(root / "run-01", runtime_report())
            quiet_run = write_run(root / "run-02", runtime_report(events=[]))
            summary = build_failure_attribution_summary(
                "failure",
                root / "out",
                [clean_run, quiet_run],
            )

        self.assertEqual(summary["conclusion"]["status"], "clean")
        self.assertEqual(summary["totals"]["failureSignals"], 3)
        self.assertEqual(summary["totals"]["classifiedSignals"], 3)
        self.assertEqual(summary["totals"]["unknownSignals"], 0)
        self.assertEqual(summary["totals"]["missingEvidenceSignals"], 0)
        self.assertEqual(summary["runs"][1]["classification"], "clean")

    def test_unknown_failure_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = write_run(root / "run-01", runtime_report(unknown=True))
            summary = build_failure_attribution_summary("failure", root / "out", [run])

        self.assertEqual(
            summary["runs"][0]["classification"],
            "unknown-failure-attribution",
        )
        self.assertEqual(
            summary["conclusion"]["status"],
            "failure-attribution-needs-evidence",
        )

    def test_missing_evidence_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = write_run(root / "run-01", runtime_report(missing_evidence=True))
            summary = build_failure_attribution_summary("failure", root / "out", [run])

        self.assertEqual(summary["runs"][0]["classification"], "failure-evidence-missing")
        self.assertEqual(summary["totals"]["missingEvidenceSignals"], 1)


def runtime_report(
    *,
    events: list[dict[str, object]] | None = None,
    unknown: bool = False,
    missing_evidence: bool = False,
) -> dict[str, object]:
    if events is None:
        events = failure_events(missing_evidence)
    if unknown:
        events.append(event("tcp-session-failed", {"status": "failed"}))
    return {
        "schema": "dynet-runtime-report/v1alpha1",
        "status": "pass",
        "events": events,
    }


def failure_events(missing_evidence: bool) -> list[dict[str, object]]:
    attempt = {
        "flowId": "tcp-session-1",
        "kind": "trojan",
        "protocol": "tcp-connect",
        "status": "failed",
        "errorDisposition": "pending-timeout",
        "errorType": "trojan",
        "transport": "tcp",
    }
    if missing_evidence:
        attempt.pop("errorType")
    return [
        event("outbound-attempt-finished", attempt),
        event("outbound-stage-finished", {
            "flowId": "tcp-session-1",
            "kind": "trojan",
            "stage": "trojan-tls-handshake",
            "status": "failed",
            "errorDisposition": "pending-timeout",
            "errorType": "trojan",
        }),
        event("dialer-cascade-attempt-finished", {
            "flowId": "tcp-session-1",
            "status": "failed",
            "failureScope": "bound",
            "retryAllowed": "true",
            "retryStopReason": "retry-bound-failure-before-replay",
            "failureStage": "trojan-tls-handshake",
            "failureStageKind": "trojan",
            "failureStageDisposition": "pending-timeout",
            "failureStageErrorType": "trojan",
        }),
    ]


def event(kind: str, event_fields: dict[str, str]) -> dict[str, object]:
    return {"kind": kind, "fields": event_fields}


def write_run(path: Path, report: dict[str, object]) -> Path:
    path.mkdir()
    (path / "runtime-report.json").write_text(json.dumps(report, sort_keys=True))
    (path / "summary.json").write_text(json.dumps({"label": path.name}))
    return path


if __name__ == "__main__":
    unittest.main()
