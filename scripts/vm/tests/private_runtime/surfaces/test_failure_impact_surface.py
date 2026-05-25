from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[5]
VM_PATH = ROOT / "scripts" / "vm"
sys.path.insert(0, str(VM_PATH))

from private_runtime_lib.reporting.workload_surface.event.impact import (
    build_failure_impact_summary,
)


class FailureImpactSurfaceTest(unittest.TestCase):
    def test_recovered_node_clean(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = write_run(root / "run-01", runtime_report())
            quiet = write_run(root / "run-02", runtime_report(events=[]))
            summary = build_failure_impact_summary("impact", root / "out", [run, quiet])

        self.assertEqual(summary["conclusion"]["status"], "clean")
        self.assertEqual(summary["totals"]["failureSignals"], 1)
        self.assertEqual(summary["totals"]["recoveredNodeSuspectSignals"], 1)
        self.assertEqual(summary["totals"]["unsafePenaltySignals"], 0)
        self.assertEqual(summary["runs"][1]["classification"], "clean")

    def test_unbounded_node_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = write_run(root / "run-01", runtime_report(recovered=False))
            summary = build_failure_impact_summary("impact", root / "out", [run])

        self.assertEqual(summary["runs"][0]["classification"], "unsafe-penalty-impact")
        self.assertEqual(summary["totals"]["unsafePenaltySignals"], 1)
        self.assertEqual(summary["conclusion"]["status"], "failure-impact-needs-evidence")

    def test_target_probe_controlled(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = write_run(root / "run-01", runtime_report(events=[dns_failure()]))
            summary = build_failure_impact_summary("impact", root / "out", [run])

        self.assertEqual(summary["conclusion"]["status"], "clean")
        self.assertEqual(summary["totals"]["controlledSignals"], 1)
        self.assertEqual(summary["totals"]["targetOrProbeSignals"], 1)

    def test_masked_node_controlled(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = write_run(root / "run-01", runtime_report(events=[
                attempt_failure(),
                target_probe_stage_failure(),
            ]))
            summary = build_failure_impact_summary("impact", root / "out", [run])

        self.assertEqual(summary["conclusion"]["status"], "clean")
        self.assertEqual(summary["totals"]["maskedNodeSuspectSignals"], 1)
        self.assertEqual(summary["totals"]["unsafePenaltySignals"], 0)


def runtime_report(
    *,
    recovered: bool = True,
    events: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    if events is None:
        events = [attempt_failure()]
        if recovered:
            events.append(event("tcp-session-established", {"flowId": "tcp-session-1"}))
    return {
        "schema": "dynet-runtime-report/v1alpha1",
        "status": "pass",
        "events": events,
    }


def attempt_failure() -> dict[str, object]:
    return event("outbound-attempt-finished", {
        "flowId": "tcp-session-1",
        "kind": "trojan",
        "protocol": "tcp-connect",
        "status": "failed",
        "errorDisposition": "pending-timeout",
        "errorType": "trojan",
    })


def dns_failure() -> dict[str, object]:
    return event("dns-resolve-failed", {
        "dnsQueryId": "dns-query-1",
        "failureResponseCode": "SERVFAIL",
        "errorDisposition": "protocol-invalid",
    })


def target_probe_stage_failure() -> dict[str, object]:
    return event("outbound-stage-finished", {
        "flowId": "tcp-session-1",
        "kind": "trojan",
        "stage": "private-trojan-connect",
        "status": "failed",
        "errorDisposition": "protocol-invalid",
        "errorType": "trojan",
    })


def event(kind: str, event_fields: dict[str, str]) -> dict[str, object]:
    return {"kind": kind, "fields": event_fields}


def write_run(path: Path, report: dict[str, object]) -> Path:
    path.mkdir()
    (path / "runtime-report.json").write_text(json.dumps(report, sort_keys=True))
    (path / "summary.json").write_text(json.dumps({"label": path.name}))
    return path


if __name__ == "__main__":
    unittest.main()
