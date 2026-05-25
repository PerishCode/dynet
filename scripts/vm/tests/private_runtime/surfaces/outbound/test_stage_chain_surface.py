from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[6]
VM_PATH = ROOT / "scripts" / "vm"
sys.path.insert(0, str(VM_PATH))

from private_runtime_lib.reporting.workload_surface.outbound.stage_chain import (
    build_stage_chain_summary,
)


class StageChainSurfaceTest(unittest.TestCase):
    def test_trojan_chain_clean(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = write_run(root / "run-01", runtime_report())
            summary = build_stage_chain_summary("chain", root / "out", [run])

        self.assertEqual(summary["conclusion"]["status"], "clean")
        self.assertEqual(summary["totals"]["attempts"], 1)
        self.assertEqual(summary["totals"]["successMissingRequiredStages"], 0)
        self.assertEqual(summary["totals"]["unknownProfileAttempts"], 0)

    def test_required_stage_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = write_run(root / "run-01", runtime_report(missing_tls=True))
            summary = build_stage_chain_summary("chain", root / "out", [run])

        self.assertEqual(
            summary["runs"][0]["classification"],
            "success-required-stage-missing",
        )
        self.assertEqual(
            summary["conclusion"]["status"],
            "stage-chain-surface-needs-evidence",
        )


def runtime_report(missing_tls: bool = False) -> dict[str, object]:
    stages = [
        stage("tcp-connect"),
        stage("trojan-request-write"),
        stage("payload-decode"),
    ]
    if not missing_tls:
        stages.append(stage("trojan-tls-handshake"))
    return {
        "schema": "dynet-runtime-report/v1alpha1",
        "status": "pass",
        "events": [attempt("success"), *stages],
    }


def attempt(status: str) -> dict[str, object]:
    return event("outbound-attempt-finished", {
        "flowId": "tcp-session-1",
        "outbound": "tunnel-001",
        "kind": "trojan",
        "protocol": "tcp-connect",
        "status": status,
        "elapsedMs": "12",
    })


def stage(name: str) -> dict[str, object]:
    return event("outbound-stage-finished", {
        "flowId": "tcp-session-1",
        "outbound": "tunnel-001",
        "kind": "trojan",
        "stage": name,
        "status": "success",
        "elapsedMs": "10",
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
