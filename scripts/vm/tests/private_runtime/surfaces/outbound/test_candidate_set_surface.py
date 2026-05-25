from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[6]
VM_PATH = ROOT / "scripts" / "vm"
sys.path.insert(0, str(VM_PATH))

from private_runtime_lib.reporting.workload_surface.outbound.candidate import (
    build_candidate_set_summary,
)


class CandidateSetSurfaceTest(unittest.TestCase):
    def test_candidate_set_clean(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = write_run(root / "run-01", runtime_report())
            summary = build_candidate_set_summary("candidate", root / "out", [run])

        self.assertEqual(summary["conclusion"]["status"], "clean")
        self.assertEqual(summary["totals"]["candidateSets"], 1)
        self.assertEqual(summary["totals"]["selectedMissingFromList"], 0)
        self.assertEqual(summary["totals"]["missingGraph"], 0)

    def test_missing_graph_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = write_run(root / "run-01", runtime_report(missing_graph=True))
            summary = build_candidate_set_summary("candidate", root / "out", [run])

        self.assertEqual(summary["runs"][0]["classification"], "candidate-graph-missing")
        self.assertEqual(summary["conclusion"]["status"], "candidate-set-surface-needs-evidence")


def runtime_report(missing_graph: bool = False) -> dict[str, object]:
    events = [
        event("route-matched", base_fields()),
        event("outbound-candidate-set", candidate_fields()),
    ]
    if not missing_graph:
        events.append(event("outbound-graph-selected", base_fields()))
    events.extend([
        event("outbound-egress-passed", base_fields()),
        event("dialer-cascade-selected", base_fields()),
        event("dialer-cascade-attempt-started", base_fields()),
    ])
    return {
        "schema": "dynet-runtime-report/v1alpha1",
        "status": "pass",
        "events": events,
    }


def base_fields() -> dict[str, str]:
    return {
        "flowId": "tcp-session-1",
        "scope": "dialer-bound",
        "selected": "tunnel-001",
        "sessionTransport": "tcp",
    }


def candidate_fields() -> dict[str, str]:
    return {
        **base_fields(),
        "candidateCount": "2",
        "candidates": "tunnel-001,tunnel-002",
        "candidatesJson": json.dumps([
            {"to": "tunnel-001", "type": "trojan", "quality": {"score": 1}},
            {"to": "tunnel-002", "type": "trojan", "quality": {"score": 0}},
        ]),
        "strategyKey": "cascade-quality",
        "strategySource": "internal",
        "strategyVersion": "v1alpha1",
        "selector": "CascadeQuality",
        "selectedEdgeType": "Candidate",
        "plan": "tunnel",
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
