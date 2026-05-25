from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[6]
VM_PATH = ROOT / "scripts" / "vm"
sys.path.insert(0, str(VM_PATH))

from private_runtime_lib.reporting.workload_surface.outbound.quality import (
    build_candidate_quality_summary,
)


class CandidateQualitySurfaceTest(unittest.TestCase):
    def test_primary_best_clean(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = write_run(root / "run-01", runtime_report(selected_score=10, other_score=1))
            summary = build_candidate_quality_summary("quality", root / "out", [run])

        self.assertEqual(summary["conclusion"]["status"], "clean")
        self.assertEqual(summary["totals"]["primarySelectedBest"], 1)
        self.assertEqual(summary["totals"]["selectedBehind"], 0)

    def test_primary_behind_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = write_run(root / "run-01", runtime_report(selected_score=1, other_score=10))
            summary = build_candidate_quality_summary("quality", root / "out", [run])

        self.assertEqual(summary["runs"][0]["classification"], "primary-selected-behind")
        self.assertEqual(summary["conclusion"]["status"], "candidate-quality-needs-evidence")
        self.assertEqual(summary["totals"]["primarySelectedBehind"], 1)
        self.assertEqual(summary["totals"]["unrecoveredSelectedBehind"], 1)

    def test_fallback_behind_recovered(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = write_run(
                root / "run-01",
                runtime_report(selected_score=1, other_score=10, prior_failure=True),
            )
            summary = build_candidate_quality_summary("quality", root / "out", [run])

        self.assertEqual(summary["conclusion"]["status"], "clean")
        self.assertEqual(summary["totals"]["fallbackSelectedBehind"], 1)
        self.assertEqual(summary["totals"]["recoveredSelectedBehind"], 1)
        self.assertEqual(summary["totals"]["unrecoveredSelectedBehind"], 0)


def runtime_report(
    *,
    selected_score: int,
    other_score: int,
    prior_failure: bool = False,
) -> dict[str, object]:
    events = []
    if prior_failure:
        events.append(event("dialer-cascade-attempt-finished", {"status": "failed"}))
    events.extend([
        event("outbound-candidate-set", candidate_fields(selected_score, other_score)),
        event("tcp-session-established", base_fields()),
    ])
    return {
        "schema": "dynet-runtime-report/v1alpha1",
        "status": "pass",
        "events": events,
    }


def base_fields() -> dict[str, str]:
    return {"flowId": "tcp-session-1", "scope": "dialer-bound"}


def candidate_fields(selected_score: int, other_score: int) -> dict[str, str]:
    return {
        **base_fields(),
        "selected": "tunnel-001",
        "candidateCount": "2",
        "candidates": "tunnel-001,tunnel-002",
        "candidatesJson": json.dumps([
            quality_candidate("tunnel-001", selected_score),
            quality_candidate("tunnel-002", other_score),
        ]),
        "strategyKey": "cascade-quality",
    }


def quality_candidate(name: str, score: int) -> dict[str, object]:
    return {
        "to": name,
        "type": "trojan",
        "quality": {
            "score": score,
            "reason": "exact-and-overall-quality",
            "stale": False,
            "matches": [
                {"scope": "dialer-bound", "verdict": "healthy", "confidence": "low"},
            ],
        },
    }


def event(kind: str, event_fields: dict[str, str]) -> dict[str, object]:
    return {"kind": kind, "fields": {**base_fields(), **event_fields}}


def write_run(path: Path, report: dict[str, object]) -> Path:
    path.mkdir()
    (path / "runtime-report.json").write_text(json.dumps(report, sort_keys=True))
    (path / "summary.json").write_text(json.dumps({"label": path.name}))
    return path


if __name__ == "__main__":
    unittest.main()
