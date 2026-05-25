from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
VM_PATH = ROOT / "scripts" / "vm"
sys.path.insert(0, str(VM_PATH))


def load_probe_smoke():
    spec = importlib.util.spec_from_file_location(
        "probe_smoke", VM_PATH / "probe_smoke.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


probe_smoke = load_probe_smoke()
from lib import probe_smoke_artifact


class ProbeSmokeTest(unittest.TestCase):
    def test_output_dir(self) -> None:
        resolved = probe_smoke.task_output_dir(None, "unit-label")
        self.assertEqual(
            resolved,
            (ROOT / ".task" / "resources" / "vm-probe-smoke" / "unit-label").resolve(
                strict=False
            ),
        )
        with self.assertRaises(probe_smoke.CommandError):
            probe_smoke.task_output_dir("/tmp/outside-dynet-task", "unit-label")

    def test_report_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output_dir = Path(temp)
            summary_path = output_dir / "summary.json"
            summary_path.write_text(
                json.dumps(
                    {
                        "items": [
                            {
                                "id": "0001",
                                "reportPath": "/tmp/dynet-smoke/0001-example.json",
                            }
                        ]
                    }
                )
            )

            probe_smoke_artifact.rewrite_summary_report_paths(output_dir)

            summary = json.loads(summary_path.read_text())
            self.assertEqual(summary["items"][0]["reportPath"], "0001-example.json")

    def test_plan_context(self) -> None:
        self.assertEqual(
            json.loads(probe_smoke.plan_context("candidate.example")),
            {"destinationDomain": "candidate.example"},
        )

    def test_verification(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output_dir = Path(temp)
            write_complete_artifact(output_dir)

            verification = probe_smoke_artifact.build_verification(
                output_dir,
                require_plan=True,
            )

            self.assertEqual(verification["status"], "pass")


def write_json(path: Path, data: object) -> None:
    path.write_text(json.dumps(data))


def write_complete_artifact(output_dir: Path) -> None:
    write_json(
        output_dir / "summary.json",
        {
            "totals": {"attempted": 6, "passed": 6, "failed": 0},
            "server": {
                "connections": 6,
                "totalBytes": 128,
                "rawPayloadStored": False,
            },
        },
    )
    write_json(
        output_dir / "attribution.json",
        {
            "totals": {
                "items": 2,
                "passed": 6,
                "failed": 0,
                "unknown": 0,
                "withMissingEvidence": 0,
            },
            "candidateQuality": {"withQuality": 6},
        },
    )
    write_json(output_dir / "probe-batch.json", {"totals": {"withQuality": 6}})
    write_json(
        output_dir / "quality-observe.json",
        {"plannerFeedback": {"penaltyObservations": 0}},
    )
    write_json(
        output_dir / "quality-penalize.json",
        {"plannerFeedback": {"penaltyObservations": 0}},
    )
    write_json(output_dir / "plan-candidate.json", plan_artifact())
    write_json(output_dir / "plan-candidate-vmess.json", plan_artifact("private-vmess"))
    write_json(output_dir / "plan-candidate-trojan.json", plan_artifact("private-trojan"))


def plan_artifact(selected: str = "private-ss") -> dict[str, object]:
    return {
        "outboundPath": {
            "selected": selected,
            "decisions": [
                {
                    "candidates": [
                        {
                            "to": selected,
                            "quality": {"stale": False, "score": 5100},
                        }
                    ]
                }
            ],
        }
    }


if __name__ == "__main__":
    unittest.main()
