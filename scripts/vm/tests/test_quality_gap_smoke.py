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


def load_quality_gap_smoke():
    spec = importlib.util.spec_from_file_location(
        "quality_gap_smoke", VM_PATH / "smokes" / "quality_gap.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


quality_gap_smoke = load_quality_gap_smoke()


class QualityGapSmokeTest(unittest.TestCase):
    def test_output_dir(self) -> None:
        resolved = quality_gap_smoke.task_output_dir(None, "unit-label")
        self.assertEqual(
            resolved,
            (
                ROOT / ".task" / "resources" / "vm-quality-gap-smoke" / "unit-label"
            ).resolve(strict=False),
        )
        with self.assertRaises(quality_gap_smoke.CommandError):
            quality_gap_smoke.task_output_dir("/tmp/outside-dynet-task", "unit-label")

    def test_result_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output_dir = Path(temp)
            write_json(
                output_dir / "summary.json",
                {"totals": {"attempted": 2, "passed": 2, "failed": 0}},
            )
            write_json(
                output_dir / "verification.json",
                {
                    "status": "pass",
                    "qualityRefresh": {
                        "entry": {"attempts": 4, "confidence": "medium"},
                        "planQuality": {"score": 5400, "stale": False},
                    },
                },
            )

            result = quality_gap_smoke.result_summary(output_dir, skipped=False)

        self.assertEqual(result["verification"], "pass")
        self.assertEqual(result["attempted"], 2)
        self.assertEqual(result["qualityRefresh"]["attempts"], 4)
        self.assertEqual(result["qualityRefresh"]["score"], 5400)


def write_json(path: Path, data: object) -> None:
    path.write_text(json.dumps(data))


if __name__ == "__main__":
    unittest.main()
