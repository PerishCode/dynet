from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from dynet_trace.quality_feedback import planner_feedback
from tests.dynet_trace.support import write_product_effect_context


class PromotionContextTest(unittest.TestCase):
    def test_auto_with_context(self) -> None:
        with tempfile.TemporaryDirectory() as raw_dir:
            root = Path(raw_dir)
            batch = write_batch(root / "batch.json")
            proof = write_runtime_proof(root / "runtime-repeat.json")
            context = write_product_effect_context(root / "product-effect.json")

            feedback = planner_feedback(
                [str(batch)],
                "auto",
                1000,
                [str(proof)],
                [str(context)],
            )

        summary = feedback["summary"]
        promotion = summary["promotion"]
        self.assertEqual(summary["mode"], "penalize")
        self.assertEqual(summary["penaltyObservations"], 1)
        self.assertTrue(promotion["eligible"])
        self.assertEqual(promotion["action"], "allow-penalty-feedback")
        self.assertEqual(promotion["contexts"], 1)
        self.assertEqual(action_ids(promotion["observeOnlyActions"]), [
            "retain-recovered-stage-pressure-observe-only",
        ])
        self.assertEqual(action_ids(promotion["policyActions"]), [
            "keep-planner-penalties-disabled",
        ])


def write_batch(path: Path) -> Path:
    path.write_text(json.dumps({
        "schema": "dynet-probe-attribution-batch/v1alpha1",
        "repeatedQualityGaps": [{
            "key": ["github", "api.github.com", "dialer-bound", "auto", "a", "b"],
            "runs": ["a", "b"],
            "items": 2,
        }],
        "privateSourcePolicySignals": [],
    }))
    return path


def write_runtime_proof(path: Path) -> Path:
    path.write_text(json.dumps({
        "schema": "dynet-vm-private-runtime-repeat/v1alpha1",
        "totals": {
            "runs": 2,
            "passedRuns": 2,
            "failedRuns": 0,
            "workloadFailedRuns": 0,
            "workloadAttempted": 2,
            "workloadSuccess": 2,
            "workloadFailure": 0,
            "qualityBoundCandidateSets": 2,
            "qualityBoundSelectedWithQuality": 2,
            "qualityBoundSelectedBehind": 0,
        },
        "runs": [
            {"tcpClosedSessions": 1, "tcpSessionFailures": 0, "workloadSuccessRate": 1.0},
            {"tcpClosedSessions": 1, "tcpSessionFailures": 0, "workloadSuccessRate": 1.0},
        ],
    }))
    return path


def action_ids(rows: list[dict[str, object]]) -> list[str]:
    return [str(item["id"]) for item in rows]


if __name__ == "__main__":
    unittest.main()
