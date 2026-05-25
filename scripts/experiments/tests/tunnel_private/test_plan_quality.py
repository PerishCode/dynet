from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
EXPERIMENTS = ROOT / "scripts" / "experiments"
sys.path.insert(0, str(EXPERIMENTS))

from tunnel_private import plan_quality

from .support import argparse_like, config_inputs_stub, plan_report_stub


class PlanQualityTest(unittest.TestCase):
    def test_plan_candidate_summary(self) -> None:
        summary = plan_quality.summarize_plan(
            argparse_like(
                target_url="https://chatgpt.com/",
                quality_state="/tmp/quality-state.json",
                plan_quality_scope="plan-candidate",
            ),
            config_inputs_stub(),
            direct_plan_report(),
        )

        self.assertEqual(summary["status"], "pass")
        self.assertEqual(summary["inspectionScope"], "plan-candidate")
        self.assertEqual(summary["inspectedPath"]["selected"], "tunnel-002")
        self.assertEqual(summary["candidateQuality"]["selected"]["to"], "tunnel-002")
        self.assertEqual(
            summary["candidateQuality"]["selected"]["quality"]["matches"][0]["scope"],
            "plan-candidate",
        )

    def test_plan_candidate_routes(self) -> None:
        routes = plan_quality.plan_inspection_routes(
            argparse_like(
                target_url="https://chatgpt.com/",
                domain=[],
                domain_suffix=["chatgpt.com"],
                plan_quality_scope="plan-candidate",
            )
        )

        self.assertEqual(routes[0], {"domain": "chatgpt.com", "outbound": "tunnel"})
        self.assertEqual(routes[-1], {"outbound": "direct"})

    def test_plan_quality_summary(self) -> None:
        summary = plan_quality.summarize_plan(
            argparse_like(
                target_url="https://chatgpt.com/",
                quality_state="/tmp/quality-state.json",
            ),
            config_inputs_stub(),
            plan_report_stub(),
        )

        self.assertEqual(summary["schema"], plan_quality.INSPECTION_SCHEMA)
        self.assertEqual(summary["status"], "pass")
        self.assertEqual(summary["dialerBoundPath"]["selected"], "tunnel-001")
        self.assertEqual(summary["candidateQuality"]["withQuality"], 1)
        self.assertTrue(summary["candidateQuality"]["selectedBest"])
        self.assertEqual(summary["candidateQuality"]["selectedBehind"], 0)
        self.assertTrue(summary["candidateQuality"]["selectedHasMatches"])
        self.assertEqual(summary["candidateQuality"]["selectedScore"], 5400)
        selected = summary["candidateQuality"]["selected"]
        self.assertEqual(selected["to"], "tunnel-001")
        self.assertEqual(selected["quality"]["matches"][0]["scope"], "dialer-bound")

    def test_plan_quality_gap(self) -> None:
        summary = plan_quality.summarize_plan(
            argparse_like(
                target_url="https://chatgpt.com/",
                quality_state="/tmp/quality-state.json",
            ),
            config_inputs_stub(),
            plan_report_stub(selected_score=100, best_score=200),
        )

        self.assertEqual(summary["status"], "fail")
        self.assertEqual(summary["candidateQuality"]["selectedBehind"], 1)

    def test_plan_quality_comparison(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            observe = write_plan_inspection(root / "observe", "observe", False)
            auto = write_plan_inspection(root / "auto", "penalize", True)

            summary = plan_quality.compare_plan_quality([observe, auto])

        self.assertEqual(summary["schema"], plan_quality.COMPARISON_SCHEMA)
        self.assertEqual(summary["status"], "pass")
        self.assertFalse(summary["totals"]["selectionChanged"])
        self.assertEqual(summary["totals"]["promotionEligible"], 1)
        self.assertEqual(summary["totals"]["promotionContexts"], 1)
        self.assertEqual(summary["rows"][1]["promotionObserveOnlyActions"], [
            "retain-recovered-stage-pressure-observe-only",
        ])
        self.assertEqual(summary["rows"][1]["promotionPolicyActions"], [
            "keep-planner-penalties-disabled",
        ])
        self.assertEqual(
            summary["conclusion"]["nextLever"],
            "none-current-quality-already-selects-best",
        )

    def test_empty_comparison_fails(self) -> None:
        summary = plan_quality.compare_plan_quality([])

        self.assertEqual(summary["status"], "fail")

    def test_plan_quality_routes(self) -> None:
        routes = plan_quality.plan_inspection_routes(
            argparse_like(
                target_url="https://chatgpt.com/",
                domain=[],
                domain_suffix=["chatgpt.com"],
            )
        )

        self.assertEqual(
            routes[0],
            {"domain": "chatgpt.com", "outbound": "private-via-tunnel"},
        )
        self.assertEqual(routes[-1], {"outbound": "direct"})


def write_plan_inspection(root: Path, mode: str, promotion: bool) -> Path:
    root.mkdir(parents=True)
    quality_path = root / "quality.json"
    summary_path = root / "summary.json"
    quality_path.write_text(json.dumps({
        "plannerFeedback": {
            "mode": mode,
            "requestedMode": "auto" if promotion else mode,
            "penaltyObservations": 1 if promotion else 0,
            "promotion": promotion_summary(promotion),
        }
    }))
    summary_path.write_text(json.dumps({
        "status": "pass",
        "qualityState": str(quality_path),
        "dialerBoundPath": {"selected": "tunnel-001"},
        "candidateQuality": {
            "withQuality": 3,
            "selectedBest": True,
            "selectedBehind": 0,
            "selectedHasMatches": True,
            "selectedScore": 5400,
            "bestScore": 5400,
            "selected": {"to": "tunnel-001"},
            "best": {"to": "tunnel-001"},
        },
    }))
    return summary_path


def promotion_summary(promotion: bool) -> dict[str, object]:
    if not promotion:
        return {"eligible": False}
    return {
        "eligible": True,
        "contexts": 1,
        "observeOnlyActions": [
            {"id": "retain-recovered-stage-pressure-observe-only"},
        ],
        "policyActions": [
            {"id": "keep-planner-penalties-disabled"},
        ],
    }


def direct_plan_report() -> dict[str, object]:
    return {
        "_exitCode": 0,
        "verdict": {
            "status": "accept",
            "action": {"type": "use-outbound", "tag": "tunnel"},
            "outbound": {"tag": "tunnel", "type": "plan"},
        },
        "outboundPath": {
            "requested": "tunnel",
            "selected": "tunnel-002",
            "hops": [
                {"tag": "tunnel", "type": "plan"},
                {"tag": "tunnel-002", "type": "vmess", "edgeType": "candidate"},
            ],
            "decisions": [
                {
                    "plan": "tunnel",
                    "selected": "tunnel-002",
                    "selectedEdgeType": "candidate",
                    "candidates": [
                        candidate("tunnel-001", 100, False),
                        candidate("tunnel-002", 200, True),
                    ],
                }
            ],
        },
    }


def candidate(tag: str, score: int, selected: bool) -> dict[str, object]:
    return {
        "to": tag,
        "type": "vmess",
        "selected": selected,
        "quality": {
            "stale": False,
            "targetFamily": "chatgpt.com",
            "score": score,
            "reason": "exact-quality",
            "matches": [
                {
                    "scope": "plan-candidate",
                    "targetFamily": "chatgpt.com",
                    "transport": "tcp",
                    "verdict": "healthy",
                    "attempts": 3,
                    "successes": 3,
                    "failures": 0,
                    "confidence": "medium",
                    "weightedScore": score,
                }
            ],
        },
    }


if __name__ == "__main__":
    unittest.main()
