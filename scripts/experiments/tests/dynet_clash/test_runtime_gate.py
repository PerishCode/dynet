from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from dynet_clash import runtime_gate


class RuntimeGateTest(unittest.TestCase):
    def test_quality_route_clean(self) -> None:
        gate = runtime_gate.build(quality_route_plan_repeat(), "runtime.json")

        self.assertTrue(gate["clean"])
        self.assertEqual(gate["classification"], "runtime-route-plan-quality-clean")
        self.assertEqual(gate["totals"]["qualityBoundSelectedWithQuality"], 8)
        self.assertEqual(gate["totals"]["tcpFlowRouteGraphSelected"], 8)
        self.assertEqual(gate["totals"]["tcpFlowRuleMatched"], 0)
        self.assertEqual(gate["totals"]["tcpFlowRouteFallbackUsed"], 0)

    def test_route_fallback_propagates(self) -> None:
        gate = runtime_gate.build(quality_route_plan_repeat(route_fallback=True), "runtime.json")

        self.assertTrue(gate["clean"])
        self.assertEqual(gate["classification"], "runtime-route-plan-quality-clean")
        self.assertEqual(gate["totals"]["tcpFlowRouteFallbackCandidate"], 8)
        self.assertEqual(gate["totals"]["tcpFlowRouteFallbackAttempts"], 16)
        self.assertEqual(gate["totals"]["tcpFlowRouteFallbackUsed"], 8)
        self.assertEqual(gate["totals"]["tcpFlowRouteFallbackEstablished"], 8)
        self.assertEqual(
            gate["totals"]["tcpFlowRouteFallbackByRouteSelected"],
            [{"count": 8, "key": "bad-trojan"}],
        )

    def test_quality_needs_route(self) -> None:
        gate = runtime_gate.build(quality_route_plan_repeat(route_selected=0), "runtime.json")

        self.assertFalse(gate["clean"])
        self.assertEqual(gate["classification"], "runtime-route-plan-quality-suspect")
        self.assertIn("route-plan-present", gate["failedChecks"])
        self.assertIn("route-plan-covered", gate["failedChecks"])


def quality_route_plan_repeat(route_selected: int = 4, route_fallback: bool = False) -> dict[str, object]:
    return {
        "qualityStateUsed": True,
        "totals": {
            "runs": 2,
            "failedRuns": 0,
            "workloadAttempted": 8,
            "workloadSuccess": 8,
            "workloadFailure": 0,
            "workloadErrors": [],
            "workloadStrictFailedRuns": 0,
            "workloadFlowEntries": 8,
            "workloadFlowTcpAttemptedEntries": 8,
            "workloadFlowTcpAttemptedCoveredEntries": 8,
            "workloadFlowRuntimePreflowMatchedEntries": 8,
            "workloadFlowRuntimePacketHandshakeEntries": 8,
            "workloadFlowTunCaptureMatchedEntries": 8,
            "workloadFlowUnmatchedEntries": 0,
            "workloadFlowRuntimePacketTerminalEntries": 0,
            "tcpFlowFailed": 0,
            "tcpFlowFailedAfterPathComplete": 0,
            "tcpFlowFailedAfterUpstreamOnly": 0,
            "tcpSlotPressureEvents": 0,
            "qualityBoundCandidateSets": 8,
            "qualityBoundSelectedWithQuality": 8,
            "qualityBoundSelectedBehind": 0,
        },
        "runs": [run(route_selected, route_fallback), run(route_selected, route_fallback)],
    }


def run(route_selected: int, route_fallback: bool = False) -> dict[str, object]:
    fallback = route_fallback_values(4) if route_fallback else {}
    return {
        "boundSelection": {
            "candidateSets": 4,
            "selectedWithQuality": 4,
            "selectedBehind": 0,
        },
        "tcpFlow": {
            "routeMatchedFlows": 4,
            "routeGraphSelectedFlows": route_selected,
            "ruleMatchedFlows": 0,
            "planBypassedFlows": 0,
            **fallback,
        },
    }


def route_fallback_values(count: int) -> dict[str, object]:
    return {
        "routeFallbackCandidateFlows": count,
        "routeFallbackAttemptEvents": count * 2,
        "routeFallbackUsedFlows": count,
        "routeFallbackEstablishedFlows": count,
        "routeFallbackFailedFlows": 0,
        "routeFallbackByRouteSelected": [{"count": count, "key": "bad-trojan"}],
        "routeFallbackByFinalOutbound": [{"count": count, "key": "direct"}],
        "routeFallbackByAttemptedOutbound": [
            {"count": count, "key": "bad-trojan"},
            {"count": count, "key": "direct"},
        ],
    }


if __name__ == "__main__":
    unittest.main()
