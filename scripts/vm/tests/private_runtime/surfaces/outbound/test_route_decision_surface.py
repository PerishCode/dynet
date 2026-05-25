from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[6]
VM_PATH = ROOT / "scripts" / "vm"
sys.path.insert(0, str(VM_PATH))

from private_runtime_lib.reporting.workload_surface.outbound.route_decision import (
    build_route_decision_summary,
)


class RouteDecisionSurfaceTest(unittest.TestCase):
    def test_route_decision_clean(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = write_run(root / "run-01", runtime_report())
            summary = build_route_decision_summary("route", root / "out", [run])

        self.assertEqual(summary["conclusion"]["status"], "clean")
        self.assertEqual(summary["totals"]["routeMatchedEvents"], 2)
        self.assertEqual(summary["totals"]["planBypassedEvents"], 1)
        self.assertEqual(summary["totals"]["routeDecisionCounterMismatches"], 0)
        self.assertEqual(summary["totals"]["udpRouteGraphMismatches"], 0)

    def test_missing_graph_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = write_run(root / "run-01", runtime_report(missing_tcp_graph=True))
            summary = build_route_decision_summary("route", root / "out", [run])

        self.assertEqual(summary["runs"][0]["classification"], "tcp-route-graph-missing")
        self.assertEqual(
            summary["conclusion"]["status"],
            "route-decision-surface-needs-evidence",
        )


def runtime_report(missing_tcp_graph: bool = False) -> dict:
    events = [
        event("route-matched", {
            "flowId": "tcp-session-1",
            "session": "tcp-session-1",
            "transport": "tcp",
            "status": "Accept",
            "outbound": "selected",
        }),
        event("route-matched", {
            "transport": "udp",
            "status": "Accept",
            "outbound": "direct",
        }),
        event("plan-bypassed", {"dnsQueryId": "dns-query-1"}),
        event("outbound-graph-selected", {
            "dnsQueryId": "dns-query-1",
            "scope": "plan-candidate",
            "selected": "selected",
            "requested": "selected",
        }),
        event("outbound-graph-selected", {
            "scope": "udp-route",
            "selected": "direct",
            "requested": "direct",
        }),
        event("outbound-candidate-set", {
            "flowId": "tcp-session-1",
            "scope": "tcp-route",
            "selected": "selected",
            "candidateCount": "2",
        }),
    ]
    if not missing_tcp_graph:
        events.append(event("outbound-graph-selected", {
            "flowId": "tcp-session-1",
            "scope": "tcp-route",
            "selected": "selected",
            "requested": "selected",
        }))
    return {
        "schema": "dynet-runtime-report/v1alpha1",
        "status": "pass",
        "routeDecisions": 2,
        "events": events,
    }


def event(kind: str, fields: dict[str, str]) -> dict[str, object]:
    return {"kind": kind, "fields": fields}


def write_run(path: Path, report: dict) -> Path:
    path.mkdir()
    (path / "runtime-report.json").write_text(json.dumps(report, sort_keys=True))
    (path / "summary.json").write_text(json.dumps({"label": path.name}))
    return path


if __name__ == "__main__":
    unittest.main()
