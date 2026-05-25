from __future__ import annotations

import argparse
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
VM_PATH = ROOT / "scripts" / "vm"
sys.path.insert(0, str(VM_PATH))

from private_runtime_lib.briefs import selection_brief
from private_runtime_lib.checks import acceptance_checks
from private_runtime_lib.config import POISON_DIALER_TAG
from private_runtime_lib.summary import build_repeat_summary
from private_runtime_lib.tcp_flow import tcp_flow_brief
from private_runtime_lib.tcp_flow.route_fallback_checks import (
    direct_fallback_checks,
    non_direct_fallback_checks,
)
from tests.private_runtime_fixtures import (
    lifecycle_report,
    runtime_args,
    tcp_event,
    tcp_identity_payload_events,
    tcp_identity_report,
)


class PrivateRuntimeRouteFallbackTest(unittest.TestCase):
    def test_tcp_flow_summary(self) -> None:
        report = tcp_identity_report()
        report["events"] = route_fallback_events()
        flow = tcp_flow_brief(report)

        self.assertEqual(flow["routeFallbackCandidateFlows"], 1)
        self.assertEqual(flow["routeFallbackAttemptEvents"], 2)
        self.assertEqual(flow["routeFallbackUsedFlows"], 1)
        self.assertEqual(flow["routeFallbackEstablishedFlows"], 1)
        self.assertEqual(flow["routeFallbackFailedFlows"], 0)
        self.assertEqual(
            flow["routeFallbackByRouteSelected"],
            [{"count": 1, "key": "bad-trojan"}],
        )
        self.assertEqual(flow["routeFallbackByFinalOutbound"], [{"count": 1, "key": "direct"}])
        self.assertEqual(
            flow["routeFallbackByAttemptedOutbound"],
            [{"count": 1, "key": "bad-trojan"}, {"count": 1, "key": "direct"}],
        )
        self.assertEqual(flow["pathCompleteFlows"], 1)
        self.assertEqual(flow["stageFailedFlows"], 1)

    def test_acceptance_filter(self) -> None:
        report = route_fallback_report()
        args = runtime_args(tcp_forward=True)
        args.tcp_probe = False
        args.tcp_route_direct_fallback = True
        args.workload_manifest = None
        args.quality_state = None
        checks = acceptance_checks(
            report,
            lifecycle_report(),
            lifecycle_report(),
            {"results": []},
            {},
            {},
            {},
            [],
            args,
            {"tcpClosedSessions": 0, "protocolShortReadErrors": 0},
        )

        by_name = {item["name"]: item["passed"] for item in checks}
        self.assertNotIn("tcp-adapter-target-reported", by_name)
        self.assertNotIn("tcp-target-chain-complete", by_name)
        self.assertTrue(by_name["route-direct-fallback-used"])
        self.assertTrue(by_name["route-direct-fallback-final-direct"])
        self.assertTrue(by_name["route-direct-fallback-bound-exhausted"])

    def test_direct_fallback_acceptance(self) -> None:
        checks = direct_fallback_checks(route_fallback_report())

        by_name = {item["name"]: item["passed"] for item in checks}
        self.assertTrue(all(by_name.values()))

    def test_non_direct_acceptance(self) -> None:
        checks = non_direct_fallback_checks(non_direct_fallback_report())

        by_name = {item["name"]: item["passed"] for item in checks}
        self.assertTrue(all(by_name.values()), by_name)

    def test_route_private_checks(self) -> None:
        report = non_direct_fallback_report()
        args = runtime_args(tcp_forward=True)
        args.tcp_probe = False
        args.tcp_route_non_direct_fallback = True
        args.workload_manifest = None
        args.quality_state = None
        checks = acceptance_checks(
            report,
            lifecycle_report(),
            lifecycle_report(),
            {"results": []},
            {},
            {},
            {},
            [],
            args,
            {"tcpClosedSessions": 0, "protocolShortReadErrors": 0},
        )

        by_name = {item["name"]: item["passed"] for item in checks}
        self.assertIn("tcp-adapter-target-reported", by_name)
        self.assertIn("tcp-target-chain-complete", by_name)
        self.assertTrue(by_name["tcp-target-chain-complete"])
        self.assertTrue(by_name["route-non-direct-fallback-used"])
        self.assertTrue(by_name["route-non-direct-fallback-final-private"])
        self.assertTrue(by_name["route-non-direct-fallback-bound-exhausted"])

    def test_repeat_totals(self) -> None:
        summary = build_repeat_summary(
            "dynet-smoke",
            "repeat",
            Path("/tmp/repeat"),
            [
                repeat_run(route_fallback_case(2, 4, 2, established=2)),
                repeat_run(route_fallback_case(1, 2, 1, failed=1), failed=1),
            ],
            repeat_args(),
        )

        totals = summary["totals"]
        self.assertTrue(summary["candidateControl"]["tcpRouteNonDirectFallback"])
        self.assertEqual(totals["tcpFlowRouteFallbackCandidate"], 3)
        self.assertEqual(totals["tcpFlowRouteFallbackAttempts"], 6)
        self.assertEqual(totals["tcpFlowRouteFallbackUsed"], 3)
        self.assertEqual(totals["tcpFlowRouteFallbackEstablished"], 2)
        self.assertEqual(totals["tcpFlowRouteFallbackFailed"], 1)
        self.assertEqual(
            totals["tcpFlowRouteFallbackByRouteSelected"],
            [{"count": 3, "key": "bad-trojan"}],
        )
        self.assertEqual(
            totals["tcpFlowRouteFallbackByFinalOutbound"],
            [{"count": 2, "key": "direct"}, {"count": 1, "key": "fallback-failed"}],
        )
        self.assertEqual(
            totals["tcpFlowRouteFallbackByAttemptedOutbound"],
            [{"count": 3, "key": "bad-trojan"}, {"count": 3, "key": "direct"}],
        )


def route_fallback_report() -> dict[str, object]:
    report = tcp_identity_report()
    report["events"] = route_fallback_events()
    report["_selectionBrief"] = selection_brief(report)
    return report


def non_direct_fallback_report() -> dict[str, object]:
    report = tcp_identity_report()
    report["events"] = non_direct_events()
    report["_selectionBrief"] = selection_brief(report)
    return report


def route_fallback_events() -> list[dict[str, object]]:
    target = "104.20.23.154:443"
    return [
        tcp_event("tcp-session-started", {"target": target, "clientPort": "45678"}),
        tcp_event("tcp-session-attributed", {"target": target, "outbound": "bad-trojan"}),
        tcp_event("route-matched", {"target": target, "outbound": "auto-fallback"}),
        tcp_event("outbound-graph-selected", {"scope": "tcp-route", "selected": "bad-trojan"}),
        tcp_event(
            "outbound-candidate-set",
            {"scope": "dialer-bound", "selected": "tunnel-poison-001"},
        ),
        tcp_event(
            "outbound-graph-selected",
            {"scope": "dialer-bound", "selected": "tunnel-poison-001"},
        ),
        tcp_event(
            "dialer-cascade-selected",
            {"boundSelected": "tunnel-poison-001", "private": "private"},
        ),
        tcp_event("outbound-attempt-started", {"outbound": "tunnel-poison-001"}),
        tcp_event(
            "tcp-session-outbound-connecting",
            fallback_fields("bad-trojan", "trojan", 1),
        ),
        tcp_event(
            "outbound-stage-finished",
            {
                "outbound": "bad-trojan",
                "kind": "trojan",
                "stage": "tcp-connect",
                "status": "failed",
                "errorType": "refused",
                "errorDisposition": "connection-refused",
            },
        ),
        tcp_event(
            "dialer-cascade-attempt-finished",
            {
                "attempt": "1",
                "boundSelected": "tunnel-poison-001",
                "candidateCount": "1",
                "dialer": "bad-trojan",
                "failureScope": "bound",
                "failureStage": "tcp-connect",
                "failureStageDisposition": "connection-refused",
                "failureStageErrorType": "refused",
                "failureStageKind": "trojan",
                "failureStageOutbound": "tunnel-poison-001",
                "retryAllowed": "false",
                "retryStopReason": "bound-candidates-exhausted",
                "status": "failed",
            },
        ),
        tcp_event("tcp-session-outbound-connecting", fallback_fields("direct", "direct", 2)),
        tcp_event(
            "tcp-session-established",
            {"target": target, "outbound": "direct", "routeSelected": "bad-trojan"},
        ),
    ]


def non_direct_events() -> list[dict[str, object]]:
    target = "104.20.23.154:443"
    return (
        non_direct_poison_events(target)
        + non_direct_private_events(target)
        + tcp_identity_payload_events()
    )


def non_direct_poison_events(target: str) -> list[dict[str, object]]:
    return [
        tcp_event("tcp-session-started", {"target": target, "clientPort": "45678"}),
        tcp_event(
            "tcp-session-attributed",
            {"target": target, "outbound": POISON_DIALER_TAG},
        ),
        tcp_event("route-matched", {"target": target, "outbound": "auto-fallback"}),
        tcp_event(
            "outbound-graph-selected",
            {"scope": "tcp-route", "selected": POISON_DIALER_TAG},
        ),
        tcp_event(
            "outbound-candidate-set",
            {"scope": "dialer-bound", "selected": "tunnel-poison-001"},
        ),
        tcp_event(
            "outbound-graph-selected",
            {"scope": "dialer-bound", "selected": "tunnel-poison-001"},
        ),
        tcp_event(
            "dialer-cascade-selected",
            {"boundSelected": "tunnel-poison-001", "private": "private"},
        ),
        tcp_event("outbound-attempt-started", {"outbound": "tunnel-poison-001"}),
        tcp_event(
            "tcp-session-outbound-connecting",
            fallback_fields(
                POISON_DIALER_TAG,
                "dialer",
                1,
                route_selected=POISON_DIALER_TAG,
            ),
        ),
        tcp_event(
            "outbound-stage-finished",
            {
                "outbound": POISON_DIALER_TAG,
                "kind": "dialer",
                "stage": "dialer-payload-decode",
                "status": "success",
            },
        ),
        tcp_event(
            "outbound-stage-finished",
            {
                "outbound": "tunnel-poison-001",
                "kind": "vmess",
                "stage": "tcp-connect",
                "status": "failed",
                "errorType": "refused",
                "errorDisposition": "connection-refused",
            },
        ),
        tcp_event(
            "dialer-cascade-attempt-finished",
            {
                "attempt": "1",
                "boundSelected": "tunnel-poison-001",
                "candidateCount": "1",
                "dialer": POISON_DIALER_TAG,
                "failureScope": "bound",
                "failureStage": "tcp-connect",
                "failureStageDisposition": "connection-refused",
                "failureStageErrorType": "refused",
                "failureStageKind": "vmess",
                "failureStageOutbound": "tunnel-poison-001",
                "retryAllowed": "false",
                "retryStopReason": "bound-candidates-exhausted",
                "status": "failed",
            },
        ),
    ]


def non_direct_private_events(target: str) -> list[dict[str, object]]:
    return [
        tcp_event(
            "tcp-session-outbound-connecting",
            fallback_fields(
                "private-via-tunnel",
                "dialer",
                2,
                route_selected=POISON_DIALER_TAG,
            ),
        ),
        tcp_event(
            "outbound-candidate-set",
            {"scope": "dialer-bound", "selected": "tunnel-001"},
        ),
        tcp_event(
            "outbound-graph-selected",
            {"scope": "dialer-bound", "selected": "tunnel-001"},
        ),
        tcp_event(
            "dialer-cascade-selected",
            {"boundSelected": "tunnel-001", "private": "private"},
        ),
        tcp_event("outbound-attempt-started", {"outbound": "tunnel-001"}),
        tcp_event("outbound-attempt-finished", {"outbound": "tunnel-001", "status": "success"}),
        tcp_event(
            "outbound-stage-finished",
            {
                "outbound": "private",
                "kind": "trojan",
                "stage": "private-trojan-connect",
                "status": "success",
                "adapterTarget": "www.cloudflare.com:443",
                "adapterTargetKind": "domain",
            },
        ),
        tcp_event(
            "tcp-session-established",
            {
                "target": target,
                "outbound": "private-via-tunnel",
                "routeSelected": POISON_DIALER_TAG,
            },
        ),
    ]


def fallback_fields(
    outbound: str,
    kind: str,
    attempt: int,
    route_selected: str = "bad-trojan",
) -> dict[str, str]:
    return {
        "outbound": outbound,
        "kind": kind,
        "connectTarget": "www.cloudflare.com:443",
        "identityDomain": "www.cloudflare.com",
        "targetAddressSource": "dns-reverse-rule-domain",
        "routeSelected": route_selected,
        "routeFallbackAttempt": str(attempt),
        "routeFallbackCandidateCount": "2",
    }


def repeat_run(route_fallback: dict[str, object], failed: int = 0) -> dict[str, object]:
    return {
        "label": "route-fallback",
        "passed": True,
        "tcpFlow": {
            "startedFlows": 1,
            "lifecycleCompleteFlows": 0 if failed else 1,
            "pathCompleteFlows": 0,
            "closedWithByteTotals": 0,
            "closedWithoutPayloadFlows": 0,
            "closedByReason": [],
            "closedWithoutPayloadByReason": [],
            "payloadStartedFlows": 0,
            "payloadBidirectionalFlows": 0,
            "payloadCloseConsistent": 0,
            "failedFlows": failed,
            "failedAfterPathComplete": 0,
            "failedAfterUpstreamOnly": 0,
            "failedByErrorType": [],
            "failedBySurface": [],
            "stageFailedFlows": 0,
            "stageFailureByErrorType": [],
            "stageFailureByStage": [],
            "stageFailureBySurface": [],
            "duplicateClosedFlows": 0,
            **route_fallback,
        },
    }


def route_fallback_case(
    candidate: int,
    attempts: int,
    used: int,
    established: int = 0,
    failed: int = 0,
) -> dict[str, object]:
    return {
        "routeFallbackCandidateFlows": candidate,
        "routeFallbackAttemptEvents": attempts,
        "routeFallbackUsedFlows": used,
        "routeFallbackEstablishedFlows": established,
        "routeFallbackFailedFlows": failed,
        "routeFallbackByRouteSelected": keyed_count("bad-trojan", used),
        "routeFallbackByFinalOutbound": (
            keyed_count("direct", established) + keyed_count("fallback-failed", failed)
        ),
        "routeFallbackByAttemptedOutbound": [
            {"key": "bad-trojan", "count": used},
            {"key": "direct", "count": used},
        ],
    }


def keyed_count(key: str, count: int) -> list[dict[str, object]]:
    return [{"key": key, "count": count}] if count else []


def repeat_args() -> argparse.Namespace:
    return argparse.Namespace(
        **{
            "tcp_forward": True,
            "udp_forward": False,
            "udp_direct_probe": False,
            "ipv6_no_leak": False,
            "quality_state": None,
            "tcp_listen_slots_per_port": 8,
            "tcp_route_direct_fallback": False,
            "tcp_route_non_direct_fallback": True,
            "workload_min_success_rate": 1,
            "workload_require_all_success": True,
        }
    )


if __name__ == "__main__":
    unittest.main()
