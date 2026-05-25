from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
VM_PATH = ROOT / "scripts" / "vm"
sys.path.insert(0, str(VM_PATH))

from private_runtime_lib.briefs import tcp_target_identity_brief
from private_runtime_lib.checks import tcp_acceptance_checks, tcp_lifecycle_counts
from private_runtime_lib.tcp_flow import tcp_flow_brief, workload_flow_brief
from tests.private_runtime_fixtures import (
    duplicate_close_report,
    event_by_kind,
    event_by_stage,
    tcp_event,
    tcp_identity_path_events,
    tcp_identity_payload_events,
    tcp_identity_report,
    tcp_identity_target_events,
    route_plan_events,
)


class PrivateRuntimeTcpFlowTest(unittest.TestCase):
    def test_tcp_identity(self) -> None:
        report = tcp_identity_report()
        brief = tcp_target_identity_brief(report)
        flow = tcp_flow_brief(report)
        by_name = {item["name"]: item["passed"] for item in tcp_checks(report)}

        self.assertEqual(brief["domainTargets"], ["chatgpt.com:443"])
        self.assertEqual(brief["domainConnectTargets"], 1)
        self.assertEqual(brief["adapterTargets"], ["chatgpt.com:443"])
        self.assertEqual(brief["adapterDomainTargets"], 1)
        self.assertEqual(brief["targetChainFlows"], 1)
        self.assertEqual(brief["targetChainMatched"], 1)
        self.assertEqual(brief["targetChainMismatched"], 0)
        self.assertEqual(brief["targetChainMissingAdapter"], 0)
        self.assertEqual(brief["targetChainMissingConnect"], 0)
        self.assertEqual(flow["lifecycleCompleteFlows"], 1)
        self.assertEqual(flow["pathCompleteFlows"], 1)
        self.assertEqual(flow["boundCandidateSetFlows"], 1)
        self.assertEqual(flow["cascadeSelectedFlows"], 1)
        self.assertEqual(flow["closedWithByteTotals"], 1)
        self.assertEqual(flow["closedByReason"], [{"count": 1, "key": "outbound-eof"}])
        self.assertEqual(flow["closedWithoutPayloadFlows"], 0)
        self.assertEqual(flow["closedWithoutPayloadByReason"], [])
        self.assertEqual(flow["payloadBidirectionalFlows"], 1)
        self.assertEqual(flow["payloadCloseConsistent"], 1)
        self.assertTrue(by_name["tcp-connect-target-reported"])
        self.assertTrue(by_name["tcp-target-source-reported"])
        self.assertTrue(by_name["tcp-identity-domain-reported"])
        self.assertTrue(by_name["tcp-domain-connect-target"])
        self.assertTrue(by_name["tcp-adapter-target-reported"])
        self.assertTrue(by_name["tcp-adapter-domain-target"])
        self.assertTrue(by_name["tcp-target-chain-complete"])
        self.assertTrue(by_name["tcp-target-chain-matched"])
        self.assertTrue(by_name["tcp-flow-lifecycle-complete"])
        self.assertTrue(by_name["tcp-flow-path-complete"])
        self.assertTrue(by_name["tcp-flow-close-byte-totals"])
        self.assertTrue(by_name["tcp-flow-payload-bidirectional"])

    def test_tcp_chain_mismatch(self) -> None:
        report = tcp_identity_report()
        event_by_stage(report, "private-ss-connect")["fields"]["adapterTarget"] = "example.com:443"
        brief = tcp_target_identity_brief(report)
        by_name = {item["name"]: item["passed"] for item in tcp_checks(report)}

        self.assertEqual(brief["targetChainMatched"], 0)
        self.assertEqual(brief["targetChainMismatched"], 1)
        self.assertTrue(by_name["tcp-target-chain-complete"])
        self.assertFalse(by_name["tcp-target-chain-matched"])

    def test_route_plan_path(self) -> None:
        report = tcp_identity_report()
        report["events"] = (
            tcp_identity_target_events()
            + route_plan_events()
            + tcp_identity_payload_events()
        )
        flow = tcp_flow_brief(report)
        by_name = {item["name"]: item["passed"] for item in tcp_checks(report)}

        self.assertEqual(flow["pathCompleteFlows"], 1)
        self.assertEqual(flow["ruleMatchedFlows"], 0)
        self.assertEqual(flow["routeMatchedFlows"], 1)
        self.assertEqual(flow["planBypassedFlows"], 0)
        self.assertEqual(flow["routeCandidateSetFlows"], 0)
        self.assertEqual(flow["routeGraphSelectedFlows"], 1)
        self.assertTrue(by_name["tcp-flow-path-complete"])

    def test_tcp_bytes_mismatch(self) -> None:
        report = tcp_identity_report()
        event_by_kind(report, "tcp-session-closed")["fields"]["downstreamBytes"] = "0"
        flow = tcp_flow_brief(report)
        by_name = {item["name"]: item["passed"] for item in tcp_checks(report)}

        self.assertEqual(flow["payloadBidirectionalFlows"], 1)
        self.assertEqual(flow["payloadCloseConsistent"], 0)
        self.assertFalse(by_name["tcp-flow-payload-bidirectional"])

    def test_tcp_upstream_failure(self) -> None:
        report = tcp_identity_report()
        report["events"].pop()
        report["events"].append(
            tcp_event(
                "tcp-session-failed",
                {
                    "target": "104.18.32.47:443",
                    "upstreamBytes": "517",
                    "downstreamBytes": "0",
                    "errorType": "shadowsocks",
                    "failurePhase": "forwarding",
                    "cleanupAction": "socket-abort",
                    "replaySafe": "post-payload",
                },
            )
        )
        flow = tcp_flow_brief(report)

        self.assertEqual(flow["failedFlows"], 1)
        self.assertEqual(flow["failedAfterPathComplete"], 1)
        self.assertEqual(flow["failedAfterUpstreamOnly"], 1)
        self.assertEqual(flow["failedByErrorType"], [{"count": 1, "key": "shadowsocks"}])
        self.assertEqual(flow["failedByPhase"], [{"count": 1, "key": "forwarding"}])
        self.assertEqual(flow["failedByCleanupAction"], [{"count": 1, "key": "socket-abort"}])
        self.assertEqual(flow["failedByReplaySafe"], [{"count": 1, "key": "post-payload"}])
        self.assertEqual(
            flow["failedBySurface"],
            [{"count": 1, "key": "path-complete-upstream-only-shadowsocks"}],
        )

    def test_stage_failure_surface(self) -> None:
        report = tcp_identity_report()
        report["events"] = tcp_identity_target_events() + tcp_identity_path_events()
        report["events"].append(
            tcp_event(
                "outbound-stage-finished",
                {
                    "outbound": "tunnel-003",
                    "stage": "tcp-connect",
                    "status": "failed",
                    "errorType": "trojan",
                    "errorDisposition": "pending-timeout",
                },
            )
        )
        report["events"].append(
            tcp_event(
                "tcp-session-failed",
                {
                    "outbound": "private-via-tunnel",
                    "errorType": "trojan",
                    "failurePhase": "session-start",
                    "cleanupAction": "socket-abort",
                    "replaySafe": "pre-payload",
                    "failureStage": "tcp-connect",
                    "failureStageOutbound": "tunnel-003",
                    "failureStageKind": "trojan",
                    "failureStageErrorType": "trojan",
                    "failureStageDisposition": "pending-timeout",
                },
            )
        )
        flow = tcp_flow_brief(report)

        self.assertEqual(flow["failedFlows"], 1)
        self.assertEqual(flow["stageFailedFlows"], 1)
        self.assertEqual(flow["stageFailureByErrorType"], [{"count": 1, "key": "trojan"}])
        self.assertEqual(
            flow["stageFailureByDisposition"],
            [{"count": 1, "key": "pending-timeout"}],
        )
        self.assertEqual(flow["stageFailureByStage"], [{"count": 1, "key": "tcp-connect"}])
        self.assertEqual(
            flow["stageFailureBySurface"],
            [{"count": 1, "key": "tcp-connect:trojan"}],
        )
        self.assertEqual(flow["failedByPhase"], [{"count": 1, "key": "session-start"}])
        self.assertEqual(flow["failedByCleanupAction"], [{"count": 1, "key": "socket-abort"}])
        self.assertEqual(flow["failedByReplaySafe"], [{"count": 1, "key": "pre-payload"}])
        self.assertEqual(flow["failedByFailureStage"], [{"count": 1, "key": "tcp-connect"}])
        self.assertEqual(
            flow["failedByFailureStageOutbound"],
            [{"count": 1, "key": "tunnel-003"}],
        )
        self.assertEqual(
            flow["failedByFailureStageKind"],
            [{"count": 1, "key": "trojan"}],
        )
        self.assertEqual(
            flow["failedByFailureStageErrorType"],
            [{"count": 1, "key": "trojan"}],
        )
        self.assertEqual(
            flow["failedByFailureStageDisposition"],
            [{"count": 1, "key": "pending-timeout"}],
        )

    def test_recovered_stage_flow(self) -> None:
        report = tcp_identity_report()
        report["events"].insert(
            -1,
            tcp_event(
                "outbound-stage-finished",
                {"outbound": "tunnel-003", "stage": "tcp-connect", "status": "failed", "errorType": "trojan"},
            ),
        )
        flow = tcp_flow_brief(report)
        workload = workload_flow_brief(report, successful_workload_report())

        self.assertEqual((flow["failedFlows"], flow["lifecycleCompleteFlows"], flow["stageFailedFlows"]), (0, 1, 1))
        self.assertEqual(flow["stageFailureByErrorType"], [{"count": 1, "key": "trojan"}])
        self.assertEqual(flow["failedByErrorType"], [])
        self.assertEqual(
            (
                workload["matchedFlowFailedAttempts"],
                workload["matchedRecoveredFailureEntries"],
                workload["matchedFlowStageFailedAttempts"],
            ),
            (0, 1, 1),
        )

    def test_no_payload_close(self) -> None:
        report = tcp_identity_report()
        report["events"] = tcp_identity_target_events() + tcp_identity_path_events()
        report["events"].append(
            tcp_event(
                "tcp-session-closed",
                {
                    "target": "104.18.32.47:443",
                    "upstreamBytes": "0",
                    "downstreamBytes": "0",
                    "reason": "tun-closed-before-payload",
                },
            )
        )
        flow = tcp_flow_brief(report)

        self.assertEqual(flow["closedWithByteTotals"], 1)
        self.assertEqual(flow["closedByReason"], [{"count": 1, "key": "tun-closed-before-payload"}])
        self.assertEqual(flow["closedWithoutPayloadFlows"], 1)
        self.assertEqual(
            flow["closedWithoutPayloadByReason"],
            [{"count": 1, "key": "tun-closed-before-payload"}],
        )

    def test_workload_flow_join(self) -> None:
        brief = workload_flow_brief(tcp_identity_report(), matched_workload_report())

        self.assertEqual(brief["entries"], 1)
        self.assertEqual(brief["entriesWithLocalPort"], 1)
        self.assertEqual(brief["matchedEntries"], 1)
        self.assertEqual(brief["matchedFlowAttempts"], 1)
        self.assertEqual(brief["matchedDuplicateFlowEntries"], 0)
        self.assertEqual(brief["matchedRecoveredFailureEntries"], 0)
        self.assertEqual(brief["matchedFlowFailedAttempts"], 0)
        self.assertEqual(brief["matchedFlowStageFailedAttempts"], 0)
        self.assertEqual(brief["matchedFailures"], 1)
        self.assertEqual(brief["matchedPathComplete"], 1)
        self.assertEqual(brief["matchedLifecycleComplete"], 1)
        self.assertEqual(brief["matchedPayloadBidirectional"], 1)
        self.assertEqual(
            brief["failureSurfaces"],
            [{"count": 1, "key": "https-head:tls-handshake:timeout:route-dynet:tun-witnessed"}],
        )
        self.assertEqual(brief["unmatchedFailureSurfaces"], [])

    def test_recovered_flow_join(self) -> None:
        report = tcp_identity_report()
        report["events"] = (
            flow_events("tcp-session-0")
            + [
                tcp_event_for_flow(
                    "tcp-session-0",
                    "outbound-stage-finished",
                    {
                        "outbound": "tunnel-003",
                        "stage": "tcp-connect",
                        "status": "failed",
                        "errorType": "trojan",
                    },
                )
            ]
            + tcp_identity_report()["events"]
        )
        brief = workload_flow_brief(report, matched_workload_report())
        row = brief["rows"][0]

        self.assertEqual(brief["matchedFlowAttempts"], 2)
        self.assertEqual(brief["matchedDuplicateFlowEntries"], 1)
        self.assertEqual(brief["matchedRecoveredFailureEntries"], 1)
        self.assertEqual(brief["matchedFlowFailedAttempts"], 0)
        self.assertEqual(brief["matchedFlowStageFailedAttempts"], 1)
        self.assertEqual(row["flowMatchedCount"], 2)
        self.assertEqual(row["flowIds"], ["tcp-session-0", "tcp-session-1"])
        self.assertEqual(row["flowId"], "tcp-session-1")
        self.assertEqual(row["flowFailedCount"], 0)
        self.assertEqual(row["flowStageFailedCount"], 1)
        self.assertTrue(row["flowRecoveredFailure"])

    def test_unmatched_failure_surface(self) -> None:
        brief = workload_flow_brief(unmatched_report(), unmatched_workload_report())

        self.assert_unmatched_counts(brief)
        self.assert_unmatched_runtime(brief)
        self.assertEqual(
            brief["unmatchedFailureSurfaces"],
            [{"count": 1, "key": "https-head:tls-handshake:timeout:route-dynet:tun-witnessed"}],
        )

    def assert_unmatched_counts(self, brief: dict) -> None:
        self.assertEqual(brief["matchedFailures"], 0)
        self.assertEqual(brief["coveredEntries"], 0)
        self.assertEqual(brief["packetTerminalEntries"], 0)
        self.assertEqual(brief["unmatchedFailures"], 1)
        self.assertEqual(brief["unmatchedTcpConnectedFailures"], 1)
        self.assertEqual(brief["unmatchedRouteViaDynetFailures"], 1)
        self.assertEqual(brief["unmatchedTunWitnessedFailures"], 1)

    def assert_unmatched_runtime(self, brief: dict) -> None:
        self.assertEqual(brief["runtimePreflowMatchedEntries"], 1)
        self.assertEqual(brief["unmatchedRuntimePreflowMatched"], 1)
        self.assertEqual(brief["unmatchedRuntimePreflowMatchedFailures"], 1)
        self.assertEqual(brief["runtimePacketMatchedEntries"], 1)
        self.assertEqual(brief["runtimeIngressSynMatchedEntries"], 1)
        self.assertEqual(brief["runtimeEgressSynAckMatchedEntries"], 1)
        self.assertEqual(brief["runtimePacketTerminalEntries"], 1)
        self.assertEqual(
            brief["runtimePacketTerminalByReason"],
            [{"count": 1, "key": "closed-before-preflow"}],
        )
        self.assertEqual(brief["unmatchedRuntimePacketMatched"], 1)
        self.assertEqual(brief["unmatchedRuntimePacketMatchedFailures"], 1)
        self.assertEqual(brief["unmatchedRuntimePacketTerminalMatched"], 1)
        self.assertEqual(brief["unmatchedRuntimePacketTerminalFailures"], 1)
        self.assertEqual(
            brief["unmatchedRuntimePacketTerminalByReason"],
            [{"count": 1, "key": "closed-before-preflow"}],
        )
        self.assertEqual(
            brief["unmatchedRuntimePacketTerminalFailureByReason"],
            [{"count": 1, "key": "closed-before-preflow"}],
        )
        self.assertEqual(brief["unmatchedTcpConnectedRuntimePacketMissing"], 0)
        self.assertTrue(brief["rows"][0]["runtimePacketTerminalMatched"])
        self.assertEqual(brief["rows"][0]["runtimePacketTerminalReason"], "closed-before-preflow")
        self.assertEqual(brief["rows"][0]["runtimePacketTerminalIngressPayloadBytes"], 517)
        self.assertEqual(brief["tunCaptureMatchedEntries"], 1)
        self.assertEqual(brief["unmatchedTunCaptureMatched"], 1)
        self.assertEqual(brief["unmatchedTunCaptureMatchedFailures"], 1)
        self.assertEqual(brief["unmatchedTcpConnectedTunCaptureMissing"], 0)

    def test_close_events_unique(self) -> None:
        counts = tcp_lifecycle_counts(duplicate_close_report())

        self.assertEqual(counts["startedEvents"], 1)
        self.assertEqual(counts["closeEvents"], 2)
        self.assertEqual(counts["uniqueClosed"], 1)

    def test_workload_https_blackbox(self) -> None:
        checks = tcp_acceptance_checks(
            tcp_identity_report(),
            {"results": [{"name": "chatgpt.com", "error": "timed out"}]},
            ["chatgpt.com"],
            {
                "tcp-session-started",
                "tcp-session-attributed",
                "tcp-session-established",
                "tcp-session-payload-first-write",
            },
            {"tcpClosedSessions": 1, "protocolShortReadErrors": 0},
            {"results": [{"domain": "chatgpt.com", "probe": "https-head", "ok": True}]},
        )

        by_name = {item["name"]: item["passed"] for item in checks}
        self.assertTrue(by_name["tcp-blackbox-https"])


def tcp_checks(report: dict) -> list[dict]:
    return tcp_acceptance_checks(
        report,
        {"results": [{"name": "chatgpt.com", "https": {"ok": True}}]},
        ["chatgpt.com"],
        {
            "tcp-session-started",
            "tcp-session-attributed",
            "tcp-session-established",
            "tcp-session-payload-first-write",
        },
        {"tcpClosedSessions": 1, "protocolShortReadErrors": 0},
    )


def matched_workload_report() -> dict:
    return workload_report(45678, "chatgpt.com", "example-head-1")


def successful_workload_report() -> dict:
    report = workload_report(45678, "chatgpt.com", "example-head-1")
    report["results"][0].update({"ok": True, "errorStage": None, "errorType": None})
    return report


def unmatched_workload_report() -> dict:
    return workload_report(45679, "api.github.com", "github-head-1")


def workload_report(port: int, domain: str, item_id: str) -> dict:
    return {
        "tunCapture": {"ports": [capture_port(port)]},
        "results": [
            {
                "id": item_id,
                "probe": "https-head",
                "domain": domain,
                "ok": False,
                "localPort": port,
                "errorStage": "tls-handshake",
                "errorType": "timeout",
                "routeViaDynet": True,
                "tunWitness": {"observed": True},
                "stages": [{"name": "tcp-connect", "ok": True}],
            }
        ],
    }


def capture_port(port: int) -> dict:
    return {
        "localPort": port,
        "toTargetPackets": 2,
        "fromTargetPackets": 1,
        "synPackets": 1,
        "synAckPackets": 1,
    }


def unmatched_report() -> dict:
    report = tcp_identity_report()
    report["events"].append({"kind": "tcp-forwarder-preflow", "fields": {"clientPort": "45679"}})
    report["events"].extend(
        [
            packet_event("ingress", "false"),
            packet_event("egress", "true"),
            terminal_event(),
        ]
    )
    return report


def flow_events(flow_id: str) -> list[dict]:
    return [
        tcp_event_for_flow(flow_id, event["kind"], dict(event["fields"]))
        for event in (tcp_identity_target_events() + tcp_identity_path_events())
    ]


def tcp_event_for_flow(flow_id: str, kind: str, fields: dict[str, str]) -> dict[str, object]:
    return {"kind": kind, "fields": {**fields, "flowId": flow_id}}


def packet_event(direction: str, ack: str) -> dict:
    return {
        "kind": "tcp-forwarder-packet",
        "fields": {
            "clientPort": "45679",
            "direction": direction,
            "syn": "true",
            "ack": ack,
        },
    }


def terminal_event() -> dict:
    return {
        "kind": "tcp-forwarder-packet-terminal",
        "fields": {
            "clientPort": "45679",
            "reason": "closed-before-preflow",
            "ingressControlPackets": "2",
            "ingressSynPackets": "1",
            "egressControlPackets": "2",
            "egressSynAckPackets": "1",
            "ingressPayloadPackets": "1",
            "ingressPayloadBytes": "517",
            "egressPayloadPackets": "0",
            "egressPayloadBytes": "0",
            "finPackets": "1",
            "rstPackets": "1",
        },
    }


if __name__ == "__main__":
    unittest.main()
