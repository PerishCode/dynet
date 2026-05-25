from __future__ import annotations

import argparse
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
VM_PATH = ROOT / "scripts" / "vm"
sys.path.insert(0, str(VM_PATH))

from private_runtime_lib.summary import build_repeat_summary
class PrivateRuntimeSummaryTest(unittest.TestCase):
    def test_repeat_totals(self) -> None:
        summary = build_repeat_summary(
            "dynet-smoke",
            "repeat",
            Path("/tmp/repeat"),
            [
                repeat_run("a", 8, 8, 5),
                repeat_run("b", 7, 7, 4),
            ],
            repeat_args(),
        )

        totals = summary["totals"]
        self.assertEqual(summary["workloadMinSuccessRate"], 1)
        self.assertTrue(summary["workloadRequireAllSuccess"])
        self.assertEqual(totals["tcpFlowStarted"], 15)
        self.assertEqual(totals["tcpFlowLifecycleComplete"], 15)
        self.assertEqual(totals["tcpFlowPathComplete"], 15)
        self.assertEqual(totals["tcpFlowClosedWithoutPayload"], 6)
        self.assertEqual(
            totals["tcpFlowClosedByReason"],
            [
                {"count": 9, "key": "outbound-eof"},
                {"count": 6, "key": "tun-closed-before-payload"},
            ],
        )
        self.assertEqual(
            totals["tcpFlowClosedWithoutPayloadByReason"],
            [{"count": 6, "key": "tun-closed-before-payload"}],
        )
        self.assertEqual(totals["tcpFlowPayloadStarted"], 9)
        self.assertEqual(totals["tcpFlowPayloadBidirectional"], 9)
        self.assertEqual(totals["tcpFlowPayloadCloseConsistent"], 9)
        self.assertEqual(totals["tcpFlowFailed"], 0)
        self.assertEqual(totals["tcpFlowFailedAfterPathComplete"], 0)
        self.assertEqual(totals["tcpFlowFailedAfterUpstreamOnly"], 0)
        self.assertEqual(totals["tcpFlowFailedByErrorType"], [])
        self.assertEqual(totals["tcpFlowFailedBySurface"], [])
        self.assertEqual(totals["tcpFlowStageFailed"], 0)
        self.assertEqual(totals["tcpFlowStageFailureByErrorType"], [])
        self.assertEqual(totals["tcpFlowStageFailureByStage"], [])
        self.assertEqual(totals["tcpFlowStageFailureBySurface"], [])
        self.assertEqual(totals["cascadeFinishedAttempts"], 0)
        self.assertEqual(totals["cascadeFailedAttempts"], 0)

    def test_repeat_failures(self) -> None:
        summary = build_repeat_summary(
            "dynet-smoke",
            "repeat",
            Path("/tmp/repeat"),
            [
                repeat_run(
                    "a",
                    3,
                    2,
                    1,
                    failed=1,
                    error_type="shadowsocks",
                    surface="path-complete-upstream-only-shadowsocks",
                ),
                repeat_run(
                    "b",
                    3,
                    1,
                    1,
                    failed=2,
                    failed_path=0,
                    failed_upstream=0,
                    error_type="vmess",
                    surface="path-incomplete-vmess",
                    stage_failed=1,
                    stage_error_type="trojan",
                    stage="tcp-connect",
                    stage_surface="tcp-connect:trojan",
                ),
                repeat_run(
                    "c",
                    3,
                    2,
                    1,
                    failed=1,
                    error_type="shadowsocks",
                    surface="path-complete-upstream-only-shadowsocks",
                ),
            ],
            repeat_args(),
        )

        totals = summary["totals"]
        self.assertEqual(totals["tcpFlowFailed"], 4)
        self.assertEqual(totals["tcpFlowFailedAfterPathComplete"], 2)
        self.assertEqual(totals["tcpFlowFailedAfterUpstreamOnly"], 2)
        self.assertEqual(
            totals["tcpFlowFailedByErrorType"],
            [{"count": 2, "key": "shadowsocks"}, {"count": 2, "key": "vmess"}],
        )
        self.assertEqual(
            totals["tcpFlowFailedBySurface"],
            [
                {"count": 2, "key": "path-complete-upstream-only-shadowsocks"},
                {"count": 2, "key": "path-incomplete-vmess"},
            ],
        )
        self.assertEqual(totals["tcpFlowStageFailed"], 1)
        self.assertEqual(totals["tcpFlowStageFailureByErrorType"], [{"count": 1, "key": "trojan"}])
        self.assertEqual(totals["tcpFlowStageFailureByStage"], [{"count": 1, "key": "tcp-connect"}])
        self.assertEqual(totals["tcpFlowStageFailureBySurface"], [{"count": 1, "key": "tcp-connect:trojan"}])

    def test_repeat_cascade_totals(self) -> None:
        summary = build_repeat_summary(
            "dynet-smoke",
            "repeat",
            Path("/tmp/repeat"),
            [
                repeat_run(
                    "a",
                    1,
                    1,
                    1,
                    cascade=cascade_summary(
                        finished=2,
                        failed=1,
                        retryable=1,
                        recovered=1,
                        disposition="pending-timeout",
                        stop_reason="retry-bound-failure-before-replay",
                    ),
                ),
                repeat_run(
                    "b",
                    1,
                    1,
                    1,
                    cascade=cascade_summary(
                        finished=1,
                        failed=1,
                        stopped=1,
                        disposition="protocol-invalid",
                        stop_reason="non-bound-failure",
                    ),
                ),
            ],
            repeat_args(),
        )

        totals = summary["totals"]
        self.assertEqual(totals["cascadeFinishedAttempts"], 3)
        self.assertEqual(totals["cascadeFailedAttempts"], 2)
        self.assertEqual(totals["cascadeRetryableFailures"], 1)
        self.assertEqual(totals["cascadeStoppedFailures"], 1)
        self.assertEqual(totals["cascadeRecoveredFlows"], 1)
        self.assertEqual(totals["cascadeFailedByDisposition"], [
            {"count": 1, "key": "pending-timeout"},
            {"count": 1, "key": "protocol-invalid"},
        ])
        self.assertEqual(totals["cascadeFailedByStageSurface"], [
            {"count": 1, "key": "private-trojan-connect:trojan"},
            {"count": 1, "key": "trojan-tls-handshake:trojan"},
        ])
        self.assertEqual(totals["cascadeFailedByStageDisposition"], [
            {"count": 1, "key": "pending-timeout"},
            {"count": 1, "key": "protocol-invalid"},
        ])

    def test_workload_totals(self) -> None:
        surface = "https-head:tls-handshake:timeout:route-dynet:tun-witnessed"
        summary = build_repeat_summary(
            "dynet-smoke",
            "repeat",
            Path("/tmp/repeat"),
            [
                repeat_run(
                    "a",
                    4,
                    4,
                    2,
                    workload_attempted=6,
                    workload_success=6,
                ),
                repeat_run(
                    "b",
                    4,
                    4,
                    2,
                    workload_attempted=6,
                    workload_success=5,
                    workload_failure=1,
                    workload_errors=[{"key": "timeout", "count": 1}],
                    workload_flow=workload_case(
                        matched=5,
                        matched_attempts=6,
                        matched_duplicate=1,
                        matched_recovered=1,
                        matched_flow_failed=1,
                        matched_stage_failed=1,
                        unmatched=1,
                        covered=6,
                        packet_terminal=1,
                        unmatched_tcp=1,
                        unmatched_route=1,
                        unmatched_tun=1,
                        runtime_preflow=6,
                        unmatched_preflow=1,
                        unmatched_preflow_fail=1,
                        runtime_packet=6,
                        unmatched_packet=1,
                        unmatched_packet_fail=1,
                        runtime_terminal=1,
                        unmatched_terminal=1,
                        unmatched_terminal_fail=1,
                        tun_capture=6,
                        unmatched_capture=1,
                        unmatched_capture_fail=1,
                    ),
                    workload_surfaces=[{"key": surface, "count": 1}],
                ),
            ],
            repeat_args(),
        )

        totals = summary["totals"]
        self.assert_workload_base(totals, surface)
        self.assert_workload_runtime(totals)

    def assert_workload_base(self, totals: dict, surface: str) -> None:
        self.assertEqual(totals["workloadAttempted"], 12)
        self.assertEqual(totals["workloadSuccess"], 11)
        self.assertEqual(totals["workloadFailure"], 1)
        self.assertEqual(totals["workloadStrictFailedRuns"], 1)
        self.assertEqual(totals["workloadErrors"], [{"count": 1, "key": "timeout"}])
        self.assertEqual(totals["workloadFlowEntries"], 12)
        self.assertEqual(totals["workloadFlowTcpAttemptedEntries"], 12)
        self.assertEqual(totals["workloadFlowPreTcpEntries"], 0)
        self.assertEqual(totals["workloadFlowTcpAttemptedCoveredEntries"], 12)
        self.assertEqual(totals["workloadFlowMatchedEntries"], 11)
        self.assertEqual(totals["workloadFlowUnmatchedEntries"], 1)
        self.assertEqual(totals["workloadFlowMatchedFlowAttempts"], 12)
        self.assertEqual(totals["workloadFlowMatchedDuplicateFlowEntries"], 1)
        self.assertEqual(totals["workloadFlowMatchedRecoveredFailureEntries"], 1)
        self.assertEqual(totals["workloadFlowMatchedFlowFailedAttempts"], 1)
        self.assertEqual(totals["workloadFlowMatchedFlowStageFailedAttempts"], 1)
        self.assertEqual(totals["workloadFlowCoveredEntries"], 12)
        self.assertEqual(totals["workloadFlowPacketTerminalEntries"], 1)
        self.assertEqual(totals["workloadFlowUnmatchedPacketTerminalEntries"], 1)
        self.assertEqual(totals["workloadFlowUnmatchedNonTerminalEntries"], 0)
        self.assertEqual(totals["workloadFlowMatchedFailures"], 1)
        self.assertEqual(
            totals["workloadFailedBySurface"],
            [{"count": 1, "key": surface}],
        )
        self.assertEqual(
            totals["workloadFlowFailureSurfaces"],
            [{"count": 1, "key": surface}],
        )
        self.assertEqual(totals["workloadFlowUnmatchedFailureSurfaces"], [])
        self.assertEqual(totals["workloadFlowUnmatchedTcpConnectedFailures"], 1)
        self.assertEqual(totals["workloadFlowUnmatchedRouteViaDynetFailures"], 1)
        self.assertEqual(totals["workloadFlowUnmatchedTunWitnessedFailures"], 1)

    def assert_workload_runtime(self, totals: dict) -> None:
        self.assertEqual(totals["workloadFlowRuntimePreflowMatchedEntries"], 6)
        self.assertEqual(totals["workloadFlowUnmatchedRuntimePreflowMatched"], 1)
        self.assertEqual(totals["workloadFlowUnmatchedRuntimePreflowMatchedFailures"], 1)
        self.assertEqual(totals["workloadFlowRuntimePacketMatchedEntries"], 6)
        self.assertEqual(totals["workloadFlowUnmatchedRuntimePacketMatched"], 1)
        self.assertEqual(totals["workloadFlowUnmatchedRuntimePacketMatchedFailures"], 1)
        self.assertEqual(totals["workloadFlowRuntimePacketTerminalEntries"], 1)
        self.assertEqual(
            totals["workloadFlowRuntimePacketTerminalByReason"],
            [{"count": 1, "key": "closed-before-preflow"}],
        )
        self.assertEqual(totals["workloadFlowUnmatchedRuntimePacketTerminalMatched"], 1)
        self.assertEqual(totals["workloadFlowUnmatchedRuntimePacketTerminalFailures"], 1)
        self.assertEqual(
            totals["workloadFlowUnmatchedRuntimePacketTerminalByReason"],
            [{"count": 1, "key": "closed-before-preflow"}],
        )
        self.assertEqual(
            totals["workloadFlowUnmatchedRuntimePacketTerminalFailureByReason"],
            [{"count": 1, "key": "closed-before-preflow"}],
        )
        self.assertEqual(totals["workloadFlowUnmatchedTcpConnectedRuntimePacketMissing"], 0)
        self.assertEqual(totals["workloadFlowTunCaptureMatchedEntries"], 6)
        self.assertEqual(totals["workloadFlowUnmatchedTunCaptureMatched"], 1)
        self.assertEqual(totals["workloadFlowUnmatchedTunCaptureMatchedFailures"], 1)
        self.assertEqual(totals["workloadFlowUnmatchedTcpConnectedTunCaptureMissing"], 0)


def workload_case(**values: int) -> dict[str, int]:
    return values


def repeat_run(
    label: str,
    flows: int,
    complete: int,
    payload: int,
    failed: int = 0,
    failed_path: int | None = None,
    failed_upstream: int | None = None,
    error_type: str | None = None,
    surface: str | None = None,
    stage_failed: int = 0,
    stage_error_type: str | None = None,
    stage: str | None = None,
    stage_surface: str | None = None,
    workload_attempted: int = 0,
    workload_success: int = 0,
    workload_failure: int = 0,
    workload_errors: list[dict[str, object]] | None = None,
    workload_surfaces: list[dict[str, object]] | None = None,
    workload_flow: dict[str, int] | None = None,
    cascade: dict[str, object] | None = None,
) -> dict[str, object]:
    if failed_path is None:
        failed_path = failed
    if failed_upstream is None:
        failed_upstream = failed
    no_payload = max(complete - payload, 0)
    flow = workload_flow or {}
    matched = flow_value(flow, "matched", workload_success + workload_failure)
    unmatched = flow_value(flow, "unmatched")
    covered = flow_value(flow, "covered", matched)
    terminal = flow_value(flow, "packet_terminal")
    runtime_packet = flow_value(flow, "runtime_packet")
    tun_capture = flow_value(flow, "tun_capture")
    return {
        "label": label,
        "passed": True,
        "workloadAttempted": workload_attempted,
        "workloadSuccess": workload_success,
        "workloadFailure": workload_failure,
        "workloadErrors": workload_errors or [],
        "workloadFailedBySurface": workload_surfaces or [],
        "workloadFlow": {
            "entries": matched + unmatched,
            "entriesWithLocalPort": matched + unmatched,
            "tcpAttemptedEntries": matched + unmatched,
            "preTcpEntries": 0,
            "tcpAttemptedEntriesWithLocalPort": matched + unmatched,
            "tcpAttemptedCoveredEntries": covered,
            "tcpAttemptedUnmatchedEntries": unmatched,
            "matchedEntries": matched,
            "unmatchedEntries": unmatched,
            "coveredEntries": covered,
            "packetTerminalEntries": terminal,
            "unmatchedPacketTerminalEntries": terminal,
            "unmatchedNonTerminalEntries": max(unmatched - terminal, 0),
            "matchedFailures": workload_failure,
            "unmatchedFailures": 0,
            "matchedFlowAttempts": flow_value(flow, "matched_attempts", matched),
            "matchedDuplicateFlowEntries": flow_value(flow, "matched_duplicate"),
            "matchedRecoveredFailureEntries": flow_value(flow, "matched_recovered"),
            "matchedFlowFailedAttempts": flow_value(flow, "matched_flow_failed"),
            "matchedFlowStageFailedAttempts": flow_value(flow, "matched_stage_failed"),
            "matchedPathComplete": matched,
            "matchedLifecycleComplete": matched,
            "matchedPayloadStarted": matched,
            "matchedPayloadBidirectional": matched,
            "matchedClosed": matched,
            "matchedFlowFailed": 0,
            "failureSurfaces": workload_surfaces or [],
            "unmatchedFailureSurfaces": [],
            "unmatchedTcpConnectedFailures": flow_value(flow, "unmatched_tcp"),
            "unmatchedRouteViaDynetFailures": flow_value(flow, "unmatched_route"),
            "unmatchedTunWitnessedFailures": flow_value(flow, "unmatched_tun"),
            "runtimePreflowMatchedEntries": flow_value(flow, "runtime_preflow"),
            "unmatchedRuntimePreflowMatched": flow_value(flow, "unmatched_preflow"),
            "unmatchedRuntimePreflowMatchedFailures": flow_value(flow, "unmatched_preflow_fail"),
            "runtimePacketMatchedEntries": runtime_packet,
            "tcpAttemptedRuntimePacketMatchedEntries": runtime_packet,
            "runtimeIngressSynMatchedEntries": runtime_packet,
            "tcpAttemptedRuntimeIngressSynMatchedEntries": runtime_packet,
            "runtimeEgressSynAckMatchedEntries": runtime_packet,
            "runtimePacketTerminalEntries": flow_value(flow, "runtime_terminal"),
            "runtimePacketTerminalByReason": keyed_count(
                "closed-before-preflow",
                flow_value(flow, "runtime_terminal"),
            ),
            "unmatchedRuntimePacketMatched": flow_value(flow, "unmatched_packet"),
            "unmatchedRuntimePacketMatchedFailures": flow_value(flow, "unmatched_packet_fail"),
            "unmatchedRuntimePacketTerminalMatched": flow_value(flow, "unmatched_terminal"),
            "unmatchedRuntimePacketTerminalFailures": flow_value(flow, "unmatched_terminal_fail"),
            "unmatchedRuntimePacketTerminalByReason": keyed_count(
                "closed-before-preflow",
                flow_value(flow, "unmatched_terminal"),
            ),
            "unmatchedRuntimePacketTerminalFailureByReason": keyed_count(
                "closed-before-preflow",
                flow_value(flow, "unmatched_terminal_fail"),
            ),
            "unmatchedTcpConnectedRuntimePacketMissing": 0,
            "tunCaptureMatchedEntries": tun_capture,
            "tcpAttemptedTunCaptureMatchedEntries": tun_capture,
            "unmatchedTunCaptureMatched": flow_value(flow, "unmatched_capture"),
            "unmatchedTunCaptureMatchedFailures": flow_value(flow, "unmatched_capture_fail"),
            "unmatchedTcpConnectedTunCaptureMissing": 0,
        },
        "tcpFlow": {
            "startedFlows": flows,
            "lifecycleCompleteFlows": complete,
            "pathCompleteFlows": complete,
            "closedWithByteTotals": complete,
            "closedWithoutPayloadFlows": no_payload,
            "closedByReason": close_counts(payload, no_payload),
            "closedWithoutPayloadByReason": keyed_count("tun-closed-before-payload", no_payload),
            "payloadStartedFlows": payload,
            "payloadBidirectionalFlows": payload,
            "payloadCloseConsistent": payload,
            "failedFlows": failed,
            "failedAfterPathComplete": failed_path,
            "failedAfterUpstreamOnly": failed_upstream,
            "failedByErrorType": keyed_count(error_type, failed),
            "failedBySurface": keyed_count(surface, failed),
            "stageFailedFlows": stage_failed,
            "stageFailureByErrorType": keyed_count(stage_error_type, stage_failed),
            "stageFailureByStage": keyed_count(stage, stage_failed),
            "stageFailureBySurface": keyed_count(stage_surface, stage_failed),
            "duplicateClosedFlows": 0,
        },
        "cascadeAttempts": cascade or {},
    }


def flow_value(flow: dict[str, int], key: str, default: int = 0) -> int:
    return int(flow.get(key, default))


def keyed_count(key: str | None, count: int) -> list[dict[str, object]]:
    if not key or count == 0:
        return []
    return [{"key": key, "count": count}]


def close_counts(payload: int, no_payload: int) -> list[dict[str, object]]:
    return keyed_count("outbound-eof", payload) + keyed_count("tun-closed-before-payload", no_payload)


def cascade_summary(
    finished: int,
    failed: int,
    disposition: str,
    stop_reason: str,
    retryable: int = 0,
    stopped: int = 0,
    recovered: int = 0,
) -> dict[str, object]:
    stage = "trojan-tls-handshake" if retryable else "private-trojan-connect"
    return {
        "finishedAttempts": finished,
        "failedAttempts": failed,
        "retryableFailures": retryable,
        "stoppedFailures": stopped,
        "recoveredFlows": recovered,
        "failedByDisposition": keyed_count(disposition, failed),
        "failedByStage": keyed_count(stage, failed),
        "failedByStageSurface": keyed_count(f"{stage}:trojan", failed),
        "failedByStageDisposition": keyed_count(disposition, failed),
        "failedByStopReason": keyed_count(stop_reason, failed),
    }


def repeat_args() -> argparse.Namespace:
    return argparse.Namespace(
        **{
            "tcp_forward": True,
            "udp_forward": False,
            "udp_direct_probe": False,
            "ipv6_no_leak": False,
            "quality_state": None,
            "tcp_listen_slots_per_port": 8,
            "workload_min_success_rate": 1,
            "workload_require_all_success": True,
        }
    )


if __name__ == "__main__":
    unittest.main()
