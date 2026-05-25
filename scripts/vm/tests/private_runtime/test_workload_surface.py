from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
VM_PATH = ROOT / "scripts" / "vm"
sys.path.insert(0, str(VM_PATH))

from tests.private_runtime_fixtures import gap_runtime
from tests.private_runtime_fixtures import duplicate_close_report, tcp_identity_report
from private_runtime_lib.reporting import workload_surface
from private_runtime_lib.reporting.workload_surface.payload import build_payload_surface_summary
from private_runtime_lib.reporting.workload_surface.stage import build_stage_surface_summary


class PrivateRuntimeWorkloadSurfaceTest(unittest.TestCase):
    def test_clean_payload_surface(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run_dir = write_payload_run(root / "run", tcp_identity_report())

            summary = build_payload_surface_summary("payload", root / "out", [run_dir])

        self.assertEqual(summary["conclusion"]["status"], "clean")
        self.assertEqual(summary["totals"]["runs"], 1)
        self.assertEqual(summary["totals"]["cleanRuns"], 1)
        self.assertEqual(summary["totals"]["flows"], 1)
        self.assertEqual(summary["totals"]["closedWithByteTotals"], 1)
        self.assertEqual(summary["totals"]["payloadBidirectionalFlows"], 1)
        self.assertEqual(summary["totals"]["payloadCloseConsistent"], 1)
        self.assertEqual(summary["totals"]["closedWithoutPayloadFlows"], 0)
        self.assertEqual(summary["totals"]["duplicateClosedFlows"], 0)

    def test_duplicate_close_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run_dir = write_payload_run(root / "run", duplicate_close_report())

            summary = build_payload_surface_summary("payload", root / "out", [run_dir])

        row = summary["runs"][0]
        self.assertEqual(summary["conclusion"]["status"], "payload-surface-needs-evidence")
        self.assertEqual(row["classification"], "duplicate-close")
        self.assertFalse(row["clean"])
        self.assertEqual(summary["totals"]["duplicateClosedFlows"], 1)

    def test_recovered_stage_surface(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run_dir = write_payload_run(root / "run", recovered_stage_report())

            summary = build_stage_surface_summary("stage", root / "out", [run_dir])

        self.assertEqual(summary["conclusion"]["status"], "clean")
        self.assertEqual(summary["totals"]["failedStageEvents"], 1)
        self.assertEqual(summary["totals"]["recoveredStageFailedFlows"], 1)
        self.assertEqual(summary["totals"]["unrecoveredStageFailedFlows"], 0)

    def test_unrecovered_stage_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run_dir = write_payload_run(root / "run", unrecovered_stage_report())

            summary = build_stage_surface_summary("stage", root / "out", [run_dir])

        row = summary["runs"][0]
        self.assertEqual(summary["conclusion"]["status"], "stage-surface-needs-evidence")
        self.assertEqual(row["classification"], "flow-failure")
        self.assertEqual(summary["totals"]["unrecoveredStageFailedFlows"], 1)

    def test_splits_surfaces(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run_a = write_run(root / "run-a", dns_pre_tcp_run(), dns_runtime_report())
            run_b = write_run(
                root / "run-b",
                gap_runtime("packet-terminal", 2935, workload_success=7, terminal=1),
            )

            summary = workload_surface.build_workload_surface_summary(
                "workload-surface",
                root / "out",
                [run_a, run_b],
            )

        self.assert_split_base(summary)
        self.assert_split_breakdowns(summary["totals"])
        self.assert_split_failed_rows(summary["failedRows"])

    def assert_split_base(self, summary: dict) -> None:
        self.assertEqual(summary["schema"], workload_surface.WORKLOAD_SURFACE_SCHEMA)
        self.assertEqual(summary["conclusion"]["status"], "split-pre-tcp-and-packet-terminal")
        self.assertEqual(
            summary["conclusion"]["nextAction"],
            "isolate-dns-preflow-and-packet-terminal-separately",
        )
        self.assertFalse(summary["policy"]["plannerPenaltySafe"])
        self.assertFalse(summary["policy"]["qualityPenaltySafe"])
        self.assertFalse(summary["policy"]["productEffectClaimSafe"])
        totals = summary["totals"]
        self.assertEqual(totals["runs"], 2)
        self.assertEqual(totals["workloadFailure"], 2)
        self.assertEqual(totals["failedRows"], 2)
        self.assertEqual(totals["preTcpFailures"], 1)
        self.assertEqual(totals["packetTerminalFailures"], 1)
        self.assertEqual(totals["runtimeDnsFailures"], 1)
        self.assertEqual(totals["preTcpFailuresWithRuntimeDnsFailure"], 1)
        self.assertEqual(totals["failedRowsWithRuntimeDnsFailure"], 1)
        self.assertEqual(totals["tcpConnectedFailures"], 1)
        self.assertEqual(totals["routeViaDynetFailures"], 1)
        self.assertEqual(totals["tunWitnessedFailures"], 2)
        self.assertEqual(totals["packetTerminalWithIngressPayload"], 1)
        self.assertEqual(totals["packetTerminalIngressPayloadBytes"], 517)
        self.assertEqual(totals["packetTerminalByCloseSignal"], [{"count": 1, "key": "fin"}])

    def assert_split_breakdowns(self, totals: dict) -> None:
        self.assertEqual(
            totals["failedByRuntimeDnsDisposition"],
            [{"count": 1, "key": "pending-timeout"}, {"count": 1, "key": "unknown"}],
        )
        self.assertEqual(
            totals["failedByRuntimeDnsResponseCode"],
            [{"count": 1, "key": "SERVFAIL"}, {"count": 1, "key": "unknown"}],
        )
        self.assertEqual(
            totals["failedByMechanism"],
            [
                {"count": 1, "key": "packet-terminal-before-runtime-session"},
                {"count": 1, "key": "pre-tcp-workload-failure"},
            ],
        )
        self.assertEqual(
            totals["failedByMechanismSurface"],
            [
                {
                    "count": 1,
                    "failureSurface": "https-head:tls-handshake:tls:route-dynet:tun-witnessed",
                    "mechanism": "packet-terminal-before-runtime-session",
                },
                {
                    "count": 1,
                    "failureSurface": "https-head:dns:timeout:route-unknown:tun-witnessed",
                    "mechanism": "pre-tcp-workload-failure",
                },
            ],
        )
        self.assertEqual(
            totals["failedByMechanismStage"],
            [
                {
                    "count": 1,
                    "errorStage": "tls-handshake",
                    "errorType": "tls",
                    "mechanism": "packet-terminal-before-runtime-session",
                },
                {
                    "count": 1,
                    "errorStage": "dns",
                    "errorType": "timeout",
                    "mechanism": "pre-tcp-workload-failure",
                },
            ],
        )
        self.assertEqual(
            totals["failedByStage"],
            [{"count": 1, "key": "dns"}, {"count": 1, "key": "tls-handshake"}],
        )
        self.assertEqual(
            totals["runtimePacketTerminalByReason"],
            [{"count": 1, "key": "closed-before-preflow"}, {"count": 1, "key": "unknown"}],
        )

    def assert_split_failed_rows(self, failed_rows: list[dict]) -> None:
        self.assertEqual(
            [row["mechanism"] for row in failed_rows],
            ["pre-tcp-workload-failure", "packet-terminal-before-runtime-session"],
        )
        self.assertTrue(failed_rows[0]["runtimeDnsFailureMatched"])
        self.assertEqual(failed_rows[0]["runtimeDnsFailureOutbound"], "direct")
        self.assertEqual(failed_rows[0]["runtimeDnsFailureUpstream"], "8.8.8.8:53")
        self.assertEqual(failed_rows[0]["runtimeDnsFailureResponseCode"], "SERVFAIL")
        self.assertFalse(failed_rows[1]["runtimeDnsFailureMatched"])
        self.assertEqual(failed_rows[1]["runtimePacketTerminalCloseSignal"], "fin")
        self.assertEqual(failed_rows[1]["runtimePacketTerminalIngressPayloadBytes"], 517)

    def test_expands_repeat_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run_a = write_run(root / "run-a", dns_pre_tcp_run())
            run_b = write_run(
                root / "run-b",
                gap_runtime("packet-terminal", 2935, workload_success=7, terminal=1),
            )
            repeat = root / "repeat"
            repeat.mkdir()
            write_json(
                repeat / "summary.json",
                {
                    "schema": workload_surface.REPEAT_SCHEMA,
                    "runs": [{"path": str(run_a)}, {"path": str(run_b)}],
                },
            )

            summary = workload_surface.build_workload_surface_summary(
                "workload-surface",
                root / "out",
                [repeat],
            )

        self.assertEqual(summary["totals"]["runs"], 2)
        self.assertEqual(summary["totals"]["failedRows"], 2)
        self.assertEqual(
            summary["conclusion"]["status"],
            "split-pre-tcp-and-packet-terminal",
        )

    def test_mixed_runtime_surfaces(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = write_run(root / "run", mixed_runtime_run())

            summary = workload_surface.build_workload_surface_summary(
                "workload-surface",
                root / "out",
                [run],
            )

        conclusion = summary["conclusion"]
        self.assertEqual(conclusion["status"], "mixed-runtime-workload-surface")
        self.assertEqual(
            conclusion["nextAction"],
            "split-runtime-stage-terminal-and-protocol-surfaces",
        )
        self.assertEqual(summary["totals"]["preTcpFailures"], 0)
        self.assertEqual(summary["totals"]["runtimePacketMatchedFailures"], 3)
        self.assertEqual(summary["totals"]["packetTerminalWithIngressPayload"], 1)
        self.assertEqual(summary["totals"]["packetTerminalIngressPayloadBytes"], 517)
        self.assertEqual(summary["totals"]["failedRowsWithCascadeStoppedFlow"], 1)
        self.assertEqual(summary["totals"]["cascadeStoppedFlowCandidateExhaustedFailures"], 1)
        self.assertEqual(
            summary["totals"]["failedByCascadeStoppedFlowStageSurface"],
            [{"count": 1, "key": "trojan-tls-handshake:trojan"}],
        )
        self.assertEqual(
            [(item["mechanism"], item["category"]) for item in conclusion["mechanisms"]],
            [
                ("failed-workload-with-runtime-stage-failure", "runtime-stage"),
                ("packet-terminal-before-runtime-session", "packet-terminal"),
                ("workload-protocol-after-runtime-session", "post-session-protocol"),
            ],
        )
        self.assertEqual(
            [item["nextAction"] for item in conclusion["mechanisms"]],
            [
                "inspect-runtime-stage-failure-and-cascade-context",
                "inspect-preflow-promotion-after-client-payload",
                "classify-post-session-workload-protocol",
            ],
        )
        packet = conclusion["mechanisms"][1]
        self.assertEqual(packet["context"]["withIngressPayload"], 1)
        self.assertEqual(packet["context"]["ingressPayloadBytes"], 517)
        self.assertEqual(packet["context"]["closeSignals"], [{"count": 1, "key": "fin"}])
        stage = conclusion["mechanisms"][0]
        self.assertEqual(stage["context"]["cascadeStoppedBoundExhaustedFlows"], 1)
        self.assertEqual(stage["context"]["failedRowsWithCascadeStoppedFlow"], 1)


def dns_pre_tcp_run() -> dict:
    run = gap_runtime("dns-pre-tcp", 2935, workload_success=7)
    failed = next(item for item in run["workloadProbe"]["results"] if not item["ok"])
    failed.update(
        {
            "errorStage": "dns",
            "errorType": "timeout",
            "errorClass": "TimeoutError",
            "domain": "www.cloudflare.com",
            "localPort": None,
        }
    )
    run["stability"]["workloadErrors"] = [{"key": "timeout", "count": 1}]
    run["workloadFlow"].update(
        {
            "matchedEntries": 7,
            "unmatchedEntries": 1,
            "coveredEntries": 7,
            "runtimePacketTerminalByReason": [],
            "unmatchedRuntimePacketTerminalByReason": [],
        }
    )
    failed_flow = next(
        item for item in run["workloadFlow"]["rows"] if item["workloadId"] == failed["id"]
    )
    failed_flow.update(
        {
            "domain": "www.cloudflare.com",
            "localPort": None,
            "workloadTcpConnectOk": False,
            "workloadRouteViaDynet": False,
            "workloadTunWitnessed": True,
            "runtimePreflowMatched": False,
            "runtimePacketMatched": False,
            "runtimeIngressSynPackets": 0,
            "runtimeEgressSynAckPackets": 0,
            "runtimeFinPackets": 0,
            "runtimeRstPackets": 0,
            "runtimePacketTerminalMatched": False,
            "runtimePacketTerminalReason": None,
            "runtimePacketTerminalHandshakeComplete": False,
            "runtimePacketTerminalPromotedToSession": False,
            "tunCaptureMatched": False,
            "tunCaptureSynPackets": 0,
            "tunCaptureSynAckPackets": 0,
            "flowMatched": False,
            "flowMatchedCount": 0,
            "flowFailedCount": 0,
            "flowStageFailedCount": 0,
            "flowRecoveredFailure": False,
            "failureSurface": "https-head:dns:timeout:route-unknown:tun-witnessed",
        }
    )
    return run


def mixed_runtime_run() -> dict:
    run = gap_runtime("mixed-runtime", 2935, workload_success=5, terminal=1)
    failed_results = [item for item in run["workloadProbe"]["results"] if not item["ok"]]
    failed_results[1]["errorType"] = "reset"
    failed_results[1]["errorClass"] = "ConnectionResetError"
    flow_rows = {
        str(row["workloadId"]): row
        for row in run["workloadFlow"]["rows"]
    }
    stage_row = flow_rows[str(failed_results[1]["id"])]
    stage_row["flowStageFailedCount"] = 1
    stage_row["flowId"] = "tcp-session-8"
    stage_row["flowIds"] = ["tcp-session-8"]
    stage_row["failureSurface"] = "https-head:tls-handshake:reset:route-dynet:tun-witnessed"
    run["selection"]["cascadeAttempts"].update({
        "failedAttempts": 4,
        "retryableFailures": 3,
        "stoppedFailures": 1,
        "stoppedFlows": 1,
        "stoppedBoundExhaustedFlows": 1,
        "recoveredFlows": 0,
        "failedByStageSurface": [{"key": "trojan-tls-handshake:trojan", "count": 4}],
        "failedByStopReason": [
            {"key": "bound-candidates-exhausted", "count": 1},
            {"key": "retry-bound-failure-before-replay", "count": 3},
        ],
        "stoppedFlowByStageSurface": [{"key": "trojan-tls-handshake:trojan", "count": 1}],
        "stoppedFlowByStopReason": [{"key": "bound-candidates-exhausted", "count": 1}],
        "stoppedFlowByAttemptCount": [{"key": "4", "count": 1}],
        "stoppedRows": [
            {
                "flowId": "tcp-session-8",
                "stopReason": "bound-candidates-exhausted",
                "candidateExhausted": True,
                "attemptCount": 4,
                "failedAttemptCount": 4,
                "retryableFailureCount": 3,
                "candidateCount": 4,
                "failureScope": "bound",
                "errorDisposition": "pending-timeout",
                "failureStageSurface": "trojan-tls-handshake:trojan",
                "boundSelectedSequence": [
                    "tunnel-004",
                    "tunnel-001",
                    "tunnel-002",
                    "tunnel-003",
                ],
                "failedSelectedSequence": [
                    "tunnel-004",
                    "tunnel-001",
                    "tunnel-002",
                    "tunnel-003",
                ],
                "retryableSelectedSequence": ["tunnel-004", "tunnel-001", "tunnel-002"],
                "lastBoundSelected": "tunnel-003",
            }
        ],
    })
    return run


def dns_runtime_report() -> dict:
    return {
        "events": [
            {
                "kind": "outbound-attempt-started",
                "fields": {
                    "flowId": "dns-query-1",
                    "transport": "dns",
                    "outbound": "direct",
                    "upstream": "8.8.8.8:53",
                },
            },
            {
                "kind": "outbound-attempt-finished",
                "fields": {
                    "flowId": "dns-query-1",
                    "transport": "dns",
                    "status": "failed",
                    "outbound": "direct",
                    "elapsedMs": "5374",
                    "errorType": "dns",
                    "error": "failed to receive upstream DNS response: Resource temporarily unavailable",
                },
            },
            {
                "kind": "dns-resolve-failed",
                "fields": {
                    "flowId": "dns-query-1",
                    "dnsQueryId": "1",
                    "listener": "udp",
                    "query": "www.cloudflare.com",
                    "elapsedMs": "5375",
                    "errorType": "dns",
                    "errorDisposition": "pending-timeout",
                    "failureResponseCode": "SERVFAIL",
                    "failureResponseBytes": "33",
                },
            },
        ]
    }


def recovered_stage_report() -> dict:
    report = tcp_identity_report()
    report["events"].insert(-1, failed_stage_event())
    return report


def unrecovered_stage_report() -> dict:
    return {
        "events": [
            {"kind": "tcp-session-started", "fields": {"flowId": "tcp-session-1"}},
            failed_stage_event(),
            {
                "kind": "tcp-session-failed",
                "fields": {
                    "flowId": "tcp-session-1",
                    "upstreamBytes": "517",
                    "downstreamBytes": "0",
                    "errorType": "trojan",
                    "failurePhase": "stage",
                },
            },
        ],
    }


def failed_stage_event() -> dict:
    return {
        "kind": "outbound-stage-finished",
        "fields": {
            "flowId": "tcp-session-1",
            "stage": "trojan-tls-handshake",
            "kind": "trojan",
            "status": "failed",
            "errorDisposition": "reset",
        },
    }


def write_run(path: Path, summary: dict, runtime_report: dict | None = None) -> Path:
    path.mkdir()
    if runtime_report is not None:
        summary = {**summary, "runtimeReport": runtime_report}
    write_json(path / "summary.json", summary)
    return path


def write_payload_run(path: Path, report: dict) -> Path:
    path.mkdir()
    write_json(path / "runtime-report.json", report)
    write_json(path / "summary.json", {"label": path.name})
    return path


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n")


if __name__ == "__main__":
    unittest.main()
