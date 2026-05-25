from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
VM_PATH = ROOT / "scripts" / "vm"
sys.path.insert(0, str(VM_PATH))

from private_runtime_lib.checks import tcp_acceptance_checks
from private_runtime_lib.reporting.workload_surface.close import (
    build_close_surface_summary,
)
from private_runtime_lib.reporting.workload_surface.outbound_timing import (
    build_outbound_timing_summary,
)
from private_runtime_lib.reporting.workload_surface.outbound.gate import (
    build_outbound_gate_summary,
)
from private_runtime_lib.reporting.workload_surface.packet import (
    build_packet_surface_summary,
)
from private_runtime_lib.reporting.workload_surface.udp.session import (
    build_udp_session_summary,
)
from tests.private_runtime_fixtures import duplicate_close_report, tcp_identity_report


class TcpPressureTest(unittest.TestCase):
    def test_pressure_recovered(self) -> None:
        report = tcp_identity_report()
        report["tcpSlotPressureEvents"] = 3

        checks = tcp_acceptance_checks(
            report,
            {"results": []},
            ["chatgpt.com"],
            {event["kind"] for event in report["events"]},
            {"tcpClosedSessions": 1, "protocolShortReadErrors": 0},
            {
                "totals": {"count": 1, "success": 1, "failure": 0, "successRate": 1},
                "results": [
                    {
                        "domain": "chatgpt.com",
                        "probe": "https-head",
                        "ok": True,
                    }
                ],
            },
        )

        by_name = {item["name"]: item["passed"] for item in checks}
        self.assertTrue(by_name["tcp-no-slot-pressure"])

    def test_pressure_terminal(self) -> None:
        report = tcp_identity_report()
        report["tcpSlotPressureEvents"] = 3

        checks = tcp_acceptance_checks(
            report,
            {"results": []},
            ["chatgpt.com"],
            {event["kind"] for event in report["events"]},
            {"tcpClosedSessions": 1, "protocolShortReadErrors": 0},
            {"totals": {"count": 1, "success": 0, "failure": 1, "successRate": 0}},
        )

        by_name = {item["name"]: item["passed"] for item in checks}
        self.assertFalse(by_name["tcp-no-slot-pressure"])


class OutboundTimingSurfaceTest(unittest.TestCase):
    def test_clean(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run_dir = write_run(root / "run", outbound_timing_report())

            summary = build_outbound_timing_summary("outbound", root / "out", [run_dir])

        self.assertEqual(summary["conclusion"]["status"], "clean")
        self.assertEqual(summary["totals"]["flows"], 1)
        self.assertEqual(summary["totals"]["successfulCascadeFlows"], 1)
        self.assertEqual(
            summary["totals"]["timings"]["successfulCascadeElapsedMs"]["p95"],
            125,
        )
        self.assertNotIn("_attempts", summary["runs"][0])

    def test_recovered_clean(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report = outbound_timing_report(recovered_failure=True)
            run_dir = write_run(root / "run", report)

            summary = build_outbound_timing_summary("outbound", root / "out", [run_dir])

        self.assertEqual(summary["conclusion"]["status"], "clean")
        self.assertEqual(summary["totals"]["failedAttemptEvents"], 1)
        self.assertEqual(summary["totals"]["failedCascadeEvents"], 1)
        self.assertEqual(summary["totals"]["recoveredFailureFlows"], 1)
        self.assertEqual(summary["totals"]["unrecoveredFailureFlows"], 0)

    def test_missing_cascade_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report = outbound_timing_report(missing_cascade=True)
            run_dir = write_run(root / "run", report)

            summary = build_outbound_timing_summary("outbound", root / "out", [run_dir])

        self.assertEqual(
            summary["conclusion"]["status"],
            "outbound-timing-surface-needs-evidence",
        )
        self.assertEqual(summary["runs"][0]["classification"], "cascade-success-missing")
        self.assertEqual(summary["totals"]["successfulCascadeFlows"], 0)


class CloseSurfaceTest(unittest.TestCase):
    def test_clean(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run_dir = write_run(root / "run", tcp_identity_report())

            summary = build_close_surface_summary("close", root / "out", [run_dir])

        self.assertEqual(summary["conclusion"]["status"], "clean")
        self.assertEqual(summary["totals"]["flows"], 1)
        self.assertEqual(summary["totals"]["terminalEvents"], 1)
        self.assertEqual(summary["totals"]["closedReasonFlows"], 1)
        self.assertEqual(summary["totals"]["closedByReason"], [
            {"count": 1, "key": "outbound-eof"},
        ])

    def test_duplicate_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run_dir = write_run(root / "run", duplicate_close_report())

            summary = build_close_surface_summary("close", root / "out", [run_dir])

        self.assertEqual(summary["conclusion"]["status"], "close-surface-needs-evidence")
        self.assertEqual(summary["runs"][0]["classification"], "duplicate-close")
        self.assertEqual(summary["totals"]["duplicateClosedFlows"], 1)


class PacketSurfaceTest(unittest.TestCase):
    def test_clean(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run_dir = write_run(root / "run", packet_report())

            summary = build_packet_surface_summary("packet", root / "out", [run_dir])

        self.assertEqual(summary["conclusion"]["status"], "clean")
        self.assertEqual(summary["totals"]["flows"], 1)
        self.assertEqual(summary["totals"]["packetHandshakePorts"], 1)
        self.assertEqual(summary["totals"]["preflowPorts"], 1)
        self.assertEqual(summary["totals"]["packetTerminalPorts"], 0)
        self.assertEqual(summary["totals"]["ingressPayloadBytes"], 256)

    def test_terminal_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run_dir = write_run(root / "run", packet_report(terminal=True))

            summary = build_packet_surface_summary("packet", root / "out", [run_dir])

        self.assertEqual(summary["conclusion"]["status"], "packet-surface-needs-evidence")
        self.assertEqual(summary["runs"][0]["classification"], "packet-terminal")
        self.assertEqual(summary["totals"]["packetTerminalByReason"], [
            {"count": 1, "key": "closed-before-preflow"},
        ])

    def test_missing_preflow_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run_dir = write_run(root / "run", packet_report(missing_preflow=True))

            summary = build_packet_surface_summary("packet", root / "out", [run_dir])

        self.assertEqual(summary["runs"][0]["classification"], "preflow-missing")
        self.assertEqual(summary["totals"]["preflowPorts"], 0)


class OutboundGateSurfaceTest(unittest.TestCase):
    def test_clean(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run_dir = write_run(root / "run", outbound_gate_report())

            summary = build_outbound_gate_summary("gate", root / "out", [run_dir])

        self.assertEqual(summary["conclusion"]["status"], "clean")
        self.assertEqual(summary["totals"]["flows"], 1)
        self.assertEqual(summary["totals"]["routeAdmissionFlows"], 1)
        self.assertEqual(summary["totals"]["routeEgressFlows"], 1)
        self.assertEqual(summary["totals"]["boundAdmissionFlows"], 1)
        self.assertEqual(summary["totals"]["boundEgressFlows"], 1)
        self.assertEqual(summary["totals"]["routeEgressMismatches"], 0)

    def test_bound_egress_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report = outbound_gate_report(include_bound_egress=False)
            run_dir = write_run(root / "run", report)

            summary = build_outbound_gate_summary("gate", root / "out", [run_dir])

        self.assertEqual(summary["runs"][0]["classification"], "bound-egress-missing")
        self.assertEqual(summary["conclusion"]["status"], "outbound-gate-surface-needs-evidence")

    def test_route_mismatch_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report = outbound_gate_report(route_mismatch=True)
            run_dir = write_run(root / "run", report)

            summary = build_outbound_gate_summary("gate", root / "out", [run_dir])

        self.assertEqual(summary["runs"][0]["classification"], "route-egress-mismatch")
        self.assertEqual(summary["totals"]["routeEgressMismatches"], 1)


class UdpSessionSurfaceTest(unittest.TestCase):
    def test_clean(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run_dir = write_run(root / "run", udp_session_report())

            summary = build_udp_session_summary("udp", root / "out", [run_dir])

        self.assertEqual(summary["conclusion"]["status"], "clean")
        self.assertEqual(summary["totals"]["sessions"], 1)
        self.assertEqual(summary["totals"]["establishedSessions"], 1)
        self.assertEqual(summary["totals"]["sentBytes"], 48)
        self.assertEqual(summary["totals"]["receivedBytes"], 48)

    def test_receive_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report = udp_session_report(received=False)
            run_dir = write_run(root / "run", report)

            summary = build_udp_session_summary("udp", root / "out", [run_dir])

        self.assertEqual(summary["runs"][0]["classification"], "udp-payload-received-missing")
        self.assertEqual(summary["conclusion"]["status"], "udp-session-surface-needs-evidence")

    def test_failure_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report = udp_session_report(failed=True)
            run_dir = write_run(root / "run", report)

            summary = build_udp_session_summary("udp", root / "out", [run_dir])

        self.assertEqual(summary["runs"][0]["classification"], "udp-session-failure")
        self.assertEqual(summary["totals"]["failedByErrorType"], [
            {"count": 1, "key": "udp-write"},
        ])


def outbound_timing_report(
    recovered_failure: bool = False,
    missing_cascade: bool = False,
) -> dict:
    report = tcp_identity_report()
    events = []
    for event in report["events"]:
        if event["kind"] == "outbound-stage-finished":
            event["fields"]["elapsedMs"] = "80"
        if event["kind"] == "outbound-attempt-finished":
            event["fields"].update(success_attempt_fields())
            events.extend(recovered_events(recovered_failure))
        events.append(event)
        if event["kind"] == "outbound-attempt-finished" and not missing_cascade:
            events.append(cascade_event("125", "none", "success"))
    report["events"] = events
    return report


def outbound_gate_report(
    include_bound_egress: bool = True,
    route_mismatch: bool = False,
) -> dict:
    report = tcp_identity_report()
    selected_route = "direct" if route_mismatch else "private-via-tunnel"
    events = [
        gate_event("outbound-admission-passed", "tcp-route", outbound="private-via-tunnel"),
        gate_event(
            "outbound-egress-passed",
            "tcp-route",
            requested="private-via-tunnel",
            selected=selected_route,
        ),
        gate_event("outbound-admission-passed", "dialer-bound", outbound="tunnel"),
    ]
    if include_bound_egress:
        events.append(
            gate_event(
                "outbound-egress-passed",
                "dialer-bound",
                requested="tunnel",
                selected="tunnel-001",
            )
        )
    report["events"] = events + report["events"]
    return report


def gate_event(kind: str, scope: str, **fields: str) -> dict[str, object]:
    return {
        "kind": kind,
        "fields": {
            "flowId": "tcp-session-1",
            "scope": scope,
            "transport": "tcp",
            "sessionTransport": "tcp",
            **fields,
        },
    }


def udp_session_report(received: bool = True, failed: bool = False) -> dict:
    events = [
        udp_event("udp-session-started"),
        udp_event("udp-session-attributed", outbound="direct-udp-probe"),
        udp_event(
            "udp-session-outbound-connecting",
            outbound="direct-udp-probe",
            udpEgressSupport="direct",
        ),
        udp_event("udp-session-established", outbound="direct-udp-probe"),
        udp_event("udp-session-payload-sent", bytes="48", outbound="direct-udp-probe"),
    ]
    if received:
        events.append(
            udp_event("udp-session-payload-received", bytes="48", outbound="direct-udp-probe")
        )
    if failed:
        events.append(udp_event("udp-session-failed", errorType="udp-write"))
    return {
        "udpSessions": 1,
        "udpUpstreamBytes": 48,
        "udpDownstreamBytes": 48 if received else 0,
        "udpSessionFailures": 1 if failed else 0,
        "udpDroppedPackets": 0,
        "events": events,
    }


def udp_event(kind: str, **fields: str) -> dict[str, object]:
    return {
        "kind": kind,
        "fields": {
            "flowId": "udp-session-1",
            "session": "1",
            "transport": "udp",
            **fields,
        },
    }


def packet_report(
    terminal: bool = False,
    missing_preflow: bool = False,
) -> dict:
    report = tcp_identity_report()
    events = [
        {"kind": "tcp-forwarder-capacity", "fields": {"capacity": "16"}},
        packet_event("ingress", syn=True),
        packet_event("egress", syn=True, ack=True),
        packet_event("ingress", payload_bytes=256),
        packet_event("egress", payload_bytes=512),
    ]
    if not missing_preflow:
        events.insert(2, {
            "kind": "tcp-forwarder-preflow",
            "fields": {
                "clientPort": "45678",
                "port": "443",
                "state": "SynReceived",
                "transport": "tcp",
            },
        })
    if terminal:
        events.append({
            "kind": "tcp-forwarder-packet-terminal",
            "fields": {
                "clientPort": "45678",
                "reason": "closed-before-preflow",
                "packetHandshakeComplete": "true",
                "promotedToRuntimeSession": "false",
            },
        })
    report["events"] = events + report["events"]
    return report


def packet_event(
    direction: str,
    syn: bool = False,
    ack: bool = False,
    payload_bytes: int = 0,
) -> dict[str, object]:
    return {
        "kind": "tcp-forwarder-packet",
        "fields": {
            "clientPort": "45678",
            "direction": direction,
            "payloadBytes": str(payload_bytes),
            "port": "443",
            "syn": str(syn).lower(),
            "ack": str(ack).lower(),
            "fin": "false",
            "rst": "false",
            "transport": "tcp",
        },
    }


def recovered_events(enabled: bool) -> list[dict[str, object]]:
    if not enabled:
        return []
    return [
        timing_event("outbound-attempt-finished", {
            "elapsedMs": "8000",
            "kind": "vmess",
            "protocol": "tcp-connect",
            "status": "failed",
        }),
        cascade_event("8001", "bound", "failed"),
    ]


def success_attempt_fields() -> dict[str, str]:
    return {
        "elapsedMs": "120",
        "kind": "vmess",
        "protocol": "tcp-connect",
        "status": "success",
    }


def cascade_event(elapsed_ms: str, failure_scope: str, status: str) -> dict[str, object]:
    return timing_event("dialer-cascade-attempt-finished", {
        "elapsedMs": elapsed_ms,
        "failureScope": failure_scope,
        "status": status,
    })


def timing_event(kind: str, fields: dict[str, str]) -> dict[str, object]:
    return {"kind": kind, "fields": {"flowId": "tcp-session-1", **fields}}


def write_run(path: Path, report: dict) -> Path:
    path.mkdir()
    write_json(path / "runtime-report.json", report)
    write_json(path / "summary.json", {"label": path.name})
    return path


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, sort_keys=True))


if __name__ == "__main__":
    unittest.main()
