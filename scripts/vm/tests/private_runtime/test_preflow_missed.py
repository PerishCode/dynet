from __future__ import annotations

import sys
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
VM_PATH = ROOT / "scripts" / "vm"
sys.path.insert(0, str(VM_PATH))

from tests.private_runtime_fixtures import tcp_identity_report
from private_runtime_lib.tcp_flow.workload import workload_flow_brief
from private_runtime_lib.reporting.workload_surface.lifecycle.collection import (
    build_collection_stage_summary,
)
from private_runtime_lib.reporting.workload_surface.event.stream import (
    build_event_stream_summary,
)
from private_runtime_lib.reporting.workload_surface.event.correlation import (
    build_event_correlation_summary,
)
from private_runtime_lib.reporting.workload_surface.event.causality import (
    build_event_causality_summary,
)
from private_runtime_lib.reporting.workload_surface.outbound.retry import (
    build_outbound_retry_summary,
)


class PrivateRuntimePreflowMissedTest(unittest.TestCase):
    def test_preflow_missed_surface(self) -> None:
        brief = workload_flow_brief(preflow_missed_report(), workload_report())
        row = brief["rows"][0]

        self.assertEqual(brief["runtimePreflowCandidateEntries"], 1)
        self.assertEqual(brief["unmatchedRuntimePreflowCandidateFailures"], 1)
        self.assertEqual(
            brief["runtimePreflowCandidateByReason"],
            [{"count": 1, "key": "ingress-payload-before-preflow-service"}],
        )
        self.assertEqual(brief["runtimePreflowMissedEntries"], 1)
        self.assertEqual(brief["unmatchedRuntimePreflowMissedFailures"], 1)
        self.assertEqual(
            brief["runtimePreflowMissedByReason"],
            [{"count": 1, "key": "socket-closed-before-preflow-service"}],
        )
        self.assertTrue(row["runtimePreflowCandidateMatched"])
        self.assertEqual(row["runtimePreflowCandidateIngressPayloadBytes"], 517)
        self.assertTrue(row["runtimePreflowMissedMatched"])
        self.assertEqual(row["runtimePreflowMissedSocketState"], "Closed")
        self.assertEqual(row["runtimePreflowMissedIngressPayloadBytes"], 517)


class CollectionStageSurfaceTest(unittest.TestCase):
    def test_clean(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = root / "run-01"
            write_collection_run(run)
            summary = build_collection_stage_summary("collection", root / "out", [run])
        self.assertEqual(summary["conclusion"]["status"], "clean")
        self.assertEqual(summary["totals"]["orderViolations"], 0)

    def test_stage_order_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = root / "run-01"
            write_collection_run(run, cleanup_first=True)
            summary = build_collection_stage_summary("collection", root / "out", [run])
        self.assertEqual(summary["runs"][0]["classification"], "collection-stage-order-invalid")


class EventStreamSurfaceTest(unittest.TestCase):
    def test_clean(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = root / "run-01"
            write_event_run(run)
            summary = build_event_stream_summary("event", root / "out", [run])
        self.assertEqual(summary["conclusion"]["status"], "clean")
        self.assertEqual(summary["totals"]["counterMismatches"], 0)

    def test_sequence_gap_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = root / "run-01"
            write_event_run(run, second_sequence=3)
            summary = build_event_stream_summary("event", root / "out", [run])
        self.assertEqual(summary["runs"][0]["classification"], "event-sequence-gap")


class EventCorrelationSurfaceTest(unittest.TestCase):
    def test_clean(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = root / "run-01"
            write_event_correlation_run(run)
            summary = build_event_correlation_summary("correlation", root / "out", [run])
        self.assertEqual(summary["conclusion"]["status"], "clean")
        self.assertEqual(summary["totals"]["orphanFlowRefs"], 0)

    def test_orphan_flow_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = root / "run-01"
            write_event_correlation_run(run, orphan=True)
            summary = build_event_correlation_summary("correlation", root / "out", [run])
        self.assertEqual(summary["runs"][0]["classification"], "orphan-flow-ref")


class EventCausalitySurfaceTest(unittest.TestCase):
    def test_clean(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = root / "run-01"
            write_event_causality_run(run)
            summary = build_event_causality_summary("causality", root / "out", [run])
        self.assertEqual(summary["conclusion"]["status"], "clean")
        self.assertEqual(summary["totals"]["tcpOrderViolations"], 0)

    def test_tcp_order_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = root / "run-01"
            write_event_causality_run(run, tcp_order_violation=True)
            summary = build_event_causality_summary("causality", root / "out", [run])
        self.assertEqual(summary["runs"][0]["classification"], "tcp-order-invalid")


class OutboundRetrySurfaceTest(unittest.TestCase):
    def test_retry_clean(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = root / "run-01"
            write_outbound_retry_run(run)
            summary = build_outbound_retry_summary("retry", root / "out", [run])
        self.assertEqual(summary["conclusion"]["status"], "clean")
        self.assertEqual(summary["totals"]["retryableMissingNextAttempt"], 0)
        self.assertEqual(summary["totals"]["tcpUnrecoveredFailureFlows"], 0)

    def test_stop_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = root / "run-01"
            write_outbound_retry_run(run, non_retryable_continued=True)
            summary = build_outbound_retry_summary("retry", root / "out", [run])
        self.assertEqual(summary["runs"][0]["classification"], "non-retryable-continued")


def preflow_missed_report() -> dict:
    report = tcp_identity_report()
    report["events"].extend([preflow_candidate_event(), terminal_event(), preflow_missed_event()])
    return report


def terminal_event() -> dict:
    return {
        "kind": "tcp-forwarder-packet-terminal",
        "fields": {
            "clientPort": "45679",
            "reason": "closed-before-preflow",
            "ingressPayloadBytes": "517",
            "finPackets": "1",
        },
    }


def preflow_candidate_event() -> dict:
    fields = dict(terminal_event()["fields"])
    fields["reason"] = "ingress-payload-before-preflow-service"
    return {"kind": "tcp-forwarder-preflow-candidate", "fields": fields}


def preflow_missed_event() -> dict:
    fields = dict(terminal_event()["fields"])
    fields.update(
        {
            "reason": "socket-closed-before-preflow-service",
            "socketState": "Closed",
            "terminalReason": "closed-before-preflow",
        }
    )
    return {"kind": "tcp-forwarder-preflow-missed", "fields": fields}


def workload_report() -> dict:
    return {
        "tunCapture": {"ports": [{"localPort": 45679}]},
        "results": [
            {
                "id": "github-head-1",
                "probe": "https-head",
                "domain": "api.github.com",
                "ok": False,
                "localPort": 45679,
                "errorStage": "tls-handshake",
                "errorType": "timeout",
                "routeViaDynet": True,
                "tunWitness": {"observed": True},
                "stages": [{"name": "tcp-connect", "ok": True}],
            }
        ],
    }


def write_collection_run(path: Path, cleanup_first: bool = False) -> None:
    path.mkdir()
    stages = collection_stages()
    if cleanup_first:
        stages = [stages[-1], *stages[:-1]]
    write_json(path / "summary.json", collection_summary(stages))
    write_json(path / "stage-report.json", {"stages": stages})
    for name in [
        "runtime-report.json", "install-report.json", "uninstall-report.json",
        "tcp-probe.json", "workload-probe.json",
    ]:
        write_json(path / name, {"schema": name})
    (path / "runtime-log.txt").write_text("diagnostic")


def write_event_run(path: Path, second_sequence: int = 2) -> None:
    path.mkdir()
    write_json(path / "summary.json", {"label": "run-01"})
    write_json(path / "runtime-report.json", runtime_event_report(second_sequence))


def write_event_correlation_run(path: Path, orphan: bool = False) -> None:
    path.mkdir()
    write_json(path / "summary.json", {"label": "run-01"})
    write_json(path / "runtime-report.json", runtime_correlation_report(orphan))


def write_event_causality_run(path: Path, tcp_order_violation: bool = False) -> None:
    path.mkdir()
    write_json(path / "summary.json", {"label": "run-01"})
    write_json(path / "runtime-report.json", runtime_causality_report(tcp_order_violation))


def write_outbound_retry_run(path: Path, non_retryable_continued: bool = False) -> None:
    path.mkdir()
    write_json(path / "summary.json", {"label": "run-01"})
    write_json(path / "runtime-report.json", runtime_retry_report(non_retryable_continued))


def runtime_event_report(second_sequence: int) -> dict:
    return {
        "schema": "dynet-runtime-report/v1alpha1",
        "status": "pass",
        "dnsQueries": 1,
        "dnsRecords": 0,
        "proxiedDnsQueries": 0,
        "routeDecisions": 0,
        "tcpSessions": 1,
        "tcpClosedSessions": 1,
        "tcpSlotPressureEvents": 0,
        "tcpUpstreamBytes": 3,
        "tcpDownstreamBytes": 5,
        "udpSessions": 0,
        "udpUpstreamBytes": 0,
        "udpDownstreamBytes": 0,
        "ipv6PacketsDenied": 0,
        "events": [dns_query_event(), tcp_started_event(second_sequence), tcp_closed_event()],
    }


def runtime_causality_report(tcp_order_violation: bool) -> dict:
    route = tcp_event(2, "route-matched", "tcp-session-1")
    attributed = tcp_event(3, "tcp-session-attributed", "tcp-session-1")
    middle = [attributed, route] if tcp_order_violation else [route, attributed]
    return {
        "schema": "dynet-runtime-report/v1alpha1",
        "status": "pass",
        "events": [
            tcp_started_event(1),
            *middle,
            tcp_event(4, "tcp-session-outbound-connecting", "tcp-session-1"),
            tcp_event(5, "tcp-session-established", "tcp-session-1"),
            tcp_event(6, "tcp-session-payload-first-write", "tcp-session-1"),
            tcp_event(7, "tcp-session-payload-received", "tcp-session-1"),
            tcp_closed_event(),
            dns_query_event(),
            dns_completed_event(10),
        ],
    }


def runtime_retry_report(non_retryable_continued: bool) -> dict:
    first = cascade_finished(1, "failed", "1", "bound", "true", "retry-bound-failure-before-replay")
    if non_retryable_continued:
        first = cascade_finished(1, "failed", "1", "downstream", "false", "non-bound-failure")
    return {
        "schema": "dynet-runtime-report/v1alpha1",
        "status": "pass",
        "events": [
            tcp_started_event(1),
            first,
            cascade_finished(3, "success", "2", "none", None, None),
            tcp_event(4, "tcp-session-established", "tcp-session-1"),
        ],
    }


def runtime_correlation_report(orphan: bool) -> dict:
    flow_id = "tcp-session-2" if orphan else "tcp-session-1"
    events = [
        tcp_started_event(1),
        tcp_event(2, "tcp-session-attributed", "tcp-session-1"),
        tcp_event(3, "route-matched", flow_id),
        tcp_event(4, "tcp-session-outbound-connecting", "tcp-session-1"),
        tcp_event(5, "tcp-session-established", "tcp-session-1"),
        tcp_event(6, "tcp-session-payload-first-write", "tcp-session-1"),
        tcp_event(7, "tcp-session-payload-received", "tcp-session-1"),
        tcp_closed_event(),
        dns_query_event(),
        runtime_event(10, "dns-resolve-completed", {
            "dnsQueryId": "1",
            "elapsedMs": "1",
            "flowId": "dns-query-1",
            "listener": "udp",
            "proxied": "false",
        }),
    ]
    return {
        "schema": "dynet-runtime-report/v1alpha1",
        "status": "pass",
        "events": events,
    }


def dns_query_event() -> dict:
    return runtime_event(1, "dns-query-received", {
        "dnsQueryId": "1",
        "flowId": "dns-query-1",
        "listener": "udp",
        "queryBytes": "20",
    })


def tcp_started_event(sequence: int) -> dict:
    return runtime_event(sequence, "tcp-session-started", {
        "clientPort": "443",
        "flowId": "tcp-session-1",
        "session": "1",
        "transport": "tcp",
    })


def tcp_closed_event() -> dict:
    return runtime_event(3, "tcp-session-closed", {
        "downstreamBytes": "5",
        "flowId": "tcp-session-1",
        "reason": "tun-closed",
        "session": "1",
        "upstreamBytes": "3",
    })


def dns_completed_event(sequence: int) -> dict:
    return runtime_event(sequence, "dns-resolve-completed", {
        "dnsQueryId": "1",
        "elapsedMs": "1",
        "flowId": "dns-query-1",
        "listener": "udp",
        "proxied": "false",
    })


def tcp_event(sequence: int, kind: str, flow_id: str) -> dict:
    return runtime_event(sequence, kind, {
        "flowId": flow_id,
        "outbound": "private-via-tunnel",
        "routeSelected": "private-via-tunnel",
        "session": "1",
        "status": "pass",
        "transport": "tcp",
    })


def cascade_finished(
    sequence: int,
    status: str,
    attempt: str,
    failure_scope: str,
    retry_allowed: str | None,
    retry_stop_reason: str | None,
) -> dict:
    event_fields = {
        "attempt": attempt,
        "cascadeAttemptId": f"tcp-session-1-cascade-{attempt}",
        "failureScope": failure_scope,
        "flowId": "tcp-session-1",
        "session": "1",
        "sessionTransport": "tcp",
        "status": status,
    }
    if retry_allowed is not None:
        event_fields["retryAllowed"] = retry_allowed
    if retry_stop_reason is not None:
        event_fields["retryStopReason"] = retry_stop_reason
    return runtime_event(sequence, "dialer-cascade-attempt-finished", event_fields)


def runtime_event(sequence: int, kind: str, event_fields: dict[str, str]) -> dict:
    return {
        "schema": "dynet-runtime-event/v1alpha1",
        "kind": kind,
        "sequence": sequence,
        "emittedAtUnixMs": 1000 + sequence,
        "fields": event_fields,
    }


def collection_summary(stages: list[dict]) -> dict:
    return {
        "label": "run-01",
        "stages": {"stages": stages},
        "privacy": {"rawSecretsStored": False},
        "metadata": {"privacy": {"rawSecretsStored": False}},
        "workloadProbe": {"privacy": {"responseBodiesStored": False}},
    }


def collection_stages() -> list[dict]:
    names = [
        "run-acceptance",
        "collect-runtime-report",
        "collect-runtime-log",
        "collect-install-report",
        "collect-uninstall-report",
        "collect-tcp-probe-report",
        "collect-workload-probe-report",
        "cleanup-guest-files",
    ]
    return [stage(name, index) for index, name in enumerate(names)]


def stage(name: str, index: int) -> dict:
    return {
        "name": name,
        "status": "pass",
        "startedAt": f"2026-01-01T00:00:{index:02d}+00:00",
        "finishedAt": f"2026-01-01T00:00:{index + 1:02d}+00:00",
        "elapsedMs": 1,
    }


def write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload))


if __name__ == "__main__":
    unittest.main()
