from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
VM_PATH = ROOT / "scripts" / "vm"
sys.path.insert(0, str(VM_PATH))

from private_runtime_lib.reporting.flow_refresh import (
    build_dns_refresh_summary,
    build_flow_refresh_summary,
    build_identity_refresh_summary,
)
from private_runtime_lib.reporting.cascade_refresh import (
    build_cascade_refresh_summary,
    build_route_refresh_summary,
    build_selection_refresh_summary,
)
from private_runtime_lib.reporting.workload_surface.timing import (
    build_timing_surface_summary,
)
from private_runtime_lib.reporting.workload_surface.dns_timing import (
    build_dns_timing_summary,
)
from tests.private_runtime.cascade_fixtures import (
    cascade_stage_report,
    stale_cascade_summary,
)
from tests.private_runtime_fixtures import runtime_report, tcp_event, tcp_identity_report


class PrivateRuntimeFlowRefreshTest(unittest.TestCase):
    def test_recovered_stage_refresh(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            run_dir = Path(temp_dir) / "run"
            run_dir.mkdir()
            write_json(run_dir / "runtime-report.json", recovered_stage_report())
            write_json(run_dir / "workload-probe.json", successful_workload_report())
            write_json(run_dir / "summary.json", stale_summary())

            summary = build_flow_refresh_summary("flow-refresh", Path(temp_dir) / "out", [run_dir])

        row = summary["runs"][0]
        self.assertEqual(row["classification"], "recovered-stage-separated")
        self.assertTrue(row["changed"])
        self.assertEqual(summary["totals"]["recoveredStageSeparatedRuns"], 1)
        self.assertEqual(row["current"]["tcpFlow"]["failedFlows"], 0)
        self.assertEqual(row["current"]["tcpFlow"]["stageFailedFlows"], 1)
        self.assertEqual(row["current"]["workloadFlow"]["matchedRecoveredFailureEntries"], 1)
        self.assertEqual(row["current"]["workloadFlow"]["matchedFlowFailedAttempts"], 0)
        self.assertIn(
            {"key": "failedFlows", "previous": 1, "current": 0},
            row["changes"]["tcpFlow"],
        )

    def test_cascade_stage_refresh(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run_dir = root / "run"
            run_dir.mkdir()
            write_json(run_dir / "runtime-report.json", cascade_stage_report())
            write_json(run_dir / "summary.json", stale_cascade_summary())

            summary = build_cascade_refresh_summary(
                "cascade-refresh",
                root / "out",
                [run_dir],
            )

        row = summary["runs"][0]
        self.assertEqual(row["classification"], "changed")
        self.assertTrue(row["changed"])
        self.assertEqual(summary["totals"]["changedRuns"], 1)
        self.assertEqual(summary["totals"]["failedAttempts"], 2)
        self.assertEqual(summary["totals"]["retryableFailures"], 1)
        self.assertEqual(summary["totals"]["stoppedFailures"], 1)
        self.assertEqual(summary["totals"]["stoppedNonBoundFlows"], 1)
        self.assertEqual(summary["totals"]["stoppedRetryableFailures"], 1)
        self.assertEqual(row["current"]["failedByStageDisposition"], [
            {"count": 1, "key": "protocol-invalid"},
            {"count": 1, "key": "reset"},
        ])
        self.assertNotIn("rows", row["current"])
        self.assertNotIn("stoppedRows", row["current"])
        self.assertIn(
            {
                "key": "failedByDisposition",
                "previous": [{"key": "reset", "count": 2}],
                "current": [
                    {"count": 1, "key": "protocol-invalid"},
                    {"count": 1, "key": "reset"},
                ],
            },
            row["changes"],
        )

    def test_route_refresh(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run_dir = root / "run"
            run_dir.mkdir()
            write_json(run_dir / "runtime-report.json", tcp_identity_report())
            write_json(run_dir / "summary.json", stale_route_summary())

            summary = build_route_refresh_summary("route-refresh", root / "out", [run_dir])

        row = summary["runs"][0]
        self.assertEqual(row["classification"], "changed")
        self.assertTrue(row["changed"])
        self.assertEqual(summary["totals"]["changedRuns"], 1)
        self.assertEqual(summary["totals"]["ruleMatchedFlows"], 1)
        self.assertEqual(summary["totals"]["planBypassedFlows"], 1)
        self.assertEqual(summary["totals"]["boundGraphSelectedFlows"], 1)
        self.assertEqual(summary["totals"]["pathCompleteFlows"], 1)
        self.assertIn(
            {"key": "planBypassedFlows", "previous": None, "current": 1},
            row["changes"],
        )

    def test_selection_refresh(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run_dir = root / "run"
            run_dir.mkdir()
            write_json(run_dir / "runtime-report.json", runtime_report())
            write_json(run_dir / "summary.json", stale_selection_summary())

            summary = build_selection_refresh_summary(
                "selection-refresh",
                root / "out",
                [run_dir],
            )

        row = summary["runs"][0]
        self.assertEqual(row["classification"], "changed")
        self.assertTrue(row["changed"])
        self.assertEqual(summary["totals"]["changedRuns"], 1)
        self.assertEqual(summary["totals"]["candidateSets"], 1)
        self.assertEqual(summary["totals"]["selectedWithQuality"], 1)
        self.assertEqual(summary["totals"]["selectedBest"], 1)
        self.assertEqual(summary["totals"]["selectedBehind"], 0)
        self.assertIn(
            {"key": "selectedBehind", "previous": 1, "current": 0},
            row["changes"],
        )

    def test_timing_surface_clean(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run_dir = write_timing_run(root / "run", timed_report())

            summary = build_timing_surface_summary("timing", root / "out", [run_dir])

        self.assertEqual(summary["conclusion"]["status"], "clean")
        self.assertEqual(summary["totals"]["flows"], 1)
        self.assertEqual(summary["totals"]["orderedFlows"], 1)
        self.assertEqual(summary["totals"]["timings"]["closedMs"]["p95"], 700)
        self.assertNotIn("_deltas", summary["runs"][0])

    def test_timing_missing_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report = timed_report(skip_kind="tcp-session-payload-received")
            run_dir = write_timing_run(root / "run", report)

            summary = build_timing_surface_summary("timing", root / "out", [run_dir])

        self.assertEqual(summary["conclusion"]["status"], "timing-surface-needs-evidence")
        self.assertEqual(summary["runs"][0]["classification"], "timing-order-incomplete")
        self.assertEqual(summary["totals"]["firstDownstreamFlows"], 0)

    def test_dns_timing_clean(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run_dir = write_timing_run(root / "run", dns_timing_report())

            summary = build_dns_timing_summary("dns-timing", root / "out", [run_dir])

        self.assertEqual(summary["conclusion"]["status"], "clean")
        self.assertEqual(summary["totals"]["queries"], 1)
        self.assertEqual(summary["totals"]["queriesWithRecords"], 1)
        self.assertEqual(summary["totals"]["resolveMs"]["p95"], 120)
        self.assertNotIn("_queries", summary["runs"][0])

    def test_dns_failure_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run_dir = write_timing_run(root / "run", dns_timing_report(failed=True))

            summary = build_dns_timing_summary("dns-timing", root / "out", [run_dir])

        self.assertEqual(summary["conclusion"]["status"], "dns-timing-surface-needs-evidence")
        self.assertEqual(summary["runs"][0]["classification"], "dns-failure")
        self.assertEqual(summary["totals"]["failedQueries"], 1)

    def test_dns_refresh(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run_dir = root / "run"
            run_dir.mkdir()
            write_json(run_dir / "runtime-report.json", dns_report())
            write_json(run_dir / "summary.json", stale_dns_summary())

            summary = build_dns_refresh_summary("dns-refresh", root / "out", [run_dir])

        row = summary["runs"][0]
        self.assertEqual(row["classification"], "changed")
        self.assertTrue(row["changed"])
        self.assertTrue(row["consistent"])
        self.assertEqual(summary["totals"]["changedRuns"], 1)
        self.assertEqual(summary["totals"]["inconsistentRuns"], 0)
        self.assertEqual(summary["totals"]["dnsQueries"], 1)
        self.assertEqual(summary["totals"]["reverseRecordEvents"], 1)
        self.assertIn(
            {"key": "dnsRecords", "previous": 0, "current": 1},
            row["changes"],
        )

    def test_dns_refresh_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run_dir = root / "run"
            run_dir.mkdir()
            write_json(run_dir / "runtime-report.json", dns_failed_report())
            write_json(run_dir / "summary.json", dns_failed_summary())

            summary = build_dns_refresh_summary("dns-refresh", root / "out", [run_dir])

        row = summary["runs"][0]
        self.assertEqual(row["classification"], "unchanged")
        self.assertTrue(row["consistent"])
        self.assertEqual(summary["totals"]["resolveFailedEvents"], 1)
        self.assertEqual(summary["totals"]["queriesMissingCompletion"], 0)

    def test_target_identity_refresh(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run_dir = root / "run"
            run_dir.mkdir()
            write_json(run_dir / "runtime-report.json", tcp_identity_report())
            write_json(run_dir / "summary.json", stale_target_identity_summary())

            summary = build_identity_refresh_summary(
                "target-identity-refresh",
                root / "out",
                [run_dir],
            )

        row = summary["runs"][0]
        self.assertEqual(row["classification"], "changed")
        self.assertTrue(row["changed"])
        self.assertEqual(summary["totals"]["changedRuns"], 1)
        self.assertEqual(summary["totals"]["targetChainFlows"], 1)
        self.assertEqual(summary["totals"]["targetChainMatched"], 1)
        self.assertEqual(summary["totals"]["targetChainMismatched"], 0)
        self.assertIn(
            {"key": "targetChainMatched", "previous": 0, "current": 1},
            row["changes"],
        )


def recovered_stage_report() -> dict:
    report = tcp_identity_report()
    report["events"].insert(
        -1,
        tcp_event(
            "outbound-stage-finished",
            {"outbound": "tunnel-003", "stage": "tcp-connect", "status": "failed", "errorType": "trojan"},
        ),
    )
    return report


def successful_workload_report() -> dict:
    return {
        "tunCapture": {"ports": [{"localPort": 45678, "synPackets": 1, "synAckPackets": 1}]},
        "results": [
            {
                "id": "example-head-1",
                "probe": "https-head",
                "domain": "chatgpt.com",
                "ok": True,
                "localPort": 45678,
                "routeViaDynet": True,
                "tunWitness": {"observed": True},
                "stages": [{"name": "tcp-connect", "ok": True}],
            }
        ],
    }


def stale_summary() -> dict:
    return {
        "label": "stale-run",
        "tcpFlow": {"failedFlows": 1, "stageFailedFlows": 1, "lifecycleCompleteFlows": 0},
        "workloadFlow": {
            "matchedRecoveredFailureEntries": 0,
            "matchedFlowFailedAttempts": 1,
            "matchedFlowStageFailedAttempts": 1,
        },
    }


def dns_report() -> dict:
    return {
        "dnsQueries": 1,
        "dnsRecords": 1,
        "proxiedDnsQueries": 0,
        "events": [
            dns_event("dns-query-received", {"dnsQueryId": "1"}),
            dns_event("dns-reverse-record", {"dnsQueryId": "1"}),
            dns_event(
                "dns-resolve-completed",
                {"dnsQueryId": "1", "proxied": "false", "routeDecision": "false"},
            ),
        ],
    }


def dns_failed_report() -> dict:
    return {
        "dnsQueries": 1,
        "dnsRecords": 0,
        "proxiedDnsQueries": 0,
        "events": [
            dns_event("dns-query-received", {"dnsQueryId": "1"}),
            dns_event("dns-resolve-failed", {"dnsQueryId": "1"}),
        ],
    }


def dns_event(kind: str, fields: dict[str, str]) -> dict[str, object]:
    return {"kind": kind, "fields": fields}


def stale_dns_summary() -> dict:
    return {
        "label": "stale-dns-run",
        "runtime": {
            "dnsQueries": 1,
            "dnsRecords": 0,
            "proxiedDnsQueries": 0,
        },
    }


def dns_failed_summary() -> dict:
    return {
        "label": "failed-dns-run",
        "runtime": {
            "dnsQueries": 1,
            "dnsRecords": 0,
            "proxiedDnsQueries": 0,
        },
    }


def stale_route_summary() -> dict:
    return {
        "label": "stale-route-run",
        "tcpFlow": {
            "routeMatchedFlows": 1,
            "routeGraphSelectedFlows": 0,
            "boundCandidateSetFlows": 1,
            "boundGraphSelectedFlows": 0,
            "cascadeSelectedFlows": 1,
            "boundAttemptStartedFlows": 1,
            "boundAttemptSucceededFlows": 1,
            "privateConnectFlows": 1,
            "pathCompleteFlows": 0,
            "lifecycleCompleteFlows": 1,
            "failedFlows": 0,
            "stageFailedFlows": 0,
        },
    }


def stale_selection_summary() -> dict:
    return {
        "label": "stale-selection-run",
        "selection": {
            "boundSelection": {
                "candidateSets": 1,
                "attemptCandidateSets": 1,
                "fallbackCandidateSets": 0,
                "withBoundSelected": 1,
                "selectedWithQuality": 0,
                "selectedBest": 0,
                "selectedBehind": 1,
                "fallbackSelectedWithQuality": 0,
                "fallbackSelectedBehind": 0,
            },
        },
    }


def stale_target_identity_summary() -> dict:
    return {
        "label": "stale-target-run",
        "targetIdentity": {
            "connectingEvents": 1,
            "adapterConnectEvents": 1,
            "targetChainFlows": 1,
            "targetChainMatched": 0,
            "targetChainMismatched": 1,
            "targetChainMissingAdapter": 0,
            "targetChainMissingConnect": 0,
            "targetChainDuplicateAdapterFlows": 0,
        },
    }


def timed_report(skip_kind: str = "") -> dict:
    report = tcp_identity_report()
    offsets = {
        "tcp-session-started": 0,
        "tcp-session-attributed": 10,
        "tcp-session-outbound-connecting": 20,
        "tcp-session-established": 120,
        "tcp-session-payload-first-write": 180,
        "tcp-session-payload-received": 420,
        "tcp-session-closed": 700,
    }
    events = []
    for event in report["events"]:
        if event["kind"] == skip_kind:
            continue
        offset = offsets.get(str(event["kind"]))
        if offset is not None:
            event = {**event, "emittedAtUnixMs": 1000 + offset}
        events.append(event)
    report["events"] = events
    return report


def dns_timing_report(failed: bool = False) -> dict:
    events = [
        dns_timing_event(
            "dns-query-received",
            1000,
            {"dnsQueryId": "1", "flowId": "dns-query-1"},
        ),
    ]
    if failed:
        events.append(
            dns_timing_event(
                "dns-resolve-failed",
                1120,
                {"dnsQueryId": "1", "flowId": "dns-query-1", "elapsedMs": "120"},
            )
        )
    else:
        events.extend([
            dns_timing_event(
                "dns-reverse-record",
                1120,
                {"dnsQueryId": "1", "flowId": "dns-query-1"},
            ),
            dns_timing_event(
                "dns-resolve-completed",
                1120,
                {"dnsQueryId": "1", "flowId": "dns-query-1", "elapsedMs": "120"},
            ),
        ])
    return {"events": events}


def dns_timing_event(kind: str, timestamp: int, fields: dict[str, str]) -> dict:
    return {"kind": kind, "emittedAtUnixMs": timestamp, "fields": fields}


def write_timing_run(path: Path, report: dict) -> Path:
    path.mkdir()
    write_json(path / "runtime-report.json", report)
    write_json(path / "summary.json", {"label": path.name})
    return path


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, sort_keys=True))


if __name__ == "__main__":
    unittest.main()
