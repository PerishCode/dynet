from __future__ import annotations

import argparse
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VM_PATH = ROOT / "scripts" / "vm"
VM_TESTS_PATH = VM_PATH / "tests"
sys.path.insert(0, str(VM_PATH))
sys.path.insert(0, str(VM_TESTS_PATH))

from private_runtime_lib.briefs import selection_brief
from private_runtime_lib.checks import (
    acceptance_checks,
    fallback_acceptance_checks,
    workload_acceptance_checks,
)
from private_runtime_lib.config import (
    POISON_TAG,
    runtime_command,
    workload_is_concurrent,
)
from private_runtime_lib.workload_script import workload_probe_python
from private_runtime_fixtures import (
    lifecycle_report,
    runtime_args,
    runtime_report,
    tcp_identity_report,
)
import private_probe
import private_runtime


class PrivateRuntimeTest(unittest.TestCase):
    def test_bound_selection(self) -> None:
        brief = selection_brief(runtime_report())

        bound = brief["boundSelection"]

        self.assertEqual(bound["candidateSets"], 1)
        self.assertEqual(bound["withBoundSelected"], 1)
        self.assertEqual(bound["selectedWithQuality"], 1)
        self.assertEqual(bound["selectedBest"], 1)
        self.assertEqual(bound["selectedBehind"], 0)
        self.assertEqual(bound["bySelected"], [{"count": 1, "key": "tunnel-001"}])

    def test_quality_checks(self) -> None:
        report = runtime_report()
        report["_selectionBrief"] = selection_brief(report)

        checks = acceptance_checks(
            report,
            lifecycle_report(),
            lifecycle_report(),
            {"results": []},
            {},
            {},
            {},
            [],
            argparse.Namespace(
                tcp_forward=True,
                udp_forward=False,
                udp_direct_probe=False,
                ipv6_no_leak=False,
                workload_manifest=None,
                quality_state="/tmp/quality.json",
            ),
            {"tcpClosedSessions": 0},
        )

        by_name = {item["name"]: item["passed"] for item in checks}
        self.assertTrue(by_name["quality-bound-candidate-set"])
        self.assertTrue(by_name["quality-bound-selected"])
        self.assertTrue(by_name["quality-bound-selected-has-quality"])
        self.assertTrue(by_name["quality-bound-selected-best"])

    def test_supported_override(self) -> None:
        runtime_args = private_runtime.build_parser().parse_args([
            "guest",
            "dynet-smoke",
            "--supported-type",
            "vmess",
        ])
        probe_args = private_probe.build_parser().parse_args([
            "guest",
            "dynet-smoke",
            "--supported-type",
            "vmess",
        ])

        self.assertEqual(runtime_args.supported_type, ["vmess"])
        self.assertEqual(probe_args.supported_type, ["vmess"])

    def test_group_filter_default(self) -> None:
        runtime_args = private_runtime.build_parser().parse_args([
            "guest",
            "dynet-smoke",
        ])
        probe_args = private_probe.build_parser().parse_args([
            "guest",
            "dynet-smoke",
        ])

        self.assertIsNone(runtime_args.filter)
        self.assertIsNone(probe_args.filter)

    def test_probe_quality_window(self) -> None:
        args = private_probe.build_parser().parse_args([
            "guest",
            "dynet-smoke",
            "--quality-ttl-seconds",
            "1800",
            "--quality-window-seconds",
            "3600",
        ])

        self.assertEqual(args.quality_ttl_seconds, 1800)
        self.assertEqual(args.quality_window_seconds, 3600)
    def test_poison_fallback_checks(self) -> None:
        checks = fallback_acceptance_checks({
            "events": [
                fallback_started("dns-query-1", "pre-query", POISON_TAG),
                fallback_finished("dns-query-1", POISON_TAG, "failed", "bound"),
                fallback_finished("dns-query-1", "tunnel-001", "success", "none"),
                fallback_started("tcp-session-1", "pre-payload", POISON_TAG),
                fallback_finished("tcp-session-1", POISON_TAG, "failed", "bound"),
                fallback_finished("tcp-session-1", "tunnel-001", "success", "none"),
                {
                    "kind": "tcp-session-payload-first-write",
                    "fields": {"candidateRetryAllowed": "false"},
                },
            ]
        })

        by_name = {item["name"]: item["passed"] for item in checks}
        self.assertTrue(by_name["dns-pre-query-fallback"])
        self.assertTrue(by_name["tcp-pre-payload-fallback"])
        self.assertTrue(by_name["tcp-payload-lock"])
    def test_tcp_no_limits(self) -> None:
        command = runtime_command(
            "test",
            "/tmp/dynet.json",
            "/tmp/quality.json",
            None,
            ["chatgpt.com"],
            runtime_args(tcp_forward=True),
        )

        self.assertIn("--experimental-tcp-forward", command)
        self.assertIn("--max-tcp-terminal-sessions", command)
        self.assertIn("--outbound-tcp-connect-timeout-ms 8000", command)
        self.assertIn("--outbound-tcp-read-write-timeout-ms 8000", command)
        self.assertNotIn("--max-dns-queries", command)
        self.assertNotIn("--max-tun-packets", command)
    def test_tcp_slots_flag(self) -> None:
        args = runtime_args(tcp_forward=True)
        args.tcp_listen_slots_per_port = 12
        command = runtime_command(
            "test",
            "/tmp/dynet.json",
            "/tmp/quality.json",
            None,
            ["chatgpt.com"],
            args,
        )

        self.assertIn("--experimental-tcp-listen-slots-per-port 12", command)
    def test_dns_keeps_limits(self) -> None:
        command = runtime_command(
            "test",
            "/tmp/dynet.json",
            None,
            None,
            ["chatgpt.com"],
            runtime_args(tcp_forward=False),
        )

        self.assertIn("--max-dns-queries", command)
        self.assertIn("--max-tun-packets", command)
        args = runtime_args(tcp_forward=False)
        args.udp_forward = True; args.udp_direct_probe = True
        udp = runtime_command("test", "/tmp/dynet.json", None, None, ["chatgpt.com"], args)
        self.assertIn("--experimental-udp-forward", udp)
        self.assertIn("--max-udp-downstream-bytes 1", udp)
        self.assertNotIn("--max-udp-sessions", udp)

    def test_workload_tcp_gate(self) -> None:
        command = runtime_command(
            "test",
            "/tmp/dynet.json",
            "/tmp/quality.json",
            "/tmp/workload.json",
            ["chatgpt.com"],
            runtime_args(tcp_forward=True),
            {
                "entries": [
                    {"domain": "example.com", "probe": "dns"},
                    {"domain": "example.com", "probe": "tcp-connect"},
                    {"domain": "chatgpt.com", "probe": "https-head"},
                ]
            },
        )

        self.assertIn("--max-tcp-terminal-sessions 3", command)
    def test_workload_tcp_only(self) -> None:
        args = runtime_args(tcp_forward=True)
        args.tcp_probe = False
        command = runtime_command(
            "test",
            "/tmp/dynet.json",
            "/tmp/quality.json",
            "/tmp/workload.json",
            ["chatgpt.com"],
            args,
            {"entries": [{"domain": "chatgpt.com", "probe": "https-head"}]},
        )

        self.assertIn("--max-tcp-terminal-sessions 1", command)
        self.assertNotIn("[runtime-private] tcp", command)
    def test_tcp_only_acceptance(self) -> None:
        report = tcp_identity_report()
        report.update({"dnsQueries": 1, "dnsRecords": 1, "tunPackets": 1})
        report["events"].append(
            {"kind": "outbound-attempt-finished", "fields": {"query": "chatgpt.com"}}
        )
        args = runtime_args(tcp_forward=True)
        args.tcp_probe = False
        args.workload_manifest = "/tmp/workload.json"
        args.workload_min_success_rate = 1
        args.quality_state = None
        checks = acceptance_checks(
            report,
            lifecycle_report(),
            lifecycle_report(),
            {"results": []},
            {},
            {},
            {
                "totals": {"count": 1, "success": 1, "failure": 0, "successRate": 1},
                "results": [
                    {"domain": "chatgpt.com", "probe": "https-head", "ok": True}
                ],
            },
            ["www.cloudflare.com", "chatgpt.com"],
            args,
            {"tcpClosedSessions": 1},
        )

        by_name = {item["name"]: item["passed"] for item in checks}
        self.assertTrue(by_name["dns-queries"])
        self.assertTrue(by_name["dns-forwarding"])
        self.assertTrue(by_name["dns-records"])
        self.assertTrue(by_name["all-dns-names-observed"])
        self.assertTrue(by_name["tcp-blackbox-https"])
    def test_workload_timeout_floor(self) -> None:
        args = runtime_args(tcp_forward=True)
        args.timeout = 30; args.dns_timeout = 35
        command = runtime_command(
            "test",
            "/tmp/dynet.json",
            None,
            "/tmp/workload.json",
            ["chatgpt.com"],
            args,
            {
                "workload": {"durationSeconds": 8},
                "entries": [{"domain": "api.github.com", "probe": "https-head"}],
            },
        )

        self.assertIn("--timeout 158", command)
        parallel_manifest = {
            "workload": {"mode": "paired-parallel-noschedule"},
            "entries": [
                {"domain": name, "probe": "https-head"}
                for name in ["api.github.com", "chatgpt.com", "www.gstatic.com"]
            ],
        }
        args.workload_concurrency_limit = 2
        parallel = runtime_command("test", "/tmp/dynet.json", None, "/tmp/workload.json", ["chatgpt.com"], args, parallel_manifest)
        self.assertIn("--timeout 290", parallel)
        self.assertTrue(workload_is_concurrent({"mode": "paired-parallel-noschedule"}))

    def test_workload_concurrency(self) -> None:
        command = workload_probe_python(
            "/tmp/workload.json",
            "8.8.8.8",
            "53",
            30,
            "/tmp/out.json",
            True,
        )
        checks = workload_acceptance_checks(
            argparse.Namespace(workload_min_success_rate=1),
            {"tcpSessions": 1, "tcpActiveSlotsMax": 2},
            {
                "concurrency": {"enabled": True},
                "totals": {"count": 1, "successRate": 1},
                "results": [{"domain": "example.com", "probe": "tcp-connect", "ok": True}],
            },
            [],
            {"example.com"},
        )

        by_name = {item["name"]: item["passed"] for item in checks}
        body = command.split("\n", 1)[1].rsplit("PY_DYNET_PRIVATE_WORKLOAD", 1)[0]
        compile(body, "workload-probe.py", "exec")
        self.assertIn("import threading", command)
        self.assertIn("threading.Thread", command)
        self.assertIn("'parallel' in mode", command)
        self.assertIn("'concurrency': concurrency_summary()", command)
        self.assertTrue(by_name["workload-concurrent-sessions"])

    def test_workload_probe_sessions(self) -> None:
        checks = workload_acceptance_checks(
            argparse.Namespace(workload_min_success_rate=1, workload_require_all_success=True),
            {"tcpSessions": 2},
            {
                "totals": {"count": 2, "success": 2, "failure": 0, "successRate": 1},
                "results": [
                    {"domain": "example.com", "probe": "https-head", "ok": True},
                    {"domain": "example.com", "probe": "https-head", "ok": True},
                ],
            },
            ["example.com"],
            {"example.com"},
            {"results": [{"name": "example.com", "error": "timed out"}]},
        )

        by_name = {item["name"]: item["passed"] for item in checks}
        self.assertTrue(by_name["workload-tcp-sessions"])

    def test_workload_strict_gate(self) -> None:
        checks = workload_acceptance_checks(
            argparse.Namespace(workload_min_success_rate=0.75, workload_require_all_success=True),
            {"tcpSessions": 3, "tcpActiveSlotsMax": 2},
            {
                "concurrency": {"enabled": True},
                "totals": {"count": 4, "success": 3, "failure": 1, "successRate": 0.75},
                "results": [
                    {"domain": "example.com", "probe": "tcp-connect", "ok": True},
                    {"domain": "example.com", "probe": "tcp-connect", "ok": True},
                    {"domain": "example.com", "probe": "tcp-connect", "ok": True},
                    {"domain": "example.com", "probe": "https-head", "ok": False},
                ],
            },
            [],
            {"example.com"},
        )

        by_name = {item["name"]: item["passed"] for item in checks}
        self.assertTrue(by_name["workload-totals-consistent"])
        self.assertTrue(by_name["workload-success-rate"])
        self.assertFalse(by_name["workload-all-success"])

    def test_workload_flow_checks(self) -> None:
        report = tcp_identity_report()
        report["events"].append(
            {
                "kind": "tcp-forwarder-packet",
                "fields": {
                    "clientPort": "45678",
                    "direction": "ingress",
                    "syn": "true",
                    "ack": "false",
                },
            }
        )
        checks = workload_acceptance_checks(
            argparse.Namespace(
                workload_min_success_rate=1,
                workload_require_all_success=True,
                tcp_forward=True,
            ),
            report,
            {
                "totals": {"count": 1, "success": 1, "failure": 0, "successRate": 1},
                "tunCapture": {
                    "enabled": True,
                    "started": True,
                    "rawLinesStored": False,
                    "rawPcapStored": False,
                    "ports": [{"localPort": 45678, "toTargetPackets": 1}],
                },
                "results": [
                    {
                        "domain": "chatgpt.com",
                        "probe": "https-head",
                        "ok": True,
                        "localPort": 45678,
                    }
                ],
            },
            [],
            {"chatgpt.com"},
        )

        by_name = {item["name"]: item["passed"] for item in checks}
        self.assertTrue(by_name["workload-flow-local-ports"])
        self.assertTrue(by_name["workload-flow-covered"])
        self.assertTrue(by_name["workload-flow-path-complete"])
        self.assertTrue(by_name["workload-flow-lifecycle-complete"])
        self.assertTrue(by_name["workload-flow-terminal"])
        self.assertTrue(by_name["workload-tun-capture-started"])
        self.assertTrue(by_name["workload-tun-capture-privacy"])
        self.assertTrue(by_name["workload-flow-tun-capture-matched"])
        self.assertTrue(by_name["workload-flow-runtime-packet-matched"])
        self.assertTrue(by_name["workload-flow-runtime-syn-matched"])

    def test_dns_preflow_ignore(self) -> None:
        report = tcp_identity_report()
        report["events"].append(
            {
                "kind": "tcp-forwarder-packet",
                "fields": {
                    "clientPort": "45678",
                    "direction": "ingress",
                    "syn": "true",
                    "ack": "false",
                },
            }
        )
        checks = workload_acceptance_checks(
            argparse.Namespace(
                workload_min_success_rate=0.5,
                workload_require_all_success=False,
                tcp_forward=True,
            ),
            report,
            {
                "totals": {"count": 2, "success": 1, "failure": 1, "successRate": 0.5},
                "tunCapture": {
                    "enabled": True,
                    "started": True,
                    "rawLinesStored": False,
                    "rawPcapStored": False,
                    "ports": [{"localPort": 45678, "toTargetPackets": 1}],
                },
                "results": [
                    {
                        "domain": "chatgpt.com",
                        "probe": "https-head",
                        "ok": True,
                        "localPort": 45678,
                        "stages": [{"name": "tcp-connect", "ok": True}],
                    },
                    {
                        "domain": "api.github.com",
                        "probe": "https-head",
                        "ok": False,
                        "errorStage": "dns",
                        "errorType": "timeout",
                        "tunWitness": {"observed": True},
                        "stages": [{"name": "dns", "ok": False}],
                    },
                ],
            },
            [],
            {"chatgpt.com", "api.github.com"},
        )

        by_name = {item["name"]: item["passed"] for item in checks}
        self.assertTrue(by_name["workload-flow-local-ports"])
        self.assertTrue(by_name["workload-flow-covered"])
        self.assertTrue(by_name["workload-flow-tun-capture-matched"])
        self.assertTrue(by_name["workload-flow-runtime-packet-matched"])
        self.assertTrue(by_name["workload-flow-runtime-syn-matched"])

def fallback_started(flow_id: str, replay_safe: str, bound: str) -> dict[str, object]:
    return {
        "kind": "dialer-cascade-attempt-started",
        "fields": {
            "flowId": flow_id,
            "replaySafe": replay_safe,
            "boundSelected": bound,
        },
    }


def fallback_finished(
    flow_id: str,
    bound: str,
    status: str,
    scope: str,
) -> dict[str, object]:
    return {
        "kind": "dialer-cascade-attempt-finished",
        "fields": {
            "flowId": flow_id,
            "boundSelected": bound,
            "status": status,
            "failureScope": scope,
        },
    }


if __name__ == "__main__":
    unittest.main()
