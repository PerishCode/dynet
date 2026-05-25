from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[5]
VM_PATH = ROOT / "scripts" / "vm"
sys.path.insert(0, str(VM_PATH))

from private_runtime_lib.reporting.workload_surface.tcp.target import (
    build_tcp_target_summary,
)


class TcpTargetSurfaceTest(unittest.TestCase):
    def test_clean_target_chain(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = write_run(root / "run-01", runtime_report())
            summary = build_tcp_target_summary("target", root / "out", [run])
        self.assertEqual(summary["conclusion"]["status"], "clean")
        self.assertEqual(summary["totals"]["coveredConnects"], 2)
        self.assertEqual(summary["totals"]["socketPreservedDirectConnects"], 1)
        self.assertEqual(summary["totals"]["adapterMatchedConnects"], 1)

    def test_controlled_missing_adapter(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = write_run(root / "run-01", runtime_report(include_adapter=False, include_failed_cascade=True))
            summary = build_tcp_target_summary("target", root / "out", [run])
        self.assertEqual(summary["conclusion"]["status"], "clean")
        self.assertEqual(summary["totals"]["controlledMissingAdapterConnects"], 1)

    def test_uncontrolled_missing_adapter(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = write_run(root / "run-01", runtime_report(include_adapter=False))
            summary = build_tcp_target_summary("target", root / "out", [run])
        self.assertEqual(summary["runs"][0]["classification"], "adapter-target-missing")

    def test_direct_socket_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = write_run(root / "run-01", runtime_report(bad_direct=True))
            summary = build_tcp_target_summary("target", root / "out", [run])
        self.assertEqual(summary["runs"][0]["classification"], "direct-target-not-preserved")


def runtime_report(
    *,
    include_adapter: bool = True,
    include_failed_cascade: bool = False,
    bad_direct: bool = False,
) -> dict:
    events = [
        runtime_event("tcp-session-outbound-connecting", {
            "connectTarget": "example.test:443",
            "flowId": "tcp-session-1",
            "identityDomain": "example.test",
            "kind": "dialer",
            "targetAddressSource": "dns-reverse-rule-domain",
        }),
        runtime_event("tcp-session-outbound-connecting", {
            "connectTarget": "direct.example.test:443" if bad_direct else "203.0.113.10:443",
            "flowId": "tcp-session-2",
            "identityDomain": "direct.example.test",
            "kind": "direct",
            "targetAddressSource": "dns-reverse-rule-domain" if bad_direct else "socket-ip-direct-preserved",
        }),
    ]
    if include_adapter:
        events.append(runtime_event("outbound-stage-finished", {
            "adapterTarget": "example.test:443",
            "adapterTargetKind": "domain",
            "flowId": "tcp-session-1",
            "kind": "vmess",
            "stage": "private-vmess-connect",
            "status": "success",
        }))
    if include_failed_cascade:
        events.append(runtime_event("dialer-cascade-attempt-finished", {
            "failureScope": "bound",
            "flowId": "tcp-session-1",
            "status": "failed",
        }))
    return {
        "schema": "dynet-runtime-report/v1alpha1",
        "status": "pass",
        "events": events,
    }


def runtime_event(kind: str, fields: dict[str, str]) -> dict[str, object]:
    return {"kind": kind, "fields": fields}


def write_run(path: Path, report: dict) -> Path:
    path.mkdir()
    (path / "runtime-report.json").write_text(json.dumps(report, sort_keys=True))
    (path / "summary.json").write_text(json.dumps({"label": path.name}))
    return path


if __name__ == "__main__":
    unittest.main()
