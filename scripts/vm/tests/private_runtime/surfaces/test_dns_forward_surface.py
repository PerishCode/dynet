from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[5]
VM_PATH = ROOT / "scripts" / "vm"
sys.path.insert(0, str(VM_PATH))

from private_runtime_lib.reporting.workload_surface.dns.forward import (
    build_dns_forward_summary,
)


class DnsForwardSurfaceTest(unittest.TestCase):
    def test_diagnostic_forward_clean(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            clean = write_run(root / "run-01", runtime_report())
            quiet = write_run(root / "run-02", runtime_report(no_diagnostic=True))
            summary = build_dns_forward_summary("dns-forward", root / "out", [clean, quiet])

        self.assertEqual(summary["conclusion"]["status"], "clean")
        self.assertEqual(summary["totals"]["runs"], 2)
        self.assertEqual(summary["totals"]["diagnosticQueries"], 1)
        self.assertEqual(summary["totals"]["proxyForwardQueries"], 1)
        self.assertEqual(summary["totals"]["terminalFailureQueries"], 1)
        self.assertEqual(summary["totals"]["orderViolations"], 0)

    def test_missing_terminal_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = write_run(root / "run-01", runtime_report(missing_terminal=True))
            summary = build_dns_forward_summary("dns-forward", root / "out", [run])

        self.assertEqual(
            summary["runs"][0]["classification"],
            "forward-terminal-missing",
        )
        self.assertEqual(
            summary["conclusion"]["status"],
            "dns-forward-surface-needs-evidence",
        )


def runtime_report(
    *,
    missing_terminal: bool = False,
    no_diagnostic: bool = False,
) -> dict:
    events = [runtime_event("dns-query-received", {"dnsQueryId": "dns-query-1"})]
    if no_diagnostic:
        events.append(runtime_event("dns-resolve-completed", {"dnsQueryId": "dns-query-1"}))
    else:
        events.extend(diagnostic_events(missing_terminal))
    return {
        "schema": "dynet-runtime-report/v1alpha1",
        "status": "pass",
        "events": events,
    }


def diagnostic_events(missing_terminal: bool) -> list[dict[str, object]]:
    events = [
        runtime_event("rule-matched", {
            "dnsQueryId": "dns-query-1",
            "bypassesPlan": "true",
            "listener": "udp",
            "transport": "dns",
        }),
        runtime_event("plan-bypassed", {"dnsQueryId": "dns-query-1"}),
        runtime_event("dns-proxy-forward", {
            "dnsQueryId": "dns-query-1",
            "listener": "udp",
            "outbound": "selected",
            "upstream": "configured",
        }),
    ]
    if not missing_terminal:
        events.append(runtime_event("dns-resolve-failed", {
            "dnsQueryId": "dns-query-1",
            "errorDisposition": "protocol-invalid",
            "failureResponseCode": "SERVFAIL",
        }))
    return events


def runtime_event(kind: str, event_fields: dict[str, str]) -> dict[str, object]:
    return {"kind": kind, "fields": event_fields}


def write_run(path: Path, report: dict) -> Path:
    path.mkdir()
    (path / "runtime-report.json").write_text(json.dumps(report, sort_keys=True))
    (path / "summary.json").write_text(json.dumps({"label": path.name}))
    return path


if __name__ == "__main__":
    unittest.main()
