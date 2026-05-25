from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[5]
VM_PATH = ROOT / "scripts" / "vm"
sys.path.insert(0, str(VM_PATH))

from private_runtime_lib.reporting.workload_surface.tcp.pressure import (
    build_tcp_pressure_summary,
)


class TcpPressureSurfaceTest(unittest.TestCase):
    def test_pressure_clean(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = write_run(root / "run-01", runtime_report())
            summary = build_tcp_pressure_summary("pressure", root / "out", [run])
        self.assertEqual(summary["conclusion"]["status"], "clean")
        self.assertEqual(summary["totals"]["pressureCountMismatches"], 0)

    def test_over_capacity_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            run = write_run(root / "run-01", runtime_report(over_capacity=True))
            summary = build_tcp_pressure_summary("pressure", root / "out", [run])
        self.assertEqual(
            summary["runs"][0]["classification"],
            "pressure-active-over-capacity",
        )


def runtime_report(over_capacity: bool = False) -> dict:
    active_slots = "17" if over_capacity else "8"
    return {
        "schema": "dynet-runtime-report/v1alpha1",
        "status": "pass",
        "tcpListenCapacity": 16,
        "tcpListenPorts": [443, 80],
        "tcpListenSlotsPerPort": 8,
        "tcpActiveSlotsMax": 17 if over_capacity else 8,
        "tcpSlotPressureEvents": 1,
        "tcpSessions": 1,
        "tcpClosedSessions": 1,
        "tcpSessionFailures": 0,
        "events": [
            runtime_event("tcp-session-started", {"flowId": "tcp-session-1"}),
            runtime_event("tcp-forwarder-capacity", {
                "capacity": "16",
                "listenPorts": "443,80",
                "slotsPerPort": "8",
            }),
            runtime_event("tcp-forwarder-pressure", {
                "activeSlots": active_slots,
                "capacity": "16",
                "pressurePorts": "443",
            }),
        ],
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
