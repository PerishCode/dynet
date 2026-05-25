from __future__ import annotations

import argparse
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
VM_PATH = ROOT / "scripts" / "vm"
EXPERIMENTS = ROOT / "scripts" / "experiments"
sys.path.insert(0, str(VM_PATH))
sys.path.insert(0, str(EXPERIMENTS))

import private_probe
import private_runtime
from lib import private_paired
from lib.private_paired_report import paired_selection_summary
from lib.private_paired_summary import comparison_summary


class PrivateProbeInterfaceTest(unittest.TestCase):
    def test_interface_parser(self) -> None:
        runtime_args = private_runtime.build_parser().parse_args([
            "guest",
            "dynet-smoke",
            "--trojan-interface-name",
            "auto",
        ])
        probe_args = private_probe.build_parser().parse_args([
            "guest",
            "dynet-smoke",
            "--trojan-interface-name",
            "auto",
        ])

        self.assertEqual(runtime_args.trojan_interface_name, "auto")
        self.assertEqual(probe_args.trojan_interface_name, "auto")

    def test_config_interface(self) -> None:
        args = private_probe.build_parser().parse_args([
            "guest",
            "dynet-smoke",
            "--trojan-interface-name",
            "eth0",
            "--candidate-offset",
            "3",
        ])

        command = private_probe.private_config_command(
            args,
            Path("/tmp/private.json"),
            Path("/tmp/meta.json"),
        )

        self.assertIn("--trojan-interface-name", command)
        self.assertEqual(command[command.index("--trojan-interface-name") + 1], "eth0")
        self.assertIn("--candidate-offset", command)
        self.assertEqual(command[command.index("--candidate-offset") + 1], "3")

    def test_group_filter_default(self) -> None:
        args = private_probe.build_parser().parse_args([
            "guest",
            "dynet-smoke",
        ])

        command = private_probe.private_config_command(
            args,
            Path("/tmp/private.json"),
            Path("/tmp/meta.json"),
        )

        self.assertIsNone(args.filter)
        self.assertNotIn("--filter", command)

    def test_filter_override(self) -> None:
        args = private_probe.build_parser().parse_args([
            "guest",
            "dynet-smoke",
            "--filter",
            "Basic-美国",
        ])

        command = private_probe.private_config_command(
            args,
            Path("/tmp/private.json"),
            Path("/tmp/meta.json"),
        )

        self.assertIn("--filter", command)
        self.assertEqual(command[command.index("--filter") + 1], "Basic-美国")

    def test_paired_parser(self) -> None:
        args = private_probe.build_parser().parse_args([
            "paired",
            "dynet-smoke",
            "--manifest",
            "/tmp/manifest.json",
            "--candidate-limit",
            "2",
            "--entry-limit",
            "3",
            "--trojan-interface-name",
            "auto",
        ])

        self.assertEqual(args.command, "paired")
        self.assertEqual(args.guest, "dynet-smoke")
        self.assertEqual(args.candidate_limit, 2)
        self.assertEqual(args.entry_limit, 3)
        self.assertTrue(args.resolve_tunnel_server)
        self.assertTrue(args.respect_schedule)
        self.assertEqual(args.trojan_interface_name, "auto")

    def test_paired_selection(self) -> None:
        args = argparse.Namespace(
            probe_type=None,
            bucket=["github"],
            domain=None,
            behavior=None,
            entry_limit=1,
        )
        manifest = {"entries": [
            paired_entry("cloudflare-head", "cloudflare", "www.cloudflare.com", 0),
            paired_entry("github-head", "github", "api.github.com", 500),
            paired_entry("github-tls", "github", "github.com", 250, probe="tls-handshake"),
        ]}

        rows = private_paired.selected_entries(manifest, args)

        self.assertEqual([row["id"] for row in rows], ["github-head"])

    def test_paired_comparison_summary(self) -> None:
        clash = {"totals": {"count": 2, "success": 1, "failure": 1, "successRate": 0.5}}
        dynet = {
            "totals": {"count": 2, "success": 2, "failure": 0, "successRate": 1.0},
            "targetHosts": ["api.github.com"],
        }
        pairs = {"schema": "pairs", "count": 2, "pairGapMs": {"p95": 10}}

        summary = comparison_summary(clash, dynet, pairs)

        self.assertEqual(summary["schema"], "dynet-clash-proof-comparison/v1alpha1")
        self.assertEqual(summary["status"], "dynet-parity-candidate")
        self.assertEqual(summary["runtimeCarrier"], "linux-interface-bound")
        self.assertEqual(summary["targetHosts"], ["api.github.com"])
        self.assertEqual(summary["totals"]["successRateDelta"], 0.5)

    def test_paired_selection_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = write_paired_source(root / "paired", dynet_failure=0)

            summary = paired_selection_summary("paired-selection", root / "out", [source])

        self.assertEqual(summary["status"], "paired-selection-product-clean")
        self.assertEqual(summary["totals"]["rows"], 2)
        self.assertEqual(summary["totals"]["failure"], 0)
        self.assertEqual(summary["selection"]["byCandidateTarget"], [
            {"key": "tunnel-002:www.cloudflare.com", "count": 1},
            {"key": "tunnel-004:api.github.com", "count": 1},
        ])
        self.assertFalse(summary["policy"]["plannerPenaltySafe"])

    def test_paired_selection_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = write_paired_source(root / "paired", dynet_failure=1)

            summary = paired_selection_summary("paired-selection", root / "out", [source])

        self.assertEqual(summary["status"], "paired-selection-needs-failure-classification")
        self.assertEqual(summary["totals"]["failure"], 1)
        self.assertEqual(summary["selection"]["failuresByCandidateTarget"], [
            {"key": "tunnel-004:api.github.com", "count": 1},
        ])

    def test_paired_pressure_join(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = write_paired_source(root / "paired", dynet_failure=0)
            pressure = root / "pressure.json"
            write_json(pressure, pressure_summary())

            summary = paired_selection_summary(
                "paired-selection",
                root / "out",
                [source],
                pressure_path=pressure,
            )

        join = summary["pressureJoin"]["rows"]
        self.assertEqual(join[0]["candidate"], "tunnel-004")
        self.assertEqual(join[0]["targetHost"], "api.github.com")
        self.assertEqual(join[0]["pairedCleanSelections"], 1)


def paired_entry(
    item_id: str,
    bucket: str,
    domain: str,
    offset: int,
    *,
    probe: str = "https-head",
) -> dict[str, object]:
    return {
        "id": item_id,
        "bucket": bucket,
        "domain": domain,
        "probe": probe,
        "scheduledOffsetMs": offset,
    }


def write_paired_source(path: Path, *, dynet_failure: int) -> Path:
    (path / "dynet").mkdir(parents=True)
    write_json(path / "comparison.json", paired_comparison(dynet_failure))
    write_json(path / "pairs.json", {"pairGapMs": {"p95": 1}})
    write_json(path / "dynet" / "summary.json", paired_dynet_summary(dynet_failure))
    return path


def paired_comparison(dynet_failure: int) -> dict[str, object]:
    dynet_success = 2 - dynet_failure
    return {
        "schema": "dynet-clash-proof-comparison/v1alpha1",
        "status": "dynet-parity-candidate" if dynet_failure == 0 else "below-parity",
        "runtimeCarrier": "linux-interface-bound",
        "totals": {
            "clash": {"count": 2, "success": 2, "failure": 0},
            "dynet": {"count": 2, "success": dynet_success, "failure": dynet_failure},
        },
        "pairedReplay": {"count": 2},
    }


def paired_dynet_summary(dynet_failure: int) -> dict[str, object]:
    return {
        "results": [
            paired_result("github", "api.github.com", "tunnel-004", ok=dynet_failure == 0),
            paired_result("cloudflare", "www.cloudflare.com", "tunnel-002", ok=True),
        ],
    }


def paired_result(
    bucket: str,
    domain: str,
    candidate: str,
    *,
    ok: bool,
) -> dict[str, object]:
    return {
        "id": f"{bucket}-head",
        "bucket": bucket,
        "domain": domain,
        "probe": "https-head",
        "boundSelected": candidate,
        "ok": ok,
        "failedStage": None if ok else "trojan-tls-handshake",
        "failureScope": "none" if ok else "bound",
        "elapsedMs": 1000,
    }


def pressure_summary() -> dict[str, object]:
    return {
        "status": "observe-only-product-clean",
        "stagePressure": {
            "rows": [
                {
                    "candidate": "tunnel-004",
                    "target": "api.github.com:443",
                    "stage": "trojan-tls-handshake",
                    "disposition": "reset",
                    "recovered": True,
                }
            ]
        },
    }


def write_json(path: Path, payload: dict[str, object]) -> None:
    path.write_text(json.dumps(payload))


if __name__ == "__main__":
    unittest.main()
