from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
VM_PATH = ROOT / "scripts" / "vm"
sys.path.insert(0, str(VM_PATH))

from private_runtime_lib.config import (
    POISON_BOUND_PLAN_TAG,
    POISON_DIALER_TAG,
    POISON_TAG,
    ROUTE_FALLBACK_TAG,
    augment_runtime_config,
    runtime_command,
)
from private_runtime_lib.diagnostics.quality import quality_acceptance_checks
from tests.private_runtime_fixtures import runtime_args
import private_runtime


class PrivateRuntimeConfigTest(unittest.TestCase):
    def test_poison_parser(self) -> None:
        args = private_runtime.build_parser().parse_args([
            "guest",
            "dynet-smoke",
            "--poison-first-bound-candidate",
        ])

        self.assertTrue(args.poison_first_bound_candidate)

    def test_bound_only_parser(self) -> None:
        args = private_runtime.build_parser().parse_args([
            "guest",
            "dynet-smoke",
            "--poison-bound-only",
        ])

        self.assertTrue(args.poison_bound_only)

    def test_force_parser(self) -> None:
        args = private_runtime.build_parser().parse_args([
            "guest",
            "dynet-smoke",
            "--force-bound-candidate",
            "tunnel-004",
            "--candidate-offset",
            "3",
        ])

        self.assertEqual(args.force_bound_candidate, "tunnel-004")
        self.assertEqual(args.candidate_offset, 3)

    def test_route_plan_parser(self) -> None:
        args = private_runtime.build_parser().parse_args([
            "guest",
            "dynet-smoke",
            "--tcp-route-plan-private",
        ])

        self.assertTrue(args.tcp_route_plan_private)

    def test_route_fallback_parser(self) -> None:
        args = private_runtime.build_parser().parse_args([
            "guest",
            "dynet-smoke",
            "--tcp-route-direct-fallback",
        ])

        self.assertTrue(args.tcp_route_direct_fallback)

    def test_non_direct_parser(self) -> None:
        args = private_runtime.build_parser().parse_args([
            "guest",
            "dynet-smoke",
            "--tcp-route-non-direct-fallback",
        ])

        self.assertTrue(args.tcp_route_non_direct_fallback)

    def test_udp_dns_parser(self) -> None:
        args = private_runtime.build_parser().parse_args([
            "guest",
            "dynet-smoke",
            "--runtime-udp-dns",
        ])

        self.assertTrue(args.runtime_udp_dns)

    def test_tcp_probe_parser(self) -> None:
        args = private_runtime.build_parser().parse_args([
            "guest",
            "dynet-smoke",
            "--no-tcp-probe",
        ])

        self.assertFalse(args.tcp_probe)

    def test_tcp_timeouts(self) -> None:
        args = runtime_args(tcp_forward=True)
        args.outbound_tcp_connect_timeout_ms = 1200
        args.outbound_tcp_read_write_timeout_ms = 3400
        command = runtime_command(
            "test",
            "/tmp/dynet.json",
            "/tmp/quality.json",
            None,
            ["chatgpt.com"],
            args,
        )

        self.assertIn("--outbound-tcp-connect-timeout-ms 1200", command)
        self.assertIn("--outbound-tcp-read-write-timeout-ms 3400", command)

    def test_config_dns_default(self) -> None:
        args = runtime_args(tcp_forward=True)
        command = runtime_command(
            "test",
            "/tmp/dynet.json",
            "/tmp/quality.json",
            None,
            ["chatgpt.com"],
            args,
        )

        self.assertNotIn("--upstream-dns", command)

    def test_udp_dns_override(self) -> None:
        args = runtime_args(tcp_forward=True)
        args.runtime_udp_dns = True
        command = runtime_command(
            "test",
            "/tmp/dynet.json",
            "/tmp/quality.json",
            None,
            ["chatgpt.com"],
            args,
        )

        self.assertIn("--upstream-dns 8.8.8.8:53", command)

    def test_poison_config(self) -> None:
        args = runtime_args(tcp_forward=True)
        args.poison_first_bound_candidate = True
        config = {
            "outbounds": [
                {"tag": "direct", "type": "direct"},
                {
                    "tag": "tunnel",
                    "type": "plan",
                    "payload": {"selection": {"edges": [{"type": "candidate", "to": "tunnel-001"}]}},
                },
            ]
        }

        augmented = json.loads(augment_runtime_config(json.dumps(config), args))

        tunnel = next(item for item in augmented["outbounds"] if item["tag"] == "tunnel")
        edges = tunnel["payload"]["selection"]["edges"]
        self.assertEqual(edges[0], {"type": "candidate", "to": POISON_TAG})
        self.assertEqual(augmented["outbounds"][1]["tag"], POISON_TAG)

    def test_bound_only_config(self) -> None:
        args = runtime_args(tcp_forward=True)
        args.poison_bound_only = True
        config = {
            "outbounds": [
                {"tag": "direct", "type": "direct"},
                {"tag": "tunnel-001", "type": "vmess"},
                {
                    "tag": "tunnel",
                    "type": "plan",
                    "payload": {
                        "selection": {
                            "edges": [
                                {"type": "candidate", "to": "tunnel-001"},
                                {"type": "candidate", "to": "tunnel-002"},
                            ]
                        }
                    },
                },
            ]
        }

        augmented = json.loads(augment_runtime_config(json.dumps(config), args))

        tunnel = next(item for item in augmented["outbounds"] if item["tag"] == "tunnel")
        self.assertEqual(
            tunnel["payload"]["selection"]["edges"],
            [{"type": "candidate", "to": POISON_TAG}],
        )
        self.assertEqual(augmented["outbounds"][1]["tag"], POISON_TAG)

    def test_force_config(self) -> None:
        args = runtime_args(tcp_forward=True)
        args.force_bound_candidate = "tunnel-004"
        config = {
            "outbounds": [
                {"tag": "direct", "type": "direct"},
                {"tag": "tunnel-001", "type": "trojan"},
                {"tag": "tunnel-004", "type": "trojan"},
                {
                    "tag": "tunnel",
                    "type": "plan",
                    "payload": {
                        "selection": {
                            "edges": [
                                {"type": "candidate", "to": "tunnel-001"},
                                {"type": "candidate", "to": "tunnel-004"},
                            ]
                        }
                    },
                },
            ]
        }

        augmented = json.loads(augment_runtime_config(json.dumps(config), args))

        tunnel = next(item for item in augmented["outbounds"] if item["tag"] == "tunnel")
        self.assertEqual(
            tunnel["payload"]["selection"]["edges"],
            [{"type": "candidate", "to": "tunnel-004"}],
        )

    def test_direct_fallback_config(self) -> None:
        args = runtime_args(tcp_forward=True)
        args.tcp_route_plan_private = True
        args.tcp_route_direct_fallback = True
        config = {
            "outbounds": [
                {"tag": "direct", "type": "direct"},
                {"tag": "private-via-tunnel", "type": "dialer"},
            ],
            "routes": [
                {
                    "inbound": "tun-in",
                    "transport": "tcp",
                    "domainSuffix": "example.com",
                    "outbound": "private-via-tunnel",
                },
                {"outbound": "direct"},
            ],
        }

        augmented = json.loads(augment_runtime_config(json.dumps(config), args))

        route = augmented["routes"][0]
        self.assertEqual(route["outbound"], ROUTE_FALLBACK_TAG)
        fallback = next(item for item in augmented["outbounds"] if item["tag"] == ROUTE_FALLBACK_TAG)
        self.assertEqual(
            fallback["payload"]["selection"]["edges"],
            [
                {"type": "candidate", "to": "private-via-tunnel"},
                {"type": "candidate", "to": "direct"},
            ],
        )

    def test_non_direct_config(self) -> None:
        args = runtime_args(tcp_forward=True)
        args.tcp_route_plan_private = True
        args.tcp_route_non_direct_fallback = True
        config = {
            "outbounds": [
                {"tag": "direct", "type": "direct"},
                {"tag": "private", "type": "trojan"},
                {"tag": "tunnel-001", "type": "trojan"},
                {
                    "tag": "tunnel",
                    "type": "plan",
                    "payload": {"selection": {"edges": [{"type": "candidate", "to": "tunnel-001"}]}},
                },
                {
                    "tag": "private-via-tunnel",
                    "type": "dialer",
                    "payload": {"bound": "tunnel", "target": "private"},
                },
            ],
            "routes": [
                {
                    "inbound": "tun-in",
                    "transport": "tcp",
                    "domainSuffix": "example.com",
                    "outbound": "private-via-tunnel",
                },
            ],
        }

        augmented = json.loads(augment_runtime_config(json.dumps(config), args))

        route = augmented["routes"][0]
        self.assertEqual(route["outbound"], ROUTE_FALLBACK_TAG)
        tunnel = next(item for item in augmented["outbounds"] if item["tag"] == "tunnel")
        self.assertEqual(
            tunnel["payload"]["selection"]["edges"],
            [{"type": "candidate", "to": "tunnel-001"}],
        )
        poison_bound = next(item for item in augmented["outbounds"] if item["tag"] == POISON_BOUND_PLAN_TAG)
        self.assertEqual(
            poison_bound["payload"]["selection"]["edges"],
            [{"type": "candidate", "to": POISON_TAG}],
        )
        poison_dialer = next(
            item
            for item in augmented["outbounds"]
            if item["tag"] == POISON_DIALER_TAG
        )
        self.assertEqual(poison_dialer["payload"]["bound"], POISON_BOUND_PLAN_TAG)
        self.assertEqual(poison_dialer["payload"]["target"], "private")
        fallback = next(item for item in augmented["outbounds"] if item["tag"] == ROUTE_FALLBACK_TAG)
        self.assertEqual(
            fallback["payload"]["selection"]["edges"],
            [
                {"type": "candidate", "to": POISON_DIALER_TAG},
                {"type": "candidate", "to": "private-via-tunnel"},
            ],
        )

    def test_fallback_requires_plan(self) -> None:
        args = runtime_args(tcp_forward=True)
        args.tcp_route_direct_fallback = True

        with self.assertRaisesRegex(Exception, "requires --tcp-route-plan-private"):
            augment_runtime_config(json.dumps({"outbounds": [], "routes": []}), args)

    def test_route_requires_plan(self) -> None:
        args = runtime_args(tcp_forward=True)
        args.tcp_route_non_direct_fallback = True

        with self.assertRaisesRegex(Exception, "requires --tcp-route-plan-private"):
            augment_runtime_config(json.dumps({"outbounds": [], "routes": []}), args)

    def test_route_fallback_conflict(self) -> None:
        args = runtime_args(tcp_forward=True)
        args.tcp_route_plan_private = True
        args.tcp_route_direct_fallback = True
        args.tcp_route_non_direct_fallback = True

        with self.assertRaisesRegex(Exception, "cannot be combined"):
            augment_runtime_config(json.dumps({"outbounds": [], "routes": []}), args)

    def test_route_poison_conflict(self) -> None:
        args = runtime_args(tcp_forward=True)
        args.tcp_route_plan_private = True
        args.tcp_route_non_direct_fallback = True
        args.poison_bound_only = True

        with self.assertRaisesRegex(Exception, "cannot be combined"):
            augment_runtime_config(json.dumps({"outbounds": [], "routes": []}), args)

    def test_route_quality(self) -> None:
        report = quality_report([
            quality_row("primary", has_quality=False, best=True),
            quality_row("fallback", has_quality=True, best=True),
        ])

        generic = {
            item["name"]: item["passed"]
            for item in quality_acceptance_checks(report)
        }
        fallback = {
            item["name"]: item["passed"]
            for item in quality_acceptance_checks(report, route_non_direct_fallback=True)
        }

        self.assertFalse(generic["quality-bound-selected-has-quality"])
        self.assertTrue(all(fallback.values()), fallback)

    def test_route_retry_quality(self) -> None:
        report = quality_report([
            quality_row("primary", has_quality=False, best=True),
            quality_row("fallback", has_quality=True, best=True),
            quality_row("fallback", has_quality=True, best=False),
        ])

        checks = {
            item["name"]: item["passed"]
            for item in quality_acceptance_checks(report, route_non_direct_fallback=True)
        }

        self.assertTrue(all(checks.values()), checks)

    def test_force_poison_conflict(self) -> None:
        args = runtime_args(tcp_forward=True)
        args.force_bound_candidate = "tunnel-004"
        args.poison_first_bound_candidate = True

        with self.assertRaisesRegex(Exception, "cannot be combined"):
            augment_runtime_config(json.dumps({"outbounds": []}), args)

    def test_bound_only_conflict(self) -> None:
        args = runtime_args(tcp_forward=True)
        args.poison_bound_only = True
        args.poison_first_bound_candidate = True

        with self.assertRaisesRegex(Exception, "cannot be combined"):
            augment_runtime_config(json.dumps({"outbounds": []}), args)


def quality_report(rows: list[dict]) -> dict:
    fallback_rows = [row for row in rows if row["selectionRole"] == "fallback"]
    return {
        "_selectionBrief": {
            "boundSelection": {
                "candidateSets": 1,
                "attemptCandidateSets": len(rows),
                "fallbackCandidateSets": len(fallback_rows),
                "withBoundSelected": 1,
                "selectedWithQuality": 0,
                "selectedBehind": 0,
                "fallbackSelectedWithQuality": sum(
                    1 for row in fallback_rows if row["selectedHasQuality"]
                ),
                "fallbackSelectedBehind": sum(
                    1 for row in fallback_rows if not row["selectedBest"]
                ),
                "rows": rows,
            }
        }
    }


def quality_row(role: str, has_quality: bool, best: bool) -> dict:
    return {
        "selectionRole": role,
        "selectedHasQuality": has_quality,
        "selectedBest": best,
    }


if __name__ == "__main__":
    unittest.main()
