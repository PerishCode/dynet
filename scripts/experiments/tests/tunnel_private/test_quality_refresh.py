from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[4]
EXPERIMENTS = ROOT / "scripts" / "experiments"
sys.path.insert(0, str(EXPERIMENTS))

import tunnel_private_config as config
from scripts.cli import tunnel_private_lab as lab
from tunnel_private import quality_refresh

from .support import argparse_like, config_inputs_stub


class QualityRefreshTest(unittest.TestCase):
    def test_parser_mode(self) -> None:
        parser = lab.build_parser()

        args = parser.parse_args([
            "quality-refresh",
            "--output-dir",
            "/tmp/out",
            "--target-url",
            "https://chatgpt.com/",
            "--probe-mode",
            "candidate",
        ])

        self.assertEqual(args.probe_mode, "candidate")

    def test_paired_parser(self) -> None:
        parser = lab.build_parser()

        args = parser.parse_args([
            "paired",
            "--output-dir",
            "/tmp/out",
            "--manifest",
            "/tmp/manifest.json",
            "--limit",
            "2",
            "--pair-limit",
            "8",
            "--side-mode",
            "parallel",
            "--parallel-side-stagger-ms",
            "1000",
        ])

        self.assertEqual(args.limit, 2)
        self.assertEqual(args.pair_limit, 8)
        self.assertEqual(args.side_mode, "parallel")
        self.assertFalse(hasattr(args, "protocol"))

    def test_paired_temp_config(self) -> None:
        inputs = config_inputs_stub()
        inputs.candidates = [vmess_proxy("node.example.com", 443)]
        inputs.supported_candidates = list(inputs.candidates)
        inputs.selected_candidates = list(inputs.candidates)
        args = argparse_like(
            output_dir=None,
            strategy_key="cascade-quality",
            domain=[],
            domain_suffix=["github.com"],
            tcp_route_plan_private=True,
            candidate_offset=0,
            limit=1,
            pair_limit=8,
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            args.output_dir = str(Path(temp_dir) / "out")
            with (
                patch.object(lab, "config_inputs", return_value=inputs),
                patch.object(lab.paired_compare, "command_run", return_value=0) as run,
            ):
                code = lab.command_paired(args)
            meta = json.loads((Path(args.output_dir) / "meta.json").read_text())

        paired_args = run.call_args.args[0]
        self.assertEqual(code, 0)
        self.assertEqual(paired_args.limit, 8)
        self.assertTrue(str(paired_args.config).endswith("dynet-route-plan-private.json"))
        self.assertFalse(meta["privacy"]["rawSecretsStored"])

    def test_candidate_configs(self) -> None:
        inputs = config_inputs_stub()
        inputs.candidates = candidate_proxies()

        with tempfile.TemporaryDirectory() as temp_dir:
            rows = quality_refresh.candidate_config_paths(
                argparse_like(
                    strategy_key="cascade-quality",
                    domain=[],
                    domain_suffix=["chatgpt.com"],
                ),
                inputs,
                Path(temp_dir),
            )
            configs = [json.loads(path.read_text()) for _, path in rows]

        self.assertEqual([tag for tag, _ in rows], ["tunnel-001", "tunnel-002"])
        self.assertEqual(configs[0]["routes"], [{"outbound": "tunnel"}])
        self.assertFalse(any(item["tag"] == "private-via-tunnel" for item in configs[0]["outbounds"]))
        self.assertEqual(configs[1]["outbounds"][1]["tag"], "tunnel-002")

    def test_candidate_offset_tags(self) -> None:
        inputs = config_inputs_stub()
        inputs.candidates = candidate_proxies()

        with tempfile.TemporaryDirectory() as temp_dir:
            rows = quality_refresh.candidate_config_paths(
                argparse_like(
                    strategy_key="cascade-quality",
                    domain=[],
                    domain_suffix=["chatgpt.com"],
                    candidate_offset=3,
                ),
                inputs,
                Path(temp_dir),
            )
            configs = [json.loads(path.read_text()) for _, path in rows]

        self.assertEqual([tag for tag, _ in rows], ["tunnel-004", "tunnel-005"])
        self.assertEqual(configs[0]["outbounds"][1]["tag"], "tunnel-004")
        self.assertEqual(configs[1]["outbounds"][1]["tag"], "tunnel-005")

    def test_route_plan_config(self) -> None:
        inputs = config_inputs_stub()
        built = config.build_config(
            argparse_like(
                strategy_key="cascade-quality",
                domain=["api.example.com"],
                domain_suffix=["example.com"],
                tcp_route_plan_private=True,
            ),
            candidate_proxies()[:1],
            inputs.private,
        )

        self.assertEqual(built["dns"]["chains"][0]["type"], "doh")
        self.assertEqual(
            built["dns"]["chains"][0]["endpoint"],
            "https://dns.alidns.com/dns-query",
        )
        self.assertEqual(built["rules"], [])
        self.assertEqual(
            built["routes"][0],
            {
                "inbound": "tun-in",
                "transport": "tcp",
                "domain": "api.example.com",
                "outbound": "private-via-tunnel",
            },
        )
        self.assertEqual(
            built["routes"][1],
            {
                "inbound": "tun-in",
                "transport": "tcp",
                "domainSuffix": "example.com",
                "outbound": "private-via-tunnel",
            },
        )
        self.assertEqual(built["routes"][-1], {"outbound": "direct"})

    def test_candidate_item(self) -> None:
        item = quality_refresh.summary_item(
            argparse_like(
                target_url="https://chatgpt.com/",
                protocol="https-head",
                probe_mode="candidate",
            ),
            "0001-tunnel-001",
            {
                "status": "pass",
                "_exitCode": 0,
                "reason": "ok",
                "events": [
                    {
                        "kind": "outbound-graph-selected",
                        "fields": {"selected": "tunnel-001"},
                    }
                ],
            },
            Path("/tmp/report.json"),
            candidate_tag="tunnel-001",
        )

        self.assertEqual(item["id"], "0001-tunnel-001")
        self.assertEqual(item["behavior"], "tunnel-private-candidate-refresh")
        self.assertEqual(item["groupId"], "refresh-chatgpt.com-tunnel-001")
        self.assertEqual(item["candidate"], "tunnel-001")
        self.assertEqual(item["readFailure"], {})

    def test_read_failure_item(self) -> None:
        item = quality_refresh.summary_item(
            argparse_like(
                target_url="https://chatgpt.com/",
                protocol="https-head",
                probe_mode="candidate",
            ),
            "0001-tunnel-002",
            {
                "status": "deny",
                "_exitCode": 1,
                "reason": "failed TLS handshake",
                "events": [read_failure_event()],
            },
            Path("/tmp/report.json"),
            candidate_tag="tunnel-002",
        )

        self.assertEqual(item["readFailure"]["marker"], "vmess-response-header-length-pending")
        self.assertEqual(item["readFailure"]["disposition"], "pending-budget-exhausted")
        self.assertEqual(item["readFailure"]["pendingRetries"], 30)

    def test_candidate_verify(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            write_candidate_fixture(root)
            result = quality_refresh.verify(root, require_pass=False)

        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["probeMode"], "candidate")
        self.assertEqual(result["failureScopes"]["windowB"], [{"count": 1, "key": "direct"}])
        self.assertEqual(result["readFailures"]["windowB"], [{"count": 1, "key": "pending-budget-exhausted"}])
        self.assertEqual(len(result["qualityState"]["planCandidate"]), 2)
        self.assertEqual(result["qualityState"]["dialerBound"], [])


def candidate_proxies() -> list[dict[str, object]]:
    return [
        vmess_proxy("first.example.com", 10001),
        vmess_proxy("second.example.com", 10002),
    ]


def vmess_proxy(server: str, port: int) -> dict[str, object]:
    return {
        "name": server,
        "type": "vmess",
        "server": server,
        "port": port,
        "uuid": "00000000-0000-0000-0000-000000000001",
        "cipher": "auto",
    }


def read_failure_event() -> dict[str, object]:
    return {
        "kind": "outbound-stage-finished",
        "fields": {
            "error": (
                "VMess response header length is not ready: "
                "failed to read VMess response header length: Resource temporarily unavailable"
            ),
            "errorType": "vmess",
            "outbound": "tunnel-002",
            "pendingBudgetMs": "8000",
            "pendingRetries": "30",
            "stage": "stream-first-read",
            "status": "failed",
        },
    }


def write_candidate_fixture(root: Path) -> None:
    config.write_json(root / "meta.json", {"probeMode": "candidate"})
    summary = {
        "totals": {"attempted": 2, "failed": 1, "passed": 1},
        "items": [
            {
                "id": "0001-tunnel-001",
                "status": "deny",
                "failureScope": "direct",
                "selectedOutbound": "tunnel-001",
                "failedStage": "tunnel-001:stream-first-read",
                "readFailure": {
                    "disposition": "pending-budget-exhausted",
                    "marker": "vmess-response-header-length-pending",
                    "pendingBudgetMs": 8000,
                    "pendingRetries": 30,
                    "stage": "stream-first-read",
                },
            },
            {
                "id": "0001-tunnel-002",
                "status": "pass",
                "failureScope": "none",
                "selectedOutbound": "tunnel-002",
                "failedStage": None,
            },
        ],
    }
    config.write_json(root / "window-a" / "summary.json", summary)
    config.write_json(root / "window-b" / "summary.json", summary)
    write_pipeline(root / "window-a", previous_states=0, previous_attributions=0)
    write_pipeline(root / "window-b", previous_states=1, previous_attributions=1)
    config.write_json(
        root / "window-b" / "quality-state.json",
        {
            "source": {
                "retainedPreviousStates": 1,
                "retainedPreviousEntries": 2,
                "currentEntries": 2,
            },
            "outbounds": [
                quality_entry("tunnel-001", "unhealthy", 1, 2),
                quality_entry("tunnel-002", "healthy", 3, 0),
            ],
        },
    )
    config.write_json(root / "window-b" / "attribution.json", {"candidateQuality": {}})


def write_pipeline(
    root: Path,
    *,
    previous_states: int,
    previous_attributions: int,
) -> None:
    config.write_json(
        root / "quality-pipeline.json",
        {
            "previousQualityStates": previous_states,
            "previousAttributions": previous_attributions,
            "plannerFeedback": {"penaltyObservations": 0},
        },
    )


def quality_entry(
    outbound: str,
    verdict: str,
    successes: int,
    failures: int,
) -> dict[str, object]:
    attempts = successes + failures
    return {
        "outbound": outbound,
        "scope": "plan-candidate",
        "targetFamily": "chatgpt.com",
        "transport": "tcp",
        "verdict": verdict,
        "attempts": attempts,
        "successes": successes,
        "failures": failures,
        "confidence": "medium",
    }


if __name__ == "__main__":
    unittest.main()
