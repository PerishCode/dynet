from __future__ import annotations

import argparse
import contextlib
import io
import socket
import ssl
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
EXPERIMENTS = ROOT / "scripts" / "experiments"
sys.path.insert(0, str(EXPERIMENTS))

from scripts.cli import tunnel_private_lab as lab
from tunnel_private.quality import adapter_readiness, transport

from .support import (
    adapter_matrix_compare_summary,
    adapter_matrix_summary,
    adapter_regression_summary,
    adapter_sweep_summary,
    adapter_vm_private_summary,
    blocked_transport_summary,
    config_inputs_stub,
    product_transport_summary,
    runtime_summary,
    write_adapter_json,
)


class TransportCheckTest(unittest.TestCase):
    def test_parser(self) -> None:
        parser = lab.build_parser()

        args = parser.parse_args([
            "transport-check",
            "--output-dir",
            "/tmp/out",
            "--supported-type",
            "trojan",
            "--candidate-offset",
            "4",
        ])

        self.assertEqual(args.command, "transport-check")
        self.assertEqual(args.check, "trojan-tls")
        self.assertEqual(args.candidate_offset, 4)

        go_args = parser.parse_args([
            "transport-check",
            "--output-dir",
            "/tmp/out",
            "--check",
            "go-tls",
        ])
        self.assertEqual(go_args.check, "go-tls")
        utls_args = parser.parse_args([
            "transport-check",
            "--output-dir",
            "/tmp/out",
            "--check",
            "utls",
            "--utls-fingerprint",
            "chrome",
        ])
        self.assertEqual(utls_args.check, "utls")
        self.assertEqual(utls_args.utls_fingerprint, ["chrome"])
        mihomo_args = parser.parse_args([
            "transport-check",
            "--output-dir",
            "/tmp/out",
            "--check",
            "mihomo-proxy",
            "--mihomo-interface-name",
            "en0",
        ])
        self.assertEqual(mihomo_args.check, "mihomo-proxy")
        self.assertEqual(mihomo_args.mihomo_interface_name, "en0")
        mihomo_delay_args = parser.parse_args([
            "transport-check",
            "--output-dir",
            "/tmp/out",
            "--check",
            "mihomo-delay",
        ])
        self.assertEqual(mihomo_delay_args.check, "mihomo-delay")

    def test_evidence_parser(self) -> None:
        parser = lab.build_parser()

        args = parser.parse_args([
            "transport-evidence",
            "--output-dir",
            "/tmp/out",
            "--transport-summary",
            "/tmp/clash.json",
            "--transport-summary",
            "/tmp/mihomo.json",
        ])

        self.assertEqual(args.command, "transport-evidence")
        self.assertEqual(args.transport_summary, ["/tmp/clash.json", "/tmp/mihomo.json"])

    def test_adapter_parser(self) -> None:
        parser = lab.build_parser()

        args = parser.parse_args([
            "adapter-readiness",
            "--output-dir",
            "/tmp/out",
            "--adapter-type",
            "vmess",
            "--product-evidence",
            "/tmp/sweep.json",
            "--runtime-evidence",
            "/tmp/runtime.json",
            "--transport-evidence",
            "/tmp/transport.json",
        ])

        self.assertEqual(args.command, "adapter-readiness")
        self.assertEqual(args.adapter_type, "vmess")
        self.assertEqual(args.product_evidence, ["/tmp/sweep.json"])
        self.assertEqual(args.runtime_evidence, ["/tmp/runtime.json"])
        self.assertEqual(args.transport_evidence, ["/tmp/transport.json"])

    def test_clash_delay_parser(self) -> None:
        parser = lab.build_parser()

        args = parser.parse_args([
            "transport-check",
            "--output-dir",
            "/tmp/out",
            "--check",
            "clash-delay",
            "--clash-controller-unix-socket",
            "/tmp/mihomo.sock",
            "--clash-delay-url",
            "https://example.com/generate_204",
        ])

        self.assertEqual(args.check, "clash-delay")
        self.assertEqual(args.clash_controller_unix_socket, "/tmp/mihomo.sock")
        self.assertEqual(args.clash_delay_url, "https://example.com/generate_204")

    def test_summary(self) -> None:
        summary = transport.transport_summary(
            argparse.Namespace(check="trojan-tls"),
            config_inputs_stub(),
            [
                {"tag": "tunnel-001", "outcome": "tls-handshake-eof"},
                {"tag": "tunnel-002", "outcome": "tls-handshake-pass"},
                {"tag": "tunnel-003", "outcome": "tls-handshake-eof"},
            ],
        )

        self.assertEqual(summary["schema"], transport.TRANSPORT_SCHEMA)
        self.assertEqual(
            summary["outcomeCounts"],
            {"tls-handshake-eof": 2, "tls-handshake-pass": 1},
        )
        self.assertFalse(summary["privacy"]["rawSecretsStored"])
        self.assertFalse(summary["privacy"]["rawNodeNamesStored"])

    def test_baseline_comparison(self) -> None:
        report = transport.baseline_comparison(
            [
                {"tag": "tunnel-001", "outcome": "clash-delay-pass"},
                {"tag": "tunnel-002", "outcome": "clash-delay-timeout"},
            ],
            [
                {
                    "check": "trojan-tls",
                    "outcomeCounts": {"tls-handshake-eof": 2},
                    "rows": [
                        {"tag": "tunnel-001", "outcome": "tls-handshake-eof"},
                        {"tag": "tunnel-002", "outcome": "tls-handshake-eof"},
                    ],
                }
            ],
        )

        self.assertEqual(
            report["conclusionCounts"],
            {"both-fail": 1, "current-pass-baseline-fail": 1},
        )
        self.assertEqual(report["baselineOutcomeCounts"], {"tls-handshake-eof": 2})

    def test_adapter_ready(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            sweep = root / "sweep.json"
            direct = root / "direct.json"
            runtime = root / "runtime.json"
            write_adapter_json(sweep, adapter_sweep_summary())
            write_adapter_json(direct, adapter_regression_summary(gate_mode="direct"))
            write_adapter_json(runtime, runtime_summary())

            summary = adapter_readiness.adapter_readiness_summary(
                "vmess",
                [sweep, direct],
                [runtime],
                [],
            )

        self.assertEqual(summary["status"], "ready")
        self.assertTrue(summary["conclusion"]["readyForMainlineAdapterWork"])
        self.assertTrue(summary["conclusion"]["directControlClean"])
        self.assertTrue(summary["conclusion"]["runtimeClean"])
        self.assertEqual(summary["productEvidence"]["product-e2e"]["runs"], 4)
        self.assertEqual(summary["productEvidence"]["direct-control"]["runs"], 1)
        self.assertEqual(summary["runtimeEvidence"]["tcpClosedSessions"], 2)
        self.assertEqual(summary["runtimeEvidence"]["workloadAttempted"], 4)
        self.assertEqual(summary["runtimeEvidence"]["workloadSuccess"], 4)
        self.assertEqual(summary["runtimeEvidence"]["workloadFlowMatchedEntries"], 4)
        self.assertEqual(summary["runtimeEvidence"]["tcpFlowPathComplete"], 4)
        self.assertEqual(summary["runtimeEvidence"]["tcpFlowPayloadBidirectional"], 4)
        self.assertEqual(summary["runtimeEvidence"]["qualityBoundFallbackCandidateSets"], 1)
        self.assertEqual(summary["runtimeEvidence"]["qualityBoundFallbackSelectedBehind"], 1)
        self.assertEqual(summary["transportEvidence"]["adapterWorkSignal"], "no-transport-evidence")
        self.assertEqual(summary["transportEvidence"]["nextProof"], "no-transport-proof-required-for-current-gate")
        self.assertTrue(summary["conclusion"]["protocolFollowupOpen"])
        self.assertEqual(
            summary["conclusion"]["protocolNextProof"],
            "collect-runtime-stage-repeat-for-read-marker-before-adapter-claim",
        )
        self.assertEqual(summary["protocolFollowup"]["strictFailures"], 1)
        self.assertEqual(
            summary["protocolFollowup"]["readMarkers"],
            [{"key": "vmess-response-header-length-eof", "count": 1}],
        )
        self.assertEqual(
            [item["id"] for item in summary["conclusion"]["nextActions"]],
            [
                "collect-runtime-stage-repeat-for-read-marker-before-adapter-claim",
                "start-mainline-adapter-runtime-work",
            ],
        )
        self.assertFalse(summary["conclusion"]["nextActions"][0]["plannerPenaltySafe"])

    def test_adapter_transport_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            product = root / "trojan-product.json"
            transport_summary_path = root / "trojan-transport.json"
            write_adapter_json(
                product,
                adapter_regression_summary(
                    gate_mode="product",
                    status="fail",
                    strict_status="fail",
                ),
            )
            write_adapter_json(transport_summary_path, blocked_transport_summary())

            summary = adapter_readiness.adapter_readiness_summary(
                "trojan",
                [product],
                [],
                [transport_summary_path],
            )

        self.assertEqual(summary["status"], "not-ready")
        self.assertFalse(summary["conclusion"]["readyForMainlineAdapterWork"])
        self.assertIn("transport-product-e2e-failed", summary["conclusion"]["notReadyReasons"])
        self.assertEqual(summary["recommendedUse"], "do-not-use-for-adapter-claims")
        transport = summary["transportEvidence"]
        self.assertEqual(transport["adapterWorkSignal"], "transport-product-e2e-blocked")
        self.assertEqual(transport["nextProof"], "collect-sanitized-product-e2e-pass-before-adapter-compat-claim")
        self.assertEqual(
            [item["id"] for item in summary["conclusion"]["nextActions"]],
            [
                "fix-product-e2e-gate",
                "collect-sanitized-product-e2e-pass",
                "review-strict-control-failure-before-adapter-claim",
            ],
        )
        self.assertIn(
            "transport-product-e2e-failed",
            summary["conclusion"]["nextActions"][0]["notReadyReasons"],
        )

    def test_runtime_closes_proof(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            product = root / "product.json"
            runtime = root / "runtime.json"
            transport = root / "transport.json"
            write_adapter_json(product, adapter_vm_private_summary())
            write_adapter_json(runtime, runtime_summary())
            write_adapter_json(transport, product_transport_summary())

            summary = adapter_readiness.adapter_readiness_summary(
                "trojan",
                [product],
                [runtime],
                [transport],
            )

        self.assertEqual(summary["status"], "ready")
        self.assertTrue(summary["conclusion"]["runtimeClean"])
        self.assertEqual(
            summary["transportEvidence"]["nextProof"],
            "join-product-baseline-with-dynet-runtime-stage-evidence",
        )
        self.assertEqual(
            summary["conclusion"]["transportNextProof"],
            "runtime-stage-evidence-clean",
        )

    def test_matrix_compare_gate(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            product = root / "matrix-compare.json"
            write_adapter_json(product, adapter_matrix_compare_summary())

            summary = adapter_readiness.adapter_readiness_summary(
                "trojan",
                [product],
                [],
                [],
            )

        product_e2e = summary["productEvidence"]["product-e2e"]
        self.assertEqual(summary["status"], "not-ready")
        self.assertEqual(product_e2e["runs"], 3)
        self.assertEqual(product_e2e["failed"], 1)
        self.assertEqual(product_e2e["matrixFailures"], 2)
        self.assertEqual(product_e2e["targets"], ["https://api.github.com/"])
        self.assertEqual(product_e2e["markerSummary"], {"trojan-tls-handshake-eof": 2})
        self.assertIn("matrix-compare-has-failures", product_e2e["requiredGateFailures"])
        self.assertEqual(product_e2e["failureStageSummary"], {"unknown": 1})
        self.assertEqual(product_e2e["failureLabelSummary"], {"unknown": 1})
        self.assertEqual(
            summary["conclusion"]["nextActions"][0]["id"],
            "fix-product-e2e-gate",
        )

    def test_matrix_product_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            product = root / "matrix.json"
            write_adapter_json(product, adapter_matrix_summary())

            summary = adapter_readiness.adapter_readiness_summary(
                "vmess",
                [product],
                [],
                [],
            )

        product_e2e = summary["productEvidence"]["product-e2e"]
        self.assertEqual(summary["status"], "ready")
        self.assertEqual(product_e2e["runs"], 1)
        self.assertEqual(product_e2e["failed"], 0)
        self.assertEqual(product_e2e["matrixFailures"], 0)
        self.assertEqual(product_e2e["targets"], ["https://chatgpt.com/"])
        self.assertFalse(summary["protocolFollowup"]["open"])
        self.assertEqual(
            summary["protocolFollowup"]["nextProof"],
            "no-current-protocol-follow-up",
        )
        self.assertEqual(
            summary["conclusion"]["nextActions"][0]["id"],
            "start-mainline-adapter-runtime-work",
        )

    def test_missing_product_action(self) -> None:
        summary = adapter_readiness.adapter_readiness_summary("trojan", [], [], [])

        self.assertEqual(summary["status"], "needs-evidence")
        self.assertEqual(
            summary["conclusion"]["nextActions"][0]["id"],
            "collect-product-e2e-evidence",
        )
        self.assertFalse(summary["conclusion"]["nextActions"][0]["plannerPenaltySafe"])

    def test_adapter_command(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            sweep = root / "sweep.json"
            output = root / "out"
            write_adapter_json(sweep, adapter_sweep_summary())

            with contextlib.redirect_stdout(io.StringIO()):
                status = adapter_readiness.command_adapter_readiness(
                    argparse.Namespace(
                        output_dir=str(output),
                        adapter_type="vmess",
                        product_evidence=[str(sweep)],
                        runtime_evidence=[],
                        transport_evidence=[],
                    )
                )

            self.assertEqual(status, 0)
            self.assertTrue((output / "summary.json").exists())
            self.assertTrue((output / "summary.md").exists())

    def test_curl_result(self) -> None:
        pass_result = transport.classify_curl_result(0, "204 ")
        self.assertEqual(pass_result["outcome"], "mihomo-proxy-pass")
        self.assertEqual(pass_result["curlStageMarkerCounts"], {})
        self.assertEqual(
            transport.classify_curl_result(35, "000 tls error")["outcome"],
            "mihomo-proxy-tls-error",
        )

    def test_clash_delay_check(self) -> None:
        original = transport.clash_delay_payload
        self.addCleanup(lambda: setattr(transport, "clash_delay_payload", original))
        transport.clash_delay_payload = lambda _args, _name: {"delay": 123}

        row = transport.check_candidate(
            argparse.Namespace(
                check="clash-delay",
                clash_delay_url="https://example.com/generate_204",
                timeout_seconds=5.0,
            ),
            {"name": "raw-node-name", "type": "trojan", "server": "s", "port": 443},
            "tunnel-001",
        )

        self.assertEqual(row["outcome"], "clash-delay-pass")
        self.assertEqual(row["delayMs"], 123)
        self.assertNotIn("name", row["candidate"])

    def test_go_tls_check(self) -> None:
        original = transport.go_tls_payload
        self.addCleanup(lambda: setattr(transport, "go_tls_payload", original))
        transport.go_tls_payload = lambda _proxy, _timeout: {"ok": True, "version": "TLS 1.3"}

        row = transport.check_candidate(
            argparse.Namespace(check="go-tls", timeout_seconds=5.0),
            {"type": "trojan", "server": "s", "port": 443},
            "tunnel-001",
        )

        self.assertEqual(row["outcome"], "go-tls-pass")
        self.assertEqual(row["tlsVersion"], "TLS 1.3")

    def test_utls_check(self) -> None:
        original = transport.utls_payload
        self.addCleanup(lambda: setattr(transport, "utls_payload", original))
        transport.utls_payload = lambda _proxy, _timeout, _fps: {
            "results": [
                {"fingerprint": "chrome", "ok": False, "message": "unexpected EOF"},
                {"fingerprint": "firefox", "ok": True, "version": "TLS 1.3"},
            ]
        }

        row = transport.check_candidate(
            argparse.Namespace(check="utls", timeout_seconds=5.0, utls_fingerprint=None),
            {"type": "trojan", "server": "s", "port": 443},
            "tunnel-001",
        )

        self.assertEqual(row["outcome"], "utls-pass")
        self.assertEqual(row["matchedFingerprint"], "firefox")
        self.assertEqual(row["fingerprints"][0]["outcome"], "eof")

    def test_clash_delay_errors(self) -> None:
        self.assertEqual(
            transport.classify_clash_delay_payload({"message": "context deadline exceeded"}),
            "clash-delay-timeout",
        )
        self.assertEqual(
            transport.classify_clash_delay_payload({"message": "unexpected EOF"}),
            "clash-delay-eof",
        )
        self.assertEqual(
            transport.classify_go_tls_payload({"ok": False, "message": "unexpected EOF"}),
            "go-tls-eof",
        )
        self.assertEqual(
            transport.classify_utls_payload(
                {"results": [{"ok": False, "message": "unexpected EOF"}]}
            ),
            "utls-eof",
        )

    def test_error_type(self) -> None:
        self.assertEqual(
            transport.classify_transport_error(ssl.SSLEOFError("eof")),
            "tls-handshake-eof",
        )
        self.assertEqual(
            transport.classify_transport_error(socket.timeout("timed out")),
            "timeout",
        )


if __name__ == "__main__":
    unittest.main()
