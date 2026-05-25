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
from tunnel_private import compare, matrix, owned_private, target_observer
from tunnel_private import quality_refresh

from .support import (
    argparse_like,
    case_summary,
    compare_matrix,
    config_inputs_stub,
    observer_summary,
    owned_summary,
    report_with_failure,
    write_refresh_fixture,
)


class TunnelPrivateLabTest(unittest.TestCase):
    def test_supported_type_override(self) -> None:
        parser = lab.build_parser()

        args = parser.parse_args([
            "build",
            "--output-config",
            "/tmp/secret.json",
            "--output-meta",
            "/tmp/meta.json",
            "--supported-type",
            "vmess",
            "--candidate-offset",
            "8",
        ])

        self.assertEqual(args.supported_type, ["vmess"])
        self.assertEqual(args.candidate_offset, 8)

    def test_private_command(self) -> None:
        parser = lab.build_parser()

        args = parser.parse_args([
            "probe-private",
            "--output-dir",
            "/tmp/out",
            "--target-url",
            "https://example.com/",
            "--protocol",
            "tcp-connect",
        ])

        self.assertEqual(args.target_url, "https://example.com/")
        self.assertEqual(args.protocol, "tcp-connect")

    def test_matrix_command(self) -> None:
        parser = lab.build_parser()

        args = parser.parse_args([
            "matrix",
            "--output-dir",
            "/tmp/out",
            "--target-url",
            "https://example.com/",
            "--supported-type",
            "vmess",
        ])

        self.assertEqual(args.target_url, "https://example.com/")
        self.assertEqual(args.supported_type, ["vmess"])
        self.assertFalse(hasattr(args, "protocol"))

    def test_compare_matrices_command(self) -> None:
        parser = lab.build_parser()

        args = parser.parse_args([
            "compare-matrices",
            "--output-dir",
            "/tmp/out",
            "--matrix",
            "/tmp/first/matrix.json",
            "--matrix",
            "/tmp/second/matrix.json",
        ])

        self.assertEqual(args.matrix, ["/tmp/first/matrix.json", "/tmp/second/matrix.json"])
        self.assertFalse(hasattr(args, "protocol"))

    def test_compare_writes_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            first = write_matrix_fixture(root / "first" / "matrix.json", "https://chatgpt.com/")
            second = write_matrix_fixture(root / "second" / "matrix.json", "https://example.com/")
            output_dir = root / "out"

            code = lab.command_compare_matrices(
                argparse_like(
                    output_dir=str(output_dir),
                    matrix=[str(first), str(second)],
                )
            )

            summary = json.loads((output_dir / "summary.json").read_text())

        self.assertEqual(code, 0)
        self.assertEqual(summary["schema"], compare.COMPARE_SCHEMA)
        self.assertEqual(summary["totals"]["matrices"], 2)
        self.assertEqual(summary["controlSummary"]["nestedTlsReadMissing"], 2)

    def test_observe_target_command(self) -> None:
        parser = lab.build_parser()

        args = parser.parse_args([
            "observe-target",
            "--output-dir",
            "/tmp/out",
            "--target-host",
            "198.51.100.1.sslip.io",
            "--supported-type",
            "vmess",
        ])

        self.assertEqual(args.target_host, "198.51.100.1.sslip.io")
        self.assertEqual(args.ssh_host, "bandwagon")
        self.assertFalse(hasattr(args, "protocol"))

    def test_owned_private_command(self) -> None:
        parser = lab.build_parser()

        args = parser.parse_args([
            "observe-owned-private",
            "--output-dir",
            "/tmp/out",
            "--private-host",
            "198.51.100.1.sslip.io",
            "--supported-type",
            "vmess",
        ])

        self.assertEqual(args.private_host, "198.51.100.1.sslip.io")
        self.assertEqual(args.ssh_host, "fuisp")
        self.assertFalse(hasattr(args, "protocol"))

    def test_quality_refresh_command(self) -> None:
        parser = lab.build_parser()

        args = parser.parse_args([
            "quality-refresh",
            "--output-dir",
            "/tmp/out",
            "--target-url",
            "https://chatgpt.com/",
            "--protocol",
            "tcp-connect",
            "--window-size",
            "3",
            "--initial-quality-state",
            "/tmp/quality-state.json",
            "--initial-attribution",
            "/tmp/attribution.json",
            "--allow-failures",
        ])

        self.assertEqual(args.protocol, "tcp-connect")
        self.assertIsNone(args.inbound)
        self.assertEqual(args.window_size, 3)
        self.assertEqual(args.initial_quality_state, "/tmp/quality-state.json")
        self.assertEqual(args.initial_attribution, "/tmp/attribution.json")
        self.assertTrue(args.allow_failures)

    def test_probe_forwards_inbound(self) -> None:
        completed = argparse_like(
            stdout='{"schema":"dynet-probe/v1alpha1","status":"pass","events":[]}',
            stderr="",
            returncode=0,
        )
        args = argparse_like(
            dynet_bin="dynet",
            target_url="https://example.com/",
            protocol="https-head",
            quality_state=None,
            inbound="tun-in",
        )

        with patch.object(lab.subprocess, "run", return_value=completed) as run:
            report = lab.run_probe(args, Path("/tmp/config.json"))

        command = run.call_args.args[0]
        self.assertEqual(report["_exitCode"], 0)
        self.assertIn("--inbound", command)
        self.assertIn("tun-in", command)

    def test_inspect_plan_quality(self) -> None:
        parser = lab.build_parser()

        args = parser.parse_args([
            "inspect-plan-quality",
            "--output-dir",
            "/tmp/out",
            "--target-url",
            "https://chatgpt.com/",
            "--quality-state",
            "/tmp/quality-state.json",
        ])

        self.assertEqual(args.target_url, "https://chatgpt.com/")
        self.assertEqual(args.quality_state, "/tmp/quality-state.json")
        self.assertFalse(hasattr(args, "protocol"))

    def test_compare_quality_command(self) -> None:
        parser = lab.build_parser()

        args = parser.parse_args([
            "compare-plan-quality",
            "--output-dir",
            "/tmp/out",
            "--inspection",
            "/tmp/observe/summary.json",
            "--inspection",
            "/tmp/auto/summary.json",
        ])

        self.assertEqual(args.inspection, ["/tmp/observe/summary.json", "/tmp/auto/summary.json"])
        self.assertFalse(hasattr(args, "protocol"))

    def test_refresh_verification(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            write_refresh_fixture(root)
            verification = quality_refresh.verify(root, require_pass=False)

        self.assertEqual(verification["status"], "pass")
        self.assertEqual(
            verification["windowPipelines"]["windowA"]["previousQualityStates"],
            0,
        )
        self.assertEqual(
            verification["failureScopes"]["windowB"],
            [{"count": 1, "key": "downstream"}],
        )
        self.assertEqual(
            verification["failures"]["windowB"],
            [
                {
                    "id": "0001",
                    "status": "deny",
                    "failureScope": "downstream",
                    "selectedOutbound": "private-via-tunnel",
                    "failedStage": "private-via-tunnel:stream-first-read",
                }
            ],
        )
        self.assertEqual(
            verification["boundSelection"]["windowB"]["bySelected"],
            [{"count": 1, "key": "tunnel-001"}],
        )

    def test_clean_report(self) -> None:
        report = {
            "schema": "dynet-probe/v1alpha1",
            "reason": "failed TLS with `node.example.com`: 198.51.100.1:443",
            "_exitCode": 1,
            "events": [
                {
                    "kind": "outbound-stage-finished",
                    "fields": {
                        "target": "198.51.100.1:8388",
                        "error": "failed with `node.example.com`",
                        "reason": "dialer `private-via-tunnel` failed `node.example.com`",
                        "errorType": "trojan",
                    },
                }
            ],
        }

        cleaned = lab.clean_report(report)

        self.assertNotIn("_exitCode", cleaned)
        self.assertEqual(
            cleaned["reason"],
            "failed TLS with `<redacted>`: <redacted-ip-port>",
        )
        fields = cleaned["events"][0]["fields"]
        self.assertEqual(fields["target"], "<redacted-target>")
        self.assertEqual(fields["error"], "failed with `<redacted>`")
        self.assertEqual(fields["reason"], "dialer `<redacted>` failed `<redacted>`")
        self.assertEqual(fields["errorType"], "trojan")

    def test_failure_scope(self) -> None:
        self.assertEqual(lab.failure_scope(report_with_failure("tunnel-001")), "bound")
        self.assertEqual(lab.failure_scope(report_with_failure("private")), "downstream")
        self.assertEqual(lab.failure_scope({"status": "pass", "events": []}), "none")

    def test_safe_proxy(self) -> None:
        row = config.safe_proxy(
            {
                "name": "Sensitive Provider Node",
                "type": "trojan",
                "server": "secret.example.com",
                "port": 443,
                "password": "secret",
            },
            "tunnel-001",
        )

        self.assertNotIn("name", row)
        self.assertEqual(row["nameLength"], 23)
        self.assertEqual(row["serverLength"], 18)
        self.assertNotIn("cipher", row)
        self.assertEqual(row["passwordLength"], 6)

    def test_matrix_summary(self) -> None:
        args = argparse_like(target_url="https://example.com/")
        summary = matrix.matrix_summary(
            args,
            [
                case_summary("private-direct", "private-direct", "https-head", "pass", "none"),
                case_summary("tunnel-private-https", "private", "https-head", "deny", "downstream"),
            ],
        )

        self.assertEqual(summary["schema"], matrix.MATRIX_SCHEMA)
        self.assertEqual(summary["totals"], {"attempted": 2, "passed": 1, "failed": 1})
        self.assertEqual(summary["cases"][1]["failureScope"], "downstream")
        self.assertFalse(summary["privacy"]["rawSecretsStored"])

    def test_matrix_tls_case(self) -> None:
        labels = [item["label"] for item in matrix.matrix_cases()]

        self.assertEqual(
            labels,
            [
                "private-direct",
                "candidate-direct",
                "tunnel-private-tcp",
                "tunnel-private-tls",
                "tunnel-private-https",
            ],
        )

    def test_matrix_compare(self) -> None:
        first = compare_matrix("https://chatgpt.com/")
        second = compare_matrix("https://example.com/")

        summary = compare.compare_matrices_from_data([first, second])

        self.assertEqual(summary["schema"], compare.COMPARE_SCHEMA)
        self.assertEqual(summary["totals"], {"matrices": 2, "targets": 2, "failures": 2, "signatures": 1})
        signature = summary["failureSignatures"][0]
        self.assertEqual(signature["targets"], ["https://chatgpt.com/", "https://example.com/"])
        self.assertIn("vmess-response-header-length-pending", signature["markers"])
        self.assertEqual(
            summary["controlSummary"],
            {
                "candidateDirectHttpsPass": 2,
                "nestedTcpFlushPass": 2,
                "nestedTlsAllCandidatesFailed": 2,
                "nestedTlsAttempts": 4,
                "nestedTlsFailedAttempts": 4,
                "nestedTlsReadMissing": 2,
                "nestedTlsUniqueFailedTagsMax": 2,
                "stableTlsFailureTargets": 2,
                "targetCount": 2,
                "usableCandidateMax": 2,
            },
        )

    def test_source_policy_split(self) -> None:
        summary = compare.split_from_data(
            observer_summary(4, 0),
            owned_summary(5, 5),
        )

        self.assertEqual(summary["schema"], compare.SOURCE_POLICY_SPLIT_SCHEMA)
        self.assertTrue(summary["conclusion"]["supportsRealPrivateSourcePolicy"])
        self.assertEqual(
            summary["conclusion"]["limits"],
            ["usable candidate counts differ between retained windows"],
        )

    def test_observer_redacts_target(self) -> None:
        report = {
            "schema": "dynet-probe/v1alpha1",
            "events": [{"fields": {"host": "observer.example", "port": "443"}}],
            "target": {"host": "observer.example", "port": 443, "path": "/"},
        }

        cleaned = target_observer.redact_observer_report(report)

        self.assertEqual(
            cleaned["target"],
            {"host": "<observer-target>", "port": 443, "path": "/"},
        )
        self.assertEqual(
            cleaned["events"],
            [{"fields": {"host": "<observer-target>", "port": "<observer-port>"}}],
        )

    def test_observer_signals(self) -> None:
        summary = target_observer.observer_signals(
            {
                "connections": [
                    {"receivedBytes": 0, "sentBytes": 0, "tlsClientHelloLike": False},
                    {"receivedBytes": 12, "sentBytes": 8, "tlsClientHelloLike": True},
                ]
            }
        )

        self.assertEqual(
            summary,
            {
                "connections": 2,
                "receivedConnections": 1,
                "sentConnections": 1,
                "tlsClientHelloLikeConnections": 1,
            },
        )

    def test_owned_private_signals(self) -> None:
        summary = owned_private.owned_signals(
            {
                "privateConnections": [
                    {"decoded": True, "targetConnected": True, "responseSentBytes": 64},
                    {"decoded": False, "targetConnected": False, "responseSentBytes": 0},
                ],
                "targetConnections": [
                    {"receivedBytes": 249, "sentBytes": 28, "tlsClientHelloLike": True},
                    {"receivedBytes": 0, "sentBytes": 0, "tlsClientHelloLike": False},
                ],
            }
        )

        self.assertEqual(summary["privateConnections"], 2)
        self.assertEqual(summary["privateDecodedConnections"], 1)
        self.assertEqual(summary["privateForwardedTargets"], 1)
        self.assertEqual(summary["targetConnections"], 2)
        self.assertEqual(summary["targetTlsClientHelloLikeConnections"], 1)


def write_matrix_fixture(path: Path, target: str) -> Path:
    path.parent.mkdir(parents=True)
    data = compare_matrix(target)
    for case in data["cases"]:
        case["reportPath"] = str(path.parent / str(case["label"]) / "report.json")
    path.write_text(json.dumps(data))
    return path


if __name__ == "__main__":
    unittest.main()
