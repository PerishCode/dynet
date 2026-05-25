from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
EXPERIMENTS = ROOT / "scripts" / "experiments"
sys.path.insert(0, str(EXPERIMENTS))

import tunnel_private_config as config
from scripts.cli import tunnel_private_lab as lab


class ConfigMetadataTest(unittest.TestCase):
    def test_offset_parser(self) -> None:
        parser = lab.build_parser()

        args = parser.parse_args([
            "build",
            "--output-config",
            "/tmp/secret.json",
            "--output-meta",
            "/tmp/meta.json",
            "--candidate-offset",
            "8",
        ])

        self.assertEqual(args.candidate_offset, 8)

    def test_trojan_interface_parser(self) -> None:
        parser = lab.build_parser()

        args = parser.parse_args([
            "build",
            "--output-config",
            "/tmp/secret.json",
            "--output-meta",
            "/tmp/meta.json",
            "--trojan-interface-name",
            "en0",
        ])

        self.assertEqual(args.trojan_interface_name, "en0")

    def test_safe_proxy_shape(self) -> None:
        row = config.safe_proxy(
            {
                "name": "private name",
                "type": "trojan",
                "server": "secret.example",
                "server-ip": "203.0.113.1",
                "port": 443,
                "password": "secret-password",
                "sni": "secret.example",
                "skip-cert-verify": True,
                "alpn": ["h2", "http/1.1"],
                "client-fingerprint": "chrome",
                "interface-name": "en0",
            },
            "tunnel-001",
        )

        self.assertEqual(row["tag"], "tunnel-001")
        self.assertEqual(row["type"], "trojan")
        self.assertEqual(row["passwordLength"], len("secret-password"))
        self.assertTrue(row["serverIpPresent"])
        self.assertTrue(row["interfaceNameConfigured"])
        self.assertEqual(row["interfaceNameLength"], 3)
        self.assertTrue(row["sniPresent"])
        self.assertTrue(row["skipCertVerify"])
        self.assertEqual(row["alpnCount"], 2)
        self.assertTrue(row["clientFingerprintPresent"])
        self.assertNotIn("server", row)
        self.assertNotIn("password", row)
        self.assertNotIn("sni", row)
        self.assertNotIn("interfaceName", row)

    def test_trojan_payload_interface(self) -> None:
        outbound = config.dynet_trojan(
            {
                "type": "trojan",
                "server": "secret.example",
                "port": 443,
                "password": "secret-password",
                "interface-name": "en0",
            },
            "tunnel-001",
        )

        self.assertEqual(outbound["payload"]["interfaceName"], "en0")

    def test_trojan_interface_annotation(self) -> None:
        trojan = config.with_trojan_interface_name({"type": "trojan"}, "en0")
        vmess = config.with_trojan_interface_name({"type": "vmess"}, "en0")

        self.assertEqual(trojan["interface-name"], "en0")
        self.assertNotIn("interface-name", vmess)

    def test_resolution_slice_meta(self) -> None:
        summary = config.resolution_metadata(
            True,
            [{"type": "trojan"}] * 10,
            [{"type": "trojan"}] * 3,
            [{"type": "trojan"}] * 2,
            [{"errorType": "resolve-failed"}],
            4,
            3,
        )

        self.assertEqual(summary["input"], 3)
        self.assertEqual(summary["usable"], 2)
        self.assertEqual(
            summary["selection"],
            {
                "candidateOffset": 4,
                "candidateLimit": 3,
                "supportedBeforeOffset": 10,
                "selectedBeforeResolution": 3,
            },
        )

    def test_metadata_offset_tags(self) -> None:
        summary = config.metadata(
            {"name": "Tunnel", "type": "select", "use": ["provider"]},
            [{"type": "trojan"}],
            [{"type": "trojan"}],
            [{"type": "trojan"}],
            [{"type": "trojan"}],
            {"type": "ss", "server": "private", "port": 8388},
            {
                "skipped": 0,
                "selection": {
                    "candidateOffset": 3,
                },
            },
        )

        self.assertEqual(summary["candidates"][0]["tag"], "tunnel-004")


if __name__ == "__main__":
    unittest.main()
