from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from real_access import controller


class RealAccessControllerTest(unittest.TestCase):
    def test_sanitize_hashes_chains(self) -> None:
        item = {
            "metadata": {"host": "api.github.com", "network": "tcp", "type": "HTTP"},
            "rule": "DomainSuffix",
            "rulePayload": "github.com",
            "chains": ["proxy-group", "node-a"],
        }

        result = controller.sanitize_connection(item, "api.github.com", "salt", "domain")

        self.assertEqual(result["domain"], "api.github.com")
        self.assertEqual(result["matchSource"], "domain")
        self.assertEqual(result["rule"], "DomainSuffix")
        self.assertEqual(result["chainLength"], 2)
        self.assertEqual(len(result["chainHashes"]), 2)
        self.assertNotIn("node-a", result["chainHashes"])

    def test_matches_host_only(self) -> None:
        self.assertTrue(
            controller.connection_matches(
                {"metadata": {"host": "api.github.com"}},
                "api.github.com",
            )
        )
        self.assertFalse(
            controller.connection_matches(
                {"metadata": {"host": "github.com"}},
                "api.github.com",
            )
        )

    def test_matches_sniff_host(self) -> None:
        self.assertTrue(
            controller.connection_matches(
                {"metadata": {"sniffHost": "api.github.com"}},
                "api.github.com",
            )
        )
        self.assertTrue(
            controller.connection_matches(
                {"metadata": {"remoteDestination": "api.github.com:443"}},
                "api.github.com",
            )
        )

    def test_matches_destination_ip(self) -> None:
        self.assertTrue(
            controller.connection_matches(
                {"metadata": {"destinationIP": "203.0.113.10"}},
                "api.github.com",
                {"203.0.113.10"},
            )
        )

    def test_summarizes_samples(self) -> None:
        summary = controller.summarize_samples([
            {"chainHashes": ["a", "b"], "rule": "Match"},
            {"chainHashes": ["a", "b"], "rule": "Match"},
        ])

        self.assertTrue(summary["observed"])
        self.assertEqual(summary["samples"], 2)
        self.assertEqual(summary["chainKeys"], ["a>b"])
        self.assertEqual(summary["rules"], ["Match"])
        self.assertIsNone(summary["missReason"])

    def test_summarizes_miss_reason(self) -> None:
        summary = controller.summarize_samples(
            [],
            polls=3,
            fetch_errors=0,
            connections_seen=10,
        )

        self.assertFalse(summary["observed"])
        self.assertEqual(summary["missReason"], "no-domain-match")

    def test_decodes_chunked_body(self) -> None:
        body = b"7\r\n{\"a\":1}\r\n0\r\n\r\n"

        self.assertEqual(controller.decode_chunked(body), b'{"a":1}')


if __name__ == "__main__":
    unittest.main()
