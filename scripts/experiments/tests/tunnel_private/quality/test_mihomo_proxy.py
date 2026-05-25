from __future__ import annotations

import argparse
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[5]
EXPERIMENTS = ROOT / "scripts" / "experiments"
sys.path.insert(0, str(EXPERIMENTS))

from tunnel_private.quality import mihomo_proxy, transport


VMESS_UUID = "11111111-1111-4111-8111-111111111111"


class MihomoProxyTest(unittest.TestCase):
    def test_vmess_config(self) -> None:
        rendered = mihomo_proxy.mihomo_proxy(
            {
                "name": "raw-node-name",
                "type": "vmess",
                "server": "edge.example.com",
                "server-ip": "203.0.113.10",
                "port": 443,
                "uuid": VMESS_UUID,
                "alter-id": 0,
                "cipher": "auto",
                "tls": True,
                "clientFingerprint": "chrome",
            }
        )

        self.assertEqual(rendered["name"], "node")
        self.assertEqual(rendered["type"], "vmess")
        self.assertEqual(rendered["server"], "203.0.113.10")
        self.assertEqual(rendered["servername"], "edge.example.com")
        self.assertEqual(rendered["alterId"], 0)
        self.assertEqual(rendered["client-fingerprint"], "chrome")
        self.assertNotIn("raw-node-name", rendered.values())

    def test_vmess_row_sanitized(self) -> None:
        original = mihomo_proxy.mihomo_proxy_probe
        self.addCleanup(lambda: setattr(mihomo_proxy, "mihomo_proxy_probe", original))
        mihomo_proxy.mihomo_proxy_probe = lambda _args, _proxy: {
            "outcome": "mihomo-proxy-pass",
            "httpStatus": 204,
        }

        row = transport.check_candidate(
            argparse.Namespace(
                check="mihomo-proxy",
                timeout_seconds=5.0,
                mihomo_interface_name=None,
            ),
            {
                "name": "raw-node-name",
                "type": "vmess",
                "server": "edge.example.com",
                "port": 443,
                "uuid": VMESS_UUID,
                "cipher": "auto",
            },
            "tunnel-001",
        )

        self.assertEqual(row["outcome"], "mihomo-proxy-pass")
        self.assertEqual(row["httpStatus"], 204)
        self.assertEqual(row["candidate"]["type"], "vmess")
        self.assertEqual(row["candidate"]["uuidLength"], 36)
        self.assertNotIn("uuid", row["candidate"])
        self.assertNotIn("name", row["candidate"])


if __name__ == "__main__":
    unittest.main()
