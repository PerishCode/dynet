from __future__ import annotations

import argparse
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[5]
EXPERIMENTS = ROOT / "scripts" / "experiments"
sys.path.insert(0, str(EXPERIMENTS))

from tunnel_private.quality import mihomo_proxy, transport_evidence

from ..support import write_adapter_json, write_transport_summary


class TransportEvidenceTest(unittest.TestCase):
    def test_transport_evidence_conclusion(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            clash = root / "clash.json"
            mihomo = root / "mihomo.json"
            tls = root / "tls.json"
            write_transport_summary(clash, "clash-delay", {"clash-delay-pass": 2})
            write_transport_summary(mihomo, "mihomo-proxy", {"mihomo-proxy-tls-error": 2})
            write_transport_summary(tls, "trojan-tls", {"tls-handshake-eof": 2})
            write_adapter_json(mihomo, staged_summary(mihomo))
            write_adapter_json(clash, environment_summary(clash))

            summary = transport_evidence.transport_evidence_summary([clash, mihomo, tls])

        surfaces = {item["surface"]: item for item in summary["surfaces"]}
        self.assertEqual(surfaces["controller-health"]["passCount"], 2)
        self.assertEqual(surfaces["product-e2e"]["passCount"], 0)
        self.assertEqual(surfaces["transport-handshake"]["passCount"], 0)
        self.assertTrue(summary["conclusion"]["controllerContradictsProductE2e"])
        self.assertFalse(summary["conclusion"]["controllerHealthOnly"])
        self.assertTrue(summary["conclusion"]["experimentShapeSuspect"])
        self.assertEqual(
            summary["conclusion"]["environmentNextProof"],
            "rerun-isolated-mihomo-with-running-tun-disabled-or-clean-network-namespace",
        )
        self.assertEqual(
            surfaces["product-e2e"]["failureCategoryCounts"],
            {"proxy-dial-timeout": 2},
        )
        self.assertEqual(
            surfaces["product-e2e"]["configFeatureCounts"],
            {
                "interface-name:false": 1,
                "interface-name:true": 1,
                "resolved-server-ip:true": 2,
            },
        )
        self.assertEqual(
            surfaces["product-e2e"]["stageMarkerCounts"],
            {"mihomo-dial-timeout": 3},
        )
        self.assertEqual(
            summary["conclusion"]["recommendedUse"],
            "controller-health-is-weak-signal-not-product-proof",
        )
        self.assertFalse(summary["conclusion"]["plannerPenaltySafe"])
        self.assertEqual(summary["privacy"]["unsafeFlags"], [])

    def test_transport_evidence_command(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "mihomo.json"
            output = root / "out"
            write_transport_summary(source, "mihomo-proxy", {"mihomo-proxy-pass": 1})

            with contextlib.redirect_stdout(io.StringIO()):
                status = transport_evidence.command_transport_evidence(
                    argparse.Namespace(output_dir=str(output), transport_summary=[str(source)])
                )

            self.assertEqual(status, 0)
            self.assertTrue((output / "summary.json").exists())
            self.assertTrue((output / "summary.md").exists())

    def test_mihomo_stage_evidence(self) -> None:
        probe = mihomo_proxy.classify_curl_result(
            35,
            "000 SSL connect error",
            "curl: (35) SSL_connect: unexpected EOF",
        )
        evidence = mihomo_proxy.stage_evidence(
            probe,
            "warn: dial tcp 203.0.113.1:443: i/o timeout",
        )

        self.assertEqual(evidence["curlExitCode"], 35)
        self.assertEqual(evidence["failureCategory"], "proxy-dial-timeout")
        self.assertIn("curl-ssl-connect-error", evidence["stageMarkerCounts"])
        self.assertIn("mihomo-dial-timeout", evidence["stageMarkerCounts"])
        self.assertFalse(evidence["rawLogsStored"])

    def test_resolved_server_ip(self) -> None:
        proxy = {
            "type": "trojan",
            "server": "node.example",
            "server-ip": "203.0.113.9",
            "port": 443,
            "password": "secret",
            "skip-cert-verify": True,
        }

        rendered = mihomo_proxy.mihomo_proxy(proxy)
        args = type("Args", (), {"mihomo_interface_name": "en0"})()
        features = mihomo_proxy.mihomo_proxy_features(proxy, args)

        self.assertEqual(rendered["server"], "203.0.113.9")
        self.assertEqual(rendered["sni"], "node.example")
        self.assertTrue(features["resolvedServerIpUsed"])
        self.assertTrue(features["skipCertVerify"])
        self.assertTrue(features["interfaceNameConfigured"])
        self.assertEqual(features["interfaceNameLength"], 3)


def staged_summary(path: Path) -> dict[str, object]:
    data = json.loads(path.read_text())
    data["rows"] = [
        {
            "stageEvidence": {
                "failureCategory": "proxy-dial-timeout",
                "stageMarkerCounts": {"mihomo-dial-timeout": 1},
            },
            "configFeatures": {
                "interfaceNameConfigured": True,
                "resolvedServerIpUsed": True,
            },
        },
        {
            "stageEvidence": {
                "failureCategory": "proxy-dial-timeout",
                "stageMarkerCounts": {"mihomo-dial-timeout": 2},
            },
            "configFeatures": {
                "interfaceNameConfigured": False,
                "resolvedServerIpUsed": True,
            },
        },
    ]
    return data


def environment_summary(path: Path) -> dict[str, object]:
    data = json.loads(path.read_text())
    data["environment"] = {
        "mergedConfigPresent": True,
        "tunEnabled": True,
        "tunAutoRoute": True,
        "dnsEnabled": True,
    }
    return data


if __name__ == "__main__":
    unittest.main()
