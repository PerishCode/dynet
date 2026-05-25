from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[5]
EXPERIMENTS = ROOT / "scripts" / "experiments"
sys.path.insert(0, str(EXPERIMENTS))

from tunnel_private.quality import adapter_readiness

from ..support import adapter_vm_private_summary, write_adapter_json


class VmPrivateProductTest(unittest.TestCase):
    def test_product_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            product = root / "vm-private.json"
            write_adapter_json(product, adapter_vm_private_summary())

            summary = adapter_readiness.adapter_readiness_summary(
                "trojan",
                [product],
                [],
                [],
            )

        product_e2e = summary["productEvidence"]["product-e2e"]
        self.assertEqual(summary["status"], "ready")
        self.assertEqual(product_e2e["runs"], 2)
        self.assertEqual(product_e2e["failed"], 0)
        self.assertEqual(
            product_e2e["targets"],
            ["https://api.github.com/", "https://www.cloudflare.com/"],
        )

    def test_product_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            product = root / "vm-private.json"
            write_adapter_json(product, adapter_vm_private_summary(failures=1))

            summary = adapter_readiness.adapter_readiness_summary(
                "trojan",
                [product],
                [],
                [],
            )

        product_e2e = summary["productEvidence"]["product-e2e"]
        self.assertEqual(summary["status"], "not-ready")
        self.assertEqual(product_e2e["failed"], 1)
        self.assertEqual(product_e2e["failureStageSummary"], {"tunnel-001:tcp-connect": 1})
        self.assertEqual(product_e2e["failureScopeSummary"], {"bound": 1})
        self.assertIn("vm-private-cascade-has-failures", product_e2e["requiredGateFailures"])


if __name__ == "__main__":
    unittest.main()
