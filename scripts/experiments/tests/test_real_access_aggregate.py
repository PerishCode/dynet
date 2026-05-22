from __future__ import annotations

import sys
import unittest
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from real_access import aggregate


class RealAccessAggregateTest(unittest.TestCase):
    def test_controller_failure_groups(self) -> None:
        summary = aggregate.controller_summary([
            result(False, "api.github.com", ["a>b"], ["RuleSet"]),
            result(False, "github.com", [], []),
            result(True, "api.github.com", ["c>d"], ["RuleSet"]),
        ])

        self.assertEqual(summary["observed"], 2)
        self.assertEqual(summary["missing"], 1)
        self.assertEqual(summary["matchSources"], [])
        self.assertEqual(summary["missReasons"], [{"key": "unknown", "count": 1}])
        self.assertEqual(
            summary["failureGroups"],
            [
                {
                    "chainKey": "a>b",
                    "observed": True,
                    "missReason": None,
                    "domain": "api.github.com",
                    "bucket": "github-proof",
                    "probe": "tls-handshake",
                    "errorStage": "tls-handshake",
                    "errorType": "tls.eof",
                    "count": 1,
                    "rules": [{"key": "RuleSet", "count": 1}],
                    "matchSources": [],
                },
                {
                    "chainKey": "missing-observation",
                    "observed": False,
                    "missReason": "unknown",
                    "domain": "github.com",
                    "bucket": "github-proof",
                    "probe": "tls-handshake",
                    "errorStage": "tls-handshake",
                    "errorType": "tls.eof",
                    "count": 1,
                    "rules": [],
                    "matchSources": [],
                },
            ],
        )


def result(
    ok: bool,
    domain: str,
    chain_keys: list[str],
    rules: list[str],
) -> dict[str, Any]:
    return {
        "ok": ok,
        "domain": domain,
        "bucket": "github-proof",
        "probe": "tls-handshake",
        "errorStage": None if ok else "tls-handshake",
        "errorType": None if ok else "tls.eof",
        "clashController": {
            "enabled": True,
            "observed": bool(chain_keys),
            "chainKeys": chain_keys,
            "rules": rules,
        },
    }


if __name__ == "__main__":
    unittest.main()
