from __future__ import annotations

import argparse
import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import dynet_clash_contract as contract


class DynetClashContractTest(unittest.TestCase):
    def test_github_contract(self) -> None:
        profile = {
            "schema": "dynet-clash-verge-access-profile/v1alpha1",
            "source": {"firstSeen": "a", "lastSeen": "b"},
            "summary": {"events": 1200, "errors": 30},
            "topSites": [
                {
                    "site": "github.com",
                    "category": "developer",
                    "count": 1000,
                    "errors": 25,
                    "activeWindows5m": 8,
                    "egressGroups": ["GitHub"],
                }
            ],
            "topDomains": [
                {
                    "domain": "api.github.com",
                    "site": "github.com",
                    "category": "developer",
                    "count": 900,
                    "errors": 24,
                    "activeWindows5m": 8,
                    "maxPer5m": 140,
                    "egressGroups": ["GitHub"],
                    "matches": ["RuleSet(github)"],
                },
                {
                    "domain": "powerformer.feilian.cn",
                    "site": "feilian.cn",
                    "category": "work",
                    "count": 300,
                    "errors": 0,
                    "activeWindows5m": 8,
                    "maxPer5m": 50,
                    "egressGroups": ["DIRECT"],
                },
            ],
        }
        args = argparse.Namespace(**{
            "profile": ".task/resources/clash-verge-access-profile.json",
            "primary_site": "github.com",
            "primary_limit": 8,
            "control_limit": 8,
            "bucket_minutes": 5,
            "min_primary_events": 500,
            "min_primary_warnings": 10,
            "min_primary_windows": 4,
            "min_comparable_buckets": 4,
            "direct_control_max_timeout_rate": 0.01,
            "github_timeout_improvement_min": 0.01,
            "github_p95_improvement_min_ms": 100,
            "manifest_count": 96,
            "manifest_duration_seconds": 300,
        })

        built = contract.build_contract_from_profile(profile, args)

        self.assertEqual(
            built["hypothesis"]["weakBaselineSignal"]["status"],
            "stable-weak",
        )
        self.assertEqual(built["targetLanes"]["primary"]["domains"][0]["domain"], "api.github.com")
        self.assertEqual(
            built["targetLanes"]["directControls"]["domains"][0]["domain"],
            "powerformer.feilian.cn",
        )


if __name__ == "__main__":
    unittest.main()
