from __future__ import annotations

import argparse
import json
import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from real_access import manifest


class RealAccessManifestTest(unittest.TestCase):
    def test_repeat_scope(self) -> None:
        built = build_manifest("repeat")

        assert_scoped_domains(self, built)

    def test_burst_scope(self) -> None:
        built = build_manifest("burst")

        assert_scoped_domains(self, built)


def assert_scoped_domains(
    case: unittest.TestCase,
    built: dict[str, object],
) -> None:
        domains_by_bucket = {}
        for entry in built["entries"]:
            domains_by_bucket.setdefault(entry["bucket"], set()).add(entry["domain"])
        case.assertEqual(domains_by_bucket["github-proof"], {"api.github.com"})
        case.assertEqual(domains_by_bucket["work-direct"], {"powerformer.feilian.cn"})


def build_manifest(behavior: str) -> dict[str, object]:
    with tempfile.TemporaryDirectory() as temp_dir:
        profile = Path(temp_dir) / "profile.json"
        profile.write_text(json.dumps(sample_profile()))
        args = argparse.Namespace(**manifest_args(profile, behavior))
        return manifest.build_manifest(args)


def manifest_args(profile: Path, behavior: str) -> dict[str, object]:
    return {
        "profile": str(profile),
        "environment": "test",
        "seed": "repeat-pool-test",
        "count": 40,
        "buckets": "work-direct",
        "probe_modes": "tls-handshake",
        "behaviors": behavior,
        "duration_seconds": 0,
        "spacing_ms": 0,
        "jitter_ms": 0,
        "burst_groups": 1,
        "burst_window_ms": 1,
        "control_domain": [],
        "control_weight": 1,
        "no_default_controls": True,
        "focus_domain": ["api.github.com"],
        "focus_weight": 1,
        "focus_bucket": "github-proof",
        "timeout_seconds": 5,
    }


def sample_profile() -> dict[str, object]:
    return {
        "schema": "dynet-clash-verge-access-profile/v1alpha1",
        "summary": {},
        "experimentProfile": {
            "samplePools": [
                {
                    "name": "work-direct",
                    "weight": 1,
                    "domains": ["powerformer.feilian.cn"],
                    "probeModes": ["tls-handshake"],
                }
            ]
        },
    }


if __name__ == "__main__":
    unittest.main()
