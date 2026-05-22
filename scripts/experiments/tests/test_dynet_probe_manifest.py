from __future__ import annotations

import argparse
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import dynet_probe_manifest as manifest


class DynetProbeManifestTest(unittest.TestCase):
    def test_source_maps_tls(self) -> None:
        args = argparse.Namespace(dynet_protocol="source")

        self.assertEqual(
            manifest.dynet_protocol(args, {"probe": "tls-handshake"}),
            "tls-handshake",
        )
        self.assertEqual(
            manifest.dynet_protocol(args, {"probe": "https-head"}),
            "https-head",
        )
        self.assertEqual(
            manifest.dynet_protocol(args, {"probe": "https-get"}),
            "https-head",
        )

    def test_explicit_overrides_source(self) -> None:
        args = argparse.Namespace(dynet_protocol="https-head")

        self.assertEqual(
            manifest.dynet_protocol(args, {"probe": "tls-handshake"}),
            "https-head",
        )

    def test_schedule_scaling(self) -> None:
        args = argparse.Namespace(schedule_scale=0.5)

        self.assertEqual(
            manifest.replay_target_ms(args, {"scheduledOffsetMs": 3000}, 1000),
            1000,
        )

    def test_negative_scale_denied(self) -> None:
        with self.assertRaises(argparse.ArgumentTypeError):
            manifest.non_negative_float("-0.1")


if __name__ == "__main__":
    unittest.main()
