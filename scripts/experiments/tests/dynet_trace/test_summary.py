from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from dynet_trace import summary as trace_summary


class DynetTraceSummaryTest(unittest.TestCase):
    def test_session_failures(self) -> None:
        summary = trace_summary.build_summary({
            "schema": "dynet-runtime-report/v1alpha1",
            "status": "pass",
            "events": [
                {
                    "kind": "tcp-session-failed",
                    "sequence": 7,
                    "fields": {
                        "flowId": "tcp-session-1",
                        "session": "1",
                        "outbound": "private-via-tunnel",
                        "target": "104.16.123.96:443",
                        "errorType": "shadowsocks",
                        "error": "failed to read proxied TCP payload",
                    },
                },
            ],
        })

        self.assertTrue(summary["attributionReadiness"]["present"]["failures"])
        self.assertEqual(summary["failures"][0]["kind"], "tcp-session-failed")
        self.assertEqual(summary["failures"][0]["errorType"], "shadowsocks")


if __name__ == "__main__":
    unittest.main()
