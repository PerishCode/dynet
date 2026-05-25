from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from private_runtime_lib.reporting.workload_surface.tcp import cascade_stop_surface


class CascadeStopSurfaceTest(unittest.TestCase):
    def test_bound_shape_sanitized(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "round-gap.json"
            source.write_text(json.dumps(round_gap_summary(), sort_keys=True))
            report = cascade_stop_surface.build_cascade_stop_summary(
                "cascade-stop",
                root / "out",
                [source],
            )

        self.assertEqual(report["schema"], cascade_stop_surface.SCHEMA)
        self.assertEqual(report["conclusion"]["status"], "cascade-stop-shape-clean")
        self.assertEqual(report["totals"]["stoppedRows"], 1)
        self.assertEqual(report["totals"]["boundExhaustedRows"], 1)
        self.assertEqual(report["totals"]["attemptCount"], 4)
        self.assertEqual(report["totals"]["failedAttemptCount"], 4)
        self.assertEqual(report["totals"]["retryableFailureCount"], 3)
        self.assertEqual(report["totals"]["stageSurfaces"], [
            {"count": 1, "key": "trojan-tls-handshake:trojan"},
        ])
        self.assertEqual(report["totals"]["pendingWaitClasses"], [
            {"count": 1, "key": "socket-read-timeout"},
        ])
        encoded = json.dumps(report, sort_keys=True)
        for value in ("tunnel-001", "tunnel-002", "tcp-session-8", "chatgpt.com"):
            self.assertNotIn(value, encoded)
        for key in ("flowId", "domain", "boundSelectedSequence", "failedSelectedSequence"):
            self.assertNotIn(f'"{key}"', encoded)

    def test_shape_mismatch_blocks(self) -> None:
        summary = round_gap_summary()
        stopped = summary["runs"][0]["cascade"]["stoppedRows"][0]
        stopped["candidateCount"] = 5
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "round-gap.json"
            source.write_text(json.dumps(summary, sort_keys=True))
            report = cascade_stop_surface.build_cascade_stop_summary(
                "cascade-stop",
                root / "out",
                [source],
            )

        self.assertEqual(
            report["conclusion"]["status"],
            "cascade-stop-shape-needs-evidence",
        )
        self.assertEqual(report["totals"]["uniqueCandidateCountMismatches"], 1)
        self.assertEqual(report["totals"]["classifications"], [
            {"count": 1, "key": "candidate-count-mismatch"},
        ])

    def test_no_stopped_rows(self) -> None:
        summary = round_gap_summary()
        summary["runs"][0]["cascade"]["stoppedRows"] = []
        summary["runs"][0]["schedule"]["failedRows"] = []
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "round-gap.json"
            source.write_text(json.dumps(summary, sort_keys=True))
            report = cascade_stop_surface.build_cascade_stop_summary(
                "cascade-stop",
                root / "out",
                [source],
            )

        self.assertEqual(report["conclusion"]["status"], "no-cascade-stop-evidence")
        self.assertEqual(report["totals"]["stoppedRows"], 0)

    def test_repeat_summary_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "repeat.json"
            source.write_text(json.dumps(raw_repeat_summary(), sort_keys=True))
            report = cascade_stop_surface.build_cascade_stop_summary(
                "cascade-stop",
                root / "out",
                [source],
            )

        self.assertEqual(report["conclusion"]["status"], "cascade-stop-shape-clean")
        self.assertEqual(report["totals"]["stoppedRows"], 1)
        self.assertEqual(report["totals"]["boundExhaustedRows"], 1)
        encoded = json.dumps(report, sort_keys=True)
        for value in ("tunnel-001", "tunnel-002", "tcp-session-8"):
            self.assertNotIn(value, encoded)


def round_gap_summary() -> dict[str, object]:
    return {
        "schema": cascade_stop_surface.ROUND_GAP_SCHEMA,
        "label": "round-gap",
        "totals": {"runs": 2},
        "conclusion": {"status": "mixed-with-clean-controls"},
        "runs": [
            {
                "label": "run-a",
                "cascade": {
                    "stoppedRows": [
                        {
                            "attemptCount": 4,
                            "boundSelectedSequence": [
                                "tunnel-004",
                                "tunnel-001",
                                "tunnel-002",
                                "tunnel-003",
                            ],
                            "candidateCount": 4,
                            "candidateExhausted": True,
                            "errorDisposition": "pending-timeout",
                            "failedAttemptCount": 4,
                            "failedSelectedSequence": [
                                "tunnel-004",
                                "tunnel-001",
                                "tunnel-002",
                                "tunnel-003",
                            ],
                            "failureScope": "bound",
                            "failureStageSurface": "trojan-tls-handshake:trojan",
                            "pendingWaitClass": "socket-read-timeout",
                            "failureStagePendingWaitClass": "socket-read-timeout",
                            "flowId": "tcp-session-8",
                            "lastBoundSelected": "tunnel-003",
                            "retryableFailureCount": 3,
                            "retryableSelectedSequence": [
                                "tunnel-004",
                                "tunnel-001",
                                "tunnel-002",
                            ],
                            "stopReason": "bound-candidates-exhausted",
                        },
                    ],
                },
                "schedule": {
                    "failedRows": [
                        {
                            "cascadeStoppedFlowMatched": True,
                            "domain": "chatgpt.com",
                            "flowId": "tcp-session-8",
                        },
                    ],
                },
            },
        ],
    }


def raw_repeat_summary() -> dict[str, object]:
    stopped = round_gap_summary()["runs"][0]["cascade"]["stoppedRows"][0]
    return {
        "schema": "dynet-vm-private-runtime-repeat/v1alpha1",
        "label": "repeat",
        "totals": {"runs": 1},
        "runs": [
            {
                "label": "run-a",
                "cascadeAttempts": {
                    "stoppedRows": [stopped],
                },
            },
        ],
    }


if __name__ == "__main__":
    unittest.main()
