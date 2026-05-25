from __future__ import annotations

import argparse
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from dynet_clash import gap


class DynetClashGapTest(unittest.TestCase):
    def test_gap_aggregates_pairs(self) -> None:
        with tempfile.TemporaryDirectory() as raw_dir:
            root = Path(raw_dir)
            report = gap.build_from_reports(
                [
                    comparison(root, "run1", clash_success=1, dynet_success=2),
                    comparison(root, "run2", clash_success=1, dynet_success=1),
                ],
                sample_args(),
            )

        self.assertEqual(
            report["conclusion"]["status"],
            "parity-supported-superior-gap",
        )
        self.assertEqual(report["conclusion"]["additionalNetSuccessesForSuperior"], 2)
        self.assertEqual(report["primary"]["clash"]["success"], 2)
        self.assertEqual(report["primary"]["dynet"]["success"], 3)
        self.assertEqual(report["outcomeBalance"]["clashOnlyFailure"], 2)
        self.assertEqual(report["outcomeBalance"]["dynetOnlyFailure"], 2)
        self.assertEqual(report["outcomeBalance"]["bothFailure"], 2)
        self.assertEqual(report["runtimeGate"]["cleanWindows"], 2)
        self.assertEqual(report["runtimeGate"]["missingWindows"], 0)
        self.assertEqual(
            report["byDomainProbe"],
            [
                {
                    "domain": "api.github.com",
                    "probe": "https-head",
                    "count": 8,
                    "clashOnlyFailure": 2,
                    "dynetOnlyFailure": 2,
                    "bothFailure": 2,
                    "netDynetFailureAdvantage": 0,
                }
            ],
        )
        self.assertEqual(report["dynetFailureSurfaces"][0]["reasonMarker"], "tls-eof")

    def test_window_scopes_limits(self) -> None:
        report = gap.build_from_reports(
            [
                {
                    "inputs": {},
                    "byBucket": [bucket(1, 1)],
                    "verdict": {"status": "dynet-parity-candidate", "primaryDelta": 0},
                    "limitDetails": [
                        {
                            "scope": "attribution",
                            "category": "controller",
                            "message": "observe-only",
                        },
                        {
                            "scope": "product-effect",
                            "category": "scheduler",
                            "message": "lag",
                        },
                    ],
                }
            ],
            sample_args(),
        )

        self.assertFalse(report["windows"][0]["productEffectClean"])
        self.assertEqual(len(report["windows"][0]["attributionLimits"]), 1)
        self.assertEqual(len(report["windows"][0]["productLimits"]), 1)


def comparison(
    root: Path,
    name: str,
    *,
    clash_success: int,
    dynet_success: int,
) -> dict[str, object]:
    run = root / name
    clash_dir = run / "clash"
    dynet_dir = run / "dynet"
    clash_dir.mkdir(parents=True)
    dynet_dir.mkdir(parents=True)
    write_json(clash_dir / "summary.json", clash_summary())
    write_json(dynet_dir / "summary.json", dynet_summary())
    write_json(run / "pairs.json", pair_summary())
    return {
        "inputs": {
            "clashSummary": str(clash_dir / "summary.json"),
            "dynetSummary": str(dynet_dir / "summary.json"),
        },
        "byBucket": [bucket(clash_success, dynet_success)],
        "verdict": {
            "status": "dynet-parity-candidate",
            "primaryDelta": round(dynet_success / 3 - clash_success / 3, 4),
        },
        "limitDetails": [
            {
                "scope": "attribution",
                "category": "controller",
                "message": "controller observe-only",
            }
        ],
        "dynetRuntimeGate": {
            "present": True,
            "clean": True,
            "classification": "runtime-workload-clean",
        },
    }


def clash_summary() -> dict[str, object]:
    return {
        "failureClusters": [
            {
                "bucket": "github-proof",
                "domain": "api.github.com",
                "probe": "https-head",
                "behavior": "burst",
                "errorStage": "tls-handshake",
                "errorType": "tls.eof",
                "count": 1,
            }
        ],
        "pairedReplay": {
            "pairScheduler": "open-loop",
            "sideMode": "parallel",
            "pairLagMs": {"p95": 1},
            "pairGapMs": {"p95": 1},
        },
    }


def dynet_summary() -> dict[str, object]:
    return {
        "items": [
            {
                "id": "0002",
                "bucket": "github-proof",
                "domain": "api.github.com",
                "sourceProbe": "https-head",
                "status": "fail",
                "failedStage": "tls-handshake",
                "failureScope": "direct",
                "selectedOutbound": "direct",
                "reason": "unexpected end of file",
            }
        ]
    }


def pair_summary() -> dict[str, object]:
    return {
        "count": 3,
        "items": [
            pair("0001", clash_ok=True, dynet_status="pass"),
            pair("0002", clash_ok=False, dynet_status="pass"),
            pair("0003", clash_ok=True, dynet_status="fail"),
            pair("0004", clash_ok=False, dynet_status="fail"),
        ],
    }


def pair(item_id: str, *, clash_ok: bool, dynet_status: str) -> dict[str, object]:
    return {
        "id": item_id,
        "bucket": "github-proof",
        "domain": "api.github.com",
        "probe": "https-head",
        "clashOk": clash_ok,
        "dynetStatus": dynet_status,
    }


def bucket(clash_success: int, dynet_success: int) -> dict[str, object]:
    clash = side(clash_success, 3)
    dynet = side(dynet_success, 3)
    return {
        "key": "github-proof",
        "clash": clash,
        "dynet": dynet,
        "successRateDelta": round(dynet["successRate"] - clash["successRate"], 4),
    }


def side(success: int, count: int) -> dict[str, object]:
    return {
        "count": count,
        "success": success,
        "failure": count - success,
        "successRate": round(success / count, 4),
    }


def write_json(path: Path, data: dict[str, object]) -> None:
    path.write_text(json.dumps(data))


def sample_args() -> argparse.Namespace:
    return argparse.Namespace(
        primary_bucket="github-proof",
        min_superior_delta=0.5,
    )


if __name__ == "__main__":
    unittest.main()
