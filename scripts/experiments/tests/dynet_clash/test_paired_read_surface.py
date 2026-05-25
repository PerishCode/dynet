from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from dynet_clash.paired_surface import read_surface


class DynetClashPairedReadSurfaceTest(unittest.TestCase):
    def test_later_repeat(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            one_pairs, one_followup = write_window(
                root,
                "one",
                "late-1",
                250,
                "vmess-response-header-length-eof",
                "remote-eof",
            )
            two_pairs, two_followup = write_window(
                root,
                "two",
                "late-2",
                1000,
                "vmess-response-header-length-pending",
                "pending-budget-exhausted",
            )

            summary = read_surface.paired_read_surface_batch(
                [one_pairs, two_pairs],
                [one_followup, two_followup],
                ["one", "two"],
            )

        self.assertEqual(
            summary["conclusion"]["status"],
            "dynet-later-read-surface-repeat-drift",
        )
        self.assertEqual(summary["totals"]["readFailureCount"], 2)
        self.assertEqual(summary["conclusion"]["dynetFirstReadFailures"], 0)
        self.assertEqual(summary["conclusion"]["dynetSecondReadFailures"], 2)
        self.assertEqual(
            summary["byParallelSideStaggerMs"],
            [
                {"key": "1000", "items": 2, "readFailures": 1, "failureRate": 0.5},
                {"key": "250", "items": 2, "readFailures": 1, "failureRate": 0.5},
            ],
        )
        self.assertEqual(len(summary["readFailureSurfaces"]), 2)
        self.assertEqual(
            {surface["context"] for surface in summary["readFailureSurfaces"]},
            {"shadowsocks-response-salt"},
        )
        self.assertEqual(
            [
                {
                    "label": row["label"],
                    "clashPassed": row["clashPassed"],
                    "dynetPassed": row["dynetPassed"],
                    "readFailureCount": row["readFailureCount"],
                    "productShape": row["productShape"],
                    "parallelSideStaggerMs": row["parallelSideStaggerMs"],
                }
                for row in summary["bySource"]
            ],
            [
                {
                    "label": "one",
                    "clashPassed": 2,
                    "dynetPassed": 1,
                    "readFailureCount": 1,
                    "productShape": "dynet-read-failures",
                    "parallelSideStaggerMs": 250,
                },
                {
                    "label": "two",
                    "clashPassed": 2,
                    "dynetPassed": 1,
                    "readFailureCount": 1,
                    "productShape": "dynet-read-failures",
                    "parallelSideStaggerMs": 1000,
                },
            ],
        )

    def test_clash_only_shape(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            pair_path = root / "clean-dynet" / "pairs.json"
            followup_path = root / "clean-dynet" / "protocol-followup" / "summary.json"
            write_json(pair_path, pairs_summary([
                pair_item("ok", ["clash", "dynet"], "pass", 2000),
                {
                    **pair_item("clash-failed", ["clash", "dynet"], "pass", 2000),
                    "clashOk": False,
                },
            ], 2000))
            write_json(followup_path, empty_followup_summary())

            summary = read_surface.paired_read_surface_batch(
                [pair_path],
                [followup_path],
                ["clean-dynet"],
            )

        self.assertEqual(summary["conclusion"]["status"], "paired-read-surface-clean")
        self.assertEqual(summary["bySource"][0]["clashPassed"], 1)
        self.assertEqual(summary["bySource"][0]["dynetPassed"], 2)
        self.assertEqual(summary["bySource"][0]["readFailureCount"], 0)
        self.assertEqual(
            summary["bySource"][0]["productShape"],
            "dynet-clean-clash-failures",
        )

    def test_dynet_only_source(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            pair_path = root / "dynet-only" / "summary.json"
            followup_path = root / "dynet-only" / "protocol-followup" / "summary.json"
            write_json(pair_path, dynet_only_summary([
                {"id": "one", "status": "pass", "sourceProbe": "https-head"},
                {"id": "two", "status": "pass", "sourceProbe": "https-head"},
            ]))
            write_json(followup_path, empty_followup_summary())

            summary = read_surface.paired_read_surface_batch(
                [pair_path],
                [followup_path],
                ["dynet-only"],
            )

        self.assertEqual(summary["bySource"][0]["sourceKind"], "dynet-only")
        self.assertIsNone(summary["bySource"][0]["clashPassed"])
        self.assertIsNone(summary["bySource"][0]["clashFailed"])
        self.assertEqual(summary["bySource"][0]["dynetPassed"], 2)
        self.assertEqual(summary["bySource"][0]["productShape"], "dynet-only-clean")

    def test_bracketed_pressure_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            fail_pairs, fail_followup = write_window(
                root,
                "fail",
                "fail",
                1000,
                "vmess-response-header-length-pending",
                "pending-budget-exhausted",
            )
            clean_pairs = root / "clean" / "pairs.json"
            clean_followup = root / "clean" / "protocol-followup" / "summary.json"
            write_json(clean_pairs, pairs_summary([
                pair_item("clean", ["clash", "dynet"], "pass", 1062),
            ], 1062))
            write_json(clean_followup, empty_followup_summary())

            summary = read_surface.paired_read_surface_batch(
                [fail_pairs, clean_pairs],
                [fail_followup, clean_followup],
                ["fail", "clean"],
            )

        boundary = summary["pressureBoundary"]
        actionable = summary["actionableConclusion"]
        self.assertEqual(boundary["status"], "bracketed-clean-above-failure")
        self.assertEqual(boundary["maxFailingStaggerMs"], 1000)
        self.assertEqual(boundary["minCleanStaggerAboveFailureMs"], 1062)
        self.assertEqual(boundary["boundaryGapMs"], 62)
        self.assertEqual(boundary["failingStaggerMs"], [1000])
        self.assertEqual(boundary["cleanStaggerMs"], [1062])
        self.assertEqual(actionable["status"], "actionable-pressure-bracketed")
        self.assertEqual(actionable["action"], "bisect-pressure-boundary")
        self.assertEqual(actionable["readFailureCount"], 1)
        self.assertEqual(actionable["excludedReadFailureCount"], 0)

    def test_fresh_config_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            summary = fresh_config_boundary_summary(Path(temp_dir))

        boundary = summary["pressureBoundary"]
        actionable = summary["actionableConclusion"]
        self.assertEqual(boundary["configFilter"], "fresh-config")
        self.assertEqual(boundary["status"], "no-dynet-read-failure-in-scope")
        self.assertEqual(boundary["cleanStaggerMs"], [1000, 1031])
        self.assertEqual(boundary["failingStaggerMs"], [])
        self.assertEqual(
            actionable["status"],
            "fresh-config-clean-noncurrent-controls-excluded",
        )
        self.assertEqual(
            actionable["action"],
            "exclude-stale-config-controls-from-pressure-bisection",
        )
        self.assertEqual(actionable["readFailureCount"], 0)
        self.assertEqual(actionable["savedConfigDriftReadFailureCount"], 1)
        self.assertEqual(actionable["excludedReadFailureCount"], 2)
        self.assertEqual(
            summary["pressureBoundaries"]["allSources"]["maxFailingStaggerMs"],
            1031,
        )
        self.assertEqual(
            summary["pressureBoundaries"]["savedConfigDrift"]["failingStaggerMs"],
            [1031],
        )
        self.assertEqual(
            [row["configFreshness"] for row in summary["bySource"]],
            [
                "legacy-or-unspecified",
                "saved-config-drift",
                "fresh-config",
                "fresh-config",
            ],
        )

    def test_parser(self) -> None:
        args = read_surface.build_parser().parse_args([
            "--pairs",
            "one/pairs.json",
            "--followup",
            "one/protocol-followup/summary.json",
            "--label",
            "one",
        ])

        self.assertEqual(args.pairs, ["one/pairs.json"])
        self.assertEqual(args.followup, ["one/protocol-followup/summary.json"])
        self.assertEqual(args.label, ["one"])


def fresh_config_boundary_summary(root: Path) -> dict[str, object]:
    stale_pairs, stale_followup = write_window(
        root,
        "stale",
        "stale",
        1000,
        "vmess-response-header-length-pending",
        "pending-budget-exhausted",
    )
    drift_pairs, drift_followup = write_window(
        root,
        "drift",
        "drift",
        1031,
        "vmess-response-header-length-pending",
        "pending-budget-exhausted",
    )
    fresh_1000_pairs, fresh_1000_followup = write_clean_window(root, "fresh-1000", 1000)
    fresh_1031_pairs, fresh_1031_followup = write_clean_window(root, "fresh-1031", 1031)
    return read_surface.paired_read_surface_batch(
        [stale_pairs, drift_pairs, fresh_1000_pairs, fresh_1031_pairs],
        [stale_followup, drift_followup, fresh_1000_followup, fresh_1031_followup],
        [
            "clash-first-1000ms",
            "clash-first-1031ms-saved-config-drift",
            "clash-first-1000ms-fresh-config",
            "clash-first-1031ms-fresh-config",
        ],
    )


def pairs_summary(items: list[dict[str, object]], stagger_ms: int) -> dict[str, object]:
    return {
        "schema": "dynet-clash-paired-run/v1alpha1",
        "sideMode": "parallel",
        "sideOrder": "clash-first",
        "parallelSideStaggerMs": stagger_ms,
        "pairLagMs": {"p95": 8},
        "pairGapMs": {"p95": stagger_ms},
        "items": items,
    }


def write_window(
    root: Path,
    label: str,
    failed_id: str,
    stagger_ms: int,
    marker: str,
    disposition: str,
) -> tuple[Path, Path]:
    pair_path = root / label / "pairs.json"
    followup_path = root / label / "protocol-followup" / "summary.json"
    write_json(pair_path, pairs_summary([
        pair_item(failed_id, ["clash", "dynet"], "deny", stagger_ms),
        pair_item(f"{label}-early", ["dynet", "clash"], "pass", stagger_ms),
    ], stagger_ms))
    write_json(followup_path, followup_summary(failed_id, marker, disposition))
    return pair_path, followup_path


def write_clean_window(root: Path, label: str, stagger_ms: int) -> tuple[Path, Path]:
    pair_path = root / label / "pairs.json"
    followup_path = root / label / "protocol-followup" / "summary.json"
    write_json(pair_path, pairs_summary([
        pair_item(f"{label}-ok", ["clash", "dynet"], "pass", stagger_ms),
    ], stagger_ms))
    write_json(followup_path, empty_followup_summary())
    return pair_path, followup_path


def pair_item(
    item_id: str,
    side_order: list[str],
    dynet_status: str,
    gap_ms: int,
) -> dict[str, object]:
    return {
        "id": item_id,
        "domain": "github.com",
        "probe": "https-head",
        "clashOk": True,
        "dynetStatus": dynet_status,
        "sideMode": "parallel",
        "sideOrder": side_order,
        "parallelSideStaggerMs": gap_ms,
        "pairLagMs": 8,
        "pairGapMs": gap_ms,
    }


def followup_summary(item_id: str, marker: str, disposition: str) -> dict[str, object]:
    return {
        "schema": "dynet-tunnel-private-protocol-followup/v1alpha1",
        "conclusion": {
            "status": "current-read-failure",
            "readFailureUnclassifiedCount": 0,
        },
        "reportEvidence": {
            "readFailureCount": 1,
            "readFailureUnclassifiedCount": 0,
            "sources": [
                {
                    "path": f"/tmp/{item_id}-github.com.json",
                    "status": "deny",
                    "readFailure": {
                        "marker": marker,
                        "disposition": disposition,
                        "protocolStage": "vmess-response-header-length",
                        "context": "shadowsocks-response-salt",
                        "stage": "stream-first-read",
                        "outbound": "private-via-tunnel",
                        "pendingBudgetMs": 30000,
                    },
                }
            ],
        },
    }


def dynet_only_summary(items: list[dict[str, object]]) -> dict[str, object]:
    return {
        "schema": "dynet-probe-manifest-replay/v1alpha1",
        "items": items,
        "totals": {
            "attempted": len(items),
            "passed": sum(1 for item in items if item.get("status") == "pass"),
            "failed": sum(1 for item in items if item.get("status") != "pass"),
        },
    }


def empty_followup_summary() -> dict[str, object]:
    return {
        "schema": "dynet-tunnel-private-protocol-followup/v1alpha1",
        "conclusion": {
            "status": "current-read-clean",
            "readFailureUnclassifiedCount": 0,
        },
        "reportEvidence": {
            "readFailureCount": 0,
            "readFailureUnclassifiedCount": 0,
            "sources": [],
        },
    }


def write_json(path: Path, data: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True))


if __name__ == "__main__":
    unittest.main()
