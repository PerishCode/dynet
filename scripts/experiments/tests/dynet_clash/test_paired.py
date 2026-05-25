from __future__ import annotations

import argparse
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from dynet_clash import paired, paired_retry


class DynetClashPairedTest(unittest.TestCase):
    def test_alternate_order(self) -> None:
        self.assertEqual(paired.pair_order("alternate", 0), ["clash", "dynet"])
        self.assertEqual(paired.pair_order("alternate", 1), ["dynet", "clash"])
        self.assertEqual(paired.pair_order("dynet-first", 0), ["dynet", "clash"])

    def test_selected_entries(self) -> None:
        with tempfile.TemporaryDirectory() as raw_dir:
            manifest = Path(raw_dir) / "manifest.json"
            manifest.write_text(json.dumps({
                "entries": [
                    entry("0002", "work-direct", "example.com", "tcp-connect", 1000),
                    entry("0001", "github-proof", "api.github.com", "https-head", 500),
                    entry("0003", "github-proof", "api.github.com", "dns", 1500),
                ],
            }))
            args = argparse.Namespace(
                manifest=str(manifest),
                probe_type=["https-head"],
                bucket=["github-proof"],
                domain=None,
                behavior=None,
                limit=None,
            )

            rows = paired.selected_entries(args)

        self.assertEqual([row["id"] for row in rows], ["0001"])

    def test_summary(self) -> None:
        report = paired.summarize_pairs(
            [
                {
                    "id": "0001",
                    "bucket": "github-proof",
                    "domain": "api.github.com",
                    "probe": "https-head",
                    "targetStartOffsetMs": 0,
                    "sideOrder": ["clash", "dynet"],
                    "pairGapMs": 42,
                    "clash": {"ok": True},
                    "dynet": {"status": "pass"},
                }
            ],
            paired_args(),
        )

        self.assertEqual(report["pairGapMs"]["p95"], 42)
        self.assertEqual(report["pairScheduler"], "open-loop")
        self.assertEqual(report["sideMode"], "parallel")
        self.assertEqual(report["maxConcurrency"], 4)
        self.assertEqual(report["parallelSideStaggerMs"], 0)
        self.assertFalse(report["dynetRetry"]["enabled"])
        self.assertEqual(report["dynetReadPolicy"], {})
        self.assertTrue(report["controllerAttribution"]["overlapRisk"])
        self.assertEqual(report["items"][0]["parallelSideStaggerMs"], None)
        self.assertTrue(report["items"][0]["clashOk"])

    def test_parallel_side_stagger(self) -> None:
        args = paired_args()
        args.parallel_side_stagger_ms = 250

        self.assertEqual(paired.parallel_side_stagger_ms(args), 250)
        self.assertEqual(paired.side_stagger_ms(args, "clash", ["clash", "dynet"]), 0)
        self.assertEqual(paired.side_stagger_ms(args, "dynet", ["clash", "dynet"]), 250)
        self.assertEqual(paired.side_stagger_ms(args, "clash", ["dynet", "clash"]), 250)
        args.side_mode = "sequential"
        self.assertEqual(paired.side_stagger_ms(args, "dynet", ["clash", "dynet"]), 0)

    def test_read_policy_summary(self) -> None:
        args = paired_args()
        args.read_poll_ms = 300
        args.read_budget_ms = 16000
        args.read_sleep_ms = 20
        policy = {
            "pollTimeoutMs": 300,
            "pendingBudgetMs": 16000,
            "pendingSleepMs": 20,
        }
        report = paired.summarize_pairs(
            [
                {
                    "id": "0001",
                    "bucket": "github-proof",
                    "domain": "api.github.com",
                    "probe": "https-head",
                    "sideOrder": ["clash", "dynet"],
                    "pairGapMs": 1,
                    "clash": {"ok": True},
                    "dynet": {"status": "pass", "readPolicy": policy},
                }
            ],
            args,
        )

        self.assertEqual(report["dynetReadPolicy"], policy)
        self.assertEqual(report["items"][0]["dynetReadPolicy"], policy)
        self.assertEqual(paired.pair_brief(report)["dynetReadPolicy"], policy)

    def test_dynet_retry(self) -> None:
        with tempfile.TemporaryDirectory() as raw_dir:
            root = Path(raw_dir)
            args = retry_args()
            with patch(
                "dynet_clash.paired_retry.dynet_manifest.run_probe",
                side_effect=fake_probe,
            ):
                item = paired_retry.run(
                    args,
                    entry("0001", "github-proof", "api.github.com", "https-head", 0),
                    root / "dynet",
                    0.0,
                    actual_start_offset_ms=0,
                    target_start_offset_ms=0,
                )

        self.assertEqual(item["status"], "pass")
        self.assertEqual(item["actualStartOffsetMs"], 0)
        self.assertEqual(item["directTlsRetry"]["attemptsUsed"], 2)
        self.assertTrue(item["directTlsRetry"]["recoveredAfterRetry"])
        self.assertEqual(
            item["directTlsRetry"]["attempts"][0]["classification"],
            "direct-tls-eof-after-path-complete",
        )

    def test_retry_totals(self) -> None:
        totals = paired_retry.totals(retry_pairs(), retry_args())

        self.assertEqual(totals["rowsWithMultipleAttempts"], 1)
        self.assertEqual(totals["attemptClassified"], 3)
        self.assertEqual(totals["finalClassified"], 2)
        self.assertEqual(totals["firstAttemptDirectTlsEof"], 1)
        self.assertEqual(totals["finalDirectTlsEof"], 0)
        self.assertEqual(
            totals["attemptClassifications"],
            [
                {"key": "direct-tls-eof-after-path-complete", "count": 1},
                {"key": "not-dynet-failure", "count": 2},
            ],
        )
        self.assertEqual(
            totals["finalClassifications"],
            [{"key": "not-dynet-failure", "count": 2}],
        )

    def test_summary_totals(self) -> None:
        totals = paired_retry.summary_totals(
            {
                "dynetRetry": {
                    "enabled": True,
                    "maxAttempts": 3,
                    "retrySleepMs": 0,
                },
                "items": [
                    {"dynetRetry": pair["dynet"]["directTlsRetry"]}
                    for pair in retry_pairs()
                ],
            },
            {"enabled": True, "maxAttempts": 3, "retrySleepMs": 250},
        )

        self.assertEqual(totals["attemptClassified"], 3)
        self.assertEqual(totals["finalDirectTlsEof"], 0)

    def test_parser(self) -> None:
        args = paired.build_parser().parse_args([
            "--manifest",
            "manifest.json",
            "--config",
            "dynet.json",
            "--pair-scheduler",
            "open-loop",
            "--max-concurrency",
            "8",
            "--side-mode",
            "parallel",
            "--parallel-side-stagger-ms",
            "250",
            "--dynet-direct-tls-retry-attempts",
            "3",
            "--probe-read-pending-budget-ms",
            "16000",
            "--probe-read-poll-timeout-ms",
            "300",
            "--probe-read-pending-sleep-ms",
            "20",
        ])

        self.assertEqual(args.pair_scheduler, "open-loop")
        self.assertEqual(args.max_concurrency, 8)
        self.assertEqual(args.side_mode, "parallel")
        self.assertEqual(args.parallel_side_stagger_ms, 250)
        self.assertEqual(args.dynet_direct_tls_retry_attempts, 3)
        self.assertEqual(args.read_budget_ms, 16000)
        self.assertEqual(args.read_poll_ms, 300)
        self.assertEqual(args.read_sleep_ms, 20)


def entry(
    item_id: str,
    bucket: str,
    domain: str,
    probe: str,
    offset_ms: int,
) -> dict[str, object]:
    return {
        "id": item_id,
        "bucket": bucket,
        "domain": domain,
        "probe": probe,
        "port": 443,
        "scheduledOffsetMs": offset_ms,
    }


def fake_probe(
    args: argparse.Namespace,
    item: dict[str, object],
    output_dir: Path,
    actual_start_offset_ms: int | None = None,
    target_start_offset_ms: int | None = None,
) -> dict[str, object]:
    self_check_retry_args(args)
    return {
        "id": item["id"],
        "bucket": item["bucket"],
        "behavior": item.get("behavior"),
        "groupId": item.get("groupId"),
        "domain": item["domain"],
        "sourceProbe": item["probe"],
        "dynetProtocol": item["probe"],
        "scheduledOffsetMs": item["scheduledOffsetMs"],
        "targetStartOffsetMs": target_start_offset_ms,
        "actualStartOffsetMs": actual_start_offset_ms,
        "exitCode": 0,
        "status": "pass",
        "reason": None,
        "failureScope": None,
        "selectedOutbound": "direct",
        "failedStage": None,
        "httpStatus": None,
        "reportPath": str(output_dir / f"{item['id']}-{item['domain']}.json"),
        "directTlsRetry": {
            "attemptsUsed": 2,
            "recoveredAfterRetry": True,
            "unresolvedDirectTlsEof": False,
            "attempts": [
                {"attempt": 1, "classification": "direct-tls-eof-after-path-complete"},
                {"attempt": 2, "classification": "not-dynet-failure"},
            ],
        },
    }


def self_check_retry_args(args: argparse.Namespace) -> None:
    assert args.dynet_direct_tls_retry_attempts == 3
    assert args.dynet_direct_tls_retry_sleep_ms == 0


def retry_args() -> argparse.Namespace:
    return argparse.Namespace(**retry_attrs(3, 0))


def retry_pairs() -> list[dict[str, object]]:
    return [
        {
            "dynet": {
                "directTlsRetry": {
                    "attemptsUsed": 2,
                    "recoveredAfterRetry": True,
                    "unresolvedDirectTlsEof": False,
                    "attempts": [
                        {
                            "attempt": 1,
                            "classification": "direct-tls-eof-after-path-complete",
                        },
                        {"attempt": 2, "classification": "not-dynet-failure"},
                    ],
                }
            }
        },
        {
            "dynet": {
                "directTlsRetry": {
                    "attemptsUsed": 1,
                    "recoveredAfterRetry": False,
                    "unresolvedDirectTlsEof": False,
                    "attempts": [
                        {"attempt": 1, "classification": "not-dynet-failure"}
                    ],
                }
            }
        },
    ]


def paired_args() -> argparse.Namespace:
    return argparse.Namespace(
        **{
            "replay_mode": "paired-interleaved",
            "pair_scheduler": "open-loop",
            "side_mode": "parallel",
            "max_concurrency": 4,
            "side_order": "alternate",
            "parallel_side_stagger_ms": 0,
            "clash_controller_unix_socket": "/tmp/clash.sock",
            "clash_controller_url": None,
            **retry_attrs(1, 250),
        }
    )


def retry_attrs(attempts: int, sleep_ms: int) -> dict[str, object]:
    return {
        "dynet_direct_tls_retry_attempts": attempts,
        "dynet_direct_tls_retry_sleep_ms": sleep_ms,
    }


if __name__ == "__main__":
    unittest.main()
