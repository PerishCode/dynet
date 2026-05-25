from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.cli import dynet_probe_quality as quality
from dynet_trace import batch as trace_batch
from dynet_trace import common
from dynet_trace import probe_batch
from dynet_trace import summary as trace_summary
from tests.dynet_trace.support import cascade_report, fallback_report, non_retry_report, stage


class DynetProbeBatchTest(unittest.TestCase):
    def test_repeated_gap(self) -> None:
        with tempfile.TemporaryDirectory() as raw_dir:
            workdir = Path(raw_dir)
            first = write_batch_report(workdir / "run-a" / "attribution.json", "a1")
            second = write_batch_report(workdir / "run-b" / "attribution.json", "b1")

            report = probe_batch.build_probe_batch([first, second], min_repeat_runs=2)

        self.assertEqual(report["totals"]["runs"], 2)
        self.assertEqual(report["totals"]["selectedBehind"], 2)
        self.assertEqual(report["totals"]["repeatedQualityGapKeys"], 1)
        self.assertEqual(
            report["qualityGapSignals"][0]["plannerAction"],
            "investigate-plan-choice",
        )

    def test_single_gap(self) -> None:
        with tempfile.TemporaryDirectory() as raw_dir:
            workdir = Path(raw_dir)
            first = write_batch_report(workdir / "run-a" / "attribution.json", "a1")

            report = probe_batch.build_probe_batch([first], min_repeat_runs=2)

        self.assertEqual(report["totals"]["repeatedQualityGapKeys"], 0)
        self.assertEqual(report["qualityGapSignals"][0]["plannerAction"], "observe")

    def test_private_source_batch(self) -> None:
        with tempfile.TemporaryDirectory() as raw_dir:
            workdir = Path(raw_dir)
            first = write_private_source_report(workdir / "run-a" / "attribution.json", "a1")
            second = write_private_source_report(workdir / "run-b" / "attribution.json", "b1")

            report = probe_batch.build_probe_batch([first, second], min_repeat_runs=2)

        self.assertEqual(report["totals"]["privateSourcePolicyItems"], 2)
        self.assertEqual(report["totals"]["repeatedPrivateSourcePolicyKeys"], 1)
        signal = report["privateSourcePolicySignals"][0]
        self.assertEqual(signal["plannerAction"], "observe-private-source-policy")
        self.assertEqual(signal["confidence"], "repeat-private-source-policy")


class DynetTraceBatchTest(unittest.TestCase):
    def test_fallback_signals(self) -> None:
        with tempfile.TemporaryDirectory() as raw_dir:
            root = Path(raw_dir)
            summary_path = root / "run-a" / "summary.json"
            summary_path.parent.mkdir()
            summary_path.write_text(json.dumps(trace_summary.build_summary(fallback_report())))

            report = trace_batch.build_batch([summary_path], 1, 0.1, 0.25)

        self.assertEqual(report["totals"]["fallbackSignals"], 2)
        self.assertEqual(report["totals"]["recoveredFallbackSignals"], 2)
        self.assertEqual(report["totals"]["nonRetrySafeFallbackSignals"], 0)
        self.assertEqual(report["fallbackSignals"][0]["plannerAction"], "observe")


class DynetProbeQualityFeedbackTest(unittest.TestCase):
    def test_feedback_observe(self) -> None:
        with tempfile.TemporaryDirectory() as raw_dir:
            batch_path = write_quality_batch(Path(raw_dir) / "batch.json")

            state = quality.build_state(quality_args(batch_path, "observe"))

        self.assertEqual(state["plannerFeedback"]["repeatedQualityGaps"], 1)
        self.assertEqual(state["plannerFeedback"]["penaltyObservations"], 0)
        self.assertEqual(state["outbounds"], [])
        self.assertEqual(state["signals"][0]["action"], "observe")

    def test_feedback_penalize(self) -> None:
        with tempfile.TemporaryDirectory() as raw_dir:
            batch_path = write_quality_batch(Path(raw_dir) / "batch.json")

            state = quality.build_state(quality_args(batch_path, "penalize"))

        self.assertEqual(state["plannerFeedback"]["penaltyObservations"], 1)
        family_entry = next(
            item for item in state["outbounds"] if item.get("targetFamily") == "github.com"
        )
        self.assertEqual(family_entry["outbound"], "a")
        self.assertEqual(family_entry["scope"], "dialer-bound")
        self.assertEqual(family_entry["verdict"], "unhealthy")

    def test_auto_no_proof(self) -> None:
        with tempfile.TemporaryDirectory() as raw_dir:
            batch_path = write_quality_batch(Path(raw_dir) / "batch.json")

            state = quality.build_state(quality_args(batch_path, "auto"))

        feedback = state["plannerFeedback"]
        self.assertEqual(feedback["mode"], "observe")
        self.assertEqual(feedback["requestedMode"], "auto")
        self.assertEqual(feedback["penaltyObservations"], 0)
        self.assertFalse(feedback["promotion"]["eligible"])

    def test_auto_with_proof(self) -> None:
        with tempfile.TemporaryDirectory() as raw_dir:
            root = Path(raw_dir)
            batch_path = write_quality_batch(root / "batch.json")
            proof_path = write_runtime_repeat_proof(root / "runtime-repeat.json")

            state = quality.build_state(quality_args(batch_path, "auto", proof=[proof_path]))

        feedback = state["plannerFeedback"]
        self.assertEqual(feedback["mode"], "penalize")
        self.assertEqual(feedback["penaltyObservations"], 1)
        self.assertTrue(feedback["promotion"]["eligible"])
        self.assertEqual(feedback["promotion"]["action"], "allow-penalty-feedback")

    def test_auto_bad_proof(self) -> None:
        with tempfile.TemporaryDirectory() as raw_dir:
            root = Path(raw_dir)
            batch_path = write_quality_batch(root / "batch.json")
            proof_path = write_runtime_repeat_proof(root / "runtime-repeat.json", failed_runs=1)

            state = quality.build_state(quality_args(batch_path, "auto", proof=[proof_path]))

        feedback = state["plannerFeedback"]
        self.assertEqual(feedback["mode"], "observe")
        self.assertEqual(feedback["penaltyObservations"], 0)
        self.assertFalse(feedback["promotion"]["eligible"])

    def test_source_policy_feedback(self) -> None:
        with tempfile.TemporaryDirectory() as raw_dir:
            batch_path = write_private_source_batch(Path(raw_dir) / "batch.json")

            state = quality.build_state(quality_args(batch_path, "penalize"))

        self.assertEqual(state["plannerFeedback"]["privateSourcePolicySignals"], 1)
        self.assertEqual(state["plannerFeedback"]["penaltyObservations"], 0)
        self.assertEqual(state["outbounds"], [])
        self.assertEqual(state["signals"][0]["type"], "private-source-policy")
        self.assertEqual(state["signals"][0]["action"], "observe")

    def test_fallback_observe_signal(self) -> None:
        with tempfile.TemporaryDirectory() as raw_dir:
            batch_path = write_trace_batch(Path(raw_dir) / "trace-batch.json")

            state = quality.build_state(quality_args(None, "penalize", trace_batch=[batch_path]))

        feedback = state["plannerFeedback"]
        self.assertEqual(feedback["traceBatches"], 1)
        self.assertEqual(feedback["fallbackSignals"], 2)
        self.assertEqual(feedback["recoveredFallbackSignals"], 2)
        self.assertEqual(feedback["penaltyObservations"], 0)
        self.assertEqual(state["outbounds"], [])
        self.assertEqual(state["signals"][0]["type"], "cascade-fallback")
        self.assertEqual(state["signals"][0]["action"], "observe")
        self.assertEqual(state["signals"][0]["failedBound"], "tunnel-poison-001")
        self.assertEqual(state["signals"][0]["recoveredBound"], "tunnel-001")

    def test_retains_previous_state(self) -> None:
        with tempfile.TemporaryDirectory() as raw_dir:
            state_path = write_previous_state(Path(raw_dir) / "previous.json", expires=1500)

            state = quality.build_state(quality_args(None, "observe", previous=[state_path]))

        self.assertEqual(state["source"]["retainedPreviousStates"], 1)
        self.assertEqual(state["source"]["retainedPreviousEntries"], 1)
        self.assertEqual(state["expiresAtUnixMs"], 1500)
        self.assertEqual(state["outbounds"][0]["attempts"], 2)

    def test_previous_state_expires(self) -> None:
        with tempfile.TemporaryDirectory() as raw_dir:
            state_path = write_previous_state(Path(raw_dir) / "previous.json", expires=999)

            state = quality.build_state(quality_args(None, "observe", previous=[state_path]))

        self.assertEqual(state["source"]["retainedPreviousStates"], 0)
        self.assertEqual(state["outbounds"], [])

    def test_plan_candidate_observation(self) -> None:
        rows = quality.observe({
            "schema": "dynet-probe/v1alpha1",
            "status": "pass",
            "target": {"host": "api.github.com"},
            "events": [
                {
                    "kind": "outbound-candidate-set",
                    "emittedAtUnixMs": 1000,
                    "fields": {"selected": "b"},
                },
                {
                    "kind": "outbound-graph-selected",
                    "emittedAtUnixMs": 1000,
                    "fields": {"selected": "tunnel"},
                },
                {
                    "kind": "outbound-attempt-finished",
                    "emittedAtUnixMs": 1000,
                    "fields": {"transport": "tcp", "outbound": "b"},
                },
            ],
        })

        self.assertEqual(rows[0]["scope"], "plan-candidate")
        self.assertEqual(rows[0]["outbound"], "b")
        self.assertEqual(rows[0]["targetFamily"], "github.com")

    def test_downstream_spares_bound(self) -> None:
        report = cascade_report([
            stage(11, "tunnel-001", "tcp-connect", "success"),
            stage(12, "private-via-tunnel", "stream-first-read", "failed"),
        ])
        rows = quality.observe(report)
        attempts = common.dialer_attempts(report["events"])

        self.assertEqual(rows[0]["outbound"], "tunnel-001")
        self.assertEqual(rows[0]["status"], "pass")
        self.assertEqual(rows[0]["cascade"]["failureScope"], "downstream")
        self.assertEqual(attempts[0]["failureScope"], "downstream")
        self.assertEqual(attempts[0]["private"], "private")

    def test_runtime_scope_wins(self) -> None:
        report = cascade_report(
            [stage(11, "tunnel-001", "tcp-connect", "failed")],
            failure_scope="downstream",
        )

        attempts = common.dialer_attempts(report["events"])

        self.assertEqual(attempts[0]["failureScope"], "downstream")

    def test_bound_failure_penalizes(self) -> None:
        rows = quality.observe(cascade_report([
            stage(11, "tunnel-001", "tcp-connect", "failed")
        ]))

        self.assertEqual(rows[0]["outbound"], "tunnel-001")
        self.assertEqual(rows[0]["status"], "deny")
        self.assertEqual(rows[0]["cascade"]["failureScope"], "bound")

    def test_fallback_signal(self) -> None:
        report = fallback_report()

        signals = common.fallback_signals(report["events"])
        summary = trace_summary.build_summary(report)

        self.assertEqual(len(signals), 2)
        self.assertEqual(signals[0]["type"], "pre-replay-bound-failure-recovered")
        self.assertEqual(signals[0]["replaySafe"], "pre-query")
        self.assertEqual(signals[0]["failedBound"], "tunnel-poison-001")
        self.assertEqual(signals[0]["recoveredBound"], "tunnel-001")
        self.assertEqual(signals[0]["plannerAction"], "observe")
        self.assertEqual(summary["fallbackSignals"], signals)

    def test_non_retry_signal(self) -> None:
        report = non_retry_report()
        signals = common.fallback_signals(report["events"])
        summary = trace_summary.build_summary(report)
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0]["type"], "not-retry-safe-cascade-failure")
        self.assertEqual(signals[0]["failureScope"], "downstream")
        self.assertEqual(signals[0]["plannerAction"], "observe")
        self.assertEqual(summary["fallbackSignals"], signals)


def write_batch_report(path: Path, item_id: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(batch_report_json(item_id)))
    return path


def write_quality_batch(path: Path) -> Path:
    path.write_text(json.dumps({
        "schema": "dynet-probe-attribution-batch/v1alpha1",
        "repeatedQualityGaps": [
            {
                "key": [
                    "github-proof",
                    "api.github.com",
                    "dialer-bound",
                    "auto",
                    "a",
                    "b",
                ],
                "runs": ["run-a", "run-b"],
                "items": 2,
                "maxScoreGap": 30,
            }
        ],
    }))
    return path


def write_private_source_batch(path: Path) -> Path:
    path.write_text(json.dumps({
        "schema": "dynet-probe-attribution-batch/v1alpha1",
        "privateSourcePolicySignals": [
            {
                "key": [
                    "tunnel-private",
                    "api.chatgpt.com",
                    "private-via-tunnel",
                    "private",
                ],
                "runs": ["run-a", "run-b"],
                "items": 2,
                "confidence": "repeat-private-source-policy",
            }
        ],
        "repeatedQualityGaps": [],
    }))
    return path


def write_trace_batch(path: Path) -> Path:
    summary_path = path.parent / "run-a" / "summary.json"
    summary_path.parent.mkdir(parents=True)
    summary_path.write_text(json.dumps(trace_summary.build_summary(fallback_report())))
    report = trace_batch.build_batch([summary_path], 1, 0.1, 0.25)
    path.write_text(json.dumps(report))
    return path


def write_runtime_repeat_proof(path: Path, failed_runs: int = 0) -> Path:
    passed = failed_runs == 0
    path.write_text(json.dumps({
        "schema": "dynet-vm-private-runtime-repeat/v1alpha1",
        "tcpForward": True,
        "qualityStateUsed": True,
        "totals": {
            "runs": 2,
            "passedRuns": 2 - failed_runs,
            "failedRuns": failed_runs,
            "workloadFailedRuns": failed_runs,
            "workloadAttempted": 12,
            "workloadSuccess": 12 if failed_runs == 0 else 10,
            "workloadFailure": 0 if failed_runs == 0 else 2,
            "qualityBoundCandidateSets": 10,
            "qualityBoundSelectedWithQuality": 10,
            "qualityBoundSelectedBehind": 0,
            "protocolShortReadErrors": 0,
            "pendingFrameTimeouts": 0,
            "dnsEarlyTimeouts": 0,
            "ipDenials": 0,
        },
        "runs": [
            runtime_proof_run(passed),
            runtime_proof_run(passed),
        ],
    }))
    return path


def runtime_proof_run(passed: bool) -> dict[str, object]:
    return {
        "passed": passed,
        "runtimeStatus": "pass" if passed else "fail",
        "tcpSessions": 3,
        "tcpClosedSessions": 3,
        "tcpSessionFailures": 0 if passed else 1,
        "workloadSuccessRate": 1.0 if passed else 0.5,
    }


def write_previous_state(path: Path, expires: int) -> Path:
    path.write_text(json.dumps({
        "schema": "dynet-outbound-quality-state/v1alpha1",
        "generatedAtUnixMs": 900,
        "ttlSecs": 300,
        "windowSecs": 1800,
        "expiresAtUnixMs": expires,
        "outbounds": [
            {
                "outbound": "private-a",
                "scope": "plan-candidate",
                "transport": "tcp",
                "verdict": "healthy",
                "attempts": 2,
                "successes": 2,
                "failures": 0,
                "errorRate": 0,
                "confidence": "low",
                "stages": [],
            }
        ],
    }))
    return path


def quality_args(
    batch_path: Path | None,
    mode: str,
    previous: list[Path] | None = None,
    proof: list[Path] | None = None,
    trace_batch: list[Path] | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        input=[],
        now_unix_ms=1000,
        window_seconds=1800,
        ttl_seconds=300,
        probe_batch=[str(batch_path)] if batch_path else None,
        trace_batch=[str(item) for item in trace_batch or []],
        previous_state=[str(item) for item in previous or []],
        quality_gap_mode=mode,
        quality_gap_promotion_proof=[str(item) for item in proof or []],
    )


def batch_report_json(item_id: str) -> dict[str, object]:
    return {
        "schema": "dynet-probe-attribution/v1alpha1",
        "totals": {
            "items": 1,
            "failed": 1,
            "unknown": 0,
        },
        "byClassification": [{"key": "plan-suspect", "count": 1}],
        "candidateQuality": {
            "candidateSets": 1,
            "withQuality": 1,
            "selectedBehind": 1,
            "gaps": [
                {
                    "id": item_id,
                    "bucket": "github-proof",
                    "domain": "api.github.com",
                    "scope": "dialer-bound",
                    "classification": "plan-suspect",
                    "plan": "auto",
                    "selected": "a",
                    "selectedScore": -10,
                    "bestScore": 20,
                    "scoreGap": 30,
                    "bestCandidates": ["b"],
                }
            ],
        },
    }


def write_private_source_report(path: Path, item_id: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(private_source_report_json(item_id)))
    return path


def private_source_report_json(item_id: str) -> dict[str, object]:
    return {
        "schema": "dynet-probe-attribution/v1alpha1",
        "totals": {
            "items": 1,
            "failed": 1,
            "unknown": 0,
        },
        "byClassification": [{"key": "node-suspect", "count": 1}],
        "bySuspectComponent": [{"key": "private-source-policy", "count": 1}],
        "candidateQuality": {
            "candidateSets": 0,
            "withQuality": 0,
            "selectedBehind": 0,
            "gaps": [],
        },
        "failures": [
            {
                "id": item_id,
                "bucket": "tunnel-private",
                "domain": "api.chatgpt.com",
                "status": "deny",
                "classification": "node-suspect",
                "suspectComponent": "private-source-policy",
                "selectedOutbound": "private-via-tunnel",
                "failedStage": "private-via-tunnel:stream-first-read",
                "failureScope": "downstream",
                "dialerAttempts": [
                    {
                        "dialer": "private-via-tunnel",
                        "private": "private",
                        "boundSelected": "tunnel-001",
                        "failureScope": "downstream",
                    }
                ],
            }
        ],
    }
