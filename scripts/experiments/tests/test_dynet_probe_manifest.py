from __future__ import annotations

import argparse
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.cli import dynet_probe_manifest as manifest
from probe_smoke import manifest_quality_refresh as refresh
from probe_smoke import non_direct as smoke
from probe_smoke import non_direct_manifest_refresh as nd_refresh


class DynetProbeManifestTest(unittest.TestCase):
    def test_source_maps_tls(self) -> None:
        args = argparse.Namespace(dynet_protocol="source")

        self.assertEqual(
            manifest.dynet_protocol(args, {"probe": "tcp-connect"}),
            "tcp-connect",
        )
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

    def test_quality_state_arg(self) -> None:
        args = argparse.Namespace(
            sudo=False,
            dynet_bin="dynet",
            config="dynet.json",
            dynet_protocol="https-head",
            inbound=None,
            quality_state="quality.json",
        )
        command = manifest.dynet_command(args) + [
            "probe",
            "--config",
            args.config,
            "--url",
            "https://example.com/",
            "--protocol",
            manifest.dynet_protocol(args, {"probe": "https-head"}),
            "--format",
            "json",
        ]
        if args.quality_state:
            command.extend(["--quality-state", args.quality_state])

        self.assertIn("--quality-state", command)
        self.assertIn("quality.json", command)

    def test_retry_arg(self) -> None:
        args = argparse.Namespace(
            **{
                "sudo": False,
                "dynet_bin": "dynet",
                "config": "dynet.json",
                "dynet_protocol": "source",
                "inbound": None,
                "quality_state": None,
                "retry_direct_tls_eof_attempts": 3,
                "retry_direct_tls_eof_sleep_ms": 10,
            }
        )

        command = manifest.dynet_probe_command(
            args,
            {"domain": "api.github.com", "probe": "https-head"},
        )

        self.assertIn("--retry-direct-tls-eof-attempts", command)
        self.assertIn("3", command)
        self.assertIn("--retry-direct-tls-eof-sleep-ms", command)
        self.assertIn("10", command)

    def test_read_policy_arg(self) -> None:
        args = argparse.Namespace(
            **{
                "sudo": False,
                "dynet_bin": "dynet",
                "config": "dynet.json",
                "dynet_protocol": "source",
                "inbound": None,
                "quality_state": None,
                "read_poll_ms": 125,
                "read_budget_ms": 50,
                "read_sleep_ms": 2,
                "retry_direct_tls_eof_attempts": 1,
            }
        )

        command = manifest.dynet_probe_command(
            args,
            {"domain": "api.github.com", "probe": "https-head"},
        )

        self.assertIn("--probe-read-poll-timeout-ms", command)
        self.assertIn("125", command)
        self.assertIn("--probe-read-pending-budget-ms", command)
        self.assertIn("50", command)
        self.assertIn("--probe-read-pending-sleep-ms", command)
        self.assertIn("2", command)

    def test_report_read_policy(self) -> None:
        policy = {"pendingBudgetMs": 50}

        self.assertEqual(manifest.report_read_policy({"readPolicy": policy}), policy)

    def test_retry_report(self) -> None:
        retry = {
            "enabled": True,
            "attemptsUsed": 2,
            "recoveredAfterRetry": True,
        }

        self.assertEqual(manifest.retry_report({"retry": retry}), retry)

    def test_schedule_scaling(self) -> None:
        args = argparse.Namespace(schedule_scale=0.5)

        self.assertEqual(
            manifest.replay_target_ms(args, {"scheduledOffsetMs": 3000}, 1000),
            1000,
        )

    def test_negative_scale_denied(self) -> None:
        with self.assertRaises(argparse.ArgumentTypeError):
            manifest.non_negative_float("-0.1")

    def test_summary_records_policy(self) -> None:
        with tempfile.TemporaryDirectory() as raw_dir:
            output_dir = Path(raw_dir)

            summary = manifest.write_summary(
                output_dir,
                [summary_item()],
                summary_args(),
            )

            markdown = (output_dir / "summary.md").read_text()

        self.assertEqual(
            summary["probePolicy"]["readPolicy"],
            {
                "pollTimeoutMs": 125,
                "pendingBudgetMs": 50,
                "pendingSleepMs": 2,
            },
        )
        self.assertIn("read policy", markdown)

    def test_quality_refresh(self) -> None:
        with tempfile.TemporaryDirectory() as raw_dir:
            output_dir = Path(raw_dir)
            write_manifest_probe_artifact(output_dir)
            previous = output_dir / "previous-state.json"
            context = output_dir / "product-effect.json"
            write_json(previous, previous_quality_state())
            write_json(context, product_effect_context())

            pipeline = manifest.build_quality_pipeline(
                output_dir,
                quality_pipeline_args(previous, context),
            )
            state = manifest.load_json(output_dir / "quality-state.json")
            entry = next(
                item
                for item in state["outbounds"]
                if item.get("outbound") == "private-a"
                and item.get("targetFamily") == "example.com"
            )

        self.assertEqual(pipeline["previousQualityStates"], 1)
        self.assertEqual(pipeline["qualityGapPromotionContexts"], 1)
        self.assertEqual(state["plannerFeedback"]["promotion"]["contexts"], 1)
        self.assertEqual(state["source"]["retainedPreviousStates"], 1)
        self.assertEqual(entry["attempts"], 3)
        self.assertEqual(entry["confidence"], "medium")


class ProbeSmokeHelperTest(unittest.TestCase):
    def test_non_direct_helpers(self) -> None:
        config = smoke.config_json(12345)
        outbounds = {item["tag"]: item for item in config["outbounds"]}
        report = {"events": [{"kind": "outbound-graph-selected", "fields": {"selected": "ss"}}]}
        by_bucket = smoke.aggregate(
            [
                {"status": "pass", "bucket": "a", "behavior": "x"},
                {"status": "deny", "bucket": "a", "behavior": "y"},
            ],
            "bucket",
        )

        self.assertEqual(outbounds["private-ss"]["payload"]["port"], 12345)
        self.assertEqual(outbounds["auto-ss"]["payload"]["selection"]["edges"][0]["to"], "private-ss")
        self.assertEqual(outbounds["auto-vmess"]["payload"]["selection"]["edges"][0]["to"], "private-vmess")
        self.assertEqual(outbounds["private-ss-via-bound"]["payload"]["bound"], "bound-plan")
        self.assertEqual(config["rules"][0]["outbound"], "private-ss-via-bound")
        self.assertEqual(config["rules"][1]["outbound"], "private-vmess-via-bound")
        self.assertEqual(smoke.selected_outbound(report), "ss")
        self.assertEqual(smoke.parse_report("{")["schema"], "dynet-probe/invalid-output")
        self.assertEqual(json.loads(json.dumps(by_bucket))[0]["passed"], 1)
        self.assertEqual(by_bucket[0]["failed"], 1)

    def test_refresh_helpers(self) -> None:
        config = refresh.config_json()
        outbounds = {item["tag"]: item for item in config["outbounds"]}
        with tempfile.TemporaryDirectory() as raw_dir:
            output_dir = Path(raw_dir)
            write_refresh_artifact(output_dir)

            result = refresh.verify(output_dir)

        self.assertEqual(config["routes"][0]["outbound"], "auto-direct")
        self.assertEqual(outbounds["auto-direct"]["payload"]["selection"]["edges"][0]["to"], "direct")
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["qualityState"]["entry"]["attempts"], 4)
        self.assertEqual(result["qualityPipeline"]["previousAttributions"], 1)

    def test_nd_refresh_helpers(self) -> None:
        manifest_json = nd_refresh.manifest_json()
        with tempfile.TemporaryDirectory() as raw_dir:
            output_dir = Path(raw_dir)
            write_nd_refresh_artifact(output_dir)

            result = nd_refresh.verify(output_dir)

        self.assertEqual(len(manifest_json["entries"]), len(smoke.smoke_entries()))
        self.assertEqual(manifest_json["entries"][0]["probe"], "tcp-connect")
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["server"]["connections"], 12)
        self.assertEqual(result["qualityState"]["planCandidates"]["private-ss"]["attempts"], 2)


def write_manifest_probe_artifact(output_dir: Path) -> None:
    report_path = output_dir / "0001-api.example.com.json"
    write_json(report_path, probe_report())
    write_json(
        output_dir / "summary.json",
        {
            "schema": manifest.SUMMARY_SCHEMA,
            "replay": {"schedule": False},
            "totals": {"attempted": 1, "passed": 1, "failed": 0},
            "items": [
                {
                    "id": "0001",
                    "bucket": "github-proof",
                    "behavior": "single",
                    "domain": "api.example.com",
                    "sourceProbe": "tcp-connect",
                    "dynetProtocol": "tcp-connect",
                    "status": "pass",
                    "selectedOutbound": "private-a",
                    "reportPath": report_path.name,
                }
            ],
        },
    )


def summary_item() -> dict[str, object]:
    return {
        "id": "0001",
        "status": "pass",
        "bucket": "github-proof",
        "behavior": "single",
        "domain": "api.example.com",
        "sourceProbe": "https-head",
        "dynetProtocol": "https-head",
        "selectedOutbound": "private-a",
        "scheduledOffsetMs": 0,
        "targetStartOffsetMs": 0,
        "actualStartOffsetMs": 1,
        "failedStage": None,
    }


def summary_args() -> argparse.Namespace:
    args = argparse.Namespace(
        replay_schedule=False,
        schedule_scale=1.0,
        replay_mode="open-loop",
        max_concurrency=16,
        lag_budget_ms=1000,
        dynet_protocol="https-head",
        read_poll_ms=125,
        read_budget_ms=50,
        read_sleep_ms=2,
    )
    setattr(args, "retry_direct_tls_eof_attempts", 1)
    setattr(args, "retry_direct_tls_eof_sleep_ms", 250)
    return args


def probe_report() -> dict[str, object]:
    return {
        "schema": "dynet-probe/v1alpha1",
        "status": "pass",
        "target": {"host": "api.example.com"},
        "events": [
            {
                "kind": "route-matched",
                "emittedAtUnixMs": 1000,
                "fields": {"outbound": "auto"},
            },
            {
                "kind": "outbound-candidate-set",
                "emittedAtUnixMs": 1000,
                "fields": candidate_set_fields(),
            },
            {
                "kind": "outbound-graph-selected",
                "emittedAtUnixMs": 1000,
                "fields": {"selected": "private-a", "decisions": "1"},
            },
            {
                "kind": "outbound-attempt-finished",
                "emittedAtUnixMs": 1000,
                "fields": {
                    "outbound": "private-a",
                    "transport": "tcp",
                    "status": "success",
                },
            },
        ],
    }


def candidate_set_fields() -> dict[str, object]:
    return {
        "scope": "plan-candidate",
        "plan": "auto",
        "selected": "private-a",
        "candidateCount": "1",
        "candidates": "private-a",
        "candidatesJson": json.dumps([
            {
                "to": "private-a",
                "quality": {
                    "score": 100,
                    "reason": "exact-quality",
                    "stale": False,
                },
            }
        ]),
    }


def previous_quality_state() -> dict[str, object]:
    return {
        "schema": "dynet-outbound-quality-state/v1alpha1",
        "generatedAtUnixMs": 900,
        "ttlSecs": 300,
        "windowSecs": 1800,
        "expiresAtUnixMs": 2000,
        "outbounds": [
            {
                "outbound": "private-a",
                "scope": "plan-candidate",
                "targetFamily": "example.com",
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
    }


def quality_pipeline_args(previous: Path, context: Path | None = None) -> argparse.Namespace:
    args = argparse.Namespace(
        attribution_output_json=None,
        attribution_output_md=None,
        probe_batch_output_json=None,
        probe_batch_output_md=None,
        quality_output_json=None,
        quality_output_md=None,
        previous_attribution=None,
        previous_quality_state=[str(previous)],
        min_repeat_runs=2,
        quality_now_unix_ms=1000,
        quality_window_seconds=1800,
        quality_ttl_seconds=300,
        quality_gap_mode="observe",
    )
    setattr(args, "quality_gap_promotion_proof", None)
    setattr(args, "quality_gap_promotion_context", [str(context)] if context else None)
    return args


def product_effect_context() -> dict[str, object]:
    return {
        "schema": "dynet-tunnel-private-adapter-product-effect/v1alpha1",
        "status": "product-effect-parity-candidate",
        "conclusion": {
            "nextActions": [
                {
                    "id": "retain-recovered-stage-pressure-observe-only",
                    "evidence": "maturity",
                    "priority": "observe",
                    "plannerPenaltySafe": False,
                }
            ]
        },
    }


def write_refresh_artifact(output_dir: Path) -> None:
    for window in ("window-a", "window-b"):
        write_json(output_dir / window / "summary.json", {"totals": {"attempted": 2, "passed": 2, "failed": 0}})
    write_json(output_dir / "window-b" / "quality-pipeline.json", pipeline_json())
    write_json(
        output_dir / "window-b" / "quality-state.json",
        {
            "source": {"retainedPreviousStates": 1, "retainedPreviousEntries": 2, "currentEntries": 2},
            "outbounds": [
                {
                    "outbound": "direct",
                    "scope": "plan-candidate",
                    "targetFamily": refresh.DOMAIN,
                    "attempts": 4,
                    "successes": 4,
                    "failures": 0,
                    "confidence": "medium",
                }
            ],
        },
    )
    write_json(output_dir / "window-b" / "attribution.json", {"candidateQuality": {"withQuality": 2, "selectedBehind": 0}})


def write_nd_refresh_artifact(output_dir: Path) -> None:
    count = len(smoke.smoke_entries())
    summary = {"totals": {"attempted": count, "passed": count, "failed": 0}}
    for window in ("window-a", "window-b"):
        write_json(output_dir / window / "summary.json", summary)
    write_json(output_dir / "server.json", {"connections": 12, "totalBytes": 1024, "rawPayloadStored": False})
    write_json(output_dir / "window-b" / "quality-pipeline.json", pipeline_json())
    write_json(
        output_dir / "window-b" / "quality-state.json",
        {
            "source": {"retainedPreviousStates": 1, "retainedPreviousEntries": 6, "currentEntries": 6},
            "outbounds": [
                nd_quality("private-ss", "candidate.example"),
                nd_quality("private-vmess", "candidate-vmess.example"),
                nd_quality("private-trojan", "candidate-trojan.example"),
            ],
        },
    )
    write_json(
        output_dir / "window-b" / "attribution.json",
        {"candidateQuality": {"withQuality": count, "selectedBehind": 0}},
    )


def pipeline_json() -> dict[str, object]:
    return {"previousQualityStates": 1, "previousAttributions": 1, "plannerFeedback": {"penaltyObservations": 0}}


def nd_quality(outbound: str, family: str) -> dict[str, object]:
    return {
        "outbound": outbound,
        "scope": "plan-candidate",
        "targetFamily": family,
        "attempts": 2,
        "successes": 2,
        "failures": 0,
        "confidence": "low",
    }


def write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))
