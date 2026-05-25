from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from dynet_mainline import adapter_coverage, provider_availability
from dynet_mainline.adapter_coverage_sources import BASELINE_CLEAN_FIELDS
from tunnel_private.cli import build_tunnel_private_parser


class MainlineAdapterCoverageTest(unittest.TestCase):
    def test_vmess_maturity_gap(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            baseline = write_json(root / "baseline.json", mainline_baseline())
            provider = write_json(root / "meta.json", provider_meta())
            product = write_json(root / "product.json", product_effect("trojan"))
            maturity = write_json(root / "maturity.json", adapter_maturity())
            runtime = write_json(root / "vmess-runtime.json", runtime_repeat())
            fallback = write_json(root / "fallback.json", runtime_fallback())

            summary = adapter_coverage.mainline_adapter_coverage_summary(
                expected_adapter_types=["trojan", "vmess", "ss"],
                mainline_baseline_paths=[baseline],
                provider_meta_paths=[provider],
                provider_availability_paths=[],
                adapter_product_effect_paths=[product],
                adapter_readiness_paths=[],
                adapter_maturity_paths=[maturity],
                runtime_repeat_specs=[f"vmess={runtime}"],
                runtime_fallback_paths=[fallback],
            )

        self.assertEqual(summary["status"], "adapter-coverage-gaps-open")
        self.assertFalse(summary["plannerPenaltySafe"])
        self.assertEqual(
            summary["conclusion"]["nextAdapterWork"][0]["adapterType"],
            "vmess",
        )
        self.assertEqual(
            summary["conclusion"]["nextAdapterWork"][0]["gaps"],
            ["adapter-maturity-depth-missing"],
        )
        self.assertFalse(summary["conclusion"]["runtimeWorkUnblocked"])
        by_type = {row["adapterType"]: row for row in summary["adapters"]}
        self.assertEqual(by_type["trojan"]["coverageLevel"], "product-effect-baseline")
        self.assertEqual(by_type["trojan"]["gaps"], [])
        self.assertEqual(by_type["vmess"]["coverageLevel"], "runtime-repeat-clean")
        self.assertEqual(by_type["vmess"]["runtimeRepeat"]["workloadAttempted"], 8)
        self.assertEqual(
            by_type["vmess"]["nextAction"],
            "collect-more-runtime-repeat-for-adapter-maturity",
        )
        self.assertEqual(by_type["ss"]["gaps"], ["provider-candidate-missing"])
        self.assertEqual(by_type["ssr"]["coverageLevel"], "provider-available")
        self.assertEqual(summary["runtimeFallback"]["modes"], ["non-direct"])

    def test_provider_guides_ss(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            provider = write_json(root / "meta.json", provider_meta())
            availability = write_json(
                root / "availability.json",
                provider_availability.provider_availability_summary(
                    expected_adapter_types=["trojan", "vmess", "ss"],
                    current_candidates=[vmess_candidate(), trojan_candidate()],
                ),
            )
            trojan = write_json(root / "trojan-product.json", product_effect("trojan"))
            vmess = write_json(root / "vmess-product.json", product_effect("vmess"))

            summary = adapter_coverage.mainline_adapter_coverage_summary(
                expected_adapter_types=["trojan", "vmess", "ss"],
                mainline_baseline_paths=[],
                provider_meta_paths=[provider],
                provider_availability_paths=[availability],
                adapter_product_effect_paths=[trojan, vmess],
                adapter_readiness_paths=[],
                adapter_maturity_paths=[],
                runtime_repeat_specs=[],
                runtime_fallback_paths=[],
            )

        by_type = {row["adapterType"]: row for row in summary["adapters"]}
        self.assertEqual(by_type["ss"]["providerAvailability"]["availability"], "missing")
        self.assertEqual(by_type["ss"]["gaps"], ["provider-acquisition-required"])
        self.assertEqual(by_type["ss"]["nextAction"], "acquire-current-provider-candidate-before-runtime-work")
        self.assertEqual(
            summary["conclusion"]["nextAdapterWork"][0]["providerAvailability"],
            "missing",
        )
        self.assertEqual(
            summary["conclusion"]["nextAdapterWork"][0]["nextAction"],
            "acquire-current-provider-candidate-before-runtime-work",
        )
        self.assertTrue(summary["conclusion"]["runtimeWorkUnblocked"])
        self.assertEqual(
            summary["conclusion"]["nextRuntimeWork"][0]["id"],
            "continue-runtime-owned-surface-under-current-baseline",
        )
    def test_command_writes_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            provider = write_json(root / "meta.json", provider_meta())
            runtime = write_json(root / "vmess-runtime.json", runtime_repeat())
            output = root / "out"

            with contextlib.redirect_stdout(io.StringIO()):
                status = adapter_coverage.command_mainline_adapter_coverage(
                    argparse_namespace(
                        output_dir=str(output),
                        provider_meta=[str(provider)],
                        runtime_repeat=[f"vmess={runtime}"],
                    )
                )

            self.assertEqual(status, 0)
            self.assertTrue((output / "summary.json").exists())
            self.assertTrue((output / "summary.md").exists())

    def test_parser(self) -> None:
        args = build_tunnel_private_parser(handlers()).parse_args([
            "mainline-adapter-coverage",
            "--output-dir",
            "out",
            "--expected-adapter-type",
            "trojan",
            "--mainline-baseline",
            "baseline.json",
            "--provider-meta",
            "meta.json",
            "--provider-availability",
            "availability.json",
            "--adapter-product-effect",
            "product.json",
            "--adapter-readiness",
            "readiness.json",
            "--adapter-maturity",
            "maturity.json",
            "--runtime-repeat",
            "vmess=runtime.json",
            "--runtime-fallback",
            "fallback.json",
        ])

        self.assertEqual(args.command, "mainline-adapter-coverage")
        self.assertEqual(args.expected_adapter_type, ["trojan"])
        self.assertEqual(args.mainline_baseline, ["baseline.json"])
        self.assertEqual(args.provider_meta, ["meta.json"])
        self.assertEqual(args.provider_availability, ["availability.json"])
        self.assertEqual(args.adapter_product_effect, ["product.json"])
        self.assertEqual(args.adapter_readiness, ["readiness.json"])
        self.assertEqual(args.adapter_maturity, ["maturity.json"])
        self.assertEqual(args.runtime_repeat, ["vmess=runtime.json"])
        self.assertEqual(args.runtime_fallback, ["fallback.json"])

    def test_provider_historical_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            historical = write_json(root / "historical-meta.json", {
                "schema": "dynet-tunnel-private-config/v1alpha1",
                "counts": {"matchedByType": {"ss": 3, "vmess": 2}},
            })
            summary = provider_availability.provider_availability_summary(
                expected_adapter_types=["trojan", "vmess", "ss"],
                current_candidates=[
                    vmess_candidate(),
                    trojan_candidate(),
                    {"type": "ssr", "server": "example.invalid", "port": 443},
                ],
                tunnel_group={
                    "name": "Tunnel",
                    "type": "url-test",
                    "filter": "US",
                    "use": ["provider"],
                },
                historical_provider_meta_paths=[historical],
            )

        self.assertEqual(summary["status"], "provider-availability-gaps-open")
        self.assertFalse(summary["plannerPenaltySafe"])
        by_type = {row["adapterType"]: row for row in summary["adapters"]}
        self.assertEqual(by_type["vmess"]["availability"], "current-compatible")
        self.assertEqual(by_type["trojan"]["availability"], "current-compatible")
        self.assertEqual(by_type["ss"]["availability"], "historical-only")
        self.assertEqual(by_type["ss"]["currentMatched"], 0)
        self.assertEqual(by_type["ss"]["historicalMatched"], 3)
        self.assertEqual(by_type["ss"]["gaps"], ["current-provider-candidate-missing"])
        self.assertEqual(
            by_type["ss"]["nextAction"],
            "reacquire-current-provider-candidate-before-runtime-work",
        )
        self.assertEqual(summary["conclusion"]["gapCount"], 1)
        self.assertFalse(summary["privacy"]["rawSecretsStored"])

    def test_provider_ss_available(self) -> None:
        summary = provider_availability.provider_availability_summary(
            expected_adapter_types=["ss"],
            current_candidates=[ss_candidate()],
        )

        self.assertEqual(summary["status"], "provider-availability-current-complete")
        row = summary["adapters"][0]
        self.assertEqual(row["adapterType"], "ss")
        self.assertEqual(row["availability"], "current-compatible")
        self.assertEqual(row["gaps"], [])

    def test_provider_shape_blocked(self) -> None:
        summary = provider_availability.provider_availability_summary(
            expected_adapter_types=["ss"],
            current_candidates=[
                {
                    "type": "ss",
                    "server": "example.invalid",
                    "port": 443,
                    "cipher": "2022-blake3-aes-128-gcm",
                    "network": "ws",
                }
            ],
        )

        row = summary["adapters"][0]
        self.assertEqual(row["availability"], "current-provider-shape-blocked")
        self.assertEqual(row["gaps"], ["provider-candidate-shape-unusable"])
        self.assertEqual(
            summary["currentProvider"]["incompatibleReasons"],
            [
                {"key": "ss:missing-password", "count": 1},
                {"key": "ss:network-not-tcp", "count": 1},
            ],
        )

    def test_provider_parser(self) -> None:
        args = build_tunnel_private_parser(handlers()).parse_args([
            "mainline-provider-availability",
            "--output-dir",
            "out",
            "--expected-adapter-type",
            "ss",
            "--historical-provider-meta",
            "meta.json",
        ])

        self.assertEqual(args.command, "mainline-provider-availability")
        self.assertEqual(args.expected_adapter_type, ["ss"])
        self.assertEqual(args.historical_provider_meta, ["meta.json"])

def mainline_baseline() -> dict[str, object]:
    return {
        "schema": "dynet-mainline-baseline-gate/v1alpha1",
        "status": "mainline-baseline-current-clean",
        "recommendedUse": "use-as-mainline-baseline-for-next-runtime-slice",
        "plannerPenaltySafe": False,
        "qualityPenaltySafe": False,
        "adapterProductEffect": {"adapterTypes": ["trojan"]},
        "conclusion": {field: True for field in BASELINE_CLEAN_FIELDS},
    }
def provider_meta() -> dict[str, object]:
    return {
        "schema": "dynet-tunnel-private-config-meta/v1alpha1",
        "counts": {
            "matched": 15,
            "supported": 6,
            "selected": 2,
            "matchedByType": {"trojan": 4, "vmess": 10, "ssr": 1},
        },
        "candidates": [
            {"tag": "tunnel-001", "type": "vmess"},
            {"tag": "tunnel-002", "type": "vmess"},
        ],
    }
def product_effect(adapter_type: str) -> dict[str, object]:
    return {
        "schema": "dynet-tunnel-private-adapter-product-effect/v1alpha1",
        "adapterType": adapter_type,
        "status": "product-effect-parity-candidate",
        "plannerPenaltySafe": False,
        "conclusion": {
            "productEffectParityClaimSafe": True,
            "notReadyReasons": [],
        },
        "dynetRuntimeProduct": {
            "clean": True,
            "workloadAttempted": 32,
            "workloadFailure": 0,
            "tcpFlowFailed": 0,
        },
        "pairedProductEffect": {
            "parityCandidate": True,
            "windows": 4,
            "pairedEntries": 24,
        },
    }

def adapter_maturity() -> dict[str, object]:
    return {
        "schema": "dynet-tunnel-private-adapter-maturity/v1alpha1",
        "adapterType": "vmess",
        "status": "observe-more",
        "recommendedUse": "continue-mainline-runtime-observe",
        "runtime": {
            "runs": 2,
            "workloadAttempted": 8,
            "workloadFailure": 0,
            "uniquePrimarySelectedCandidates": 2,
        },
        "conclusion": {
            "candidateMature": False,
            "promotionEvaluationEligible": False,
            "notMatureReasons": [
                "runtime-repeat-depth",
                "runtime-workload-depth",
            ],
        },
    }

def runtime_repeat() -> dict[str, object]:
    return {
        "schema": "dynet-vm-private-runtime-repeat/v1alpha1",
        "totals": {
            "runs": 2,
            "passedRuns": 2,
            "failedRuns": 0,
            "workloadFailedRuns": 0,
            "workloadAttempted": 8,
            "workloadSuccess": 8,
            "workloadFailure": 0,
            "workloadFlowEntries": 8,
            "workloadFlowMatchedEntries": 8,
            "workloadFlowCoveredEntries": 8,
            "qualityBoundCandidateSets": 8,
            "qualityBoundSelectedWithQuality": 8,
            "qualityBoundSelectedBehind": 0,
            "tcpFlowRouteGraphSelected": 8,
            "tcpFlowPathComplete": 8,
            "tcpFlowPayloadBidirectional": 8,
            "tcpFlowFailed": 0,
        },
        "runs": [runtime_run()],
    }


def runtime_run() -> dict[str, object]:
    return {
        "tcpClosedSessions": 8,
        "tcpSessionFailures": 0,
        "tcpUpstreamBytes": 4096,
        "tcpDownstreamBytes": 8192,
        "targetIdentity": {
            "domainTargets": [
                "www.cloudflare.com:443",
                "api.github.com:443",
            ]
        },
        "workloadFlow": {
            "rows": [
                {"domain": "www.cloudflare.com"},
                {"domain": "api.github.com"},
            ]
        },
        "boundSelection": {
            "rows": [
                primary_row("tunnel-001"),
                primary_row("tunnel-002"),
            ]
        },
    }


def primary_row(selected: str) -> dict[str, object]:
    return {
        "selected": selected,
        "selectionRole": "primary",
        "candidateCount": 2,
    }


def vmess_candidate() -> dict[str, object]:
    return {
        "type": "vmess",
        "server": "example.invalid",
        "port": 443,
        "uuid": "00000000-0000-0000-0000-000000000000",
    }


def trojan_candidate() -> dict[str, object]:
    return {
        "type": "trojan",
        "server": "example.invalid",
        "port": 443,
        "password": "secret",
    }


def ss_candidate() -> dict[str, object]:
    return {
        "type": "ss",
        "server": "example.invalid",
        "port": 443,
        "cipher": "2022-blake3-aes-128-gcm",
        "password": "secret",
    }


def runtime_fallback() -> dict[str, object]:
    return {
        "schema": "dynet-vm-private-runtime-run/v1alpha1",
        "checks": [{"name": "runtime-pass", "passed": True}],
        "tcpFlow": {
            "failedFlows": 0,
            "routeFallbackUsedFlows": 1,
            "routeFallbackAttemptEvents": 2,
            "routeFallbackFailedFlows": 0,
            "pathCompleteFlows": 1,
            "lifecycleCompleteFlows": 1,
            "payloadBidirectionalFlows": 1,
            "routeFallbackByFinalOutbound": [
                {"key": "private-via-tunnel", "count": 1},
            ],
        },
        "workloadProbe": {
            "totals": {"count": 1, "success": 1, "failure": 0},
            "privacy": {},
            "tunCapture": {},
        },
        "privacy": {},
    }


def argparse_namespace(**overrides: object) -> object:
    defaults = {
        "expected_adapter_type": [],
        "mainline_baseline": [],
        "provider_meta": [],
        "provider_availability": [],
        "adapter_product_effect": [],
        "adapter_readiness": [],
        "adapter_maturity": [],
        "runtime_repeat": [],
        "runtime_fallback": [],
    }
    defaults.update(overrides)
    return type("Args", (), defaults)()


def handlers() -> dict[str, object]:
    names = [
        "build",
        "probe_candidates",
        "probe_plan",
        "probe_private",
        "matrix",
        "compare_matrices",
        "observe_target",
        "observe_owned_private",
        "quality_refresh",
        "quality_regression",
        "quality_sweep",
        "quality_sweep_summary",
        "transport_check",
        "transport_evidence",
        "adapter_readiness",
        "adapter_maturity",
        "adapter_product_effect",
        "mainline_baseline",
        "mainline_provider_availability",
        "mainline_adapter_coverage",
        "mainline_runtime_handoff",
        "protocol_followup",
        "protocol_followup_batch",
        "paired",
        "inspect_plan_quality",
        "compare_plan_quality",
    ]
    return {name: noop for name in names}

def write_json(path: Path, data: dict[str, object]) -> Path:
    path.write_text(json.dumps(data, indent=2, sort_keys=True))
    return path

def noop(_: object) -> int:
    return 0

if __name__ == "__main__":
    unittest.main()
