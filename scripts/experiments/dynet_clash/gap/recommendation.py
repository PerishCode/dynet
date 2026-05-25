from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
from typing import Any

from dynet_clash.gap.followups import (
    direct_tls_followup,
    paired_shape_followup,
    protocol_read_followup,
    write_recommendation_markdown,
)
from dynet_clash.gap.isolated_current import (
    fresh_config_brief,
    fresh_config_clean,
    has_read_failures,
    isolated_current_brief,
    observe_current_isolated,
    observe_saved_config_drift,
    quality_refresh_brief,
)
from dynet_clash.gap.paired_pressure import (
    paired_pressure_brief,
)
from dynet_clash.gap.protocol_retry import protocol_retry_brief, retry_recovered


SCHEMA = "dynet-clash-product-effect-recommendation/v1alpha1"
DEFAULT_OUTPUT_JSON = ".task/resources/dynet-clash-product-effect-recommendation.json"
DEFAULT_OUTPUT_MD = ".task/resources/dynet-clash-product-effect-recommendation.md"
DIRECT_TLS_EOF = "direct-tls-eof-after-path-complete"


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True))


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def build(args: argparse.Namespace) -> dict[str, Any]:
    gap = load_json(Path(args.gap_report))
    drilldown = load_json(Path(args.drilldown))
    retry = load_optional(getattr(args, "protocol_retry_summary", None))
    paired_surface = load_optional(getattr(args, "paired_read_surface_summary", None))
    isolated = load_optional(getattr(args, "isolated_protocol_followup", None))
    isolated_quality = load_optional(getattr(args, "isolated_quality_refresh", None))
    fresh_config_summary = load_optional(getattr(args, "fresh_config_summary", None))
    fresh_config_followup = load_optional(getattr(args, "fresh_config_followup", None))
    return build_from_reports(
        gap,
        drilldown,
        args,
        retry,
        paired_surface,
        isolated,
        isolated_quality,
        fresh_config_summary,
        fresh_config_followup,
    )


def build_from_reports(
    gap: dict[str, Any],
    drilldown: dict[str, Any],
    args: argparse.Namespace,
    protocol_retry: dict[str, Any] | None = None,
    paired_surface: dict[str, Any] | None = None,
    isolated_current: dict[str, Any] | None = None,
    isolated_quality: dict[str, Any] | None = None,
    fresh_config_summary: dict[str, Any] | None = None,
    fresh_config_followup: dict[str, Any] | None = None,
) -> dict[str, Any]:
    gates = recommendation_gates(gap, drilldown, protocol_retry)
    recommendation = recommendation_from_gates(
        gates,
        gap,
        drilldown,
        protocol_retry,
        paired_surface,
        isolated_current,
        isolated_quality,
        fresh_config_summary,
        fresh_config_followup,
    )
    return {
        "schema": SCHEMA,
        "generatedAt": utc_now(),
        "inputs": {
            "gapReport": args.gap_report,
            "drilldown": args.drilldown,
            "protocolRetrySummary": getattr(args, "protocol_retry_summary", None),
            "pairedReadSurfaceSummary": getattr(
                args,
                "paired_read_surface_summary",
                None,
            ),
            "isolatedProtocolFollowup": getattr(
                args,
                "isolated_protocol_followup",
                None,
            ),
            "isolatedQualityRefresh": getattr(
                args,
                "isolated_quality_refresh",
                None,
            ),
            "freshConfigSummary": getattr(args, "fresh_config_summary", None),
            "freshConfigFollowup": getattr(args, "fresh_config_followup", None),
        },
        "privacy": {
            "rawResultsStored": False,
            "responseBodiesStored": False,
            "sourceAddressesStored": False,
        },
        "evidence": {
            "gapConclusion": gap.get("conclusion", {}),
            "runtimeGate": gap.get("runtimeGate", {}),
            "primary": gap.get("primary", {}),
            "outcomeBalance": gap.get("outcomeBalance", {}),
            "drilldownTotals": drilldown.get("totals", {}),
            "classificationCounts": drilldown.get("classificationCounts", []),
            "surfaceCounts": drilldown.get("surfaceCounts", []),
            "protocolReadSurfaceCounts": drilldown.get("protocolReadSurfaceCounts", []),
            "protocolRetry": protocol_retry_brief(protocol_retry),
            "pairedPressure": paired_pressure_brief(paired_surface),
            "isolatedCurrent": isolated_current_brief(isolated_current),
            "isolatedQuality": quality_refresh_brief(isolated_quality),
            "freshConfig": fresh_config_brief(
                fresh_config_summary,
                fresh_config_followup,
            ),
        },
        "gates": gates,
        "recommendation": recommendation,
    }


def recommendation_gates(
    gap: dict[str, Any],
    drilldown: dict[str, Any],
    protocol_retry: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    conclusion = gap.get("conclusion", {})
    totals = drilldown.get("totals", {})
    runtime = gap.get("runtimeGate", {})
    rows = int(totals.get("rows") or 0)
    both_fail = int(totals.get("bothFailure") or 0)
    dynet_only = int(totals.get("dynetOnlyFailure") or 0)
    missing = int(totals.get("rowsWithMissingEvidence") or 0)
    delta = float(conclusion.get("aggregatePrimaryDelta") or 0)
    surface = surface_counts(drilldown)
    gates = [
        gate(
            "product-effect-parity-supported",
            conclusion.get("status") in {
                "parity-supported-superior-gap",
                "superior-supported",
            }
            and delta >= 0,
            conclusion,
            "parity or better with non-negative primary delta",
        ),
        gate(
            "superior-gap-present",
            conclusion.get("status") == "parity-supported-superior-gap",
            conclusion,
            "parity repeat passed but +5% superior threshold not met",
        ),
        gate(
            "runtime-gate-clean",
            runtime_gate_clean(runtime),
            runtime_value(runtime),
            "all product-effect windows have clean dynet runtime workloadFlow gates",
        ),
        gate("retained-dynet-evidence-present", rows > 0, rows, ">0"),
        gate("retained-evidence-complete", missing == 0, missing, 0),
        gate(
            "retained-surface-supported",
            rows > 0 and (direct_tls_eof_dominates(drilldown) or protocol_read_dominates(drilldown)),
            surface,
            "all retained dynet failures classify as one supported observe-only surface",
        ),
        gate(
            "cross-side-volatility-visible",
            protocol_read_dominates(drilldown)
            or (both_fail > 0 and both_fail >= dynet_only),
            {"bothFailure": both_fail, "dynetOnlyFailure": dynet_only},
            "direct TLS EOF needs both-fail volatility; protocol-read surfaces are scoped separately",
        ),
    ]
    if protocol_retry is not None:
        gates.append(gate(
            "protocol-retry-same-path-recovered",
            retry_recovered(protocol_retry, rows),
            protocol_retry_brief(protocol_retry),
            "all retained rows recovered without selected-outbound drift",
        ))
    return gates


def recommendation_from_gates(
    gates: list[dict[str, Any]],
    gap: dict[str, Any],
    drilldown: dict[str, Any],
    protocol_retry: dict[str, Any] | None = None,
    paired_surface: dict[str, Any] | None = None,
    isolated_current: dict[str, Any] | None = None,
    isolated_quality: dict[str, Any] | None = None,
    fresh_config_summary: dict[str, Any] | None = None,
    fresh_config_followup: dict[str, Any] | None = None,
) -> dict[str, Any]:
    passed = {item["name"]: bool(item["passed"]) for item in gates}
    if direct_tls_eof_dominates(drilldown) and all(passed.values()):
        return observe_direct_tls(gap, drilldown)
    if not passed.get("runtime-gate-clean", False):
        return {
            "status": "needs-runtime-attribution",
            "action": "collect-clean-runtime-workload-gate",
            "plannerFeedback": "none",
            "qualityFeedback": "none",
            "runtimePolicy": "none",
            "reason": (
                "product-effect recommendation requires clean runtime workloadFlow "
                "evidence before classifying residual failures as target/probe"
            ),
        }
    if not passed.get("retained-evidence-complete", False):
        return {
            "status": "insufficient-evidence",
            "action": "collect-missing-dynet-evidence",
            "plannerFeedback": "none",
            "qualityFeedback": "none",
            "runtimePolicy": "none",
            "reason": "retained dynet failures still lack required probe event evidence",
        }
    if (
        protocol_read_dominates(drilldown)
        and protocol_retry is not None
            and passed.get("runtime-gate-clean", False)
        and passed.get("protocol-retry-same-path-recovered", False)
    ):
        if has_read_failures(isolated_current):
            if fresh_config_clean(fresh_config_summary, fresh_config_followup):
                return observe_saved_config_drift(
                    gap,
                    drilldown,
                    protocol_retry,
                    isolated_current,
                    isolated_quality,
                    fresh_config_summary,
                    fresh_config_followup,
                    paired_surface,
                )
            return observe_current_isolated(
                gap,
                drilldown,
                protocol_retry,
                isolated_current,
                paired_surface,
                isolated_quality,
            )
        return observe_paired_shape(gap, drilldown, protocol_retry, paired_surface)
    if protocol_read_dominates(drilldown) and all(passed.values()):
        return observe_protocol_read(gap, drilldown)
    return {
        "status": "needs-investigation",
        "action": "continue-attribution",
        "plannerFeedback": "none",
        "qualityFeedback": "none",
        "runtimePolicy": "none",
        "reason": "promotion gates did not support a direct TLS EOF observe-only conclusion",
    }


def observe_direct_tls(
    gap: dict[str, Any],
    drilldown: dict[str, Any],
) -> dict[str, Any]:
    conclusion = gap.get("conclusion", {})
    totals = drilldown.get("totals", {})
    return {
        "status": "observe-direct-tls-target-probe",
        "action": "observe-only",
        "plannerFeedback": "none",
        "qualityFeedback": "none",
        "runtimePolicy": "do-not-change-from-this-artifact-alone",
        "probePolicy": "candidate-for-targeted-direct-tls-retry-or-read-budget-experiment",
        "followUp": direct_tls_followup(),
        "reason": (
            "dynet is repeat-parity but not +5% superior; retained dynet failures "
            "are complete direct TLS EOF evidence with cross-side volatility, so this "
            "artifact does not justify planner or quality penalties"
        ),
        "superiorDeltaGap": conclusion.get("superiorDeltaGap"),
        "additionalNetSuccessesForSuperior": (
            conclusion.get("additionalNetSuccessesForSuperior")
        ),
        "retainedRows": totals.get("rows"),
    }


def observe_protocol_read(
    gap: dict[str, Any],
    drilldown: dict[str, Any],
) -> dict[str, Any]:
    conclusion = gap.get("conclusion", {})
    totals = drilldown.get("totals", {})
    return {
        "status": "observe-protocol-read-probe-budget",
        "action": "run-scoped-read-budget-experiment",
        "plannerFeedback": "none",
        "qualityFeedback": "none",
        "runtimePolicy": "do-not-change-from-this-artifact-alone",
        "probePolicy": "candidate-for-targeted-protocol-read-budget-experiment",
        "followUp": protocol_read_followup(),
        "reason": (
            "retained dynet failures are structured protocol-read surfaces under "
            "a clean runtime gate; classify them as probe/read-budget follow-up "
            "before considering planner, quality, or runtime policy"
        ),
        "superiorDeltaGap": conclusion.get("superiorDeltaGap"),
        "additionalNetSuccessesForSuperior": (
            conclusion.get("additionalNetSuccessesForSuperior")
        ),
        "retainedRows": totals.get("rows"),
        "protocolReadSurfaceCounts": drilldown.get("protocolReadSurfaceCounts", []),
    }


def observe_paired_shape(
    gap: dict[str, Any],
    drilldown: dict[str, Any],
    protocol_retry: dict[str, Any],
    paired_surface: dict[str, Any] | None = None,
) -> dict[str, Any]:
    conclusion = gap.get("conclusion", {})
    totals = drilldown.get("totals", {})
    return {
        "status": "observe-protocol-read-paired-shape",
        "action": "isolate-paired-parallel-pressure",
        "plannerFeedback": "none",
        "qualityFeedback": "none",
        "runtimePolicy": "do-not-change-from-this-artifact-alone",
        "probePolicy": "no-product-retry-from-this-artifact-alone",
        "followUp": paired_shape_followup(paired_surface),
        "reason": (
            "retained protocol-read failures recovered on scoped same-path "
            "external retry, so the evidence points at paired product-window "
            "shape rather than a stable route, candidate, planner, or quality "
            "failure"
        ),
        "superiorDeltaGap": conclusion.get("superiorDeltaGap"),
        "additionalNetSuccessesForSuperior": (
            conclusion.get("additionalNetSuccessesForSuperior")
        ),
        "retainedRows": totals.get("rows"),
        "protocolReadSurfaceCounts": drilldown.get("protocolReadSurfaceCounts", []),
        "protocolRetry": protocol_retry_brief(protocol_retry),
        "pairedPressure": paired_pressure_brief(paired_surface),
    }


def load_optional(path: Any) -> dict[str, Any] | None:
    if not path:
        return None
    raw = Path(str(path))
    if not raw.exists():
        return None
    return load_json(raw)


def classification_count(report: dict[str, Any], key: str) -> int:
    for item in report.get("classificationCounts", []):
        if isinstance(item, dict) and item.get("key") == key:
            return int(item.get("count") or 0)
    return 0


def direct_tls_eof_dominates(report: dict[str, Any]) -> bool:
    rows = int((report.get("totals") or {}).get("rows") or 0)
    return rows > 0 and classification_count(report, DIRECT_TLS_EOF) == rows


def protocol_read_dominates(report: dict[str, Any]) -> bool:
    rows = int((report.get("totals") or {}).get("rows") or 0)
    if rows <= 0:
        return False
    count = sum(
        int(item.get("count") or 0)
        for item in report.get("classificationCounts", [])
        if isinstance(item, dict)
        and str(item.get("key") or "").startswith("protocol-read-")
    )
    return count == rows


def surface_counts(report: dict[str, Any]) -> dict[str, int]:
    protocol_read = sum(
        int(item.get("count") or 0)
        for item in report.get("classificationCounts", [])
        if isinstance(item, dict)
        and str(item.get("key") or "").startswith("protocol-read-")
    )
    return {
        "directTlsEof": classification_count(report, DIRECT_TLS_EOF),
        "protocolRead": protocol_read,
        "rows": int((report.get("totals") or {}).get("rows") or 0),
    }


def runtime_gate_clean(runtime: Any) -> bool:
    if not isinstance(runtime, dict):
        return False
    windows = int(runtime.get("windowCount") or 0)
    clean = int(runtime.get("cleanWindows") or 0)
    missing = int(runtime.get("missingWindows") or 0)
    return windows > 0 and clean == windows and missing == 0


def runtime_value(runtime: Any) -> dict[str, Any]:
    if not isinstance(runtime, dict):
        return {}
    return {
        "windowCount": int(runtime.get("windowCount") or 0),
        "cleanWindows": int(runtime.get("cleanWindows") or 0),
        "missingWindows": int(runtime.get("missingWindows") or 0),
        "classificationCounts": runtime.get("classificationCounts", []),
        "failedCheckCounts": runtime.get("failedCheckCounts", []),
    }


def gate(name: str, passed: bool, value: Any, required: Any) -> dict[str, Any]:
    return {
        "name": name,
        "passed": bool(passed),
        "value": value,
        "required": required,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Recommend handling for product-effect gap drilldown evidence."
    )
    parser.add_argument("--gap-report", required=True)
    parser.add_argument("--drilldown", required=True)
    parser.add_argument("--protocol-retry-summary")
    parser.add_argument("--paired-read-surface-summary")
    parser.add_argument("--isolated-protocol-followup")
    parser.add_argument("--isolated-quality-refresh")
    parser.add_argument("--fresh-config-summary")
    parser.add_argument("--fresh-config-followup")
    parser.add_argument("--output-json", default=DEFAULT_OUTPUT_JSON)
    parser.add_argument("--output-md", default=DEFAULT_OUTPUT_MD)
    return parser


def command(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = build(args)
    output_json = Path(args.output_json)
    output_md = Path(args.output_md)
    write_json(output_json, report)
    write_recommendation_markdown(output_md, report)
    print(json.dumps({
        "outputJson": str(output_json),
        "outputMd": str(output_md),
        "status": report["recommendation"]["status"],
        "action": report["recommendation"]["action"],
    }, sort_keys=True))
    return 0
