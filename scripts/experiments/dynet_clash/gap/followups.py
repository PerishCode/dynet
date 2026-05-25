from __future__ import annotations

from pathlib import Path
from typing import Any

from dynet_clash.gap.paired_pressure import paired_pressure_followup_hint


def direct_tls_followup() -> dict[str, Any]:
    return {
        "subcommand": "gap-retry",
        "command": "uv --project scripts run python -m scripts.cli.dynet_clash_compare gap-retry",
        "artifactSchema": "dynet-clash-direct-tls-retry-experiment/v1alpha1",
        "requiredInputs": ["drilldown", "config"],
        "optionalInputs": ["dynet-bin", "inbound", "quality-state"],
        "policyFlags": ["attempts", "retry-sleep-ms"],
        "rowSelector": "classification == direct-tls-eof-after-path-complete",
        "scope": "experiment-only observe-only follow-up",
    }


def protocol_read_followup() -> dict[str, Any]:
    return {
        "subcommand": "gap-read-budget",
        "command": "uv --project scripts run python -m scripts.cli.dynet_clash_compare gap-read-budget",
        "artifactSchema": "dynet-clash-protocol-read-budget-experiment/v1alpha1",
        "requiredInputs": ["drilldown", "config", "probe-read-pending-budget-ms"],
        "optionalInputs": [
            "dynet-bin",
            "inbound",
            "quality-state",
            "probe-read-poll-timeout-ms",
            "probe-read-pending-sleep-ms",
        ],
        "policyFlags": [
            "probe-read-poll-timeout-ms",
            "probe-read-pending-budget-ms",
            "probe-read-pending-sleep-ms",
        ],
        "rowSelector": "classification startswith protocol-read-",
        "scope": "experiment-only observe-only follow-up",
    }


def paired_shape_followup(
    paired_surface: dict[str, Any] | None = None,
) -> dict[str, Any]:
    followup = {
        "subcommand": "paired",
        "command": "uv --project scripts run python -m scripts.cli.dynet_clash_compare paired",
        "artifactSchema": "dynet-clash-paired-run/v1alpha1",
        "requiredInputs": ["manifest", "config"],
        "optionalInputs": [
            "parallel-side-stagger-ms",
            "side-order",
            "probe-read-pending-budget-ms",
            "quality-state",
        ],
        "rowSelector": "same target/candidate/read-policy product shape",
        "scope": "experiment-only observe-only paired-shape follow-up",
    }
    followup.update(paired_pressure_followup_hint(paired_surface))
    return followup


def isolated_current_followup() -> dict[str, Any]:
    return {
        "subcommand": "dynet-probe-manifest",
        "command": "uv --project scripts run python -m scripts.cli.dynet_probe_manifest",
        "artifactSchema": "dynet-probe-manifest-replay/v1alpha1",
        "requiredInputs": ["manifest", "config", "quality-state"],
        "optionalInputs": [
            "inbound",
            "probe-read-pending-budget-ms",
            "limit",
            "previous-attribution",
        ],
        "rowSelector": "same target/candidate/read-policy isolated dynet shape",
        "scope": "experiment-only observe-only current isolated follow-up",
    }


def current_read_followup() -> dict[str, Any]:
    return {
        "subcommand": "protocol-followup",
        "command": "uv --project scripts run python -m scripts.cli.tunnel_private_lab protocol-followup",
        "artifactSchema": "dynet-tunnel-private-protocol-followup/v1alpha1",
        "requiredInputs": ["report-dir"],
        "optionalInputs": ["readiness", "compare", "attribution", "report"],
        "rowSelector": "fresh-quality current isolated protocol-read failures",
        "scope": "classification-only observe-only protocol-read follow-up",
    }


def write_recommendation_markdown(path: Path, report: dict[str, Any]) -> None:
    recommendation = report["recommendation"]
    lines = [
        "# Dynet vs Clash Product-Effect Recommendation",
        "",
        f"- Status: `{recommendation['status']}`",
        f"- Action: `{recommendation['action']}`",
        f"- Planner feedback: `{recommendation['plannerFeedback']}`",
        f"- Quality feedback: `{recommendation['qualityFeedback']}`",
        f"- Runtime policy: `{recommendation['runtimePolicy']}`",
        f"- Probe policy: `{recommendation.get('probePolicy', 'none')}`",
        f"- Reason: {recommendation['reason']}",
    ]
    append_followup(lines, recommendation.get("followUp"))
    lines.extend(["", "## Gates", ""])
    for item in report["gates"]:
        lines.append(
            f"- `{item['name']}` passed=`{item['passed']}` "
            f"value=`{item['value']}` required=`{item['required']}`"
        )
    path.write_text("\n".join(lines) + "\n")


def append_followup(lines: list[str], follow_up: Any) -> None:
    if not isinstance(follow_up, dict):
        return
    lines.extend([
        f"- Follow-up command: `{follow_up.get('subcommand')}`",
        f"- Follow-up artifact: `{follow_up.get('artifactSchema')}`",
        f"- Follow-up selector: `{follow_up.get('rowSelector')}`",
    ])
    suggested = follow_up.get("suggestedInputs")
    if isinstance(suggested, dict) and suggested:
        lines.append(f"- Follow-up suggested inputs: `{suggested}`")
    boundary = follow_up.get("pairedPressureBoundary")
    if isinstance(boundary, dict) and boundary.get("present"):
        lines.append(
            "- Paired pressure boundary: "
            f"`{boundary.get('maxFailingStaggerMs')}` -> "
            f"`{boundary.get('minCleanStaggerAboveFailureMs')}` ms"
        )
