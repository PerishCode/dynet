from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from scripts.lib.jsonio import load_json, write_json


def run_local_pipeline(output_dir: Path, args: Any) -> None:
    attributions = []
    for label in ["run-a", "run-b"]:
        run_dir = output_dir / label
        attribution_path = run_dir / "attribution.json"
        run_command([
            sys.executable,
            "-m",
            "scripts.cli.dynet_trace_attribution",
            "probe-manifest",
            "--summary",
            str(run_dir / "summary.json"),
            "--output-json",
            str(attribution_path),
            "--output-md",
            str(run_dir / "attribution.md"),
        ])
        attributions.append(attribution_path)
    run_command([
        sys.executable,
        "-m",
        "scripts.cli.dynet_trace_attribution",
        "probe-batch",
        "--attribution",
        str(attributions[0]),
        "--attribution",
        str(attributions[1]),
        "--min-repeat-runs",
        "2",
        "--output-json",
        str(output_dir / "probe-batch.json"),
        "--output-md",
        str(output_dir / "probe-batch.md"),
    ])
    build_quality(output_dir, "observe", include_reports=True)
    build_quality(output_dir, "penalize", include_reports=True)
    build_quality(output_dir, "penalty-only", include_reports=False)
    build_quality_refresh(output_dir)
    run_plan(output_dir, args, "plan-static-input.json", "api.gap.example", args.input_quality)
    run_plan(
        output_dir,
        args,
        "plan-cascade-observe.json",
        "plan.gap.example",
        output_dir / "quality-observe.json",
    )
    run_plan(
        output_dir,
        args,
        "plan-cascade-penalty.json",
        "plan.gap.example",
        output_dir / "quality-penalty-only.json",
    )
    run_plan(
        output_dir,
        args,
        "plan-cascade-refresh.json",
        "plan.gap.example",
        output_dir / "quality-refresh.json",
    )


def build_quality(output_dir: Path, mode: str, *, include_reports: bool) -> None:
    actual_mode = "penalize" if mode == "penalty-only" else mode
    command = [
        sys.executable,
        "-m",
        "scripts.cli.dynet_probe_quality",
        "build",
    ]
    if include_reports:
        command.extend([str(output_dir / "run-a"), str(output_dir / "run-b")])
    command.extend([
        "--probe-batch",
        str(output_dir / "probe-batch.json"),
        "--quality-gap-mode",
        actual_mode,
        "--output-json",
        str(output_dir / f"quality-{mode}.json"),
        "--output-md",
        str(output_dir / f"quality-{mode}.md"),
    ])
    run_command(command)


def build_quality_refresh(output_dir: Path) -> None:
    run_command([
        sys.executable,
        "-m",
        "scripts.cli.dynet_probe_quality",
        "build",
        str(output_dir / "run-a"),
        str(output_dir / "run-b"),
        "--previous-state",
        str(output_dir / "quality-observe.json"),
        "--output-json",
        str(output_dir / "quality-refresh.json"),
        "--output-md",
        str(output_dir / "quality-refresh.md"),
    ])


def run_plan(
    output_dir: Path,
    args: Any,
    filename: str,
    domain: str,
    quality_path: Path,
) -> None:
    command = [
        args.dynet_bin,
        "plan",
        "--config",
        str(args.config),
        "--quality-state",
        str(quality_path),
        "--context",
        json.dumps({"destinationDomain": domain}, sort_keys=True),
        "--format",
        "json",
    ]
    completed = subprocess.run(command, text=True, capture_output=True, check=True)
    write_json(output_dir / filename, json.loads(completed.stdout))


def run_command(command: list[str]) -> None:
    subprocess.run(command, check=True, capture_output=True, text=True)


def verify(output_dir: Path) -> dict[str, Any]:
    errors = []
    summary = load_json(output_dir / "summary.json")
    batch = load_json(output_dir / "probe-batch.json")
    observe = load_json(output_dir / "quality-observe.json")
    penalize = load_json(output_dir / "quality-penalize.json")
    penalty_only = load_json(output_dir / "quality-penalty-only.json")
    refresh = load_json(output_dir / "quality-refresh.json")
    static_plan = load_json(output_dir / "plan-static-input.json")
    observe_plan = load_json(output_dir / "plan-cascade-observe.json")
    penalty_plan = load_json(output_dir / "plan-cascade-penalty.json")
    refresh_plan = load_json(output_dir / "plan-cascade-refresh.json")
    refresh_entry = quality_entry(refresh, "private-a", "plan-candidate", "gap.example")
    refresh_quality = candidate_quality(refresh_plan, "private-a")

    if summary["totals"]["failed"] != 0:
        errors.append("expected both runtime probes to pass")
    if summary["server"]["connections"] != summary["totals"]["attempted"]:
        errors.append("expected sink connections to match probe attempts")
    if summary["server"]["rawPayloadStored"] is not False:
        errors.append("server artifact must not store raw payload")
    for label in ["run-a", "run-b"]:
        attribution = load_json(output_dir / label / "attribution.json")
        quality = attribution.get("candidateQuality", {})
        if quality.get("selectedBehind") != 1:
            errors.append(f"expected one selected-behind gap in {label}")
    if batch["totals"].get("repeatedQualityGapKeys") != 1:
        errors.append("expected one repeated quality-gap key")
    if observe["plannerFeedback"].get("penaltyObservations") != 0:
        errors.append("observe mode should not emit penalty observations")
    if int(penalize["plannerFeedback"].get("penaltyObservations") or 0) <= 0:
        errors.append("penalize mode should emit penalty observations")
    if not unhealthy_entry(penalty_only, "private-a"):
        errors.append("penalty-only state should mark private-a unhealthy")
    if selected(static_plan) != "private-a" or not selected_loses(static_plan):
        errors.append("static plan should select private-a while quality prefers private-b")
    if selected(observe_plan) != "private-a":
        errors.append("observe state should not move cascade plan away from private-a")
    if selected(penalty_plan) != "private-b":
        errors.append("penalty-only state should move cascade plan to private-b")
    if refresh["source"].get("retainedPreviousStates") != 1:
        errors.append("refresh should retain one previous quality state")
    if refresh["source"].get("retainedPreviousEntries", 0) <= 0:
        errors.append("refresh should retain previous quality entries")
    if refresh["source"].get("currentEntries", 0) <= 0:
        errors.append("refresh should include current quality entries")
    if not refresh_entry or refresh_entry.get("attempts") != 4:
        errors.append("refresh should merge previous and current private-a attempts")
    if refresh_entry and refresh_entry.get("confidence") != "medium":
        errors.append("refresh should raise private-a confidence to medium")
    if selected(refresh_plan) != "private-a":
        errors.append("refresh state should keep cascade plan on private-a")
    if not refresh_quality:
        errors.append("refresh plan should attach candidate quality to private-a")
    elif refresh_quality.get("stale") is not False or refresh_quality.get("score", 0) <= 0:
        errors.append("refresh plan should consume non-stale positive quality")

    result = {
        "schema": "dynet-quality-gap-smoke-verification/v1alpha1",
        "status": "pass" if not errors else "fail",
        "errors": errors,
        "summaryTotals": summary["totals"],
        "probeBatchTotals": batch["totals"],
        "observePlannerFeedback": observe["plannerFeedback"],
        "penalizePlannerFeedback": penalize["plannerFeedback"],
        "plans": {
            "staticInput": selected(static_plan),
            "cascadeObserve": selected(observe_plan),
            "cascadePenalty": selected(penalty_plan),
            "cascadeRefresh": selected(refresh_plan),
        },
        "qualityRefresh": {
            "source": refresh["source"],
            "entry": entry_summary(refresh_entry),
            "planQuality": quality_summary(refresh_quality),
        },
    }
    write_json(output_dir / "verification.json", result)
    return result


def selected(plan: dict[str, Any]) -> str | None:
    path = plan.get("outboundPath", {})
    return path.get("selected") if isinstance(path, dict) else None


def selected_loses(plan: dict[str, Any]) -> bool:
    path = plan.get("outboundPath", {})
    decisions = path.get("decisions", []) if isinstance(path, dict) else []
    for decision in decisions:
        candidates = decision.get("candidates", [])
        scores = candidate_scores(candidates)
        chosen = decision.get("selected")
        if chosen in scores and max(scores.values()) > scores[chosen]:
            return True
    return False


def candidate_scores(candidates: list[Any]) -> dict[str, int]:
    scores = {}
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        quality = candidate.get("quality", {})
        if isinstance(quality, dict) and isinstance(quality.get("score"), int):
            scores[str(candidate.get("to"))] = quality["score"]
    return scores


def candidate_quality(plan: dict[str, Any], outbound: str) -> dict[str, Any] | None:
    path = plan.get("outboundPath", {})
    decisions = path.get("decisions", []) if isinstance(path, dict) else []
    for decision in decisions:
        for candidate in decision.get("candidates", []):
            if not isinstance(candidate, dict) or candidate.get("to") != outbound:
                continue
            quality = candidate.get("quality")
            return quality if isinstance(quality, dict) else None
    return None


def quality_entry(
    state: dict[str, Any],
    outbound: str,
    scope: str,
    target_family: str,
) -> dict[str, Any] | None:
    for item in state.get("outbounds", []):
        if (
            item.get("outbound") == outbound
            and item.get("scope") == scope
            and item.get("targetFamily") == target_family
        ):
            return item
    return None


def entry_summary(entry: dict[str, Any] | None) -> dict[str, Any]:
    if not entry:
        return {}
    return {
        "outbound": entry.get("outbound"),
        "scope": entry.get("scope"),
        "targetFamily": entry.get("targetFamily"),
        "attempts": entry.get("attempts"),
        "successes": entry.get("successes"),
        "failures": entry.get("failures"),
        "confidence": entry.get("confidence"),
    }


def quality_summary(quality: dict[str, Any] | None) -> dict[str, Any]:
    if not quality:
        return {}
    return {
        "stale": quality.get("stale"),
        "score": quality.get("score"),
        "confidence": quality.get("confidence"),
        "matchReason": quality.get("matchReason"),
    }


def unhealthy_entry(state: dict[str, Any], outbound: str) -> bool:
    for item in state.get("outbounds", []):
        if item.get("outbound") == outbound and item.get("verdict") == "unhealthy":
            return True
    return False
