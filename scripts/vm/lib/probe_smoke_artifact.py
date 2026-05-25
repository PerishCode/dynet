from __future__ import annotations

import json
import tarfile
from pathlib import Path
from typing import Any

from common import CommandError


def extract_tar(tar_path: Path, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    resolved = output_dir.resolve(strict=False)
    with tarfile.open(tar_path, "r:gz") as archive:
        for member in archive.getmembers():
            target = (output_dir / member.name).resolve(strict=False)
            if target != resolved and resolved not in target.parents:
                raise CommandError(f"archive member escapes output dir: {member.name}")
        archive.extractall(output_dir)


def rewrite_summary_report_paths(output_dir: Path) -> None:
    summary_path = output_dir / "summary.json"
    summary = load_json(summary_path)
    for item in summary.get("items", []):
        if not isinstance(item, dict):
            continue
        report_path = item.get("reportPath")
        if not isinstance(report_path, str) or not report_path:
            continue
        item["reportPath"] = Path(report_path).name
    write_json(summary_path, summary)


def write_verification(output_dir: Path, *, require_plan: bool) -> dict[str, Any]:
    verification = build_verification(output_dir, require_plan=require_plan)
    write_json(output_dir / "verification.json", verification)
    if verification["status"] != "pass":
        raise CommandError(
            "VM probe smoke verification failed: " + "; ".join(verification["errors"])
        )
    return verification


def build_verification(output_dir: Path, *, require_plan: bool) -> dict[str, Any]:
    errors: list[str] = []
    summary = load_json(output_dir / "summary.json")
    attribution = load_json(output_dir / "attribution.json")
    probe_batch = load_json(output_dir / "probe-batch.json")
    quality_observe = load_json(output_dir / "quality-observe.json")
    quality_penalize = load_json(output_dir / "quality-penalize.json")
    plans = load_plans(output_dir) if require_plan else {}

    summary_totals = summary.get("totals", {})
    attempted = int(summary_totals.get("attempted") or 0)
    if attempted < 6 or summary_totals.get("failed") != 0:
        errors.append("expected at least 6 attempted probes and 0 failures")
    server = summary.get("server", {})
    if server.get("connections") != attempted:
        errors.append("expected TCP sink connections to match attempted probes")
    if int(server.get("totalBytes") or 0) <= 0:
        errors.append("expected encrypted bytes to reach the TCP sink")
    if server.get("rawPayloadStored") is not False:
        errors.append("server artifact must not store raw payload")

    attribution_totals = attribution.get("totals", {})
    if attribution_totals.get("unknown") != 0:
        errors.append("expected 0 unknown attribution rows")
    if attribution_totals.get("withMissingEvidence") != 0:
        errors.append("expected 0 rows with missing evidence")
    candidate_quality = attribution.get("candidateQuality", {})
    if int(candidate_quality.get("withQuality") or 0) < attempted:
        errors.append("expected candidate quality on every probe path")

    batch_totals = probe_batch.get("totals", {})
    if int(batch_totals.get("withQuality") or 0) < attempted:
        errors.append("expected probe batch to retain candidate quality")

    observe_feedback = quality_observe.get("plannerFeedback", {})
    penalize_feedback = quality_penalize.get("plannerFeedback", {})
    if observe_feedback.get("penaltyObservations") != 0:
        errors.append("observe quality state should not emit penalty observations")
    if penalize_feedback.get("penaltyObservations") != 0:
        errors.append("penalize quality state should have no penalties without gaps")

    plan_checks = {}
    if plans:
        plan_checks = {
            "ss": plan_check(plans["ss"], "private-ss", errors),
            "vmess": plan_check(plans["vmess"], "private-vmess", errors),
            "trojan": plan_check(plans["trojan"], "private-trojan", errors),
        }

    return {
        "schema": "dynet-vm-probe-smoke-verification/v1alpha1",
        "artifact": str(output_dir),
        "status": "pass" if not errors else "fail",
        "errors": errors,
        "summaryTotals": summary_totals,
        "server": {
            "connections": server.get("connections"),
            "totalBytes": server.get("totalBytes"),
            "rawPayloadStored": server.get("rawPayloadStored"),
        },
        "attributionTotals": attribution_totals,
        "probeBatchTotals": batch_totals,
        "observePlannerFeedback": observe_feedback,
        "penalizePlannerFeedback": penalize_feedback,
        "planObserve": plan_checks,
    }


def load_plans(output_dir: Path) -> dict[str, dict[str, Any]]:
    return {
        "ss": load_json(output_dir / "plan-candidate.json"),
        "vmess": load_json(output_dir / "plan-candidate-vmess.json"),
        "trojan": load_json(output_dir / "plan-candidate-trojan.json"),
    }


def plan_check(
    plan: dict[str, Any],
    expected: str,
    errors: list[str],
) -> dict[str, Any]:
    path = plan.get("outboundPath", {})
    selected = path.get("selected")
    if selected != expected:
        errors.append(f"expected plan quality-state to select {expected}")
    quality = selected_plan_quality(path, expected)
    if not quality:
        errors.append(f"expected {expected} plan candidate quality explanation")
    elif quality.get("stale") is True or int(quality.get("score") or 0) <= 0:
        errors.append(f"expected non-stale positive {expected} plan candidate quality")
    return {"selected": selected, "quality": quality}


def selected_plan_quality(path: dict[str, Any], selected: str) -> dict[str, Any] | None:
    for decision in path.get("decisions", []):
        if not isinstance(decision, dict):
            continue
        for candidate in decision.get("candidates", []):
            if not isinstance(candidate, dict) or candidate.get("to") != selected:
                continue
            quality = candidate.get("quality")
            return quality if isinstance(quality, dict) else None
    return None


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True))
