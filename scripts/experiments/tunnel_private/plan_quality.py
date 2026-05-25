from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from tunnel_private_config import ConfigInputs, build_config, metadata, write_json


INSPECTION_SCHEMA = "dynet-tunnel-private-plan-quality-inspection/v1alpha1"
COMPARISON_SCHEMA = "dynet-tunnel-private-plan-quality-comparison/v1alpha1"
DIALER_BOUND_SCOPE = "dialer-bound"
PLAN_CANDIDATE_SCOPE = "plan-candidate"


def command_inspect_plan_quality(
    args: argparse.Namespace,
    *,
    inputs: ConfigInputs,
) -> int:
    if not args.quality_state:
        raise SystemExit("inspect-plan-quality requires --quality-state")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="dynet-tunnel-private-plan-quality-") as temp_dir:
        config_path = Path(temp_dir) / "plan.json"
        config = plan_inspection_config(args, inputs)
        write_json(config_path, config, secret=True)
        report = run_plan(args, config_path)
    summary = summarize_plan(args, inputs, report)
    write_json(output_dir / "summary.json", summary)
    print(json.dumps({"outputDir": str(output_dir), "status": summary["status"]}, sort_keys=True))
    return 0 if summary["status"] == "pass" else 1


def command_compare_plan_quality(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = compare_plan_quality([Path(path) for path in args.inspection])
    write_json(output_dir / "summary.json", summary)
    write_comparison_markdown(output_dir / "summary.md", summary)
    print(json.dumps({"outputDir": str(output_dir), "status": summary["status"]}, sort_keys=True))
    return 0 if summary["status"] == "pass" else 1


def compare_plan_quality(paths: list[Path]) -> dict[str, Any]:
    rows = [comparison_row(path) for path in paths]
    selected = {row.get("selected") for row in rows if row.get("selected")}
    all_passed = all(row.get("status") == "pass" for row in rows)
    any_behind = any(int(row.get("selectedBehind") or 0) > 0 for row in rows)
    return {
        "schema": COMPARISON_SCHEMA,
        "status": "pass" if rows and all_passed and not any_behind else "fail",
        "totals": {
            "inspections": len(rows),
            "passed": sum(1 for row in rows if row.get("status") == "pass"),
            "failed": sum(1 for row in rows if row.get("status") != "pass"),
            "selectionChanged": len(selected) > 1,
            "selectedBehind": sum(int(row.get("selectedBehind") or 0) for row in rows),
            "promotionEligible": sum(1 for row in rows if row.get("promotionEligible")),
            "penaltyObservations": sum(int(row.get("penaltyObservations") or 0) for row in rows),
            "promotionContexts": sum(int(row.get("promotionContexts") or 0) for row in rows),
            "promotionObserveOnlyActions": sum(
                len(row.get("promotionObserveOnlyActions") or []) for row in rows
            ),
            "promotionPolicyActions": sum(
                len(row.get("promotionPolicyActions") or []) for row in rows
            ),
        },
        "rows": rows,
        "conclusion": comparison_conclusion(rows, selected),
    }


def comparison_row(path: Path) -> dict[str, Any]:
    summary = json.loads(path.read_text())
    quality_state_path = quality_state_path_for(path, summary)
    planner_feedback = planner_feedback_summary(quality_state_path)
    quality = summary.get("candidateQuality", {})
    return {
        "label": path.parent.name,
        "path": str(path),
        "status": summary.get("status"),
        "qualityState": str(summary.get("qualityState")),
        "feedbackMode": planner_feedback.get("mode"),
        "requestedFeedbackMode": planner_feedback.get("requestedMode"),
        "promotionEligible": planner_feedback.get("promotionEligible"),
        "promotionContexts": planner_feedback.get("promotionContexts", 0),
        "promotionObserveOnlyActions": planner_feedback.get("promotionObserveOnlyActions", []),
        "promotionPolicyActions": planner_feedback.get("promotionPolicyActions", []),
        "penaltyObservations": planner_feedback.get("penaltyObservations", 0),
        "selected": inspected_path(summary).get("selected"),
        "best": quality.get("best", {}).get("to") if isinstance(quality, dict) else None,
        "selectedBest": quality.get("selectedBest") if isinstance(quality, dict) else None,
        "selectedBehind": quality.get("selectedBehind") if isinstance(quality, dict) else None,
        "selectedHasMatches": quality.get("selectedHasMatches") if isinstance(quality, dict) else None,
        "selectedScore": quality.get("selectedScore") if isinstance(quality, dict) else None,
        "bestScore": quality.get("bestScore") if isinstance(quality, dict) else None,
        "withQuality": quality.get("withQuality") if isinstance(quality, dict) else None,
    }


def quality_state_path_for(summary_path: Path, summary: dict[str, Any]) -> Path:
    raw = Path(str(summary.get("qualityState", "")))
    if raw.exists() or raw.is_absolute():
        return raw
    return summary_path.parent / raw


def planner_feedback_summary(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    state = json.loads(path.read_text())
    feedback = state.get("plannerFeedback", {}) if isinstance(state, dict) else {}
    promotion = feedback.get("promotion", {}) if isinstance(feedback, dict) else {}
    return {
        "mode": feedback.get("mode"),
        "requestedMode": feedback.get("requestedMode"),
        "penaltyObservations": feedback.get("penaltyObservations", 0),
        "promotionEligible": promotion.get("eligible") if isinstance(promotion, dict) else None,
        "promotionContexts": promotion.get("contexts", 0) if isinstance(promotion, dict) else 0,
        "promotionObserveOnlyActions": action_ids(
            promotion.get("observeOnlyActions", []) if isinstance(promotion, dict) else []
        ),
        "promotionPolicyActions": action_ids(
            promotion.get("policyActions", []) if isinstance(promotion, dict) else []
        ),
    }


def action_ids(rows: list[Any]) -> list[str]:
    return [
        str(item.get("id"))
        for item in rows
        if isinstance(item, dict) and item.get("id")
    ]


def comparison_conclusion(rows: list[dict[str, Any]], selected: set[Any]) -> dict[str, Any]:
    any_penalty = any(int(row.get("penaltyObservations") or 0) > 0 for row in rows)
    all_best = all(row.get("selectedBest") for row in rows)
    selection_changed = len(selected) > 1
    if any_penalty and selection_changed:
        lever = "quality-gap-penalty-changed-plan"
    elif all_best and not selection_changed:
        lever = "none-current-quality-already-selects-best"
    elif not any_penalty:
        lever = "no-penalty-observation"
    else:
        lever = "inspect-selected-quality"
    return {
        "selectionChanged": selection_changed,
        "allSelectedBest": all_best,
        "penaltyApplied": any_penalty,
        "nextLever": lever,
    }


def run_plan(args: argparse.Namespace, config_path: Path) -> dict[str, Any]:
    command = [
        args.dynet_bin,
        "plan",
        "--config",
        str(config_path),
        "--format",
        "json",
        "--context",
        json.dumps({"destinationDomain": target_domain(args.target_url)}, sort_keys=True),
        "--quality-state",
        args.quality_state,
    ]
    completed = subprocess.run(command, text=True, capture_output=True, check=False)
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        report = {
            "schema": "dynet-plan/invalid-output",
            "error": f"invalid dynet plan JSON: {error}; stderr={completed.stderr.strip()}",
        }
    report["_exitCode"] = completed.returncode
    return report


def plan_inspection_config(args: argparse.Namespace, inputs: ConfigInputs) -> dict[str, Any]:
    scope = inspection_scope(args)
    config = build_config(
        args,
        inputs.candidates,
        inputs.private,
        private_path=scope == DIALER_BOUND_SCOPE,
    )
    config["routes"] = plan_inspection_routes(args)
    return config


def plan_inspection_routes(args: argparse.Namespace) -> list[dict[str, str]]:
    routes: list[dict[str, str]] = []
    outbound = inspection_outbound(args)
    add_unique_route(
        routes,
        {"domain": target_domain(args.target_url), "outbound": outbound},
    )
    for domain in args.domain:
        add_unique_route(routes, {"domain": domain, "outbound": outbound})
    for suffix in args.domain_suffix:
        add_unique_route(routes, {"domainSuffix": suffix, "outbound": outbound})
    routes.append({"outbound": "direct"})
    return routes


def inspection_outbound(args: argparse.Namespace) -> str:
    if inspection_scope(args) == PLAN_CANDIDATE_SCOPE:
        return "tunnel"
    return "private-via-tunnel"


def inspection_scope(args: argparse.Namespace) -> str:
    return str(getattr(args, "plan_quality_scope", DIALER_BOUND_SCOPE))


def add_unique_route(routes: list[dict[str, str]], route: dict[str, str]) -> None:
    if route not in routes:
        routes.append(route)


def summarize_plan(
    args: argparse.Namespace,
    inputs: ConfigInputs,
    report: dict[str, Any],
) -> dict[str, Any]:
    scope = inspection_scope(args)
    path_key = "outboundPath" if scope == PLAN_CANDIDATE_SCOPE else "dialerBoundPath"
    dialer_bound_path = report.get("dialerBoundPath")
    inspected = report.get(path_key)
    candidates = candidate_quality_rows(inspected)
    quality = candidate_quality_summary(candidates)
    status = inspection_status(report, candidates, quality)
    planner_feedback = planner_feedback_summary(Path(args.quality_state))
    return {
        "schema": INSPECTION_SCHEMA,
        "status": status,
        "inspectionScope": scope,
        "targetUrl": args.target_url,
        "context": {"destinationDomain": target_domain(args.target_url)},
        "qualityState": args.quality_state,
        "metadata": metadata(
            inputs.group,
            inputs.all_candidates,
            inputs.supported_candidates,
            inputs.selected_candidates,
            inputs.candidates,
            inputs.private,
            inputs.resolution,
        ),
        "privacy": {
            "rawPlanStored": False,
            "rawSecretsStored": False,
            "identityInformationSent": False,
            "cookiesSent": False,
            "authorizationSent": False,
        },
        "verdict": verdict_summary(report.get("verdict")),
        "outboundPath": path_summary(report.get("outboundPath")),
        "dialerBoundPath": path_summary(dialer_bound_path),
        "inspectedPath": path_summary(inspected),
        "candidateQuality": quality,
        "plannerFeedback": planner_feedback,
    }


def verdict_summary(verdict: Any) -> dict[str, Any]:
    if not isinstance(verdict, dict):
        return {}
    outbound = verdict.get("outbound")
    return {
        "status": verdict.get("status"),
        "action": verdict.get("action"),
        "outbound": outbound_summary(outbound),
    }


def outbound_summary(outbound: Any) -> dict[str, Any]:
    if not isinstance(outbound, dict):
        return {}
    return {
        "tag": outbound.get("tag"),
        "type": outbound.get("type"),
        "capabilities": outbound.get("capabilities", []),
    }


def path_summary(path: Any) -> dict[str, Any]:
    if not isinstance(path, dict):
        return {}
    return {
        "requested": path.get("requested"),
        "selected": path.get("selected"),
        "hops": [
            {"tag": item.get("tag"), "type": item.get("type"), "edgeType": item.get("edgeType")}
            for item in path.get("hops", [])
            if isinstance(item, dict)
        ],
        "decisions": [
            {
                "plan": item.get("plan"),
                "selected": item.get("selected"),
                "selectedEdgeType": item.get("selectedEdgeType"),
            }
            for item in path.get("decisions", [])
            if isinstance(item, dict)
        ],
    }


def candidate_quality_rows(path: Any) -> list[dict[str, Any]]:
    if not isinstance(path, dict):
        return []
    rows = []
    for decision in path.get("decisions", []):
        if not isinstance(decision, dict):
            continue
        selected = decision.get("selected")
        for candidate in decision.get("candidates", []):
            if isinstance(candidate, dict):
                rows.append(candidate_quality_row(candidate, selected))
    return rows


def candidate_quality_row(candidate: dict[str, Any], selected: Any) -> dict[str, Any]:
    quality = candidate.get("quality")
    return {
        "to": candidate.get("to"),
        "type": candidate.get("type"),
        "selected": candidate.get("to") == selected,
        "quality": quality_summary(quality),
    }


def quality_summary(quality: Any) -> dict[str, Any]:
    if not isinstance(quality, dict):
        return {}
    return {
        "stale": quality.get("stale"),
        "targetFamily": quality.get("targetFamily"),
        "score": quality.get("score"),
        "reason": quality.get("reason"),
        "matches": [quality_match_summary(item) for item in quality.get("matches", [])],
    }


def quality_match_summary(match: Any) -> dict[str, Any]:
    if not isinstance(match, dict):
        return {}
    return {
        "scope": match.get("scope"),
        "targetFamily": match.get("targetFamily"),
        "transport": match.get("transport"),
        "verdict": match.get("verdict"),
        "attempts": match.get("attempts"),
        "successes": match.get("successes"),
        "failures": match.get("failures"),
        "confidence": match.get("confidence"),
        "weightedScore": match.get("weightedScore"),
    }


def candidate_quality_summary(candidates: list[dict[str, Any]]) -> dict[str, Any]:
    selected = selected_candidate_quality(candidates)
    best = best_candidate_quality(candidates)
    selected_score = row_score(selected)
    best_score = row_score(best)
    return {
        "withQuality": sum(1 for item in candidates if item.get("quality")),
        "selectedBest": selected_score is not None and selected_score == best_score,
        "selectedBehind": selected_behind(selected_score, best_score),
        "selectedHasMatches": row_has_matches(selected),
        "bestHasMatches": row_has_matches(best),
        "selectedScore": selected_score,
        "bestScore": best_score,
        "selected": selected,
        "best": best,
        "candidates": candidates,
    }


def selected_candidate_quality(candidates: list[dict[str, Any]]) -> dict[str, Any]:
    for item in candidates:
        if item.get("selected"):
            return item
    return {}


def best_candidate_quality(candidates: list[dict[str, Any]]) -> dict[str, Any]:
    scored = [item for item in candidates if row_score(item) is not None]
    if not scored:
        return {}
    return max(scored, key=lambda item: (row_score(item) or 0, bool(item.get("selected"))))


def selected_behind(selected_score: int | None, best_score: int | None) -> int:
    if selected_score is None or best_score is None:
        return 0
    return 1 if selected_score < best_score else 0


def row_score(row: dict[str, Any]) -> int | None:
    quality = row.get("quality")
    if not isinstance(quality, dict):
        return None
    score = quality.get("score")
    return score if isinstance(score, int) else None


def row_has_matches(row: dict[str, Any]) -> bool:
    quality = row.get("quality")
    if not isinstance(quality, dict):
        return False
    matches = quality.get("matches")
    return isinstance(matches, list) and bool(matches)


def inspection_status(
    report: dict[str, Any],
    candidates: list[dict[str, Any]],
    quality: dict[str, Any],
) -> str:
    if report.get("_exitCode") != 0 or not candidates:
        return "fail"
    if quality.get("selectedBehind") != 0:
        return "fail"
    if not quality.get("selectedBest") or not quality.get("selectedHasMatches"):
        return "fail"
    return "pass"


def inspected_path(summary: dict[str, Any]) -> dict[str, Any]:
    path = summary.get("inspectedPath")
    if isinstance(path, dict) and path:
        return path
    path = summary.get("dialerBoundPath")
    return path if isinstance(path, dict) else {}


def target_domain(url: str) -> str:
    return urlparse(url).hostname or url


def write_comparison_markdown(path: Path, summary: dict[str, Any]) -> None:
    conclusion = summary["conclusion"]
    lines = [
        "# Tunnel/Private Plan Quality Comparison",
        "",
        f"- status: `{summary['status']}`",
        f"- inspections: `{summary['totals']['inspections']}`",
        f"- selection changed: `{summary['totals']['selectionChanged']}`",
        f"- penalty observations: `{summary['totals']['penaltyObservations']}`",
        f"- promotion contexts: `{summary['totals']['promotionContexts']}`",
        f"- next lever: `{conclusion['nextLever']}`",
        "",
        "## Rows",
        "",
    ]
    for row in summary["rows"]:
        lines.append(
            f"- `{row['label']}` status=`{row['status']}` selected=`{row['selected']}` "
            f"best=`{row['best']}` mode=`{row['feedbackMode']}` "
            f"promotion=`{row['promotionEligible']}` penalties=`{row['penaltyObservations']}` "
            f"contexts=`{row['promotionContexts']}` selectedBehind=`{row['selectedBehind']}`"
        )
        for action_id in row.get("promotionObserveOnlyActions", []):
            lines.append(f"  - observe-only: `{action_id}`")
        for action_id in row.get("promotionPolicyActions", []):
            lines.append(f"  - policy: `{action_id}`")
    path.write_text("\n".join(lines) + "\n")
