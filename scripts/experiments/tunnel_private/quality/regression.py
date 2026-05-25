from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from tunnel_private.compare import compare_matrices, write_compare_markdown
from tunnel_private.matrix import command_matrix
from tunnel_private.plan_quality import command_inspect_plan_quality
from tunnel_private.quality_refresh import command_quality_refresh
from tunnel_private_config import ConfigInputs, write_json


REGRESSION_SCHEMA = "dynet-tunnel-private-quality-regression/v1alpha1"
PRODUCT_MATRIX_CASES = [
    "private-direct",
    "tunnel-private-tcp",
    "tunnel-private-tls",
    "tunnel-private-https",
]
CONTROL_MATRIX_CASES = ["candidate-direct"]

ProbeFn = Callable[[argparse.Namespace, Path], dict[str, Any]]
CleanFn = Callable[[dict[str, Any]], dict[str, Any]]
SummaryFn = Callable[[argparse.Namespace, ConfigInputs, dict[str, Any], Path], dict[str, Any]]
MarkdownFn = Callable[[Path, dict[str, Any]], None]


def command_quality_regression(
    args: argparse.Namespace,
    *,
    inputs: ConfigInputs,
    run_probe: ProbeFn,
    clean_report: CleanFn,
    plan_summary: SummaryFn,
    private_summary: SummaryFn,
    write_markdown: MarkdownFn,
) -> int:
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    phase_codes: dict[str, int | None] = {
        "qualityRefresh": None,
        "planQuality": None,
        "matrix": None,
    }

    refresh_dir = output_dir / "quality-refresh"
    refresh_args = refresh_phase_args(args, refresh_dir)
    phase_codes["qualityRefresh"] = command_quality_refresh(
        refresh_args,
        inputs=inputs,
        run_probe=run_probe,
        clean_report=clean_report,
    )

    quality_state = refresh_dir / "window-b" / "quality-state.json"
    if quality_state.exists():
        plan_dir = output_dir / "plan-quality"
        phase_codes["planQuality"] = command_inspect_plan_quality(
            quality_state_phase_args(args, plan_dir, quality_state),
            inputs=inputs,
        )

        matrix_dir = output_dir / "matrix"
        phase_codes["matrix"] = command_matrix(
            quality_state_phase_args(args, matrix_dir, quality_state),
            run_probe=run_probe,
            clean_report=clean_report,
            plan_summary=plan_summary,
            private_summary=private_summary,
            write_markdown=write_markdown,
        )
        write_baseline_compare(args, output_dir, matrix_dir / "matrix.json")

    summary = regression_summary(args, output_dir, phase_codes)
    write_json(output_dir / "summary.json", summary)
    write_regression_markdown(output_dir / "summary.md", summary)
    print(json.dumps(print_summary(output_dir, summary), sort_keys=True))
    return 0 if summary["status"] == "pass" else 1


def refresh_phase_args(args: argparse.Namespace, output_dir: Path) -> argparse.Namespace:
    values = dict(vars(args))
    values.update(
        {
            "output_dir": str(output_dir),
            "domain": domain_with_target(args),
            "probe_mode": resolved_refresh_probe_mode(args),
            "allow_failures": not bool(getattr(args, "refresh_require_pass", False)),
            "quality_state": None,
        }
    )
    return argparse.Namespace(**values)


def quality_state_phase_args(
    args: argparse.Namespace,
    output_dir: Path,
    quality_state: Path,
) -> argparse.Namespace:
    values = dict(vars(args))
    values.update(
        {
            "output_dir": str(output_dir),
            "domain": domain_with_target(args),
            "quality_state": str(quality_state),
            "plan_quality_scope": plan_quality_scope(args),
        }
    )
    return argparse.Namespace(**values)


def resolved_refresh_probe_mode(args: argparse.Namespace) -> str:
    mode = str(getattr(args, "refresh_probe_mode", "auto"))
    if mode != "auto":
        return mode
    if str(getattr(args, "gate_mode", "product")) == "direct":
        return "candidate"
    return "private"


def plan_quality_scope(args: argparse.Namespace) -> str:
    if resolved_refresh_probe_mode(args) == "candidate":
        return "plan-candidate"
    return "dialer-bound"


def domain_with_target(args: argparse.Namespace) -> list[str]:
    domains = list(getattr(args, "domain", []) or [])
    target = target_domain(str(getattr(args, "target_url", "")))
    if target and target not in domains:
        domains.append(target)
    return domains


def target_domain(url: str) -> str:
    return urlparse(url).hostname or url


def write_baseline_compare(args: argparse.Namespace, output_dir: Path, matrix_path: Path) -> None:
    baselines = [Path(path) for path in getattr(args, "baseline_matrix", [])]
    if not baselines or not matrix_path.exists():
        return
    compare_dir = output_dir / "compare"
    compare_dir.mkdir(parents=True, exist_ok=True)
    summary = compare_matrices([*baselines, matrix_path])
    write_json(compare_dir / "summary.json", summary)
    write_compare_markdown(compare_dir / "summary.md", summary)


def regression_summary(
    args: argparse.Namespace,
    output_dir: Path,
    phase_codes: dict[str, int | None],
) -> dict[str, Any]:
    refresh = load_json(output_dir / "quality-refresh" / "verification.json")
    plan = load_json(output_dir / "plan-quality" / "summary.json")
    matrix = load_json(output_dir / "matrix" / "matrix.json")
    compare = load_json(output_dir / "compare" / "summary.json")
    gates = regression_gates(
        phase_codes,
        refresh,
        plan,
        matrix,
        gate_mode=str(getattr(args, "gate_mode", "product")),
        require_candidate_direct=bool(getattr(args, "require_candidate_direct", False)),
    )
    return {
        "schema": REGRESSION_SCHEMA,
        "status": "pass" if required_gates_pass(gates) else "fail",
        "strictStatus": "pass" if all(gate["passed"] for gate in gates) else "fail",
        "targetUrl": args.target_url,
        "protocol": args.protocol,
        "gateMode": str(getattr(args, "gate_mode", "product")),
        "refreshProbeMode": resolved_refresh_probe_mode(args),
        "planQualityScope": plan_quality_scope(args),
        "requirements": {
            "candidateDirectRequired": bool(
                getattr(args, "require_candidate_direct", False)
            ),
            "productMatrixCases": PRODUCT_MATRIX_CASES,
            "controlMatrixCases": CONTROL_MATRIX_CASES,
        },
        "paths": {
            "qualityRefresh": "quality-refresh",
            "planQuality": "plan-quality",
            "matrix": "matrix",
            "compare": "compare" if compare else None,
        },
        "phaseCodes": phase_codes,
        "gates": gates,
        "refresh": refresh_summary(refresh),
        "plan": plan_summary(plan),
        "matrix": matrix_summary(matrix),
        "compare": compare_summary(compare),
        "privacy": {
            "rawSecretsStored": False,
            "identityInformationSent": False,
            "cookiesSent": False,
            "authorizationSent": False,
        },
    }


def regression_gates(
    phase_codes: dict[str, int | None],
    refresh: dict[str, Any],
    plan: dict[str, Any],
    matrix: dict[str, Any],
    *,
    gate_mode: str,
    require_candidate_direct: bool,
) -> list[dict[str, Any]]:
    quality = plan.get("candidateQuality", {}) if plan else {}
    product_required = gate_mode in {"product", "all"}
    direct_required = gate_mode in {"direct", "all"} or require_candidate_direct
    all_required = gate_mode == "all"
    return [
        gate(
            "quality-refresh-command",
            phase_codes.get("qualityRefresh") == 0,
            {"exitCode": phase_codes.get("qualityRefresh")},
            required=True,
        ),
        gate(
            "quality-refresh-verification",
            refresh.get("status") == "pass",
            refresh_errors(refresh),
            required=True,
        ),
        gate(
            "plan-quality-command",
            phase_codes.get("planQuality") == 0,
            {"exitCode": phase_codes.get("planQuality")},
            required=True,
        ),
        gate(
            "plan-quality-pass",
            plan.get("status") == "pass",
            plan_gate_detail(plan),
            required=True,
        ),
        gate(
            "plan-selected-best",
            bool(quality.get("selectedBest"))
            and int(quality.get("selectedBehind") or 0) == 0
            and bool(quality.get("selectedHasMatches")),
            quality_gate_detail(quality),
            required=True,
        ),
        gate(
            "matrix-command",
            phase_codes.get("matrix") == 0,
            {"exitCode": phase_codes.get("matrix")},
            required=True,
        ),
        gate(
            "matrix-product-pass",
            matrix_cases_pass(matrix, PRODUCT_MATRIX_CASES),
            matrix_case_group_detail(matrix, PRODUCT_MATRIX_CASES),
            required=product_required,
        ),
        gate(
            "matrix-all-pass",
            int(matrix.get("totals", {}).get("failed") or 0) == 0,
            matrix_totals(matrix),
            required=all_required,
        ),
        *matrix_case_gates(matrix, PRODUCT_MATRIX_CASES, required=product_required),
        *matrix_case_gates(matrix, CONTROL_MATRIX_CASES, required=direct_required),
    ]


def matrix_case_gates(
    matrix: dict[str, Any],
    labels: list[str],
    *,
    required: bool,
) -> list[dict[str, Any]]:
    cases = {item.get("label"): item for item in matrix.get("cases", [])}
    return [
        gate(
            f"matrix-{label}-pass",
            cases.get(label, {}).get("status") == "pass",
            case_gate_detail(cases.get(label, {})),
            required=required,
        )
        for label in labels
    ]


def matrix_cases_pass(matrix: dict[str, Any], labels: list[str]) -> bool:
    cases = {item.get("label"): item for item in matrix.get("cases", [])}
    return all(cases.get(label, {}).get("status") == "pass" for label in labels)


def matrix_case_group_detail(matrix: dict[str, Any], labels: list[str]) -> dict[str, Any]:
    cases = {item.get("label"): item for item in matrix.get("cases", [])}
    return {label: case_gate_detail(cases.get(label, {})) for label in labels}


def gate(
    name: str,
    passed: bool,
    detail: dict[str, Any],
    *,
    required: bool,
) -> dict[str, Any]:
    return {
        "name": name,
        "required": bool(required),
        "passed": bool(passed),
        "detail": detail,
    }


def required_gates_pass(gates: list[dict[str, Any]]) -> bool:
    return all(item["passed"] for item in gates if item["required"])


def refresh_errors(refresh: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": refresh.get("status"),
        "errors": refresh.get("errors", []),
        "qualityState": refresh.get("qualityState", {}),
    }


def plan_gate_detail(plan: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": plan.get("status"),
        "scope": plan.get("inspectionScope"),
        "selected": inspected_path(plan).get("selected"),
        "qualityState": plan.get("qualityState"),
    }


def quality_gate_detail(quality: dict[str, Any]) -> dict[str, Any]:
    selected = quality.get("selected", {}) if isinstance(quality.get("selected"), dict) else {}
    best = quality.get("best", {}) if isinstance(quality.get("best"), dict) else {}
    return {
        "selected": selected.get("to"),
        "best": best.get("to"),
        "selectedBest": quality.get("selectedBest"),
        "selectedBehind": quality.get("selectedBehind"),
        "selectedHasMatches": quality.get("selectedHasMatches"),
        "selectedScore": quality.get("selectedScore"),
        "bestScore": quality.get("bestScore"),
    }


def matrix_totals(matrix: dict[str, Any]) -> dict[str, Any]:
    return dict(matrix.get("totals", {}))


def case_gate_detail(case: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": case.get("status"),
        "failedStage": case.get("failedStage"),
        "failureScope": case.get("failureScope"),
        "boundSelected": case.get("boundSelected"),
    }


def refresh_summary(refresh: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": refresh.get("status"),
        "firstWindow": refresh.get("firstWindow", {}),
        "secondWindow": refresh.get("secondWindow", {}),
        "failureScopes": refresh.get("failureScopes", {}),
        "qualityState": refresh.get("qualityState", {}),
    }


def plan_summary(plan: dict[str, Any]) -> dict[str, Any]:
    quality = plan.get("candidateQuality", {}) if plan else {}
    return {
        "status": plan.get("status"),
        "scope": plan.get("inspectionScope"),
        "selected": inspected_path(plan).get("selected"),
        "quality": quality_gate_detail(quality),
    }


def inspected_path(plan: dict[str, Any]) -> dict[str, Any]:
    path = plan.get("inspectedPath")
    if isinstance(path, dict) and path:
        return path
    path = plan.get("dialerBoundPath")
    return path if isinstance(path, dict) else {}


def matrix_summary(matrix: dict[str, Any]) -> dict[str, Any]:
    return {
        "totals": matrix.get("totals", {}),
        "cases": [
            {
                "label": item.get("label"),
                "status": item.get("status"),
                "failedStage": item.get("failedStage"),
                "failureScope": item.get("failureScope"),
                "boundSelected": item.get("boundSelected"),
            }
            for item in matrix.get("cases", [])
        ],
    }


def compare_summary(compare: dict[str, Any]) -> dict[str, Any] | None:
    if not compare:
        return None
    return {
        "totals": compare.get("totals", {}),
        "controlSummary": compare.get("controlSummary", {}),
        "markerSummary": compare.get("markerSummary", {}),
    }


def print_summary(output_dir: Path, summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "outputDir": str(output_dir),
        "status": summary["status"],
        "strictStatus": summary["strictStatus"],
        "passedGates": sum(1 for gate_item in summary["gates"] if gate_item["passed"]),
        "failedGates": sum(1 for gate_item in summary["gates"] if not gate_item["passed"]),
        "failedRequiredGates": sum(
            1 for gate_item in summary["gates"] if gate_item["required"] and not gate_item["passed"]
        ),
    }


def write_regression_markdown(path: Path, summary: dict[str, Any]) -> None:
    lines = [
        "# Tunnel/Private Quality Regression",
        "",
        f"- status: `{summary['status']}`",
        f"- strict status: `{summary['strictStatus']}`",
        f"- target: `{summary['targetUrl']}`",
        f"- protocol: `{summary['protocol']}`",
        f"- gate mode: `{summary['gateMode']}`",
        f"- refresh probe mode: `{summary['refreshProbeMode']}`",
        f"- plan quality scope: `{summary['planQualityScope']}`",
        f"- candidate direct required: `{summary['requirements']['candidateDirectRequired']}`",
        f"- refresh: `{summary['refresh']['status']}`",
        f"- plan selected: `{summary['plan']['selected']}`",
        f"- matrix failed: `{summary['matrix']['totals'].get('failed')}`",
        "",
    ]
    markers = (summary.get("compare") or {}).get("markerSummary", {})
    if markers:
        lines.extend(["## Marker Summary", ""])
        for marker, count in markers.items():
            lines.append(f"- `{marker}`: `{count}`")
        lines.append("")
    lines.extend(["## Gates", ""])
    for item in summary["gates"]:
        status = "pass" if item["passed"] else "fail"
        kind = "required" if item["required"] else "control"
        lines.append(f"- `{status}` `{kind}` {item['name']}")
    path.write_text("\n".join(lines) + "\n")


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text())
