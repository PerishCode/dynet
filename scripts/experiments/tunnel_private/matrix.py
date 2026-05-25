from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path
from typing import Any, Callable

from tunnel_private_config import (
    ConfigInputs,
    build_config,
    build_private_config,
    config_inputs,
    write_json,
)


MATRIX_SCHEMA = "dynet-tunnel-private-matrix/v1alpha1"

ProbeFn = Callable[[argparse.Namespace, Path], dict[str, Any]]
CleanFn = Callable[[dict[str, Any]], dict[str, Any]]
SummaryFn = Callable[[argparse.Namespace, ConfigInputs, dict[str, Any], Path], dict[str, Any]]
MarkdownFn = Callable[[Path, dict[str, Any]], None]


def command_matrix(
    args: argparse.Namespace,
    *,
    run_probe: ProbeFn,
    clean_report: CleanFn,
    plan_summary: SummaryFn,
    private_summary: SummaryFn,
    write_markdown: MarkdownFn,
) -> int:
    inputs = config_inputs(args)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summaries = []
    with tempfile.TemporaryDirectory(prefix="dynet-tunnel-private-matrix-") as temp_dir:
        temp_root = Path(temp_dir)
        for case in matrix_cases():
            summaries.append(
                run_matrix_case(
                    args,
                    inputs,
                    case,
                    temp_root,
                    output_dir,
                    run_probe,
                    clean_report,
                    private_summary if case.get("privateDirect") else plan_summary,
                    write_markdown,
                )
            )
    matrix = matrix_summary(args, summaries)
    write_json(output_dir / "matrix.json", matrix)
    write_matrix_markdown(output_dir / "matrix.md", matrix)
    print_matrix_result(output_dir, matrix)
    return 0


def matrix_cases() -> list[dict[str, Any]]:
    return [
        {
            "label": "private-direct",
            "protocol": "https-head",
            "probeMode": "private-direct",
            "privateDirect": True,
        },
        {
            "label": "candidate-direct",
            "protocol": "https-head",
            "probeMode": "candidate",
            "privatePath": False,
        },
        {
            "label": "tunnel-private-tcp",
            "protocol": "tcp-connect",
            "probeMode": "private",
            "privatePath": True,
        },
        {
            "label": "tunnel-private-tls",
            "protocol": "tls-handshake",
            "probeMode": "private",
            "privatePath": True,
        },
        {
            "label": "tunnel-private-https",
            "protocol": "https-head",
            "probeMode": "private",
            "privatePath": True,
        },
    ]


def run_matrix_case(
    base_args: argparse.Namespace,
    inputs: ConfigInputs,
    case: dict[str, Any],
    temp_root: Path,
    output_dir: Path,
    run_probe: ProbeFn,
    clean_report: CleanFn,
    summary_fn: SummaryFn,
    write_markdown: MarkdownFn,
) -> dict[str, Any]:
    args = case_args(base_args, case)
    case_dir = output_dir / str(case["label"])
    case_dir.mkdir(parents=True, exist_ok=True)
    config_path = temp_root / f"{case['label']}.json"
    write_json(config_path, case_config(args, inputs, case), secret=True)
    report = run_probe(args, config_path)
    report_path = case_dir / "report.json"
    write_json(report_path, clean_report(report))
    summary = summary_fn(args, inputs, report, report_path)
    summary["matrixCase"] = case["label"]
    summary["protocol"] = case["protocol"]
    write_json(case_dir / "summary.json", summary)
    write_markdown(case_dir / "summary.md", summary)
    return summary


def case_args(base_args: argparse.Namespace, case: dict[str, Any]) -> argparse.Namespace:
    args = argparse.Namespace(**vars(base_args))
    args.protocol = case["protocol"]
    args.probe_mode = case["probeMode"]
    return args


def case_config(
    args: argparse.Namespace,
    inputs: ConfigInputs,
    case: dict[str, Any],
) -> dict[str, Any]:
    if case.get("privateDirect"):
        return build_private_config(inputs.private)
    return build_config(
        args,
        inputs.candidates,
        inputs.private,
        private_path=bool(case["privatePath"]),
    )


def matrix_summary(args: argparse.Namespace, summaries: list[dict[str, Any]]) -> dict[str, Any]:
    rows = [matrix_row(summary) for summary in summaries]
    return {
        "schema": MATRIX_SCHEMA,
        "targetUrl": args.target_url,
        "totals": {
            "attempted": len(rows),
            "passed": sum(1 for item in rows if item["status"] == "pass"),
            "failed": sum(1 for item in rows if item["status"] != "pass"),
        },
        "cases": rows,
        "metadata": summaries[0]["metadata"] if summaries else {},
        "privacy": {
            "rawSecretsStored": False,
            "identityInformationSent": False,
            "cookiesSent": False,
            "authorizationSent": False,
        },
    }


def matrix_row(summary: dict[str, Any]) -> dict[str, Any]:
    report = summary["report"]
    return {
        "label": summary["matrixCase"],
        "probeMode": summary["probeMode"],
        "protocol": summary["protocol"],
        "status": report["status"],
        "reason": report["reason"],
        "boundSelected": report["boundSelected"],
        "failedStage": report["failedStage"],
        "failureScope": report.get("failureScope"),
        "reportPath": report["reportPath"],
    }


def write_matrix_markdown(path: Path, matrix: dict[str, Any]) -> None:
    lines = [
        "# Tunnel Private Matrix",
        "",
        f"- target: `{matrix['targetUrl']}`",
        f"- passed: `{matrix['totals']['passed']}`",
        f"- failed: `{matrix['totals']['failed']}`",
        "",
        "## Cases",
        "",
    ]
    for item in matrix["cases"]:
        lines.append(
            f"- `{item['label']}` protocol=`{item['protocol']}` "
            f"status=`{item['status']}` scope=`{item.get('failureScope')}` "
            f"bound=`{item['boundSelected']}` failedStage=`{item['failedStage']}`"
        )
    path.write_text("\n".join(lines) + "\n")


def print_matrix_result(output_dir: Path, matrix: dict[str, Any]) -> None:
    print(json.dumps({"outputDir": str(output_dir), **matrix["totals"]}, sort_keys=True))
