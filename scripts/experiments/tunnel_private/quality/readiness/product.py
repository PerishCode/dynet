"""Product evidence readers for adapter readiness."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def source_summary(path: Path) -> dict[str, Any]:
    summary = load_json(path)
    schema = str(summary.get("schema") or "")
    if schema.endswith("quality-sweep-summary/v1alpha1") or schema.endswith("quality-sweep/v1alpha1"):
        return sweep_source(path, summary)
    if schema.endswith("quality-regression/v1alpha1"):
        return regression_source(path, summary)
    if schema.endswith("matrix-compare/v1alpha1"):
        return matrix_compare_source(path, summary)
    if schema.endswith("matrix/v1alpha1"):
        return matrix_source(path, summary)
    if schema.endswith("vm-private-cascade-run/v1alpha1"):
        return vm_private_cascade_source(path, summary)
    return unknown_source(path, summary)


def sweep_source(path: Path, summary: dict[str, Any]) -> dict[str, Any]:
    totals = summary.get("totals") or {}
    limits = summary.get("limits") or {}
    return {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "category": "product-e2e",
        "status": str(summary.get("status") or "missing"),
        "strictStatus": str(summary.get("strictStatus") or "missing"),
        "runs": int(totals.get("runs") or len(summary.get("runs", []))),
        "passed": int(totals.get("passed") or 0),
        "failed": int(totals.get("failed") or 0),
        "strictPassed": int(totals.get("strictPassed") or 0),
        "strictFailed": int(totals.get("strictFailed") or 0),
        "matrixFailures": int(totals.get("matrixFailures") or 0),
        "selectedBehindMax": int(totals.get("selectedBehindMax") or 0),
        "targets": sorted(str(item) for item in limits.get("targets", []) or []),
        "candidateOffsets": sorted(int(item) for item in limits.get("candidateOffsets", []) or []),
        "markerSummary": normalized_counts(summary.get("markerSummary") or {}),
        "requiredGateFailures": [],
        "failureStageSummary": {},
        "failureScopeSummary": {},
        "failureLabelSummary": {},
    }


def regression_source(path: Path, summary: dict[str, Any]) -> dict[str, Any]:
    gate_mode = str(summary.get("gateMode") or "product")
    category = "direct-control" if gate_mode == "direct" else "product-e2e"
    matrix = summary.get("matrix") or {}
    plan = summary.get("plan") or {}
    quality = plan.get("quality") or {}
    failed_gates = [
        str(gate.get("name"))
        for gate in summary.get("gates", [])
        if gate.get("required") and not gate.get("passed")
    ]
    failures = regression_failures(summary.get("gates", []))
    status = str(summary.get("status") or "missing")
    strict_status = str(summary.get("strictStatus") or "missing")
    return {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "category": category,
        "status": status,
        "strictStatus": strict_status,
        "runs": 1,
        "passed": 1 if status == "pass" else 0,
        "failed": 0 if status == "pass" else 1,
        "strictPassed": 1 if strict_status == "pass" else 0,
        "strictFailed": 0 if strict_status == "pass" else 1,
        "matrixFailures": int((matrix.get("totals") or {}).get("failed") or 0),
        "selectedBehindMax": int(quality.get("selectedBehind") or 0),
        "targets": [str(summary.get("targetUrl") or "")],
        "candidateOffsets": [],
        "markerSummary": normalized_counts((summary.get("compare") or {}).get("markerSummary") or {}),
        "requiredGateFailures": failed_gates,
        "failureStageSummary": count_field(failures, "failedStage"),
        "failureScopeSummary": count_field(failures, "failureScope"),
        "failureLabelSummary": count_field(failures, "label"),
        "gateMode": gate_mode,
        "refreshProbeMode": str(summary.get("refreshProbeMode") or ""),
        "planQualityScope": str(summary.get("planQualityScope") or ""),
    }


def matrix_source(path: Path, summary: dict[str, Any]) -> dict[str, Any]:
    totals = summary.get("totals") or {}
    cases = [item for item in summary.get("cases", []) if isinstance(item, dict)]
    attempted = int(totals.get("attempted") or len(cases))
    failed = int(totals.get("failed") or sum(1 for item in cases if item.get("status") != "pass"))
    passed = int(totals.get("passed") or max(attempted - failed, 0))
    status = "pass" if attempted > 0 and failed == 0 else "fail"
    return {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "category": "product-e2e",
        "status": status,
        "strictStatus": status,
        "runs": 1 if attempted > 0 else 0,
        "passed": 1 if attempted > 0 and failed == 0 else 0,
        "failed": 1 if failed > 0 else 0,
        "strictPassed": 1 if attempted > 0 and failed == 0 else 0,
        "strictFailed": 1 if failed > 0 else 0,
        "matrixFailures": failed,
        "selectedBehindMax": 0,
        "targets": single_target(summary.get("targetUrl")),
        "candidateOffsets": [],
        "markerSummary": {},
        "requiredGateFailures": ["matrix-has-failures"] if failed else [],
        "failureStageSummary": count_field(failed_matrix_cases(cases), "failedStage"),
        "failureScopeSummary": count_field(failed_matrix_cases(cases), "failureScope"),
        "failureLabelSummary": count_field(failed_matrix_cases(cases), "label"),
        "matrixAttempted": attempted,
        "matrixPassed": passed,
    }


def matrix_compare_source(path: Path, summary: dict[str, Any]) -> dict[str, Any]:
    totals = summary.get("totals") or {}
    matrices = [item for item in summary.get("matrices", []) if isinstance(item, dict)]
    runs = int(totals.get("matrices") or len(matrices))
    failures = int(totals.get("failures") or 0)
    failed_matrices = sum(1 for matrix in matrices if int(matrix.get("failed") or 0) > 0)
    if not matrices and failures > 0 and runs > 0:
        failed_matrices = 1
    return {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "category": "product-e2e",
        "status": "pass" if failures == 0 else "fail",
        "strictStatus": "pass" if failures == 0 else "fail",
        "runs": runs,
        "passed": max(runs - failed_matrices, 0),
        "failed": failed_matrices,
        "strictPassed": max(runs - failed_matrices, 0),
        "strictFailed": failed_matrices,
        "matrixFailures": failures,
        "selectedBehindMax": 0,
        "targets": matrix_compare_targets(summary),
        "candidateOffsets": [],
        "markerSummary": normalized_counts(summary.get("markerSummary") or {}),
        "requiredGateFailures": ["matrix-compare-has-failures"] if failures else [],
        "failureStageSummary": count_field(failure_signatures(summary), "failedStage"),
        "failureScopeSummary": count_field(failure_signatures(summary), "failureScope"),
        "failureLabelSummary": count_field(failure_signatures(summary), "label"),
    }


def matrix_compare_targets(summary: dict[str, Any]) -> list[str]:
    matrices = [item for item in summary.get("matrices", []) if isinstance(item, dict)]
    targets = {str(matrix.get("targetUrl") or "") for matrix in matrices}
    targets.update(
        str(target) for signature in summary.get("failureSignatures", [])
        if isinstance(signature, dict) for target in signature.get("targets", [])
    )
    return sorted(target for target in targets if target)


def vm_private_cascade_source(path: Path, summary: dict[str, Any]) -> dict[str, Any]:
    totals = summary.get("totals") or {}
    reports = [item for item in summary.get("reports", []) if isinstance(item, dict)]
    attempted = int(totals.get("attempted") or len(reports))
    failed = int(totals.get("failed") or sum(1 for item in reports if item.get("status") != "pass"))
    passed = int(totals.get("passed") or max(attempted - failed, 0))
    return {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "category": "product-e2e",
        "status": "pass" if attempted > 0 and failed == 0 else "fail",
        "strictStatus": "pass" if attempted > 0 and failed == 0 else "fail",
        "runs": attempted,
        "passed": passed,
        "failed": failed,
        "strictPassed": passed,
        "strictFailed": failed,
        "matrixFailures": failed,
        "selectedBehindMax": 0,
        "targets": sorted(
            str(item.get("targetUrl") or "") for item in reports if item.get("targetUrl")
        ),
        "candidateOffsets": [],
        "markerSummary": {},
        "requiredGateFailures": ["vm-private-cascade-has-failures"] if failed else [],
        "failureStageSummary": count_field(failed_vm_private_reports(reports), "failedStage"),
        "failureScopeSummary": count_field(failed_vm_private_reports(reports), "failureScope"),
        "failureLabelSummary": count_field(failed_vm_private_reports(reports), "targetUrl"),
    }


def unknown_source(path: Path, summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "category": "unknown",
        "status": "missing",
        "strictStatus": "missing",
        "runs": 0,
        "passed": 0,
        "failed": 0,
        "strictPassed": 0,
        "strictFailed": 0,
        "matrixFailures": 0,
        "selectedBehindMax": 0,
        "targets": [],
        "candidateOffsets": [],
        "markerSummary": {},
        "requiredGateFailures": ["unsupported-product-evidence-schema"],
        "failureStageSummary": {},
        "failureScopeSummary": {},
        "failureLabelSummary": {},
    }


def single_target(raw_target: Any) -> list[str]:
    target = str(raw_target or "")
    return [target] if target else []


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text())


def regression_failures(gates: list[Any]) -> list[dict[str, Any]]:
    rows = []
    for gate in gates:
        if not isinstance(gate, dict) or gate.get("passed"):
            continue
        detail = gate.get("detail")
        if not isinstance(detail, dict):
            continue
        for label, value in detail.items():
            if isinstance(value, dict) and value.get("status") != "pass":
                rows.append({"label": label, **value})
    return rows


def failed_matrix_cases(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [case for case in cases if case.get("status") != "pass"]


def failed_vm_private_reports(reports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [report for report in reports if report.get("status") != "pass"]


def failure_signatures(summary: dict[str, Any]) -> list[dict[str, Any]]:
    return [item for item in summary.get("failureSignatures", []) if isinstance(item, dict)]


def count_field(rows: list[dict[str, Any]], field: str) -> dict[str, int]:
    return normalized_counts({
        str(row.get(field) or "unknown"): sum(
            1 for item in rows if str(item.get(field) or "unknown") == str(row.get(field) or "unknown")
        )
        for row in rows
    })


def normalized_counts(raw: dict[str, Any]) -> dict[str, int]:
    return {
        str(key): int(value)
        for key, value in sorted(raw.items(), key=lambda item: str(item[0]))
    }
