from __future__ import annotations

import json
from pathlib import Path
from typing import Any


COMPARE_SCHEMA = "dynet-tunnel-private-matrix-compare/v1alpha1"
SOURCE_POLICY_SPLIT_SCHEMA = "dynet-tunnel-private-source-policy-split/v1alpha1"

SIGNATURE_MARKERS = [
    ("vmess-response-header-length-pending", "VMess response header length is not ready"),
    ("vmess-response-header-length-read", "failed to read VMess response header length"),
    ("vmess-response-header-length-eof", "failed to read VMess response header length: unexpected EOF"),
    ("ss-response-salt-pending", "Shadowsocks response salt is not ready"),
    ("trojan-tls-handshake", "failed Trojan TLS handshake"),
    ("tls-unexpected-eof", "unexpected end of file"),
]


def compare_matrices(paths: list[Path]) -> dict[str, Any]:
    matrices = [load_matrix(path) for path in paths]
    return compare_matrices_from_data(matrices)


def compare_source_policy_split(real_path: Path, owned_path: Path) -> dict[str, Any]:
    real = json.loads(real_path.read_text())
    owned = json.loads(owned_path.read_text())
    return split_from_data(real, owned, str(real_path), str(owned_path))


def compare_matrices_from_data(matrices: list[dict[str, Any]]) -> dict[str, Any]:
    failures = [
        failure_row(matrix, case)
        for matrix in matrices
        for case in matrix["cases"]
        if case["status"] != "pass"
    ]
    signatures = grouped_signatures(failures)
    controls = [control_row(matrix) for matrix in matrices]
    return {
        "schema": COMPARE_SCHEMA,
        "totals": {
            "matrices": len(matrices),
            "targets": len({matrix["targetUrl"] for matrix in matrices}),
            "failures": len(failures),
            "signatures": len(signatures),
        },
        "matrices": matrix_rows(matrices),
        "controls": controls,
        "controlSummary": control_summary(controls, signatures),
        "markerSummary": marker_summary(failures),
        "failureSignatures": signatures,
    }


def split_from_data(
    real: dict[str, Any],
    owned: dict[str, Any],
    real_path: str = "<memory>",
    owned_path: str = "<memory>",
) -> dict[str, Any]:
    real_case = case_by_label(real, "tunnel-private-echo")
    owned_case = case_by_label(owned, "tunnel-owned-private")
    real_row = split_real_row(real, real_case, real_path)
    owned_row = split_owned_row(owned, owned_case, owned_path)
    return {
        "schema": SOURCE_POLICY_SPLIT_SCHEMA,
        "realPrivate": real_row,
        "ownedPrivate": owned_row,
        "conclusion": split_conclusion(real_row, owned_row),
    }


def load_matrix(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text())
    data["_path"] = str(path)
    enrich_cases(data)
    return data


def enrich_cases(matrix: dict[str, Any]) -> None:
    for case in matrix.get("cases", []):
        summary_path = Path(str(case.get("reportPath", ""))).with_name("summary.json")
        if not summary_path.exists():
            continue
        summary = json.loads(summary_path.read_text())
        report = summary.get("report", {})
        attempts = report.get("cascadeAttempts", [])
        if isinstance(attempts, list):
            case["cascadeAttemptCount"] = len(attempts)
            case["cascadeFailedAttempts"] = sum(
                1 for item in attempts if item.get("status") == "failed"
            )
            case["cascadeAttemptTags"] = attempt_tags(attempts)
            case["cascadeFailedTags"] = attempt_tags(
                [item for item in attempts if item.get("status") == "failed"]
            )


def matrix_rows(matrices: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "path": matrix["_path"],
            "targetUrl": matrix["targetUrl"],
            "attempted": matrix["totals"]["attempted"],
            "passed": matrix["totals"]["passed"],
            "failed": matrix["totals"]["failed"],
        }
        for matrix in matrices
    ]


def split_real_row(
    summary: dict[str, Any],
    case: dict[str, Any] | None,
    path: str,
) -> dict[str, Any]:
    signals = case.get("signals", {}) if case else {}
    probe = case.get("probe", {}) if case else {}
    return {
        "path": path,
        "usableCandidates": summary.get("metadata", {}).get("counts", {}).get("usable"),
        "expectedTargetConnections": case.get("expectedConnections") if case else None,
        "targetConnections": int(signals.get("connections", 0)),
        "targetTlsClientHelloLikeConnections": int(
            signals.get("tlsClientHelloLikeConnections", 0)
        ),
        "failedStage": probe.get("failedStage"),
        "failureScope": probe.get("failureScope"),
    }


def split_owned_row(
    summary: dict[str, Any],
    case: dict[str, Any] | None,
    path: str,
) -> dict[str, Any]:
    signals = case.get("signals", {}) if case else {}
    probe = case.get("probe", {}) if case else {}
    return {
        "path": path,
        "usableCandidates": summary.get("metadata", {}).get("counts", {}).get("usable"),
        "expectedPrivateConnections": case.get("expectedPrivateConnections") if case else None,
        "expectedTargetConnections": case.get("expectedTargetConnections") if case else None,
        "privateDecodedConnections": int(signals.get("privateDecodedConnections", 0)),
        "privateResponseConnections": int(signals.get("privateResponseConnections", 0)),
        "targetConnections": int(signals.get("targetConnections", 0)),
        "targetTlsClientHelloLikeConnections": int(
            signals.get("targetTlsClientHelloLikeConnections", 0)
        ),
        "failedStage": probe.get("failedStage"),
        "failureScope": probe.get("failureScope"),
    }


def split_conclusion(real: dict[str, Any], owned: dict[str, Any]) -> dict[str, Any]:
    real_target_missing = real["targetConnections"] == 0
    owned_target_full = (
        owned["expectedTargetConnections"] is not None
        and owned["targetConnections"] >= int(owned["expectedTargetConnections"])
    )
    owned_private_full = (
        owned["expectedPrivateConnections"] is not None
        and owned["privateDecodedConnections"] >= int(owned["expectedPrivateConnections"])
    )
    limits = []
    if real["usableCandidates"] != owned["usableCandidates"]:
        limits.append("usable candidate counts differ between retained windows")
    return {
        "supportsRealPrivateSourcePolicy": bool(
            real_target_missing and owned_target_full and owned_private_full
        ),
        "realNestedTargetMissing": real_target_missing,
        "ownedNestedTargetFull": bool(owned_target_full),
        "ownedPrivateDecodedFull": bool(owned_private_full),
        "limits": limits,
    }


def failure_row(matrix: dict[str, Any], case: dict[str, Any]) -> dict[str, Any]:
    return {
        "matrixPath": matrix["_path"],
        "targetUrl": matrix["targetUrl"],
        "label": case["label"],
        "protocol": case["protocol"],
        "failureScope": case.get("failureScope"),
        "failedStage": case.get("failedStage"),
        "markers": case_markers(case),
    }


def control_row(matrix: dict[str, Any]) -> dict[str, Any]:
    candidate = case_by_label(matrix, "candidate-direct")
    nested_tcp = case_by_label(matrix, "tunnel-private-tcp")
    nested_tls = case_by_label(matrix, "tunnel-private-tls")
    return {
        "targetUrl": matrix["targetUrl"],
        "usableCandidates": matrix.get("metadata", {}).get("counts", {}).get("usable"),
        "candidateDirectHttpsPass": case_passed(candidate),
        "nestedTcpFlushPass": case_passed(nested_tcp),
        "nestedTlsReadMissing": nested_tls_missing(nested_tls),
        "nestedTlsAttempts": int(nested_tls.get("cascadeAttemptCount", 0)) if nested_tls else 0,
        "nestedTlsFailedAttempts": (
            int(nested_tls.get("cascadeFailedAttempts", 0)) if nested_tls else 0
        ),
        "nestedTlsAttemptTags": nested_tls.get("cascadeAttemptTags", []) if nested_tls else [],
        "nestedTlsFailedTags": nested_tls.get("cascadeFailedTags", []) if nested_tls else [],
        "nestedTlsAllCandidatesFailed": nested_tls_all_failed(nested_tls, matrix),
        "nestedTlsMarkers": case_markers(nested_tls) if nested_tls else [],
    }


def control_summary(
    controls: list[dict[str, Any]],
    signatures: list[dict[str, Any]],
) -> dict[str, Any]:
    target_count = len({control["targetUrl"] for control in controls})
    return {
        "candidateDirectHttpsPass": sum(1 for item in controls if item["candidateDirectHttpsPass"]),
        "nestedTcpFlushPass": sum(1 for item in controls if item["nestedTcpFlushPass"]),
        "nestedTlsReadMissing": sum(1 for item in controls if item["nestedTlsReadMissing"]),
        "nestedTlsAttempts": sum(item["nestedTlsAttempts"] for item in controls),
        "nestedTlsFailedAttempts": sum(item["nestedTlsFailedAttempts"] for item in controls),
        "nestedTlsAllCandidatesFailed": sum(
            1 for item in controls if item["nestedTlsAllCandidatesFailed"]
        ),
        "nestedTlsUniqueFailedTagsMax": max(
            (len(set(item["nestedTlsFailedTags"])) for item in controls),
            default=0,
        ),
        "stableTlsFailureTargets": stable_tls_targets(signatures),
        "usableCandidateMax": max(
            (int(item["usableCandidates"] or 0) for item in controls),
            default=0,
        ),
        "targetCount": target_count,
    }


def stable_tls_targets(signatures: list[dict[str, Any]]) -> int:
    tls_signatures = [
        item
        for item in signatures
        if item["label"] == "tunnel-private-tls"
        and item["failedStage"] == "private-via-tunnel:stream-first-read"
        and "vmess-response-header-length-pending" in item["markers"]
    ]
    return max((len(item["targets"]) for item in tls_signatures), default=0)


def case_by_label(matrix: dict[str, Any], label: str) -> dict[str, Any] | None:
    for case in matrix["cases"]:
        if case["label"] == label:
            return case
    return None


def case_passed(case: dict[str, Any] | None) -> bool:
    return bool(case and case.get("status") == "pass")


def nested_tls_missing(case: dict[str, Any] | None) -> bool:
    if not case or case.get("status") == "pass":
        return False
    return (
        case.get("failureScope") == "downstream"
        and case.get("failedStage") == "private-via-tunnel:stream-first-read"
        and "vmess-response-header-length-pending" in case_markers(case)
    )


def nested_tls_all_failed(
    case: dict[str, Any] | None,
    matrix: dict[str, Any],
) -> bool:
    usable = int(matrix.get("metadata", {}).get("counts", {}).get("usable") or 0)
    if not usable or not case:
        return False
    failed_tags = set(case.get("cascadeFailedTags", []))
    return len(failed_tags) >= usable


def reason_markers(reason: str) -> list[str]:
    markers = [name for name, marker in SIGNATURE_MARKERS if marker in reason]
    if "failed Trojan TLS handshake" in reason and "unexpected end of file" in reason:
        markers.append("trojan-tls-handshake-eof")
    return markers


def case_markers(case: dict[str, Any]) -> list[str]:
    markers = reason_markers(str(case.get("reason") or ""))
    for marker in report_markers(case):
        append_unique(markers, marker)
    return markers


def report_markers(case: dict[str, Any]) -> list[str]:
    report_path = case.get("reportPath")
    if not report_path:
        return []
    try:
        report = json.loads(Path(str(report_path)).read_text())
    except (OSError, json.JSONDecodeError):
        return []
    markers: list[str] = []
    for event in report.get("events", []):
        if not isinstance(event, dict):
            continue
        fields = event.get("fields")
        if not isinstance(fields, dict):
            continue
        marker = fields.get("protocolReadMarker")
        if marker:
            append_unique(markers, str(marker))
            detail = protocol_read_detail_marker(str(marker), fields)
            if detail:
                append_unique(markers, detail)
    return markers


def protocol_read_detail_marker(marker: str, fields: dict[str, Any]) -> str | None:
    disposition = str(fields.get("protocolReadDisposition") or "")
    if not disposition and pending_budget_exhausted(marker, fields):
        disposition = "pending-budget-exhausted"
    if marker == "vmess-response-header-length-pending" and disposition:
        return f"vmess-response-header-length-{disposition}"
    return None


def pending_budget_exhausted(marker: str, fields: dict[str, Any]) -> bool:
    return (
        marker == "vmess-response-header-length-pending"
        and str(fields.get("status") or "") == "failed"
        and int_or_zero(fields.get("pendingRetries")) > 0
        and int_or_zero(fields.get("pendingBudgetMs")) > 0
    )


def int_or_zero(value: Any) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0


def marker_summary(failures: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for failure in failures:
        for marker in failure["markers"]:
            counts[marker] = counts.get(marker, 0) + 1
    return dict(sorted(counts.items()))


def attempt_tags(attempts: list[dict[str, Any]]) -> list[str]:
    tags: list[str] = []
    for item in attempts:
        tag = item.get("boundSelected")
        if tag is not None:
            append_unique(tags, str(tag))
    return tags


def grouped_signatures(failures: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[Any, ...], dict[str, Any]] = {}
    for failure in failures:
        key = (
            failure["label"],
            failure["protocol"],
            failure["failureScope"],
            failure["failedStage"],
            tuple(failure["markers"]),
        )
        group = groups.setdefault(
            key,
            {
                "label": failure["label"],
                "protocol": failure["protocol"],
                "failureScope": failure["failureScope"],
                "failedStage": failure["failedStage"],
                "markers": failure["markers"],
                "targets": [],
                "matrixPaths": [],
            },
        )
        append_unique(group["targets"], failure["targetUrl"])
        append_unique(group["matrixPaths"], failure["matrixPath"])
    return sorted(
        groups.values(),
        key=lambda item: (item["label"], item["protocol"], item["failureScope"] or ""),
    )


def append_unique(values: list[str], value: str) -> None:
    if value not in values:
        values.append(value)


def write_compare_markdown(path: Path, comparison: dict[str, Any]) -> None:
    summary = comparison["controlSummary"]
    lines = [
        "# Tunnel Private Matrix Compare",
        "",
        f"- matrices: `{comparison['totals']['matrices']}`",
        f"- targets: `{comparison['totals']['targets']}`",
        f"- failures: `{comparison['totals']['failures']}`",
        f"- signatures: `{comparison['totals']['signatures']}`",
        "",
        "## Control Summary",
        "",
        f"- candidate direct HTTPS pass: `{summary['candidateDirectHttpsPass']}`",
        f"- nested TCP flush pass: `{summary['nestedTcpFlushPass']}`",
        f"- nested TLS read missing: `{summary['nestedTlsReadMissing']}`",
        f"- nested TLS all candidates failed: `{summary['nestedTlsAllCandidatesFailed']}`",
        f"- stable TLS failure targets: `{summary['stableTlsFailureTargets']}`",
        "",
        "## Marker Summary",
        "",
    ]
    for marker, count in comparison.get("markerSummary", {}).items():
        lines.append(f"- `{marker}`: `{count}`")
    lines.extend([
        "",
        "## Failure Signatures",
        "",
    ])
    for item in comparison["failureSignatures"]:
        markers = ",".join(item["markers"]) or "<none>"
        lines.append(
            f"- `{item['label']}` protocol=`{item['protocol']}` "
            f"scope=`{item['failureScope']}` stage=`{item['failedStage']}` "
            f"markers=`{markers}` targets=`{len(item['targets'])}`"
        )
    path.write_text("\n".join(lines) + "\n")


def write_compare(path: Path, comparison: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(comparison, ensure_ascii=False, indent=2, sort_keys=True))
