from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from dynet_clash import limits as limit_model


def report_limit_details(report: dict[str, Any]) -> list[dict[str, str]]:
    details = report.get("limitDetails")
    if not isinstance(details, list):
        return limit_model.legacy_details(
            [str(item) for item in report.get("limits", [])]
        )
    output = []
    for item in details:
        if not isinstance(item, dict):
            continue
        message = str(item.get("message") or "")
        if not message:
            continue
        category = str(item.get("category") or limit_model.legacy_category(message))
        scope = str(item.get("scope") or limit_model.legacy_scope(message))
        output.append(limit_model.detail(scope, category, message))
    return output


def scoped_limit_details(
    details: list[dict[str, str]],
    clean_scope: str,
) -> list[dict[str, str]]:
    if clean_scope == "all":
        return details
    return [
        item
        for item in details
        if item.get("scope") == clean_scope
    ]


def detail_categories(details: list[dict[str, str]]) -> list[str]:
    return sorted({
        str(item.get("category") or "other")
        for item in details
    })


def limit_categories(limits: list[str]) -> list[str]:
    return detail_categories(limit_model.legacy_details(limits))


def path_label(path: Path) -> str:
    if path.stem in {"comparison", "summary"} and path.parent.name:
        return path.parent.name
    return path.stem


def runtime_window(gate: Any) -> dict[str, Any]:
    if not isinstance(gate, dict):
        return {
            "present": False,
            "clean": False,
            "classification": "missing-runtime-evidence",
            "failedChecks": ["runtime-summary-present"],
        }
    return {
        "present": bool(gate.get("present", True)),
        "clean": bool(gate.get("clean")),
        "classification": gate.get("classification"),
        "failedChecks": gate.get("failedChecks", []),
        "totals": {
            key: gate.get("totals", {}).get(key)
            for key in [
                "workloadAttempted",
                "workloadSuccess",
                "workloadFailure",
                "tcpAttemptedEntries",
                "tcpAttemptedCoveredEntries",
                "runtimePreflowMatchedEntries",
                "runtimePacketHandshakeEntries",
                "tunCaptureMatchedEntries",
                "unmatchedEntries",
                "runtimePacketTerminalEntries",
                "tcpFlowFailed",
                "tcpFlowFailedAfterPathComplete",
                "tcpFlowFailedAfterUpstreamOnly",
                "tcpSlotPressureEvents",
                "tcpActiveSlotsMax",
                "qualityStateUsed",
                "qualityBoundCandidateSets",
                "qualityBoundSelectedWithQuality",
                "qualityBoundSelectedBehind",
                "tcpFlowRouteMatched",
                "tcpFlowRouteGraphSelected",
                "tcpFlowRuleMatched",
                "tcpFlowPlanBypassed",
                "tcpFlowRouteCandidateSet",
            ]
        },
        "surfaces": non_empty_surfaces(gate.get("surfaces", {})),
    }


def runtime_gate_failures(windows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    failures = []
    for window in windows:
        gate = window.get("runtimeGate", {})
        if gate.get("present") and gate.get("clean"):
            continue
        failures.append(
            {
                "window": window.get("label"),
                "classification": gate.get("classification"),
                "failedChecks": gate.get("failedChecks", []),
                "surfaces": gate.get("surfaces", {}),
                "totals": gate.get("totals", {}),
            }
        )
    return failures


def runtime_batch(windows: list[dict[str, Any]]) -> dict[str, Any]:
    gates = [window.get("runtimeGate", {}) for window in windows]
    classifications = Counter(
        str(gate.get("classification") or "unknown")
        for gate in gates
    )
    failed_checks = Counter(
        str(check)
        for gate in gates
        for check in gate.get("failedChecks", [])
    )
    return {
        "windowCount": len(windows),
        "presentWindows": sum(1 for gate in gates if gate.get("present")),
        "cleanWindows": sum(1 for gate in gates if gate.get("clean")),
        "missingWindows": sum(1 for gate in gates if gate.get("present") is False),
        "failedWindows": failure_windows(windows),
        "classificationCounts": counter_rows(classifications),
        "failedCheckCounts": counter_rows(failed_checks),
        "surfaceCounts": surface_counts(gates),
    }


def failure_windows(windows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "window": window.get("label"),
            "classification": gate.get("classification"),
            "failedChecks": gate.get("failedChecks", []),
            "surfaces": gate.get("surfaces", {}),
            "totals": gate.get("totals", {}),
        }
        for window in windows
        for gate in [window.get("runtimeGate", {})]
        if not gate.get("clean")
    ]


def surface_counts(gates: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    counters: dict[str, Counter[str]] = {}
    for gate in gates:
        for surface, rows in gate.get("surfaces", {}).items():
            counter = counters.setdefault(str(surface), Counter())
            for row in rows if isinstance(rows, list) else []:
                if isinstance(row, dict):
                    counter[str(row.get("key") or "unknown")] += int(row.get("count") or 0)
                else:
                    counter[str(row)] += 1
    return {
        key: counter_rows(counter)
        for key, counter in sorted(counters.items())
        if counter
    }


def non_empty_surfaces(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        return {}
    return {
        str(key): value
        for key, value in raw.items()
        if value
    }


def counter_rows(counter: Counter[str]) -> list[dict[str, Any]]:
    return [
        {"key": key, "count": count}
        for key, count in counter.most_common()
    ]
