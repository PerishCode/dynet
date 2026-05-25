from __future__ import annotations

from pathlib import Path
from typing import Any

from scripts.lib.jsonio import load_summary
from scripts.lib.nv import count_keys, merge_items


EXIT_LIMIT_SCHEMA = "dynet-vm-private-runtime-exit-limit-surface/v1alpha1"
COUNT_FIELDS = [
    "runs",
    "cleanRuns",
    "failedRuns",
    "commandExitZero",
    "runtimePass",
    "runtimeLimitReason",
    "failedChecks",
    "tcpExpectedTerminalSessions",
    "tcpClosedSessions",
    "tcpLimitRuns",
    "tcpLimitSatisfiedRuns",
    "udpDownstreamLimitRuns",
    "udpDownstreamSatisfiedRuns",
    "diagnosticDnsTunLimitRuns",
    "diagnosticDnsTunSatisfiedRuns",
    "runtimeTimeoutReasons",
    "unsafePrivacyFlags",
]


def runtime_exit_limit_source(path: Path) -> dict[str, Any]:
    summary = load_summary(path)
    totals = summary.get("totals") or {}
    conclusion = summary.get("conclusion") or {}
    source = {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "label": str(summary.get("label") or ""),
        "status": str(conclusion.get("status") or ""),
        **{field: int(totals.get(field) or 0) for field in COUNT_FIELDS},
        "classifications": count_keys(totals.get("classifications")),
        "limitEvidence": count_keys(totals.get("limitEvidence")),
        "unsafeFlagNames": count_keys(totals.get("unsafeFlagNames")),
    }
    source["privacy"] = privacy_flags(source)
    source["clean"] = runtime_exit_limit_clean(source)
    return source


def runtime_exit_limit_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "clean": bool(sources) and all(source["clean"] for source in sources),
        "statuses": sorted({source["status"] for source in sources if source["status"]}),
        **{field: sum(source[field] for source in sources) for field in COUNT_FIELDS},
        "classifications": merge_items(sources, "classifications"),
        "limitEvidence": merge_items(sources, "limitEvidence"),
        "unsafeFlagNames": merge_items(sources, "unsafeFlagNames"),
        "sources": sources,
    }


def runtime_exit_limit_clean(source: dict[str, Any]) -> bool:
    runs = source["runs"]
    return (
        source["schema"] == EXIT_LIMIT_SCHEMA
        and source["status"] == "clean"
        and runs > 0
        and source["cleanRuns"] == runs
        and source["failedRuns"] == 0
        and source["classifications"] == ["clean"]
        and source["commandExitZero"] == runs
        and source["runtimePass"] == runs
        and source["runtimeLimitReason"] == runs
        and source["failedChecks"] == 0
        and source["runtimeTimeoutReasons"] == 0
        and source["unsafePrivacyFlags"] == 0
        and source["tcpLimitRuns"] == source["tcpLimitSatisfiedRuns"]
        and source["udpDownstreamLimitRuns"] == source["udpDownstreamSatisfiedRuns"]
        and source["diagnosticDnsTunLimitRuns"] == source["diagnosticDnsTunSatisfiedRuns"]
        and bool(source["limitEvidence"])
        and not any(source["privacy"].values())
    )


def privacy_flags(source: dict[str, Any]) -> dict[str, bool]:
    names = set(source["unsafeFlagNames"])
    return {
        "rawLogsStored": has_flag(names, "rawLogsStored"),
        "rawPacketsStored": has_flag(names, "rawPacketsStored"),
        "rawSecretsStored": has_flag(names, "rawSecretsStored"),
        "responseBodiesStored": has_flag(names, "responseBodiesStored")
        or has_flag(names, "rawResponseBodiesStored"),
        "identityInformationSent": has_flag(names, "identityInformationSent"),
        "cookiesSent": has_flag(names, "cookiesSent"),
        "authorizationSent": has_flag(names, "authorizationSent"),
        "rawResponseHeadersStored": has_flag(names, "responseHeadersStored")
        or has_flag(names, "rawResponseHeadersStored"),
        "accountStateStored": has_flag(names, "accountStateStored"),
    }


def has_flag(names: set[str], flag: str) -> bool:
    return any(name.endswith(f".{flag}") for name in names)
