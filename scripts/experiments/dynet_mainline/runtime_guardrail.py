from __future__ import annotations

import json
from pathlib import Path
from typing import Any


REQUIRED_CHECKS = {
    "downstream-bound-stage-succeeded",
    "private-downstream-stage-failed",
    "downstream-error-disposition",
    "cascade-non-bound-stop",
    "cascade-no-second-attempt",
}


def runtime_guardrail_source(path: Path) -> dict[str, Any]:
    summary = load_json(path)
    checks = check_map(summary)
    return {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "label": str(summary.get("label") or ""),
        "checksClean": checks_clean(checks),
        "missingChecks": sorted(REQUIRED_CHECKS - set(checks)),
        "forcePrivateDownstreamFailure": bool(
            (summary.get("candidateControl") or {}).get(
                "forcePrivateDownstreamFailure"
            )
        ),
        "runtimeDnsMode": str(summary.get("runtimeDnsMode") or ""),
        "boundStageSucceeded": bool(
            checks.get("downstream-bound-stage-succeeded")
        ),
        "privateDownstreamFailed": bool(
            checks.get("private-downstream-stage-failed")
        ),
        "downstreamDispositionKnown": bool(
            checks.get("downstream-error-disposition")
        ),
        "nonBoundStop": bool(checks.get("cascade-non-bound-stop")),
        "noSecondAttempt": bool(checks.get("cascade-no-second-attempt")),
        "commandExitCode": summary.get("commandExitCode"),
        "privacy": privacy_flags(summary),
    }


def runtime_guardrail_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "clean": bool(sources) and all(runtime_guardrail_clean(source) for source in sources),
        "nonBoundStops": sum(1 for source in sources if source["nonBoundStop"]),
        "noSecondAttempts": sum(1 for source in sources if source["noSecondAttempt"]),
        "downstreamDispositions": sum(
            1 for source in sources if source["downstreamDispositionKnown"]
        ),
        "runtimeDnsModes": sorted({
            source["runtimeDnsMode"] for source in sources if source["runtimeDnsMode"]
        }),
        "sources": sources,
    }


def runtime_guardrail_clean(source: dict[str, Any]) -> bool:
    return (
        source["checksClean"]
        and not source["missingChecks"]
        and source["forcePrivateDownstreamFailure"]
        and source["runtimeDnsMode"] == "udp-diagnostic-override"
        and source["boundStageSucceeded"]
        and source["privateDownstreamFailed"]
        and source["downstreamDispositionKnown"]
        and source["nonBoundStop"]
        and source["noSecondAttempt"]
        and source["commandExitCode"] in {0, None}
        and not any(source["privacy"].values())
    )


def check_map(summary: dict[str, Any]) -> dict[str, bool]:
    result = {}
    for item in summary.get("checks", []):
        if isinstance(item, dict) and item.get("name"):
            result[str(item["name"])] = item.get("passed") is True
    return result


def checks_clean(checks: dict[str, bool]) -> bool:
    return bool(checks) and all(checks.values())


def privacy_flags(summary: dict[str, Any]) -> dict[str, bool]:
    privacy = summary.get("privacy") or {}
    return {
        "rawLogsStored": bool(privacy.get("rawLogsStored")),
        "rawPacketsStored": bool(privacy.get("rawPacketsStored")),
        "rawSecretsStored": bool(privacy.get("rawSecretsStored")),
        "responseBodiesStored": bool(privacy.get("responseBodiesStored")),
        "responseHeadersStored": bool(privacy.get("responseHeadersStored")),
        "identityInformationSent": bool(privacy.get("identityInformationSent")),
    }


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text())
