from __future__ import annotations

from pathlib import Path
from typing import Any

from scripts.lib.jsonio import load_summary
from scripts.lib.nv import count_keys, merge_items


RETAINED_ARTIFACT_SCHEMA = (
    "dynet-vm-private-runtime-retained-artifact-surface/v1alpha1"
)
COUNT_FIELDS = [
    "runs",
    "cleanRuns",
    "failedRuns",
    "totalFiles",
    "jsonFiles",
    "markdownFiles",
    "diagnosticTextFiles",
    "requiredJsonPresent",
    "requiredJsonMissing",
    "optionalJsonFiles",
    "summaryArtifacts",
    "runtimeReports",
    "installReports",
    "uninstallReports",
    "stageReports",
    "workloadProbeReports",
    "metadataReports",
    "tcpProbeReports",
    "privacyReports",
    "metadataPrivacyReports",
    "workloadPrivacyReports",
    "remoteSecretConfigCleaned",
    "resolvedIpsRedacted",
    "unsafePrivacyFlags",
    "pcapFiles",
    "rawPacketFiles",
    "secretLikeFiles",
    "externalProxyLogFiles",
    "responseBodyFiles",
    "responseHeaderFiles",
    "tunRawLinesStored",
    "tunRawPcapStored",
    "workloadResponseBodiesStored",
    "workloadResponseHeadersStored",
    "workloadResolvedIpAddressesStored",
]


def runtime_retained_artifact_source(path: Path) -> dict[str, Any]:
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
        "fileKinds": count_keys(totals.get("fileKinds")),
        "missingRequiredArtifacts": count_keys(totals.get("missingRequiredArtifacts")),
        "unsafeFlagNames": count_keys(totals.get("unsafeFlagNames")),
    }
    source["privacy"] = privacy_flags(source)
    source["clean"] = runtime_retained_artifact_clean(source)
    return source


def runtime_retained_artifact_summary(
    sources: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "clean": bool(sources) and all(source["clean"] for source in sources),
        "statuses": sorted({source["status"] for source in sources if source["status"]}),
        **{field: sum(source[field] for source in sources) for field in COUNT_FIELDS},
        "classifications": merge_items(sources, "classifications"),
        "fileKinds": merge_items(sources, "fileKinds"),
        "missingRequiredArtifacts": merge_items(sources, "missingRequiredArtifacts"),
        "unsafeFlagNames": merge_items(sources, "unsafeFlagNames"),
        "sources": sources,
    }


def runtime_retained_artifact_clean(source: dict[str, Any]) -> bool:
    runs = source["runs"]
    return (
        source["schema"] == RETAINED_ARTIFACT_SCHEMA
        and source["status"] == "clean"
        and runs > 0
        and source["cleanRuns"] == runs
        and source["failedRuns"] == 0
        and source["classifications"] == ["clean"]
        and source["summaryArtifacts"] == runs
        and source["runtimeReports"] == runs
        and source["installReports"] == runs
        and source["uninstallReports"] == runs
        and source["stageReports"] == runs
        and source["privacyReports"] == runs
        and source["metadataPrivacyReports"] == runs
        and source["workloadPrivacyReports"] == runs
        and source["remoteSecretConfigCleaned"] == runs
        and source["resolvedIpsRedacted"] == runs
        and source["requiredJsonMissing"] == 0
        and source["unsafePrivacyFlags"] == 0
        and source["pcapFiles"] == 0
        and source["rawPacketFiles"] == 0
        and source["secretLikeFiles"] == 0
        and source["externalProxyLogFiles"] == 0
        and source["responseBodyFiles"] == 0
        and source["responseHeaderFiles"] == 0
        and source["tunRawLinesStored"] == 0
        and source["tunRawPcapStored"] == 0
        and source["workloadResponseBodiesStored"] == 0
        and source["workloadResponseHeadersStored"] == 0
        and source["workloadResolvedIpAddressesStored"] == 0
        and not any(source["privacy"].values())
    )


def privacy_flags(source: dict[str, Any]) -> dict[str, bool]:
    names = set(source["unsafeFlagNames"])
    return {
        "rawLogsStored": bool(source["externalProxyLogFiles"]) or has_flag(names, "rawLogsStored"),
        "rawPacketsStored": bool(
            source["rawPacketFiles"]
            or source["pcapFiles"]
            or source["tunRawLinesStored"]
            or source["tunRawPcapStored"]
        ) or has_flag(names, "rawPacketsStored"),
        "rawSecretsStored": bool(source["secretLikeFiles"]) or has_flag(names, "rawSecretsStored"),
        "responseBodiesStored": bool(
            source["responseBodyFiles"] or source["workloadResponseBodiesStored"]
        ) or has_flag(names, "responseBodiesStored") or has_flag(names, "rawResponseBodiesStored"),
        "identityInformationSent": has_flag(names, "identityInformationSent"),
        "cookiesSent": has_flag(names, "cookiesSent"),
        "authorizationSent": has_flag(names, "authorizationSent"),
        "rawResponseHeadersStored": bool(
            source["responseHeaderFiles"] or source["workloadResponseHeadersStored"]
        ) or has_flag(names, "responseHeadersStored") or has_flag(names, "rawResponseHeadersStored"),
        "accountStateStored": has_flag(names, "accountStateStored"),
    }


def has_flag(names: set[str], flag: str) -> bool:
    return any(name.endswith(f".{flag}") for name in names)
