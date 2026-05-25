from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from common import Lab, validate_name


RETAINED_ARTIFACT_SCHEMA = (
    "dynet-vm-private-runtime-retained-artifact-surface/v1alpha1"
)
REPEAT_SCHEMA = "dynet-vm-private-runtime-repeat/v1alpha1"
REQUIRED_JSON_FILES = {
    "summary.json",
    "runtime-report.json",
    "install-report.json",
    "uninstall-report.json",
    "stage-report.json",
}
OPTIONAL_JSON_FILES = {
    "meta.json",
    "tcp-probe.json",
    "workload-manifest.json",
    "workload-probe.json",
}
KNOWN_DIAGNOSTIC_TEXT = {
    "command-stderr.txt",
    "command-stdout.txt",
    "runtime-log.txt",
}
TEXT_SUFFIXES = {".log", ".txt"}
UNSAFE_PRIVACY_FLAGS = {
    "authorizationSent",
    "cookiesSent",
    "identityInformationSent",
    "rawLogsStored",
    "rawPacketsStored",
    "rawResponseBodiesStored",
    "rawResponseHeadersStored",
    "rawSecretsStored",
    "responseBodiesStored",
    "responseHeadersStored",
    "accountStateStored",
    "resolvedIpAddressesStored",
}
COUNT_KEYS = [
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


def command_retained_artifact_surface(_lab: Lab, args: argparse.Namespace) -> None:
    label = validate_name(args.label or "retained-artifact-surface", "label")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = build_retained_artifact_summary(
        label,
        output_dir,
        [Path(item) for item in args.input],
    )
    write_retained_artifact_summary(output_dir, summary)
    print(json.dumps(retained_artifact_print(output_dir, summary), sort_keys=True))


def build_retained_artifact_summary(
    label: str,
    output_dir: Path,
    inputs: list[Path],
) -> dict[str, Any]:
    rows = [retained_artifact_row(path) for path in expand_inputs(inputs)]
    totals = retained_artifact_totals(rows)
    return {
        "schema": RETAINED_ARTIFACT_SCHEMA,
        "label": label,
        "outputDir": str(output_dir),
        "runs": rows,
        "totals": totals,
        "conclusion": retained_artifact_conclusion(totals),
        "policy": {
            "plannerPenaltySafe": False,
            "qualityPenaltySafe": False,
            "reason": "Artifact retention cleanliness is collection policy evidence, not penalty proof.",
        },
    }


def expand_inputs(inputs: list[Path]) -> list[Path]:
    paths: list[Path] = []
    for path in inputs:
        summary = load_optional_json(path / "summary.json")
        if summary.get("schema") == REPEAT_SCHEMA:
            paths.extend(
                Path(row["path"])
                for row in summary.get("runs", [])
                if isinstance(row, dict) and row.get("path")
            )
        else:
            paths.append(path)
    return paths


def retained_artifact_row(run_dir: Path) -> dict[str, Any]:
    summary = load_optional_json(run_dir / "summary.json")
    current = retained_artifact_counts(run_dir, summary)
    clean = retained_artifact_clean(current)
    return {
        "label": summary.get("label") or run_dir.name,
        "path": str(run_dir),
        "classification": "clean" if clean else retained_artifact_classification(current),
        "clean": clean,
        "current": current,
    }


def retained_artifact_counts(run_dir: Path, summary: dict[str, Any]) -> dict[str, Any]:
    files = [path for path in run_dir.iterdir() if path.is_file()] if run_dir.exists() else []
    categories = [file_category(path.name) for path in files]
    names = {path.name for path in files}
    privacy = privacy_counts(summary)
    return {
        "totalFiles": len(files),
        "jsonFiles": sum(1 for path in files if path.suffix == ".json"),
        "markdownFiles": sum(1 for path in files if path.suffix == ".md"),
        "diagnosticTextFiles": sum(1 for path in files if path.name in KNOWN_DIAGNOSTIC_TEXT),
        "requiredJsonPresent": len(REQUIRED_JSON_FILES & names),
        "requiredJsonMissing": len(REQUIRED_JSON_FILES - names),
        "optionalJsonFiles": len(OPTIONAL_JSON_FILES & names),
        "summaryArtifacts": 1 if "summary.json" in names else 0,
        "runtimeReports": 1 if "runtime-report.json" in names else 0,
        "installReports": 1 if "install-report.json" in names else 0,
        "uninstallReports": 1 if "uninstall-report.json" in names else 0,
        "stageReports": 1 if "stage-report.json" in names else 0,
        "workloadProbeReports": 1 if "workload-probe.json" in names else 0,
        "metadataReports": 1 if "meta.json" in names else 0,
        "tcpProbeReports": 1 if "tcp-probe.json" in names else 0,
        **privacy,
        "pcapFiles": categories.count("pcap"),
        "rawPacketFiles": categories.count("raw-packet"),
        "secretLikeFiles": categories.count("secret-like"),
        "externalProxyLogFiles": categories.count("external-proxy-log"),
        "responseBodyFiles": categories.count("response-body"),
        "responseHeaderFiles": categories.count("response-header"),
        "fileKinds": aggregate(categories),
        "missingRequiredArtifacts": aggregate(REQUIRED_JSON_FILES - names),
        "unsafeFlagNames": aggregate(privacy["unsafeFlagNames"]),
    }


def privacy_counts(summary: dict[str, Any]) -> dict[str, Any]:
    top = summary.get("privacy") if isinstance(summary.get("privacy"), dict) else {}
    metadata = nested_dict(summary, "metadata", "privacy")
    workload = nested_dict(summary, "workloadProbe", "privacy")
    tun = nested_dict(summary, "workloadProbe", "tunCapture")
    unsafe = [
        f"{prefix}.{flag}"
        for prefix, data in [
            ("privacy", top),
            ("metadata.privacy", metadata),
            ("workloadProbe.privacy", workload),
            ("workloadProbe.tunCapture", tun),
        ]
        for flag in UNSAFE_PRIVACY_FLAGS
        if bool(data.get(flag))
    ]
    return {
        "privacyReports": 1 if top else 0,
        "metadataPrivacyReports": 1 if metadata else 0,
        "workloadPrivacyReports": 1 if workload else 0,
        "remoteSecretConfigCleaned": 1 if top.get("remoteSecretConfigCleaned") is True else 0,
        "resolvedIpsRedacted": 1 if top.get("resolvedIpsRedacted") is True else 0,
        "unsafePrivacyFlags": len(unsafe),
        "unsafeFlagNames": unsafe,
        "tunRawLinesStored": 1 if tun.get("rawLinesStored") is True else 0,
        "tunRawPcapStored": 1 if tun.get("rawPcapStored") is True else 0,
        "workloadResponseBodiesStored": 1 if workload.get("responseBodiesStored") is True else 0,
        "workloadResponseHeadersStored": 1 if workload.get("responseHeadersStored") is True else 0,
        "workloadResolvedIpAddressesStored": 1 if workload.get("resolvedIpAddressesStored") is True else 0,
    }


def retained_artifact_clean(counts: dict[str, Any]) -> bool:
    return (
        counts["summaryArtifacts"] == 1
        and counts["requiredJsonMissing"] == 0
        and counts["privacyReports"] == 1
        and counts["metadataPrivacyReports"] == 1
        and counts["workloadPrivacyReports"] == 1
        and counts["remoteSecretConfigCleaned"] == 1
        and counts["resolvedIpsRedacted"] == 1
        and retained_artifact_forbidden_count(counts) == 0
    )


def retained_artifact_forbidden_count(counts: dict[str, Any]) -> int:
    return sum(
        int(counts.get(key) or 0)
        for key in [
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
    )


def retained_artifact_classification(counts: dict[str, Any]) -> str:
    if counts["summaryArtifacts"] == 0:
        return "summary-artifact-missing"
    if counts["requiredJsonMissing"]:
        return "required-artifact-missing"
    if forbidden_file_count(counts):
        return "forbidden-file-retained"
    if counts["privacyReports"] == 0 or counts["metadataPrivacyReports"] == 0:
        return "privacy-report-missing"
    if counts["workloadPrivacyReports"] == 0:
        return "workload-privacy-report-missing"
    if counts["unsafePrivacyFlags"]:
        return "unsafe-privacy-flag"
    if counts["remoteSecretConfigCleaned"] == 0:
        return "secret-cleanup-missing"
    if counts["resolvedIpsRedacted"] == 0:
        return "resolved-ip-redaction-missing"
    return "artifact-retention-incomplete"


def forbidden_file_count(counts: dict[str, Any]) -> int:
    return sum(
        int(counts.get(key) or 0)
        for key in [
            "pcapFiles",
            "rawPacketFiles",
            "secretLikeFiles",
            "externalProxyLogFiles",
            "responseBodyFiles",
            "responseHeaderFiles",
        ]
    )


def retained_artifact_totals(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "runs": len(rows),
        "cleanRuns": sum(1 for row in rows if row["clean"]),
        "failedRuns": sum(1 for row in rows if not row["clean"]),
        "classifications": aggregate(row["classification"] for row in rows),
        **{
            key: sum(int(row["current"].get(key) or 0) for row in rows)
            for key in COUNT_KEYS
        },
        "fileKinds": merge_count_rows(row["current"]["fileKinds"] for row in rows),
        "missingRequiredArtifacts": merge_count_rows(
            row["current"]["missingRequiredArtifacts"] for row in rows
        ),
        "unsafeFlagNames": merge_count_rows(
            row["current"]["unsafeFlagNames"] for row in rows
        ),
    }


def retained_artifact_conclusion(totals: dict[str, Any]) -> dict[str, Any]:
    clean = totals["runs"] > 0 and totals["failedRuns"] == 0
    return {
        "status": "clean" if clean else "retained-artifact-surface-needs-evidence",
        "nextAction": "return-to-runtime-surface" if clean else "inspect-retained-artifacts",
        "plannerPenaltySafe": False,
        "qualityPenaltySafe": False,
    }


def write_retained_artifact_summary(output_dir: Path, summary: dict[str, Any]) -> None:
    (output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n"
    )
    write_retained_artifact_markdown(output_dir / "summary.md", summary)


def write_retained_artifact_markdown(path: Path, summary: dict[str, Any]) -> None:
    totals = summary["totals"]
    lines = [
        "# VM Private Runtime Retained Artifact Surface",
        "",
        f"- label: `{summary['label']}`",
        f"- status: `{summary['conclusion']['status']}`",
        f"- runs: `{totals['runs']}`",
        f"- clean runs: `{totals['cleanRuns']}`",
        f"- required JSON missing: `{totals['requiredJsonMissing']}`",
        f"- unsafe privacy flags: `{totals['unsafePrivacyFlags']}`",
        f"- pcap files: `{totals['pcapFiles']}`",
        f"- raw packet files: `{totals['rawPacketFiles']}`",
        f"- response body files: `{totals['responseBodyFiles']}`",
        f"- response header files: `{totals['responseHeaderFiles']}`",
        "",
        "## Runs",
        "",
    ]
    for row in summary["runs"]:
        lines.append(
            f"- `{row['label']}` classification=`{row['classification']}` "
            f"clean=`{row['clean']}`"
        )
    path.write_text("\n".join(lines) + "\n")


def retained_artifact_print(output_dir: Path, summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "outputDir": str(output_dir),
        "runs": summary["totals"]["runs"],
        "cleanRuns": summary["totals"]["cleanRuns"],
        "status": summary["conclusion"]["status"],
    }


def file_category(name: str) -> str:
    lower = name.lower()
    suffix = Path(lower).suffix
    if suffix in {".pcap", ".pcapng"}:
        return "pcap"
    if "packet" in lower and suffix in TEXT_SUFFIXES:
        return "raw-packet"
    if lower in KNOWN_DIAGNOSTIC_TEXT:
        return "diagnostic-text"
    if "clash" in lower or "mihomo" in lower:
        return "external-proxy-log" if suffix in TEXT_SUFFIXES else "external-proxy"
    if "provider" in lower and suffix in TEXT_SUFFIXES:
        return "external-proxy-log"
    if "secret" in lower:
        return "secret-like"
    if "response-body" in lower or "body" in lower and suffix in TEXT_SUFFIXES:
        return "response-body"
    if "response-header" in lower or "headers" in lower and suffix in TEXT_SUFFIXES:
        return "response-header"
    if suffix == ".json":
        return "json"
    if suffix == ".md":
        return "markdown"
    if suffix in TEXT_SUFFIXES:
        return "diagnostic-text"
    return "other"


def nested_dict(data: dict[str, Any], *path: str) -> dict[str, Any]:
    current: Any = data
    for item in path:
        current = current.get(item) if isinstance(current, dict) else None
    return current if isinstance(current, dict) else {}


def aggregate(values: Any) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for value in values:
        key = str(value or "unknown")
        counts[key] = counts.get(key, 0) + 1
    return [{"key": key, "count": counts[key]} for key in sorted(counts)]


def merge_count_rows(row_sets: Any) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for rows in row_sets:
        for row in rows:
            key = str(row.get("key") or "")
            if key:
                counts[key] = counts.get(key, 0) + int(row.get("count") or 0)
    return [{"key": key, "count": counts[key]} for key in sorted(counts)]


def load_optional_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open() as fh:
        value = json.load(fh)
    return value if isinstance(value, dict) else {}
