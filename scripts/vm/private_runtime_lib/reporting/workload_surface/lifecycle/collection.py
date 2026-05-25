from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from common import Lab, validate_name


COLLECTION_STAGE_SCHEMA = "dynet-vm-private-runtime-collection-stage-surface/v1alpha1"
REPEAT_SCHEMA = "dynet-vm-private-runtime-repeat/v1alpha1"
REQUIRED_STAGES = {
    "run-acceptance",
    "collect-runtime-report",
    "collect-runtime-log",
    "collect-install-report",
    "collect-uninstall-report",
    "cleanup-guest-files",
}
ARTIFACT_STAGES = {
    "runtime-report.json": "collect-runtime-report",
    "runtime-log.txt": "collect-runtime-log",
    "install-report.json": "collect-install-report",
    "uninstall-report.json": "collect-uninstall-report",
    "tcp-probe.json": "collect-tcp-probe-report",
    "udp-probe.json": "collect-udp-probe-report",
    "ipv6-probe.json": "collect-ipv6-probe-report",
    "workload-probe.json": "collect-workload-probe-report",
}
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
    "stageReports",
    "stageCount",
    "stagePassed",
    "stageFailed",
    "requiredStages",
    "requiredPassed",
    "requiredMissing",
    "collectArtifactExpected",
    "collectArtifactPresent",
    "collectStageExpected",
    "collectStagePassed",
    "collectStageMissing",
    "orderViolations",
    "cleanupLast",
    "timingFieldsComplete",
    "unsafePrivacyFlags",
]


def command_collection_stage_surface(_lab: Lab, args: argparse.Namespace) -> None:
    label = validate_name(args.label or "collection-stage-surface", "label")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = build_collection_stage_summary(
        label,
        output_dir,
        [Path(item) for item in args.input],
    )
    write_collection_stage_summary(output_dir, summary)
    print(json.dumps(collection_stage_print(output_dir, summary), sort_keys=True))


def build_collection_stage_summary(
    label: str,
    output_dir: Path,
    inputs: list[Path],
) -> dict[str, Any]:
    rows = [collection_stage_row(path) for path in expand_inputs(inputs)]
    totals = collection_stage_totals(rows)
    return {
        "schema": COLLECTION_STAGE_SCHEMA,
        "label": label,
        "outputDir": str(output_dir),
        "runs": rows,
        "totals": totals,
        "conclusion": collection_stage_conclusion(totals),
        "policy": {
            "plannerPenaltySafe": False,
            "qualityPenaltySafe": False,
            "reason": "Collection-stage evidence is artifact lifecycle proof, not penalty proof.",
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


def collection_stage_row(run_dir: Path) -> dict[str, Any]:
    current = collection_stage_counts(run_dir)
    clean = collection_stage_clean(current)
    summary = load_summary(run_dir)
    return {
        "label": summary.get("label") or run_dir.name,
        "path": str(run_dir),
        "classification": "clean" if clean else collection_stage_classification(current),
        "clean": clean,
        "current": current,
    }


def collection_stage_counts(run_dir: Path) -> dict[str, Any]:
    summary = load_summary(run_dir)
    stage_report = load_optional_json(run_dir / "stage-report.json")
    stage_rows = stage_rows_from(stage_report or summary.get("stages") or {})
    names = {stage_name(row) for row in stage_rows}
    expected = expected_artifact_stages(run_dir)
    privacy = privacy_counts(summary)
    return {
        "stageReports": 1 if stage_report else 0,
        "stageCount": len(stage_rows),
        "stagePassed": sum(1 for row in stage_rows if row.get("status") == "pass"),
        "stageFailed": sum(1 for row in stage_rows if row.get("status") != "pass"),
        "requiredStages": len(REQUIRED_STAGES),
        "requiredPassed": sum(1 for name in REQUIRED_STAGES if stage_passed(stage_rows, name)),
        "requiredMissing": len(REQUIRED_STAGES - names),
        "collectArtifactExpected": len(expected),
        "collectArtifactPresent": sum(1 for name in ARTIFACT_STAGES if (run_dir / name).exists()),
        "collectStageExpected": len(expected),
        "collectStagePassed": sum(1 for name in expected if stage_passed(stage_rows, name)),
        "collectStageMissing": sum(1 for name in expected if name not in names),
        "orderViolations": order_violations(stage_rows),
        "cleanupLast": 1 if stage_rows and stage_name(stage_rows[-1]) == "cleanup-guest-files" else 0,
        "timingFieldsComplete": sum(1 for row in stage_rows if timing_complete(row)),
        **privacy,
        "stageNames": aggregate(stage_name(row) for row in stage_rows),
        "missingRequiredStages": aggregate(REQUIRED_STAGES - names),
        "missingCollectStages": aggregate(name for name in expected if name not in names),
        "missingArtifacts": aggregate(
            artifact
            for artifact, stage in ARTIFACT_STAGES.items()
            if stage in expected and not (run_dir / artifact).exists()
        ),
        "unsafeFlagNames": aggregate(privacy["unsafeFlagNames"]),
    }


def expected_artifact_stages(run_dir: Path) -> set[str]:
    return {
        stage
        for artifact, stage in ARTIFACT_STAGES.items()
        if artifact in {"runtime-report.json", "runtime-log.txt", "install-report.json", "uninstall-report.json"}
        or (run_dir / artifact).exists()
    }


def order_violations(stage_rows: list[dict[str, Any]]) -> int:
    indexes = {stage_name(row): index for index, row in enumerate(stage_rows)}
    cleanup = indexes.get("cleanup-guest-files")
    run = indexes.get("run-acceptance")
    violations = 0
    for name, index in indexes.items():
        if name.startswith("collect-") and run is not None and index <= run:
            violations += 1
        if name.startswith("collect-") and cleanup is not None and index >= cleanup:
            violations += 1
    return violations + ordered_pair_violations(indexes)


def ordered_pair_violations(indexes: dict[str, int]) -> int:
    pairs = [
        ("collect-runtime-report", "collect-runtime-log"),
        ("collect-runtime-log", "collect-install-report"),
        ("collect-install-report", "collect-uninstall-report"),
    ]
    return sum(1 for left, right in pairs if left in indexes and right in indexes and indexes[left] >= indexes[right])


def collection_stage_clean(counts: dict[str, Any]) -> bool:
    return (
        counts["stageReports"] == 1
        and counts["stageCount"] > 0
        and counts["stageFailed"] == 0
        and counts["requiredMissing"] == 0
        and counts["requiredPassed"] == counts["requiredStages"]
        and counts["collectArtifactPresent"] == counts["collectArtifactExpected"]
        and counts["collectStageMissing"] == 0
        and counts["collectStagePassed"] == counts["collectStageExpected"]
        and counts["orderViolations"] == 0
        and counts["cleanupLast"] == 1
        and counts["timingFieldsComplete"] == counts["stageCount"]
        and counts["unsafePrivacyFlags"] == 0
    )


def collection_stage_classification(counts: dict[str, Any]) -> str:
    if counts["stageReports"] == 0:
        return "stage-report-missing"
    if counts["stageFailed"]:
        return "stage-failed"
    if counts["requiredMissing"] or counts["requiredPassed"] < counts["requiredStages"]:
        return "required-stage-missing"
    if counts["collectArtifactPresent"] < counts["collectArtifactExpected"]:
        return "collection-artifact-missing"
    if counts["collectStageMissing"] or counts["collectStagePassed"] < counts["collectStageExpected"]:
        return "collection-stage-missing"
    if counts["orderViolations"] or counts["cleanupLast"] == 0:
        return "collection-stage-order-invalid"
    if counts["timingFieldsComplete"] < counts["stageCount"]:
        return "stage-timing-missing"
    if counts["unsafePrivacyFlags"]:
        return "unsafe-privacy-flag"
    return "collection-stage-incomplete"


def collection_stage_totals(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "runs": len(rows),
        "cleanRuns": sum(1 for row in rows if row["clean"]),
        "failedRuns": sum(1 for row in rows if not row["clean"]),
        "classifications": aggregate(row["classification"] for row in rows),
        **{
            key: sum(int(row["current"].get(key) or 0) for row in rows)
            for key in COUNT_KEYS
        },
        "stageNames": merge_count_rows(row["current"]["stageNames"] for row in rows),
        "missingRequiredStages": merge_count_rows(
            row["current"]["missingRequiredStages"] for row in rows
        ),
        "missingCollectStages": merge_count_rows(
            row["current"]["missingCollectStages"] for row in rows
        ),
        "missingArtifacts": merge_count_rows(row["current"]["missingArtifacts"] for row in rows),
        "unsafeFlagNames": merge_count_rows(row["current"]["unsafeFlagNames"] for row in rows),
    }


def collection_stage_conclusion(totals: dict[str, Any]) -> dict[str, Any]:
    clean = totals["runs"] > 0 and totals["failedRuns"] == 0
    return {
        "status": "clean" if clean else "collection-stage-surface-needs-evidence",
        "nextAction": "return-to-runtime-surface" if clean else "inspect-collection-stages",
        "plannerPenaltySafe": False,
        "qualityPenaltySafe": False,
    }


def write_collection_stage_summary(output_dir: Path, summary: dict[str, Any]) -> None:
    (output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n"
    )
    write_collection_stage_markdown(output_dir / "summary.md", summary)


def write_collection_stage_markdown(path: Path, summary: dict[str, Any]) -> None:
    totals = summary["totals"]
    lines = [
        "# VM Private Runtime Collection Stage Surface",
        "",
        f"- label: `{summary['label']}`",
        f"- status: `{summary['conclusion']['status']}`",
        f"- runs: `{totals['runs']}`",
        f"- clean runs: `{totals['cleanRuns']}`",
        f"- stage reports: `{totals['stageReports']}`",
        f"- failed stages: `{totals['stageFailed']}`",
        f"- required missing: `{totals['requiredMissing']}`",
        f"- collection stage missing: `{totals['collectStageMissing']}`",
        f"- order violations: `{totals['orderViolations']}`",
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


def collection_stage_print(output_dir: Path, summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "outputDir": str(output_dir),
        "runs": summary["totals"]["runs"],
        "cleanRuns": summary["totals"]["cleanRuns"],
        "status": summary["conclusion"]["status"],
    }


def stage_rows_from(data: dict[str, Any]) -> list[dict[str, Any]]:
    rows = data.get("stages") if isinstance(data, dict) else []
    return [row for row in rows or [] if isinstance(row, dict)]


def stage_name(row: dict[str, Any]) -> str:
    return str(row.get("name") or "unknown")


def stage_passed(rows: list[dict[str, Any]], name: str) -> bool:
    return any(stage_name(row) == name and row.get("status") == "pass" for row in rows)


def timing_complete(row: dict[str, Any]) -> bool:
    return all(row.get(key) is not None for key in ["startedAt", "finishedAt", "elapsedMs"])


def privacy_counts(summary: dict[str, Any]) -> dict[str, Any]:
    unsafe = [
        f"{prefix}.{flag}"
        for prefix, data in privacy_sources(summary)
        for flag in UNSAFE_PRIVACY_FLAGS
        if bool(data.get(flag))
    ]
    return {"unsafePrivacyFlags": len(unsafe), "unsafeFlagNames": unsafe}


def privacy_sources(summary: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    return [
        ("privacy", nested_dict(summary, "privacy")),
        ("metadata.privacy", nested_dict(summary, "metadata", "privacy")),
        ("workloadProbe.privacy", nested_dict(summary, "workloadProbe", "privacy")),
        ("workloadProbe.tunCapture", nested_dict(summary, "workloadProbe", "tunCapture")),
    ]


def load_summary(run_dir: Path) -> dict[str, Any]:
    return load_optional_json(run_dir if run_dir.name == "summary.json" else run_dir / "summary.json")


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
