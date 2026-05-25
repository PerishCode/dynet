from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from common import Lab, validate_name


TAKEOVER_LIFECYCLE_SCHEMA = (
    "dynet-vm-private-runtime-takeover-lifecycle-surface/v1alpha1"
)
REPEAT_SCHEMA = "dynet-vm-private-runtime-repeat/v1alpha1"
REQUIRED_INSTALL_CHECKS = {
    "apply-engine",
    "apply:preflight",
    "apply:directories",
    "apply:manifest",
    "apply:tun",
    "apply:bypass-route",
    "apply:nftables",
}
REQUIRED_UNINSTALL_CHECKS = {
    "uninstall-engine",
    "uninstall:manifest",
    "uninstall:nft-dropin",
    "uninstall:bypass-route",
    "uninstall:tun",
    "uninstall:state",
}
REQUIRED_INSTALL_PRESENT = {
    "nft-dropin",
    "nft-table",
    "tun",
    "route-table",
    "runtime-dir",
    "state-dir",
}
REQUIRED_STAGE_NAMES = {
    "run-acceptance",
    "collect-install-report",
    "collect-uninstall-report",
    "cleanup-guest-files",
}
COUNT_KEYS = [
    "installReports",
    "uninstallReports",
    "stageReports",
    "summaryInstallPassed",
    "summaryUninstallPassed",
    "installChecks",
    "installPassedChecks",
    "installFailedChecks",
    "installRequiredPassed",
    "uninstallChecks",
    "uninstallPassedChecks",
    "uninstallFailedChecks",
    "uninstallRequiredPassed",
    "installResources",
    "installOwnedResources",
    "installPresentResources",
    "installRequiredPresent",
    "uninstallResources",
    "uninstallOwnedResources",
    "uninstallPresentResources",
    "uninstallRequiredAbsent",
    "stageCount",
    "stagePassed",
    "stageFailed",
    "stageRequiredPassed",
    "diagnostics",
]


def command_takeover_lifecycle_surface(_lab: Lab, args: argparse.Namespace) -> None:
    label = validate_name(args.label or "takeover-lifecycle-surface", "label")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = build_takeover_lifecycle_summary(
        label,
        output_dir,
        [Path(item) for item in args.input],
    )
    write_takeover_lifecycle_summary(output_dir, summary)
    print(json.dumps(takeover_lifecycle_print(output_dir, summary), sort_keys=True))


def build_takeover_lifecycle_summary(
    label: str,
    output_dir: Path,
    inputs: list[Path],
) -> dict[str, Any]:
    rows = [takeover_lifecycle_row(path) for path in expand_inputs(inputs)]
    totals = takeover_lifecycle_totals(rows)
    return {
        "schema": TAKEOVER_LIFECYCLE_SCHEMA,
        "label": label,
        "outputDir": str(output_dir),
        "runs": rows,
        "totals": totals,
        "conclusion": takeover_lifecycle_conclusion(totals),
        "policy": {
            "plannerPenaltySafe": False,
            "qualityPenaltySafe": False,
            "reason": "Takeover lifecycle evidence is platform execution proof, not penalty proof.",
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


def takeover_lifecycle_row(run_dir: Path) -> dict[str, Any]:
    current = takeover_lifecycle_counts(run_dir)
    clean = takeover_lifecycle_clean(current)
    summary = load_optional_json(run_dir / "summary.json")
    return {
        "label": summary.get("label") or run_dir.name,
        "path": str(run_dir),
        "classification": "clean" if clean else takeover_lifecycle_classification(current),
        "clean": clean,
        "current": current,
    }


def takeover_lifecycle_counts(run_dir: Path) -> dict[str, Any]:
    summary = load_optional_json(run_dir / "summary.json")
    install = load_optional_json(run_dir / "install-report.json")
    uninstall = load_optional_json(run_dir / "uninstall-report.json")
    stage = load_optional_json(run_dir / "stage-report.json")
    install_checks = check_names(install)
    uninstall_checks = check_names(uninstall)
    stage_rows = stage.get("stages", []) if isinstance(stage.get("stages"), list) else []
    install_kinds = resource_kinds(install)
    uninstall_kinds = resource_kinds(uninstall)
    return {
        "installReports": 1 if install else 0,
        "uninstallReports": 1 if uninstall else 0,
        "stageReports": 1 if stage else 0,
        "summaryInstallPassed": 1 if summary_check_passed(summary, "install-apply") else 0,
        "summaryUninstallPassed": 1 if summary_check_passed(summary, "uninstall-cleanup") else 0,
        **check_counts("install", install_checks, REQUIRED_INSTALL_CHECKS),
        **check_counts("uninstall", uninstall_checks, REQUIRED_UNINSTALL_CHECKS),
        **resource_counts("install", install_kinds, require_present=True),
        **resource_counts("uninstall", uninstall_kinds, require_present=False),
        **stage_counts(stage_rows),
        "diagnostics": diagnostics_count(install) + diagnostics_count(uninstall),
        "failedInstallChecks": failed_checks(install_checks),
        "failedUninstallChecks": failed_checks(uninstall_checks),
        "installResourceKinds": aggregate(install_kinds.keys()),
        "uninstallResourceKinds": aggregate(uninstall_kinds.keys()),
        "stageNames": aggregate(stage_name(row) for row in stage_rows),
    }


def takeover_lifecycle_clean(counts: dict[str, Any]) -> bool:
    return (
        counts["installReports"] == 1
        and counts["uninstallReports"] == 1
        and counts["stageReports"] == 1
        and counts["summaryInstallPassed"] == 1
        and counts["summaryUninstallPassed"] == 1
        and counts["installFailedChecks"] == 0
        and counts["installRequiredPassed"] == len(REQUIRED_INSTALL_CHECKS)
        and counts["uninstallFailedChecks"] == 0
        and counts["uninstallRequiredPassed"] == len(REQUIRED_UNINSTALL_CHECKS)
        and counts["installRequiredPresent"] == len(REQUIRED_INSTALL_PRESENT)
        and counts["uninstallPresentResources"] == 0
        and counts["stageRequiredPassed"] == len(REQUIRED_STAGE_NAMES)
        and counts["stageFailed"] == 0
        and counts["diagnostics"] == 0
    )


def takeover_lifecycle_classification(counts: dict[str, Any]) -> str:
    if counts["installReports"] == 0 or counts["uninstallReports"] == 0:
        return "lifecycle-report-missing"
    if counts["summaryInstallPassed"] == 0 or counts["summaryUninstallPassed"] == 0:
        return "summary-lifecycle-check-failed"
    if counts["installFailedChecks"] or counts["installRequiredPassed"] < len(REQUIRED_INSTALL_CHECKS):
        return "install-apply-incomplete"
    if counts["uninstallFailedChecks"] or counts["uninstallRequiredPassed"] < len(REQUIRED_UNINSTALL_CHECKS):
        return "uninstall-cleanup-incomplete"
    if counts["installRequiredPresent"] < len(REQUIRED_INSTALL_PRESENT):
        return "install-resource-missing"
    if counts["uninstallPresentResources"]:
        return "cleanup-resource-present"
    if counts["stageFailed"] or counts["stageRequiredPassed"] < len(REQUIRED_STAGE_NAMES):
        return "lifecycle-stage-incomplete"
    if counts["diagnostics"]:
        return "lifecycle-diagnostics-present"
    return "takeover-lifecycle-incomplete"


def takeover_lifecycle_totals(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "runs": len(rows),
        "cleanRuns": sum(1 for row in rows if row["clean"]),
        "failedRuns": sum(1 for row in rows if not row["clean"]),
        "classifications": aggregate(row["classification"] for row in rows),
        **{
            key: sum(int(row["current"].get(key) or 0) for row in rows)
            for key in COUNT_KEYS
        },
        "failedInstallChecks": merge_count_rows(
            row["current"]["failedInstallChecks"] for row in rows
        ),
        "failedUninstallChecks": merge_count_rows(
            row["current"]["failedUninstallChecks"] for row in rows
        ),
        "installResourceKinds": merge_count_rows(
            row["current"]["installResourceKinds"] for row in rows
        ),
        "uninstallResourceKinds": merge_count_rows(
            row["current"]["uninstallResourceKinds"] for row in rows
        ),
        "stageNames": merge_count_rows(row["current"]["stageNames"] for row in rows),
    }


def takeover_lifecycle_conclusion(totals: dict[str, Any]) -> dict[str, Any]:
    clean = totals["runs"] > 0 and totals["failedRuns"] == 0
    return {
        "status": "clean" if clean else "takeover-lifecycle-surface-needs-evidence",
        "nextAction": "return-to-runtime-surface" if clean else "inspect-takeover-lifecycle",
        "plannerPenaltySafe": False,
        "qualityPenaltySafe": False,
    }


def write_takeover_lifecycle_summary(output_dir: Path, summary: dict[str, Any]) -> None:
    (output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n"
    )
    write_takeover_lifecycle_markdown(output_dir / "summary.md", summary)


def write_takeover_lifecycle_markdown(path: Path, summary: dict[str, Any]) -> None:
    totals = summary["totals"]
    lines = [
        "# VM Private Runtime Takeover Lifecycle Surface",
        "",
        f"- label: `{summary['label']}`",
        f"- status: `{summary['conclusion']['status']}`",
        f"- runs: `{totals['runs']}`",
        f"- clean runs: `{totals['cleanRuns']}`",
        f"- install reports: `{totals['installReports']}`",
        f"- uninstall reports: `{totals['uninstallReports']}`",
        f"- install required passed: `{totals['installRequiredPassed']}`",
        f"- uninstall required passed: `{totals['uninstallRequiredPassed']}`",
        f"- cleanup present resources: `{totals['uninstallPresentResources']}`",
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


def takeover_lifecycle_print(output_dir: Path, summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "outputDir": str(output_dir),
        "runs": summary["totals"]["runs"],
        "cleanRuns": summary["totals"]["cleanRuns"],
        "status": summary["conclusion"]["status"],
    }


def check_names(report: dict[str, Any]) -> dict[str, str]:
    return {
        str(item.get("name") or ""): str(item.get("status") or "")
        for item in report.get("checks", [])
        if isinstance(item, dict) and item.get("name")
    }


def check_counts(prefix: str, checks: dict[str, str], required: set[str]) -> dict[str, int]:
    return {
        f"{prefix}Checks": len(checks),
        f"{prefix}PassedChecks": sum(1 for status in checks.values() if status == "pass"),
        f"{prefix}FailedChecks": sum(1 for status in checks.values() if status != "pass"),
        f"{prefix}RequiredPassed": sum(1 for name in required if checks.get(name) == "pass"),
    }


def resource_kinds(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for item in report.get("resources", []):
        if isinstance(item, dict) and item.get("kind"):
            rows[str(item["kind"])] = item
    return rows


def resource_counts(
    prefix: str,
    rows: dict[str, dict[str, Any]],
    require_present: bool,
) -> dict[str, int]:
    required = REQUIRED_INSTALL_PRESENT
    return {
        f"{prefix}Resources": len(rows),
        f"{prefix}OwnedResources": sum(1 for item in rows.values() if item.get("owned") is True),
        f"{prefix}PresentResources": sum(1 for item in rows.values() if item.get("present") is True),
        f"{prefix}RequiredPresent" if require_present else f"{prefix}RequiredAbsent": sum(
            1 for kind in required if bool((rows.get(kind) or {}).get("present")) is require_present
        ),
    }


def stage_counts(rows: list[Any]) -> dict[str, int]:
    stages = [row for row in rows if isinstance(row, dict)]
    return {
        "stageCount": len(stages),
        "stagePassed": sum(1 for row in stages if row.get("status") == "pass"),
        "stageFailed": sum(1 for row in stages if row.get("status") != "pass"),
        "stageRequiredPassed": sum(
            1
            for name in REQUIRED_STAGE_NAMES
            if any(stage_name(row) == name and row.get("status") == "pass" for row in stages)
        ),
    }


def summary_check_passed(summary: dict[str, Any], name: str) -> bool:
    return any(
        isinstance(item, dict) and item.get("name") == name and item.get("passed") is True
        for item in summary.get("checks", [])
    )


def diagnostics_count(report: dict[str, Any]) -> int:
    diagnostics = report.get("diagnostics")
    return len(diagnostics) if isinstance(diagnostics, list) else 0


def failed_checks(checks: dict[str, str]) -> list[dict[str, Any]]:
    return aggregate(name for name, status in checks.items() if status != "pass")


def stage_name(row: Any) -> str:
    return str(row.get("name") or "unknown") if isinstance(row, dict) else "unknown"


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
