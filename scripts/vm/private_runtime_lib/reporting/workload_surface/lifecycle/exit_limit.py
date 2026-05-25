from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from common import Lab, validate_name


EXIT_LIMIT_SCHEMA = "dynet-vm-private-runtime-exit-limit-surface/v1alpha1"
REPEAT_SCHEMA = "dynet-vm-private-runtime-repeat/v1alpha1"
COUNT_KEYS = [
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


def command_exit_limit_surface(_lab: Lab, args: argparse.Namespace) -> None:
    label = validate_name(args.label or "exit-limit-surface", "label")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = build_exit_limit_summary(
        label,
        output_dir,
        [Path(item) for item in args.input],
    )
    write_exit_limit_summary(output_dir, summary)
    print(json.dumps(exit_limit_print(output_dir, summary), sort_keys=True))


def build_exit_limit_summary(
    label: str,
    output_dir: Path,
    inputs: list[Path],
) -> dict[str, Any]:
    rows = [exit_limit_row(path) for path in expand_inputs(inputs)]
    totals = exit_limit_totals(rows)
    return {
        "schema": EXIT_LIMIT_SCHEMA,
        "label": label,
        "outputDir": str(output_dir),
        "runs": rows,
        "totals": totals,
        "conclusion": exit_limit_conclusion(totals),
        "policy": {
            "plannerPenaltySafe": False,
            "qualityPenaltySafe": False,
            "reason": "Exit-limit evidence is runtime lifecycle proof, not penalty proof.",
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


def exit_limit_row(run_dir: Path) -> dict[str, Any]:
    summary = load_summary(run_dir)
    current = exit_limit_counts(summary)
    clean = exit_limit_clean(current)
    return {
        "label": summary.get("label") or run_dir.name,
        "path": str(run_dir),
        "classification": "clean" if clean else exit_limit_classification(current),
        "clean": clean,
        "current": current,
    }


def load_summary(run_dir: Path) -> dict[str, Any]:
    return load_optional_json(run_dir if run_dir.name == "summary.json" else run_dir / "summary.json")


def exit_limit_counts(summary: dict[str, Any]) -> dict[str, Any]:
    runtime = summary.get("runtime") if isinstance(summary.get("runtime"), dict) else {}
    tcp_expected = tcp_expected_terminals(summary)
    udp_received = int((summary.get("udpProbe") or {}).get("receivedBytes") or 0)
    diagnostic_limit = tcp_expected == 0 and udp_received == 0
    privacy = privacy_counts(summary)
    return {
        "commandExitZero": 1 if summary.get("commandExitCode") == 0 else 0,
        "runtimePass": 1 if runtime.get("status") == "pass" else 0,
        "runtimeLimitReason": 1 if runtime.get("reason") == "runtime limits reached" else 0,
        "failedChecks": int((summary.get("totals") or {}).get("failed") or 0),
        "tcpExpectedTerminalSessions": tcp_expected,
        "tcpClosedSessions": int(runtime.get("tcpClosedSessions") or 0),
        "tcpLimitRuns": 1 if tcp_expected > 0 else 0,
        "tcpLimitSatisfiedRuns": 1 if tcp_expected > 0 and int(runtime.get("tcpClosedSessions") or 0) >= tcp_expected else 0,
        "udpDownstreamLimitRuns": 1 if udp_received > 0 else 0,
        "udpDownstreamSatisfiedRuns": 1 if udp_received > 0 and int(runtime.get("udpDownstreamBytes") or 0) > 0 else 0,
        "diagnosticDnsTunLimitRuns": 1 if diagnostic_limit else 0,
        "diagnosticDnsTunSatisfiedRuns": 1 if diagnostic_limit and diagnostic_satisfied(runtime) else 0,
        "runtimeTimeoutReasons": 1 if "timeout" in str(runtime.get("reason") or "") else 0,
        **privacy,
        "limitEvidence": limit_evidence(runtime, tcp_expected, udp_received),
        "unsafeFlagNames": aggregate(privacy["unsafeFlagNames"]),
    }


def tcp_expected_terminals(summary: dict[str, Any]) -> int:
    tcp_results = (summary.get("tcpProbe") or {}).get("results")
    tcp_probe_count = len(tcp_results) if isinstance(tcp_results, list) else 0
    workload = summary.get("workloadProbe") or {}
    totals = workload.get("totals") if isinstance(workload, dict) else {}
    return tcp_probe_count + int((totals or {}).get("count") or 0)


def diagnostic_satisfied(runtime: dict[str, Any]) -> bool:
    return int(runtime.get("dnsQueries") or 0) > 0 and int(runtime.get("tunPackets") or 0) > 0


def limit_evidence(
    runtime: dict[str, Any],
    tcp_expected: int,
    udp_received: int,
) -> list[dict[str, Any]]:
    labels = []
    if tcp_expected > 0 and int(runtime.get("tcpClosedSessions") or 0) >= tcp_expected:
        labels.append("tcp-terminal-limit")
    if udp_received > 0 and int(runtime.get("udpDownstreamBytes") or 0) > 0:
        labels.append("udp-downstream-byte-limit")
    if tcp_expected == 0 and udp_received == 0 and diagnostic_satisfied(runtime):
        labels.append("diagnostic-dns-tun-limit")
    return aggregate(labels)


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


def exit_limit_clean(counts: dict[str, Any]) -> bool:
    return (
        counts["commandExitZero"] == 1
        and counts["runtimePass"] == 1
        and counts["runtimeLimitReason"] == 1
        and counts["failedChecks"] == 0
        and counts["runtimeTimeoutReasons"] == 0
        and counts["unsafePrivacyFlags"] == 0
        and evidence_satisfied(counts)
    )


def evidence_satisfied(counts: dict[str, Any]) -> bool:
    return bool(counts["limitEvidence"]) and (
        counts["tcpLimitRuns"] == counts["tcpLimitSatisfiedRuns"]
        and counts["udpDownstreamLimitRuns"] == counts["udpDownstreamSatisfiedRuns"]
        and counts["diagnosticDnsTunLimitRuns"] == counts["diagnosticDnsTunSatisfiedRuns"]
    )


def exit_limit_classification(counts: dict[str, Any]) -> str:
    if counts["commandExitZero"] == 0:
        return "command-exit-nonzero"
    if counts["runtimePass"] == 0:
        return "runtime-not-pass"
    if counts["runtimeLimitReason"] == 0:
        return "runtime-limit-reason-missing"
    if counts["failedChecks"]:
        return "failed-checks-present"
    if counts["unsafePrivacyFlags"]:
        return "unsafe-privacy-flag"
    if not counts["limitEvidence"]:
        return "limit-evidence-missing"
    if not evidence_satisfied(counts):
        return "limit-counter-unsatisfied"
    return "exit-limit-incomplete"


def exit_limit_totals(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "runs": len(rows),
        "cleanRuns": sum(1 for row in rows if row["clean"]),
        "failedRuns": sum(1 for row in rows if not row["clean"]),
        "classifications": aggregate(row["classification"] for row in rows),
        **{
            key: sum(int(row["current"].get(key) or 0) for row in rows)
            for key in COUNT_KEYS
        },
        "limitEvidence": merge_count_rows(row["current"]["limitEvidence"] for row in rows),
        "unsafeFlagNames": merge_count_rows(row["current"]["unsafeFlagNames"] for row in rows),
    }


def exit_limit_conclusion(totals: dict[str, Any]) -> dict[str, Any]:
    clean = totals["runs"] > 0 and totals["failedRuns"] == 0
    return {
        "status": "clean" if clean else "exit-limit-surface-needs-evidence",
        "nextAction": "return-to-runtime-surface" if clean else "inspect-runtime-exit-limits",
        "plannerPenaltySafe": False,
        "qualityPenaltySafe": False,
    }


def write_exit_limit_summary(output_dir: Path, summary: dict[str, Any]) -> None:
    (output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n"
    )
    write_exit_limit_markdown(output_dir / "summary.md", summary)


def write_exit_limit_markdown(path: Path, summary: dict[str, Any]) -> None:
    totals = summary["totals"]
    lines = [
        "# VM Private Runtime Exit Limit Surface",
        "",
        f"- label: `{summary['label']}`",
        f"- status: `{summary['conclusion']['status']}`",
        f"- runs: `{totals['runs']}`",
        f"- clean runs: `{totals['cleanRuns']}`",
        f"- command exit zero: `{totals['commandExitZero']}`",
        f"- runtime limit reason: `{totals['runtimeLimitReason']}`",
        f"- TCP expected terminal sessions: `{totals['tcpExpectedTerminalSessions']}`",
        f"- TCP closed sessions: `{totals['tcpClosedSessions']}`",
        f"- UDP downstream limit runs: `{totals['udpDownstreamLimitRuns']}`",
        f"- diagnostic DNS/TUN limit runs: `{totals['diagnosticDnsTunLimitRuns']}`",
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


def exit_limit_print(output_dir: Path, summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "outputDir": str(output_dir),
        "runs": summary["totals"]["runs"],
        "cleanRuns": summary["totals"]["cleanRuns"],
        "status": summary["conclusion"]["status"],
    }


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
