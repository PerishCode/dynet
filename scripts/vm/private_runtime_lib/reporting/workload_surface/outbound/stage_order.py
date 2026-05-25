from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from common import Lab, validate_name
from private_runtime_lib.briefs import fields


STAGE_ORDER_SCHEMA = "dynet-vm-private-runtime-outbound-stage-order-surface/v1alpha1"
REPEAT_SCHEMA = "dynet-vm-private-runtime-repeat/v1alpha1"
PROFILES = {
    ("tcp-connect", "trojan"): ["payload-decode", "tcp-connect", "trojan-tls-handshake", "trojan-request-write"],
    ("tcp-connect", "vmess"): ["payload-decode", "tcp-connect"],
    ("tcp-connect", "direct"): ["tcp-connect"],
    ("udp-connect", "direct"): ["udp-connect"],
    ("dns-over-tcp", "dialer"): ["dialer-payload-decode"],
}
COUNT_FIELDS = """
runs cleanRuns failedRuns eventReports runtimePass events attempts
knownProfileAttempts unknownProfileAttempts successfulAttempts failedAttempts
stageEvents orderedAttempts attemptStageMissing unexpectedStageEvents
duplicateStageEvents stageOrderViolations stageAfterFailure failedStageEvents
""".split()
BLOCKERS = """
unknownProfileAttempts attemptStageMissing unexpectedStageEvents
stageOrderViolations stageAfterFailure
""".split()


def command_stage_order_surface(_lab: Lab, args: argparse.Namespace) -> None:
    label = validate_name(args.label or "stage-order-surface", "label")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = build_stage_order_summary(
        label,
        output_dir,
        [Path(item) for item in args.input],
    )
    write_stage_order_summary(output_dir, summary)
    print(json.dumps(stage_order_print(output_dir, summary), sort_keys=True))


def build_stage_order_summary(
    label: str,
    output_dir: Path,
    inputs: list[Path],
) -> dict[str, Any]:
    rows = [stage_order_row(path) for path in expand_inputs(inputs)]
    totals = stage_order_totals(rows)
    return {
        "schema": STAGE_ORDER_SCHEMA,
        "label": label,
        "outputDir": str(output_dir),
        "runs": rows,
        "totals": totals,
        "conclusion": stage_order_conclusion(totals),
        "privacy": empty_privacy_flags(),
        "policy": {
            "plannerPenaltySafe": False,
            "qualityPenaltySafe": False,
            "reason": "Outbound stage order is observability proof, not penalty proof.",
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


def stage_order_row(run_dir: Path) -> dict[str, Any]:
    summary = load_optional_json(run_dir / "summary.json")
    current = stage_order_counts(load_optional_json(run_dir / "runtime-report.json"))
    clean = stage_order_clean(current)
    return {
        "label": summary.get("label") or run_dir.name,
        "path": str(run_dir),
        "classification": "clean" if clean else stage_order_classification(current),
        "clean": clean,
        "current": current,
    }


def stage_order_counts(report: dict[str, Any]) -> dict[str, Any]:
    raw_events = report.get("events")
    rows = [
        event_row(event, index)
        for index, event in enumerate(raw_events or [])
        if isinstance(event, dict)
    ]
    attempts = [row for row in rows if row["kind"] == "outbound-attempt-finished"]
    stages = stage_index([row for row in rows if row["kind"] == "outbound-stage-finished"])
    checks = [attempt_order_check(row, stages.get(stage_key(row), [])) for row in attempts]
    return {
        "eventReports": 1 if raw_events is not None else 0,
        "runtimePass": 1 if report.get("status") == "pass" else 0,
        "events": len(rows),
        "attempts": len(attempts),
        "knownProfileAttempts": sum(1 for row in attempts if profile_key(row) in PROFILES),
        "unknownProfileAttempts": sum(1 for row in attempts if profile_key(row) not in PROFILES),
        "successfulAttempts": sum(1 for row in attempts if row["status"] == "success"),
        "failedAttempts": sum(1 for row in attempts if row["status"] == "failed"),
        "stageEvents": sum(len(row["stages"]) for row in checks),
        "orderedAttempts": sum(1 for row in checks if row["ordered"]),
        "attemptStageMissing": sum(1 for row in checks if not row["stages"]),
        "unexpectedStageEvents": sum(row["unexpected"] for row in checks),
        "duplicateStageEvents": sum(row["duplicate"] for row in checks),
        "stageOrderViolations": sum(row["orderViolations"] for row in checks),
        "stageAfterFailure": sum(row["afterFailure"] for row in checks),
        "failedStageEvents": sum(row["failedStages"] for row in checks),
        "attemptProfiles": aggregate(profile_label(row) for row in attempts),
        "stageSequences": aggregate(sequence_label(row) for row in checks),
    }


def event_row(event: dict[str, Any], index: int) -> dict[str, Any]:
    event_fields = fields(event)
    return {
        "index": index,
        "kind": str(event.get("kind") or ""),
        "reference": event_fields.get("flowId") or event_fields.get("dnsQueryId") or "",
        "outbound": event_fields.get("outbound") or "",
        "adapterKind": event_fields.get("kind") or "",
        "protocol": event_fields.get("protocol") or "",
        "stage": event_fields.get("stage") or "",
        "status": event_fields.get("status") or "",
        "attemptId": event_fields.get("attemptId") or "",
    }


def stage_index(stage_rows: list[dict[str, Any]]) -> dict[tuple[str, str, str, str], list[dict[str, Any]]]:
    result: dict[tuple[str, str, str, str], list[dict[str, Any]]] = {}
    for row in stage_rows:
        result.setdefault(stage_key(row), []).append(row)
    for rows in result.values():
        rows.sort(key=lambda item: item["index"])
    return result


def stage_key(row: dict[str, Any]) -> tuple[str, str, str, str]:
    return (row["reference"], row["outbound"], row["adapterKind"], row["attemptId"])


def attempt_order_check(
    attempt: dict[str, Any],
    stages: list[dict[str, Any]],
) -> dict[str, Any]:
    expected = PROFILES.get(profile_key(attempt), [])
    ranks = {stage: index for index, stage in enumerate(expected)}
    seen: dict[str, int] = {}
    order_violations = 0
    last_rank = -1
    first_failed = first_failed_index(stages)
    for row in stages:
        stage = row["stage"]
        seen[stage] = seen.get(stage, 0) + 1
        rank = ranks.get(stage)
        if rank is None:
            continue
        if rank < last_rank:
            order_violations += 1
        last_rank = max(last_rank, rank)
    return {
        "attempt": attempt,
        "stages": stages,
        "expected": expected,
        "ordered": bool(stages) and order_violations == 0,
        "unexpected": sum(1 for row in stages if row["stage"] not in ranks),
        "duplicate": sum(count - 1 for count in seen.values() if count > 1),
        "orderViolations": order_violations,
        "afterFailure": sum(1 for row in stages if first_failed is not None and row["index"] > first_failed),
        "failedStages": sum(1 for row in stages if row["status"] == "failed"),
    }


def first_failed_index(stages: list[dict[str, Any]]) -> int | None:
    for row in stages:
        if row["status"] == "failed":
            return int(row["index"])
    return None


def profile_key(row: dict[str, Any]) -> tuple[str, str]:
    return (row["protocol"], row["adapterKind"])


def profile_label(row: dict[str, Any]) -> str:
    protocol, adapter_kind = profile_key(row)
    return f"{protocol or 'unknown'}:{adapter_kind or 'unknown'}:{row['status'] or 'unknown'}"


def sequence_label(row: dict[str, Any]) -> str:
    attempt = row["attempt"]
    stages = ">".join(stage["stage"] or "unknown" for stage in row["stages"])
    return f"{profile_label(attempt)}:{stages or 'none'}"


def stage_order_clean(counts: dict[str, Any]) -> bool:
    return (
        counts["eventReports"] == 1
        and counts["runtimePass"] == 1
        and counts["attempts"] > 0
        and counts["stageEvents"] > 0
        and counts["orderedAttempts"] == counts["attempts"]
        and all(int(counts[key]) == 0 for key in BLOCKERS)
    )


def stage_order_classification(counts: dict[str, Any]) -> str:
    for key, label in [
        ("unknownProfileAttempts", "unknown-attempt-profile"),
        ("attemptStageMissing", "attempt-stage-missing"),
        ("unexpectedStageEvents", "unexpected-stage"),
        ("stageOrderViolations", "stage-order-violation"),
        ("stageAfterFailure", "stage-after-failure"),
    ]:
        if int(counts[key]):
            return label
    return "stage-order-surface-incomplete"


def stage_order_totals(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "runs": len(rows),
        "cleanRuns": sum(1 for row in rows if row["clean"]),
        "failedRuns": sum(1 for row in rows if not row["clean"]),
        "classifications": aggregate(row["classification"] for row in rows),
        **{
            key: sum(int(row["current"].get(key) or 0) for row in rows)
            for key in COUNT_FIELDS
            if key not in {"runs", "cleanRuns", "failedRuns"}
        },
        "attemptProfiles": merge_count_rows(row["current"]["attemptProfiles"] for row in rows),
        "stageSequences": merge_count_rows(row["current"]["stageSequences"] for row in rows),
    }


def stage_order_conclusion(totals: dict[str, Any]) -> dict[str, Any]:
    clean = totals["runs"] > 0 and totals["failedRuns"] == 0
    return {
        "status": "clean" if clean else "stage-order-surface-needs-evidence",
        "nextAction": "return-to-runtime-surface" if clean else "inspect-protocol-stage-order",
        "plannerPenaltySafe": False,
        "qualityPenaltySafe": False,
    }


def write_stage_order_summary(output_dir: Path, summary: dict[str, Any]) -> None:
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    totals = summary["totals"]
    lines = [
        "# VM Private Runtime Outbound Stage Order Surface",
        "",
        f"- label: `{summary['label']}`",
        f"- status: `{summary['conclusion']['status']}`",
        f"- attempts: `{totals['attempts']}`",
        f"- ordered attempts: `{totals['orderedAttempts']}`",
        f"- order violations: `{totals['stageOrderViolations']}`",
        f"- stage after failure: `{totals['stageAfterFailure']}`",
    ]
    (output_dir / "summary.md").write_text("\n".join(lines) + "\n")


def stage_order_print(output_dir: Path, summary: dict[str, Any]) -> dict[str, Any]:
    totals = summary["totals"]
    return {
        "outputDir": str(output_dir),
        "status": summary["conclusion"]["status"],
        "runs": totals["runs"],
        "attempts": totals["attempts"],
        "orderViolations": totals["stageOrderViolations"],
    }


def aggregate(values: Any) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for value in values:
        key = str(value or "none")
        counts[key] = counts.get(key, 0) + 1
    return count_rows(counts)


def merge_count_rows(groups: Any) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for group in groups:
        for row in group:
            key = str(row.get("key") or "none")
            counts[key] = counts.get(key, 0) + int(row.get("count") or 0)
    return count_rows(counts)


def count_rows(counts: dict[str, int]) -> list[dict[str, Any]]:
    return [{"key": key, "count": count} for key, count in sorted(counts.items())]


def empty_privacy_flags() -> dict[str, bool]:
    return {
        "rawLogsStored": False,
        "rawPacketsStored": False,
        "rawSecretsStored": False,
        "responseBodiesStored": False,
        "identityInformationSent": False,
    }


def load_optional_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text())
