from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from common import Lab, validate_name
from private_runtime_lib.briefs import fields
from private_runtime_lib.reporting.workload_surface.event.failure import (
    classify_failure,
    failure_surface,
    is_failure_event,
    missing_evidence,
)


IMPACT_SCHEMA = "dynet-vm-private-runtime-failure-impact-surface/v1alpha1"
REPEAT_SCHEMA = "dynet-vm-private-runtime-repeat/v1alpha1"
COUNT_FIELDS = """
runs cleanRuns failedRuns eventReports runtimePass events failureSignals
classifiedSignals unknownSignals missingEvidenceSignals recoveredSignals
controlledSignals unboundedSignals nodeSuspectSignals recoveredNodeSuspectSignals
maskedNodeSuspectSignals unboundedNodeSuspectSignals experimentShapeSignals
unboundedExperimentShapeSignals targetOrProbeSignals dynetInfraSignals
planSuspectSignals unsafePenaltySignals terminalFailureSignals
""".split()
BLOCKERS = """
unknownSignals missingEvidenceSignals unboundedNodeSuspectSignals
unboundedExperimentShapeSignals planSuspectSignals unsafePenaltySignals
""".split()


def command_failure_impact_surface(_lab: Lab, args: argparse.Namespace) -> None:
    label = validate_name(args.label or "failure-impact-surface", "label")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = build_failure_impact_summary(
        label,
        output_dir,
        [Path(item) for item in args.input],
    )
    write_failure_impact_summary(output_dir, summary)
    print(json.dumps(impact_print(output_dir, summary), sort_keys=True))


def build_failure_impact_summary(
    label: str,
    output_dir: Path,
    inputs: list[Path],
) -> dict[str, Any]:
    rows = [failure_impact_row(path) for path in expand_inputs(inputs)]
    totals = failure_impact_totals(rows)
    return {
        "schema": IMPACT_SCHEMA,
        "label": label,
        "outputDir": str(output_dir),
        "runs": rows,
        "totals": totals,
        "conclusion": failure_impact_conclusion(totals),
        "privacy": empty_privacy_flags(),
        "policy": {
            "plannerPenaltySafe": False,
            "qualityPenaltySafe": False,
            "reason": "Failure impact is observability proof, not penalty proof.",
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


def failure_impact_row(run_dir: Path) -> dict[str, Any]:
    summary = load_optional_json(run_dir / "summary.json")
    current = failure_impact_counts(load_optional_json(run_dir / "runtime-report.json"))
    clean = failure_impact_clean(current)
    return {
        "label": summary.get("label") or run_dir.name,
        "path": str(run_dir),
        "classification": "clean" if clean else failure_impact_classification(current),
        "clean": clean,
        "current": current,
    }


def failure_impact_counts(report: dict[str, Any]) -> dict[str, Any]:
    raw_events = report.get("events")
    events = event_rows(raw_events or [])
    impacted = [failure_record(event) for event in events if is_failure_event(event["raw"])]
    for record in impacted:
        record["impact"] = signal_impact(record, events, impacted)
    return {
        "eventReports": 1 if raw_events is not None else 0,
        "runtimePass": 1 if report.get("status") == "pass" else 0,
        "events": len(events),
        "failureSignals": len(impacted),
        "classifiedSignals": sum(1 for row in impacted if row["category"] != "unknown"),
        "unknownSignals": sum(1 for row in impacted if row["category"] == "unknown"),
        "missingEvidenceSignals": sum(1 for row in impacted if row["missingEvidence"]),
        **impact_counts(impacted),
        **category_impact_counts(impacted),
        "categories": aggregate(row["category"] for row in impacted),
        "surfaces": aggregate(row["surface"] for row in impacted),
        "impacts": aggregate(row["impact"] for row in impacted),
        "missingEvidence": aggregate(item for row in impacted for item in row["missingEvidence"]),
    }


def event_rows(raw_events: list[Any]) -> list[dict[str, Any]]:
    rows = []
    for index, event in enumerate(raw_events):
        if not isinstance(event, dict):
            continue
        event_fields = fields(event)
        rows.append({
            "index": index,
            "kind": str(event.get("kind") or ""),
            "key": event_fields.get("flowId") or event_fields.get("dnsQueryId") or "",
            "raw": event,
        })
    return rows


def failure_record(event: dict[str, Any]) -> dict[str, Any]:
    event_fields = fields(event["raw"])
    surface = failure_surface(event["kind"])
    return {
        "index": event["index"],
        "key": event["key"],
        "surface": surface,
        "category": classify_failure(surface, event_fields),
        "missingEvidence": missing_evidence(surface, event_fields),
    }


def signal_impact(
    record: dict[str, Any],
    events: list[dict[str, Any]],
    records: list[dict[str, Any]],
) -> str:
    if record["surface"] == "ip-denial":
        return "controlled-denial"
    if has_later(events, record, success_kinds()):
        return "recovered"
    if (
        record["category"] == "node-suspect"
        and has_later_category(record, records, {"target-or-probe-suspect", "dynet-infra-suspect"})
    ):
        return "masked-by-controlled-terminal"
    if record["category"] == "target-or-probe-suspect":
        return "controlled-target-or-probe"
    if record["category"] == "dynet-infra-suspect":
        return "controlled-dynet-infra"
    if record["category"] == "experiment-shape-suspect":
        return "controlled-experiment"
    if has_later(events, record, terminal_failure_kinds()):
        return "terminal-failure"
    return "unbounded"


def has_later(
    events: list[dict[str, Any]],
    record: dict[str, Any],
    kinds: set[str],
) -> bool:
    return any(
        event["key"]
        and event["key"] == record["key"]
        and event["index"] > record["index"]
        and event["kind"] in kinds
        for event in events
    )


def has_later_category(
    record: dict[str, Any],
    records: list[dict[str, Any]],
    categories: set[str],
) -> bool:
    return any(
        row["key"]
        and row["key"] == record["key"]
        and row["index"] > record["index"]
        and row["category"] in categories
        for row in records
    )


def success_kinds() -> set[str]:
    return {"tcp-session-established", "udp-session-established", "dns-resolve-completed"}


def terminal_failure_kinds() -> set[str]:
    return {"tcp-session-failed", "udp-session-failed", "dns-resolve-failed"}


def impact_counts(signals: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "recoveredSignals": count_impact(signals, "recovered"),
        "controlledSignals": sum(
            1 for row in signals
            if str(row["impact"]).startswith("controlled-")
            or row["impact"] == "masked-by-controlled-terminal"
        ),
        "unboundedSignals": count_impact(signals, "unbounded"),
        "terminalFailureSignals": count_impact(signals, "terminal-failure"),
    }


def category_impact_counts(signals: list[dict[str, Any]]) -> dict[str, int]:
    node = [row for row in signals if row["category"] == "node-suspect"]
    experiment = [row for row in signals if row["category"] == "experiment-shape-suspect"]
    return {
        "nodeSuspectSignals": len(node),
        "recoveredNodeSuspectSignals": count_impact(node, "recovered"),
        "maskedNodeSuspectSignals": count_impact(node, "masked-by-controlled-terminal"),
        "unboundedNodeSuspectSignals": count_bad_impacts(
            node,
            {"recovered", "masked-by-controlled-terminal"},
        ),
        "experimentShapeSignals": len(experiment),
        "unboundedExperimentShapeSignals": count_bad_impacts(
            experiment,
            {"recovered", "controlled-experiment"},
        ),
        "targetOrProbeSignals": count_category(signals, "target-or-probe-suspect"),
        "dynetInfraSignals": count_category(signals, "dynet-infra-suspect"),
        "planSuspectSignals": count_category(signals, "plan-suspect"),
        "unsafePenaltySignals": unsafe_penalty_signals(signals),
    }


def unsafe_penalty_signals(signals: list[dict[str, Any]]) -> int:
    return sum(
        1 for row in signals
        if row["category"] == "plan-suspect"
        or (
            row["category"] == "node-suspect"
            and row["impact"] not in {"recovered", "masked-by-controlled-terminal"}
        )
    )


def count_bad_impacts(signals: list[dict[str, Any]], allowed: set[str]) -> int:
    return sum(1 for row in signals if row["impact"] not in allowed)


def count_impact(signals: list[dict[str, Any]], impact: str) -> int:
    return sum(1 for row in signals if row["impact"] == impact)


def count_category(signals: list[dict[str, Any]], category: str) -> int:
    return sum(1 for row in signals if row["category"] == category)


def failure_impact_clean(counts: dict[str, Any]) -> bool:
    return (
        counts["eventReports"] == 1
        and counts["runtimePass"] == 1
        and all(int(counts[key]) == 0 for key in BLOCKERS)
    )


def failure_impact_classification(counts: dict[str, Any]) -> str:
    if int(counts["unknownSignals"]):
        return "unknown-failure-impact"
    if int(counts["missingEvidenceSignals"]):
        return "failure-impact-evidence-missing"
    if int(counts["unsafePenaltySignals"]):
        return "unsafe-penalty-impact"
    return "failure-impact-incomplete"


def failure_impact_totals(rows: list[dict[str, Any]]) -> dict[str, Any]:
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
        "categories": merge_count_rows(row["current"]["categories"] for row in rows),
        "surfaces": merge_count_rows(row["current"]["surfaces"] for row in rows),
        "impacts": merge_count_rows(row["current"]["impacts"] for row in rows),
        "missingEvidence": merge_count_rows(row["current"]["missingEvidence"] for row in rows),
    }


def failure_impact_conclusion(totals: dict[str, Any]) -> dict[str, Any]:
    clean = totals["runs"] > 0 and totals["failedRuns"] == 0 and totals["failureSignals"] > 0
    return {
        "status": "clean" if clean else "failure-impact-needs-evidence",
        "nextAction": "return-to-runtime-surface" if clean else "inspect-unbounded-failure-impact",
        "plannerPenaltySafe": False,
        "qualityPenaltySafe": False,
    }


def write_failure_impact_summary(output_dir: Path, summary: dict[str, Any]) -> None:
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    write_failure_impact_markdown(output_dir / "summary.md", summary)


def write_failure_impact_markdown(path: Path, summary: dict[str, Any]) -> None:
    totals = summary["totals"]
    lines = [
        "# VM Private Runtime Failure Impact Surface",
        "",
        f"- label: `{summary['label']}`",
        f"- status: `{summary['conclusion']['status']}`",
        f"- runs: `{totals['runs']}`",
        f"- failure signals: `{totals['failureSignals']}`",
        f"- recovered signals: `{totals['recoveredSignals']}`",
        f"- controlled signals: `{totals['controlledSignals']}`",
        f"- unsafe penalty signals: `{totals['unsafePenaltySignals']}`",
        f"- impacts: `{totals['impacts']}`",
    ]
    path.write_text("\n".join(lines) + "\n")


def impact_print(output_dir: Path, summary: dict[str, Any]) -> dict[str, Any]:
    totals = summary["totals"]
    return {
        "outputDir": str(output_dir),
        "status": summary["conclusion"]["status"],
        "runs": totals["runs"],
        "failureSignals": totals["failureSignals"],
        "unsafePenaltySignals": totals["unsafePenaltySignals"],
    }


def aggregate(values: Any) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for value in values:
        key = str(value or "unknown")
        counts[key] = counts.get(key, 0) + 1
    return count_rows(counts)


def merge_count_rows(groups: Any) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for group in groups:
        for row in group:
            key = str(row.get("key") or "unknown")
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
