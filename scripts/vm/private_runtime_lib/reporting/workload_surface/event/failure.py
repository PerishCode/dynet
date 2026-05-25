from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from common import Lab, validate_name
from private_runtime_lib.briefs import fields


FAILURE_SCHEMA = "dynet-vm-private-runtime-failure-attribution-surface/v1alpha1"
REPEAT_SCHEMA = "dynet-vm-private-runtime-repeat/v1alpha1"
FAILURE_KINDS = {
    "dns-resolve-failed",
    "ip-packet-denied",
    "tcp-session-failed",
    "udp-session-failed",
}
COUNT_FIELDS = """
runs cleanRuns failedRuns eventReports runtimePass events failureSignals
classifiedSignals unknownSignals missingEvidenceSignals stageFailures
attemptFailures cascadeFailures dnsFailures ipDenials tcpFailures udpFailures
nodeSuspect dynetInfraSuspect planSuspect targetOrProbeSuspect
experimentShapeSuspect unknown
""".split()
BLOCKERS = "unknownSignals missingEvidenceSignals unknown".split()


def command_failure_attribution_surface(_lab: Lab, args: argparse.Namespace) -> None:
    label = validate_name(args.label or "failure-attribution-surface", "label")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = build_failure_attribution_summary(
        label,
        output_dir,
        [Path(item) for item in args.input],
    )
    write_failure_attribution_summary(output_dir, summary)
    print(json.dumps(failure_print(output_dir, summary), sort_keys=True))


def build_failure_attribution_summary(
    label: str,
    output_dir: Path,
    inputs: list[Path],
) -> dict[str, Any]:
    rows = [failure_attribution_row(path) for path in expand_inputs(inputs)]
    totals = failure_attribution_totals(rows)
    return {
        "schema": FAILURE_SCHEMA,
        "label": label,
        "outputDir": str(output_dir),
        "runs": rows,
        "totals": totals,
        "conclusion": failure_conclusion(totals),
        "privacy": empty_privacy_flags(),
        "policy": {
            "plannerPenaltySafe": False,
            "qualityPenaltySafe": False,
            "reason": "Failure attribution is observability proof, not penalty proof.",
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


def failure_attribution_row(run_dir: Path) -> dict[str, Any]:
    summary = load_optional_json(run_dir / "summary.json")
    current = failure_counts(load_optional_json(run_dir / "runtime-report.json"))
    clean = failure_clean(current)
    return {
        "label": summary.get("label") or run_dir.name,
        "path": str(run_dir),
        "classification": "clean" if clean else failure_classification(current),
        "clean": clean,
        "current": current,
    }


def failure_counts(report: dict[str, Any]) -> dict[str, Any]:
    raw_events = report.get("events")
    signals = [
        failure_signal(event)
        for event in raw_events or []
        if isinstance(event, dict) and is_failure_event(event)
    ]
    categories = [signal["category"] for signal in signals]
    return {
        "eventReports": 1 if raw_events is not None else 0,
        "runtimePass": 1 if report.get("status") == "pass" else 0,
        "events": len([event for event in raw_events or [] if isinstance(event, dict)]),
        "failureSignals": len(signals),
        "classifiedSignals": sum(1 for signal in signals if signal["category"] != "unknown"),
        "unknownSignals": sum(1 for signal in signals if signal["category"] == "unknown"),
        "missingEvidenceSignals": sum(1 for signal in signals if signal["missingEvidence"]),
        **surface_counts(signals),
        **category_counts(categories),
        "categories": aggregate(categories),
        "surfaces": aggregate(signal["surface"] for signal in signals),
        "profiles": aggregate(signal["profile"] for signal in signals),
        "missingEvidence": aggregate(
            item for signal in signals for item in signal["missingEvidence"]
        ),
    }


def is_failure_event(event: dict[str, Any]) -> bool:
    event_fields = fields(event)
    return event.get("kind") in FAILURE_KINDS or event_fields.get("status") == "failed"


def failure_signal(event: dict[str, Any]) -> dict[str, Any]:
    event_fields = fields(event)
    surface = failure_surface(str(event.get("kind") or ""))
    profile = failure_profile(surface, event_fields)
    return {
        "surface": surface,
        "profile": profile,
        "category": classify_failure(surface, event_fields),
        "missingEvidence": missing_evidence(surface, event_fields),
    }


def failure_surface(kind: str) -> str:
    if kind == "outbound-stage-finished":
        return "stage"
    if kind == "outbound-attempt-finished":
        return "attempt"
    if kind == "dialer-cascade-attempt-finished":
        return "cascade"
    if kind == "dns-resolve-failed":
        return "dns"
    if kind == "ip-packet-denied":
        return "ip-denial"
    if kind == "tcp-session-failed":
        return "tcp"
    if kind == "udp-session-failed":
        return "udp"
    return "unknown"


def failure_profile(surface: str, event_fields: dict[str, str]) -> str:
    if surface == "cascade":
        scope = event_fields.get("failureScope") or "unknown"
        stop = event_fields.get("retryStopReason") or "unknown"
        return f"cascade:{scope}:{stop}"
    if surface == "dns":
        return f"dns:{event_fields.get('failureResponseCode') or 'unknown'}"
    if surface == "ip-denial":
        return f"ip:{event_fields.get('protocol') or 'unknown'}"
    adapter = event_fields.get("kind") or event_fields.get("errorType") or "unknown"
    stage = event_fields.get("stage") or event_fields.get("protocol") or "unknown"
    disposition = event_fields.get("errorDisposition") or "unknown"
    return f"{surface}:{adapter}:{stage}:{disposition}"


def classify_failure(surface: str, event_fields: dict[str, str]) -> str:
    disposition = event_fields.get("errorDisposition") or event_fields.get("failureStageDisposition") or ""
    if surface == "ip-denial":
        return "dynet-infra-suspect"
    if surface == "dns":
        return "target-or-probe-suspect"
    if surface == "cascade":
        return cascade_category(event_fields)
    if disposition == "connection-refused":
        return "experiment-shape-suspect"
    if disposition in {"pending-timeout", "reset"}:
        return "node-suspect"
    if disposition == "protocol-invalid":
        return "target-or-probe-suspect"
    return "unknown"


def cascade_category(event_fields: dict[str, str]) -> str:
    scope = event_fields.get("failureScope") or ""
    stop = event_fields.get("retryStopReason") or ""
    disposition = event_fields.get("failureStageDisposition") or event_fields.get("errorDisposition") or ""
    if scope == "bound" and stop == "bound-candidates-exhausted":
        return "experiment-shape-suspect"
    if scope == "bound" and disposition in {"pending-timeout", "reset"}:
        return "node-suspect"
    if scope and scope != "bound":
        return "target-or-probe-suspect"
    return "unknown"


def missing_evidence(surface: str, event_fields: dict[str, str]) -> list[str]:
    if surface == "cascade":
        return missing_fields(event_fields, [
            "failureScope",
            "retryAllowed",
            "retryStopReason",
            "failureStage",
            "failureStageKind",
            "failureStageDisposition",
            "failureStageErrorType",
        ])
    if surface == "dns":
        return missing_fields(event_fields, ["failureResponseCode", "errorDisposition"])
    if surface == "ip-denial":
        return missing_fields(event_fields, ["reason", "protocol"])
    if surface == "stage":
        return missing_fields(event_fields, ["kind", "stage", "errorDisposition", "errorType"])
    if surface == "attempt":
        return missing_fields(event_fields, ["kind", "protocol", "errorDisposition", "errorType"])
    return ["surface"]


def missing_fields(event_fields: dict[str, str], names: list[str]) -> list[str]:
    return [name for name in names if not event_fields.get(name)]


def surface_counts(signals: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "stageFailures": count_surface(signals, "stage"),
        "attemptFailures": count_surface(signals, "attempt"),
        "cascadeFailures": count_surface(signals, "cascade"),
        "dnsFailures": count_surface(signals, "dns"),
        "ipDenials": count_surface(signals, "ip-denial"),
        "tcpFailures": count_surface(signals, "tcp"),
        "udpFailures": count_surface(signals, "udp"),
    }


def category_counts(categories: list[str]) -> dict[str, int]:
    return {
        "nodeSuspect": categories.count("node-suspect"),
        "dynetInfraSuspect": categories.count("dynet-infra-suspect"),
        "planSuspect": categories.count("plan-suspect"),
        "targetOrProbeSuspect": categories.count("target-or-probe-suspect"),
        "experimentShapeSuspect": categories.count("experiment-shape-suspect"),
        "unknown": categories.count("unknown"),
    }


def count_surface(signals: list[dict[str, Any]], surface: str) -> int:
    return sum(1 for signal in signals if signal["surface"] == surface)


def failure_clean(counts: dict[str, Any]) -> bool:
    return (
        counts["eventReports"] == 1
        and counts["runtimePass"] == 1
        and all(int(counts[key]) == 0 for key in BLOCKERS)
    )


def failure_classification(counts: dict[str, Any]) -> str:
    if int(counts["eventReports"]) != 1:
        return "runtime-event-report-missing"
    if int(counts["runtimePass"]) != 1:
        return "runtime-not-pass"
    if int(counts["unknownSignals"]):
        return "unknown-failure-attribution"
    if int(counts["missingEvidenceSignals"]):
        return "failure-evidence-missing"
    return "failure-attribution-incomplete"


def failure_attribution_totals(rows: list[dict[str, Any]]) -> dict[str, Any]:
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
        "profiles": merge_count_rows(row["current"]["profiles"] for row in rows),
        "missingEvidence": merge_count_rows(row["current"]["missingEvidence"] for row in rows),
    }


def failure_conclusion(totals: dict[str, Any]) -> dict[str, Any]:
    clean = (
        totals["runs"] > 0
        and totals["failedRuns"] == 0
        and totals["failureSignals"] > 0
    )
    return {
        "status": "clean" if clean else "failure-attribution-needs-evidence",
        "nextAction": failure_next_action(clean, totals),
        "plannerPenaltySafe": False,
        "qualityPenaltySafe": False,
    }


def failure_next_action(clean: bool, totals: dict[str, Any]) -> str:
    if clean:
        return "return-to-runtime-surface"
    if totals["failureSignals"] == 0:
        return "collect-runtime-failure-signals"
    return "inspect-unknown-failure-signals"


def write_failure_attribution_summary(output_dir: Path, summary: dict[str, Any]) -> None:
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    write_failure_markdown(output_dir / "summary.md", summary)


def write_failure_markdown(path: Path, summary: dict[str, Any]) -> None:
    totals = summary["totals"]
    lines = [
        "# VM Private Runtime Failure Attribution Surface",
        "",
        f"- label: `{summary['label']}`",
        f"- status: `{summary['conclusion']['status']}`",
        f"- runs: `{totals['runs']}`",
        f"- clean runs: `{totals['cleanRuns']}`",
        f"- failure signals: `{totals['failureSignals']}`",
        f"- unknown signals: `{totals['unknownSignals']}`",
        f"- missing evidence signals: `{totals['missingEvidenceSignals']}`",
        f"- categories: `{totals['categories']}`",
        "",
        "## Runs",
        "",
    ]
    for row in summary["runs"]:
        current = row["current"]
        lines.append(
            f"- `{row['label']}` clean=`{row['clean']}` "
            f"classification=`{row['classification']}` "
            f"signals=`{current['failureSignals']}` unknown=`{current['unknownSignals']}`"
        )
    path.write_text("\n".join(lines) + "\n")


def failure_print(output_dir: Path, summary: dict[str, Any]) -> dict[str, Any]:
    totals = summary["totals"]
    return {
        "outputDir": str(output_dir),
        "status": summary["conclusion"]["status"],
        "runs": totals["runs"],
        "failureSignals": totals["failureSignals"],
        "unknownSignals": totals["unknownSignals"],
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
