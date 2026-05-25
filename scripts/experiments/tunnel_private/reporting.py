from __future__ import annotations

from pathlib import Path
from typing import Any


def fields(event: dict[str, Any]) -> dict[str, str]:
    value = event.get("fields", {})
    if not isinstance(value, dict):
        return {}
    return {str(key): str(item) for key, item in value.items()}


def bound_selected(report: dict[str, Any]) -> str | None:
    for event in report.get("events", []):
        event_fields = fields(event)
        if event.get("kind") == "dialer-cascade-selected":
            return event_fields.get("boundSelected")
    return None


def final_bound_selected(report: dict[str, Any]) -> str | None:
    for event in report.get("events", []):
        event_fields = fields(event)
        if (
            event.get("kind") == "dialer-cascade-attempt-finished"
            and event_fields.get("status") == "success"
        ):
            return event_fields.get("boundSelected")
    return bound_selected(report)


def failed_stage(report: dict[str, Any]) -> str | None:
    for event in report.get("events", []):
        event_fields = fields(event)
        if event.get("kind") == "outbound-stage-finished" and event_fields.get("status") == "failed":
            outbound = event_fields.get("outbound", "<unknown>")
            stage = event_fields.get("stage", "unknown")
            return f"{outbound}:{stage}"
    return None


def cascade_attempts(report: dict[str, Any]) -> list[dict[str, str]]:
    attempts = []
    for event in report.get("events", []):
        if event.get("kind") != "dialer-cascade-attempt-finished":
            continue
        event_fields = fields(event)
        attempts.append(
            {
                key: value
                for key, value in {
                    "attempt": event_fields.get("attempt"),
                    "boundSelected": event_fields.get("boundSelected"),
                    "status": event_fields.get("status"),
                    "errorType": event_fields.get("errorType"),
                    "elapsedMs": event_fields.get("elapsedMs"),
                }.items()
                if value is not None
            }
        )
    return attempts


def failure_scope(report: dict[str, Any]) -> str:
    if report.get("status") == "pass":
        return "none"
    failed = failed_stage_rows(report)
    bounds = {item.get("boundSelected") for item in cascade_attempts(report)}
    if bounds and any(item.get("outbound") in bounds for item in failed):
        return "bound"
    if bounds and failed:
        return "downstream"
    if failed:
        return "direct"
    return "unknown"


def failed_stage_rows(report: dict[str, Any]) -> list[dict[str, str]]:
    rows = []
    for event in report.get("events", []):
        event_fields = fields(event)
        if event.get("kind") == "outbound-stage-finished" and event_fields.get("status") == "failed":
            rows.append({
                "outbound": event_fields.get("outbound", "<unknown>"),
                "stage": event_fields.get("stage", "unknown"),
            })
    return rows


def write_markdown(path: Path, summary: dict[str, Any]) -> None:
    lines = [
        "# Tunnel Private Probe Run",
        "",
        f"- target: `{summary['targetUrl']}`",
        f"- attempted: `{summary['totals']['attempted']}`",
        f"- passed: `{summary['totals']['passed']}`",
        f"- failed: `{summary['totals']['failed']}`",
        "",
        "## Reports",
        "",
    ]
    for item in summary["reports"]:
        lines.append(
            f"- `{item['tag']}` attempt={item['attempt']} status=`{item['status']}` "
            f"bound=`{item['boundSelected']}` failedStage=`{item['failedStage']}`"
        )
    path.write_text("\n".join(lines) + "\n")


def write_plan_markdown(path: Path, summary: dict[str, Any]) -> None:
    report = summary["report"]
    lines = [
        "# Tunnel Private Plan Probe Run",
        "",
        f"- target: `{summary['targetUrl']}`",
        f"- status: `{report['status']}`",
        f"- boundSelected: `{report['boundSelected']}`",
        f"- failedStage: `{report['failedStage']}`",
        f"- failureScope: `{report.get('failureScope')}`",
        f"- reason: `{report['reason']}`",
        "",
        "## Cascade Attempts",
        "",
    ]
    for item in report["cascadeAttempts"]:
        lines.append(
            f"- attempt=`{item.get('attempt')}` bound=`{item.get('boundSelected')}` "
            f"status=`{item.get('status')}` errorType=`{item.get('errorType')}` "
            f"elapsedMs=`{item.get('elapsedMs')}`"
        )
    path.write_text("\n".join(lines) + "\n")


def write_observer_markdown(path: Path, summary: dict[str, Any]) -> None:
    lines = [
        "# Tunnel Private Target Observer",
        "",
        f"- cases: `{summary['totals']['cases']}`",
        f"- observerConnections: `{summary['totals']['observerConnections']}`",
        f"- observerReceivedConnections: `{summary['totals']['observerReceivedConnections']}`",
        f"- observerSentConnections: `{summary['totals']['observerSentConnections']}`",
        "",
        "## Cases",
        "",
    ]
    for item in summary["cases"]:
        signals = item["signals"]
        probe = item["probe"]
        lines.append(
            f"- `{item['label']}` status=`{probe['status']}` "
            f"failedStage=`{probe['failedStage']}` "
            f"received=`{signals['receivedConnections']}` "
            f"sent=`{signals['sentConnections']}`"
        )
    path.write_text("\n".join(lines) + "\n")


def write_owned_private_markdown(path: Path, summary: dict[str, Any]) -> None:
    lines = [
        "# Tunnel Private Owned Private",
        "",
        f"- cases: `{summary['totals']['cases']}`",
        f"- privateConnections: `{summary['totals']['privateConnections']}`",
        f"- privateDecodedConnections: `{summary['totals']['privateDecodedConnections']}`",
        f"- targetConnections: `{summary['totals']['targetConnections']}`",
        "",
        "## Cases",
        "",
    ]
    for item in summary["cases"]:
        signals = item["signals"]
        probe = item["probe"]
        lines.append(
            f"- `{item['label']}` status=`{probe['status']}` "
            f"failedStage=`{probe['failedStage']}` "
            f"privateDecoded=`{signals['privateDecodedConnections']}` "
            f"target=`{signals['targetConnections']}`"
        )
    path.write_text("\n".join(lines) + "\n")
