from __future__ import annotations

import argparse
import json
from typing import Any


def parse(stdout: str) -> dict[str, Any]:
    try:
        report = json.loads(stdout)
    except json.JSONDecodeError as error:
        return invalid_report(f"failed to parse dynet probe JSON: {error}")
    return report if isinstance(report, dict) else invalid_report(
        "dynet probe JSON root was not an object"
    )


def invalid_report(reason: str) -> dict[str, Any]:
    return {
        "schema": "dynet-probe/invalid-output",
        "status": "deny",
        "reason": reason,
        "events": [],
    }


def selected_outbound(report: dict[str, Any]) -> str | None:
    for event in report.get("events", []):
        if event.get("kind") == "outbound-graph-selected":
            return fields(event).get("selected")
    for event in report.get("events", []):
        if event.get("kind") == "route-matched":
            return fields(event).get("outbound")
    return None


def bound_selected_outbound(report: dict[str, Any]) -> str | None:
    for event in report.get("events", []):
        if event.get("kind") != "outbound-graph-selected":
            continue
        event_fields = fields(event)
        if event_fields.get("scope") == "dialer-bound":
            return event_fields.get("selected")
    return None


def failed_stage(report: dict[str, Any]) -> str | None:
    for event in report.get("events", []):
        event_fields = fields(event)
        if event.get("kind") == "outbound-stage-finished" and event_fields.get("status") == "failed":
            return event_fields.get("stage")
    return None


def latest_attempt_fields(report: dict[str, Any]) -> dict[str, str]:
    for event in reversed(report.get("events", [])):
        if event.get("kind") == "probe-attempt-finished":
            return fields(event)
    return {}


def fields(event: dict[str, Any]) -> dict[str, str]:
    raw = event.get("fields", {})
    if not isinstance(raw, dict):
        return {}
    return {str(key): str(value) for key, value in raw.items()}


def expected_selected_outbound(row: dict[str, Any]) -> str | None:
    summary = row.get("dynetSummary", {})
    if isinstance(summary, dict) and summary.get("selectedOutbound"):
        return str(summary["selectedOutbound"])
    value = row.get("selectedOutbound")
    return str(value) if value else None


def selected_outbound_matches(expected: str | None, actual: str | None) -> bool:
    return expected is None or actual == expected


def safe_name(value: str) -> str:
    return "".join(char if char.isalnum() or char in ".-" else "_" for char in value)[:80]


def positive_int(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def non_negative_int(value: str) -> int:
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError("must be non-negative")
    return number
