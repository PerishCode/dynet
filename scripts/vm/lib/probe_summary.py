from __future__ import annotations


def fields(event: dict) -> dict[str, str]:
    value = event.get("fields", {})
    if not isinstance(value, dict):
        return {}
    return {str(key): str(item) for key, item in value.items()}


def final_bound_selected(report: dict) -> str | None:
    for event in report.get("events", []):
        event_fields = fields(event)
        if (
            event.get("kind") == "dialer-cascade-attempt-finished"
            and event_fields.get("status") == "success"
        ):
            return event_fields.get("boundSelected")
    for event in report.get("events", []):
        if event.get("kind") == "dialer-cascade-selected":
            return fields(event).get("boundSelected")
    return None


def failed_stage(report: dict) -> str | None:
    for event in report.get("events", []):
        event_fields = fields(event)
        if event.get("kind") == "outbound-stage-finished" and event_fields.get("status") == "failed":
            return f"{event_fields.get('outbound', '<unknown>')}:{event_fields.get('stage', 'unknown')}"
    return None


def failure_scope(report: dict) -> str:
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


def failed_stage_rows(report: dict) -> list[dict[str, str]]:
    rows = []
    for event in report.get("events", []):
        event_fields = fields(event)
        if event.get("kind") == "outbound-stage-finished" and event_fields.get("status") == "failed":
            rows.append({
                "outbound": event_fields.get("outbound", "<unknown>"),
                "stage": event_fields.get("stage", "unknown"),
            })
    return rows


def cascade_attempts(report: dict) -> list[dict[str, str]]:
    rows = []
    for event in report.get("events", []):
        if event.get("kind") != "dialer-cascade-attempt-finished":
            continue
        event_fields = fields(event)
        rows.append(
            {
                key: value
                for key, value in {
                    "attempt": event_fields.get("attempt"),
                    "boundSelected": event_fields.get("boundSelected"),
                    "status": event_fields.get("status"),
                    "errorType": event_fields.get("errorType"),
                    "elapsedMs": event_fields.get("elapsedMs"),
                    "httpStatus": event_fields.get("httpStatus"),
                }.items()
                if value is not None
            }
        )
    return rows
