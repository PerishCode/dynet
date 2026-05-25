from __future__ import annotations


def checks(
    report: dict,
    install_report: dict,
    uninstall_report: dict,
    dns_names: list[str],
    event_kinds: set,
    queries: set[str],
) -> list[dict]:
    events = [event for event in report.get("events", []) if isinstance(event, dict)]
    return [
        check("install-apply", lifecycle_pass(install_report, "apply-engine")),
        check("runtime-report-emitted", bool(report.get("status"))),
        check("tun-observed", int(report.get("tunPackets") or 0) >= 1),
        check("dns-query-observed", any(name in queries for name in dns_names)),
        check("dns-resolve-failed", "dns-resolve-failed" in event_kinds),
        check("dialer-selected", "dialer-cascade-selected" in event_kinds),
        check("downstream-bound-stage-succeeded", bound_ok(events)),
        check("private-downstream-stage-failed", private_failed(events)),
        check("downstream-error-disposition", downstream_disposition(events)),
        check("cascade-non-bound-stop", non_bound_stop(events)),
        check("cascade-no-second-attempt", no_later_attempt(events)),
        check("uninstall-cleanup", lifecycle_pass(uninstall_report, "uninstall-engine")),
    ]


def bound_ok(events: list[dict]) -> bool:
    for stop in stop_rows(events):
        bound = str(stop.get("boundSelected") or "")
        if bound and any(
            event.get("kind") == "outbound-stage-finished"
            and field(event, "outbound") == bound
            and field(event, "status") == "success"
            and stage_before(event, stop)
            for event in events
        ):
            return True
    return False


def private_failed(events: list[dict]) -> bool:
    for stop in stop_rows(events):
        if any(
            event.get("kind") == "outbound-stage-finished"
            and field(event, "outbound") == "private"
            and field(event, "stage").startswith("private-")
            and field(event, "status") == "failed"
            and stage_before(event, stop)
            for event in events
        ):
            return True
    return False


def non_bound_stop(events: list[dict]) -> bool:
    for stop in stop_rows(events):
        if (
            stop.get("retryAllowed") == "false"
            and stop.get("retryStopReason") == "non-bound-failure"
            and int_or_none(stop.get("candidateCount")) not in {None, 1}
        ):
            return True
    return False


def downstream_disposition(events: list[dict]) -> bool:
    for stop in stop_rows(events):
        if not known_disposition(stop.get("errorDisposition")):
            continue
        if any(
            event.get("kind") == "outbound-stage-finished"
            and field(event, "outbound") == "private"
            and field(event, "stage").startswith("private-")
            and field(event, "status") == "failed"
            and known_disposition(field(event, "errorDisposition"))
            and stage_before(event, stop)
            for event in events
        ):
            return True
    return False


def known_disposition(value: object) -> bool:
    disposition = str(value or "")
    return bool(disposition) and disposition != "unknown"


def no_later_attempt(events: list[dict]) -> bool:
    for stop in stop_rows(events):
        attempt = int_or_none(stop.get("attempt"))
        candidate_count = int_or_none(stop.get("candidateCount"))
        if attempt is None or candidate_count is None or candidate_count <= attempt:
            continue
        if not later_attempt(events, str(stop.get("flowId") or ""), attempt):
            return True
    return False


def stop_rows(events: list[dict]) -> list[dict]:
    rows = []
    for event in events:
        if event.get("kind") != "dialer-cascade-attempt-finished":
            continue
        event_fields = event.get("fields", {})
        if not isinstance(event_fields, dict):
            continue
        if (
            str(event_fields.get("status") or "") == "failed"
            and str(event_fields.get("failureScope") or "") == "downstream"
        ):
            rows.append(
                {
                    "flowId": str(event_fields.get("flowId") or ""),
                    "attempt": str(event_fields.get("attempt") or ""),
                    "candidateCount": str(event_fields.get("candidateCount") or ""),
                    "boundSelected": str(event_fields.get("boundSelected") or ""),
                    "errorDisposition": str(event_fields.get("errorDisposition") or ""),
                    "retryAllowed": str(event_fields.get("retryAllowed") or ""),
                    "retryStopReason": str(event_fields.get("retryStopReason") or ""),
                    "sequence": event.get("sequence"),
                }
            )
    return rows


def stage_before(event: dict, stop: dict) -> bool:
    stop_sequence = stop.get("sequence")
    sequence = event.get("sequence")
    if isinstance(sequence, int) and isinstance(stop_sequence, int):
        return sequence <= stop_sequence
    return True


def later_attempt(events: list[dict], flow_id: str, attempt: int) -> bool:
    for event in events:
        if event.get("kind") not in {
            "dialer-cascade-attempt-started",
            "dialer-cascade-attempt-finished",
        }:
            continue
        if field(event, "flowId") != flow_id:
            continue
        event_attempt = int_or_none(field(event, "attempt"))
        if event_attempt is not None and event_attempt > attempt:
            return True
    return False


def field(event: dict, key: str) -> str:
    fields = event.get("fields")
    if not isinstance(fields, dict):
        return ""
    return str(fields.get(key) or "")


def int_or_none(value: object) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def lifecycle_pass(report: dict, name: str) -> bool:
    for item in report.get("checks", []):
        if item.get("name") == name and item.get("status") == "pass":
            return True
    return False


def check(name: str, passed: bool) -> dict:
    return {"name": name, "passed": bool(passed)}
