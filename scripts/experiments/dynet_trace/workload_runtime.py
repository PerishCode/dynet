from __future__ import annotations

from collections import Counter
from typing import Any

from dynet_trace.common import event_fields, event_kind, int_value


def runtime_sessions(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for event in events:
        fields = event_fields(event)
        session = fields.get("session")
        if not session:
            continue
        row = grouped.setdefault(session, session_group_row(fields, session))
        add_session_event(row, event, fields, event_kind(event))
    output = []
    for row in grouped.values():
        output.append(
            {
                **row,
                "domains": sorted(row["domains"]),
                "outbounds": sorted(row["outbounds"]),
                "selectedCandidates": sorted(row["selectedCandidates"]),
                "selectedOutbounds": sorted(row["selectedOutbounds"]),
                "eventKinds": dict(row["eventKinds"]),
            }
        )
    return sorted(output, key=lambda item: int(item["session"]) if str(item["session"]).isdigit() else 0)

def runtime_dns_flows(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for event in events:
        fields = event_fields(event)
        dns_query_id = fields.get("dnsQueryId")
        if not dns_query_id:
            continue
        row = grouped.setdefault(dns_query_id, dns_group_row(fields, dns_query_id))
        add_dns_event(row, event, fields, event_kind(event))
    output = []
    for row in grouped.values():
        output.append(
            {
                **row,
                "outbounds": sorted(row["outbounds"]),
                "selectedCandidates": sorted(row["selectedCandidates"]),
                "selectedOutbounds": sorted(row["selectedOutbounds"]),
                "eventKinds": dict(row["eventKinds"]),
            }
        )
    return sorted(
        output,
        key=lambda item: int(item["dnsQueryId"])
        if str(item["dnsQueryId"]).isdigit()
        else 0,
    )

def session_group_row(fields: dict[str, str], session: str) -> dict[str, Any]:
    return {
        "session": session,
        "flowId": fields.get("flowId"),
        "transport": fields.get("sessionTransport"),
        "target": fields.get("target"),
        "domains": set(),
        "outbounds": set(),
        "selectedCandidates": set(),
        "selectedOutbounds": set(),
        "closeReasons": [],
        "failures": [],
        "stageFailures": [],
        "eventKinds": Counter(),
        "startedAtUnixMs": None,
        "finishedAtUnixMs": None,
    }

def dns_group_row(fields: dict[str, str], dns_query_id: str) -> dict[str, Any]:
    return {
        "dnsQueryId": dns_query_id,
        "flowId": fields.get("flowId"),
        "query": fields.get("query"),
        "listener": fields.get("listener"),
        "outbounds": set(),
        "selectedCandidates": set(),
        "selectedOutbounds": set(),
        "failures": [],
        "stageFailures": [],
        "eventKinds": Counter(),
        "startedAtUnixMs": None,
        "finishedAtUnixMs": None,
    }

def add_session_event(row: dict[str, Any], event: dict[str, Any], fields: dict[str, str], kind: str) -> None:
    update_time_bounds(row, event)
    row["eventKinds"][kind] += 1
    add_field_values(row["domains"], fields, ("domain", "query"), skip_unparsed=True)
    add_field_values(row["outbounds"], fields, ("outbound", "selected", "boundSelected"))
    add_selected_values(row, fields, kind)
    if kind in {"tcp-session-closed", "udp-session-closed"}:
        row["closeReasons"].append(fields.get("reason", "<unknown>"))
    append_event_failure(row, fields, kind, dns_failure=False)

def add_dns_event(row: dict[str, Any], event: dict[str, Any], fields: dict[str, str], kind: str) -> None:
    update_time_bounds(row, event)
    row["eventKinds"][kind] += 1
    add_field_values(row["outbounds"], fields, ("outbound", "selected", "boundSelected"))
    add_selected_values(row, fields, kind)
    append_event_failure(row, fields, kind, dns_failure=True)

def update_time_bounds(row: dict[str, Any], event: dict[str, Any]) -> None:
    timestamp = event.get("emittedAtUnixMs")
    if not isinstance(timestamp, int):
        return
    if row["startedAtUnixMs"] is None or timestamp < row["startedAtUnixMs"]:
        row["startedAtUnixMs"] = timestamp
    if row["finishedAtUnixMs"] is None or timestamp > row["finishedAtUnixMs"]:
        row["finishedAtUnixMs"] = timestamp

def add_field_values(
    target: set[str],
    fields: dict[str, str],
    keys: tuple[str, ...],
    *,
    skip_unparsed: bool = False,
) -> None:
    for key in keys:
        value = fields.get(key)
        if value and value != "<none>" and (not skip_unparsed or value != "<unparsed>"):
            target.add(value)

def add_selected_values(row: dict[str, Any], fields: dict[str, str], kind: str) -> None:
    selected = fields.get("selected")
    if kind == "outbound-candidate-set" and selected and selected != "<none>":
        row["selectedCandidates"].add(selected)
    if kind == "outbound-graph-selected" and selected and selected != "<none>":
        row["selectedOutbounds"].add(selected)
    bound_selected = fields.get("boundSelected")
    if kind == "dialer-cascade-selected" and bound_selected and bound_selected != "<none>":
        row["selectedCandidates"].add(bound_selected)

def append_event_failure(
    row: dict[str, Any],
    fields: dict[str, str],
    kind: str,
    *,
    dns_failure: bool,
) -> None:
    failed = fields.get("status") == "failed" or kind.endswith("-failed")
    if dns_failure:
        failed = fields.get("status") == "failed" or kind == "dns-resolve-failed"
    if not failed:
        return
    failure = {
        "kind": kind,
        "outbound": fields.get("outbound"),
        "stage": fields.get("stage"),
        "errorType": fields.get("errorType"),
        "reason": fields.get("reason") or fields.get("error"),
    }
    row["failures"].append(failure)
    if kind == "outbound-stage-finished":
        row["stageFailures"].append(failure)

def matching_sessions(
    result: dict[str, Any],
    candidates: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    started = int_value(result.get("startedAtUnixMs"))
    finished = int_value(result.get("finishedAtUnixMs"))
    if started is None or finished is None:
        return candidates
    lower = started - 2_000
    upper = finished + 2_000
    matched = [
        session
        for session in candidates
        if session.get("startedAtUnixMs") is not None
        and lower <= int(session["startedAtUnixMs"]) <= upper
    ]
    return matched

def matching_dns_flows(
    result: dict[str, Any],
    candidates: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    started = int_value(result.get("startedAtUnixMs"))
    finished = int_value(result.get("finishedAtUnixMs"))
    if started is None or finished is None:
        return candidates
    lower = started - 2_000
    upper = finished + 2_000
    return [
        flow
        for flow in candidates
        if flow.get("startedAtUnixMs") is not None
        and lower <= int(flow["startedAtUnixMs"]) <= upper
    ]
