#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

from scripts.lib.bootstrap import add_experiments_path
from scripts.lib.jsonio import load_json, write_json

add_experiments_path()

from dynet_trace.quality_feedback import planner_feedback, write_quality_report
from dynet_trace.quality.state import (
    merge_quality_entries,
    quality_entries,
    retained_previous_entries,
    signals,
    state_expiry,
    state_is_fresh,
)


STATE_SCHEMA = "dynet-outbound-quality-state/v1alpha1"
REPORT_SCHEMA = "dynet-probe/v1alpha1"
DEFAULT_OUTPUT_JSON = ".task/resources/dynet-probe-quality-state.json"
DEFAULT_OUTPUT_MD = ".task/resources/dynet-probe-quality-state.md"


def report_paths(inputs: list[str]) -> list[Path]:
    paths = []
    for item in inputs:
        path = Path(item)
        if path.is_dir():
            paths.extend(sorted(path.glob("*.json")))
        else:
            paths.append(path)
    return paths


def load_reports(inputs: list[str]) -> list[dict[str, Any]]:
    reports = []
    for path in report_paths(inputs):
        data = load_json(path)
        if not isinstance(data, dict) or data.get("schema") != REPORT_SCHEMA:
            continue
        data["_path"] = str(path)
        reports.append(data)
    return reports


def load_previous_states(inputs: list[str]) -> list[dict[str, Any]]:
    states = []
    for raw in inputs:
        data = load_json(Path(raw))
        if isinstance(data, dict) and data.get("schema") == STATE_SCHEMA:
            states.append(data)
    return states


def build_state(args: argparse.Namespace) -> dict[str, Any]:
    reports = load_reports(args.input)
    report_observations = [item for report in reports for item in observe(report)]
    now_ms = args.now_unix_ms or observed_now(report_observations)
    previous_states = load_previous_states(args.previous_state or [])
    retained_states = [
        state for state in previous_states if state_is_fresh(state, now_ms)
    ]
    feedback = planner_feedback(
        args.probe_batch or [],
        args.quality_gap_mode,
        now_ms,
        getattr(args, "quality_gap_promotion_proof", None) or [],
        getattr(args, "quality_gap_promotion_context", None) or [],
        getattr(args, "trace_batch", None) or [],
    )
    observations = report_observations + feedback["observations"]
    fresh = [
        item
        for item in observations
        if 0 <= now_ms - item["observedAtUnixMs"] <= args.window_seconds * 1000
    ]
    current_entries = quality_entries(fresh)
    previous_entries = retained_previous_entries(previous_states, now_ms)
    entries = merge_quality_entries(previous_entries + current_entries)
    quality_signals = signals(entries)
    return {
        "schema": STATE_SCHEMA,
        "generatedAtUnixMs": now_ms,
        "ttlSecs": args.ttl_seconds,
        "windowSecs": args.window_seconds,
        "expiresAtUnixMs": state_expiry(now_ms, args.ttl_seconds, retained_states),
        "privacy": {
            "identityInformationSent": False,
            "cookiesSent": False,
            "authorizationSent": False,
            "responseBodiesStored": False,
            "resolvedIpsStored": False,
        },
        "source": {
            "reports": len(reports),
            "previousStates": len(previous_states),
            "retainedPreviousStates": len(retained_states),
            "retainedPreviousEntries": len(previous_entries),
            "observations": len(report_observations),
            "feedbackObservations": len(feedback["observations"]),
            "freshObservations": len(fresh),
            "currentEntries": len(current_entries),
        },
        "plannerFeedback": feedback["summary"],
        "outbounds": entries,
        "signals": quality_signals + feedback["signals"],
    }


def observe(report: dict[str, Any]) -> list[dict[str, Any]]:
    events = [event for event in report.get("events", []) if isinstance(event, dict)]
    cascade_attempts = cascade_attempt_observations(report, events)
    if cascade_attempts:
        return cascade_attempts
    return [direct_observation(report, events)]


def direct_observation(report: dict[str, Any], events: list[dict[str, Any]]) -> dict[str, Any]:
    target = report.get("target") if isinstance(report.get("target"), dict) else {}
    attempt = first_event(events, "outbound-attempt-finished")
    graph = first_event(events, "outbound-graph-selected")
    route = first_event(events, "route-matched")
    candidate_set = first_event(events, "outbound-candidate-set")
    outbound = (
        fields(candidate_set).get("selected")
        or fields(graph).get("selected")
        or fields(attempt).get("outbound")
        or fields(route).get("outbound")
        or "<unknown>"
    )
    return {
        "path": report.get("_path"),
        "scope": "plan-candidate" if candidate_set else "candidate-direct",
        "observedAtUnixMs": max_event_time(events),
        "outbound": outbound,
        "targetFamily": target_family(str(target.get("host", ""))),
        "transport": fields(attempt).get("transport"),
        "status": report.get("status"),
        "reason": report.get("reason"),
        "cascade": {},
        "stages": stage_obs(events),
    }


def cascade_attempt_observations(
    report: dict[str, Any], events: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    target = report.get("target") if isinstance(report.get("target"), dict) else {}
    attempt = first_event(events, "outbound-attempt-finished")
    selected = cascade_selected_by_bound(events)
    starts = cascade_start_sequences(events)
    observations = []
    for event in events:
        if event.get("kind") != "dialer-cascade-attempt-finished":
            continue
        observations.append(
            cascade_attempt_observation(report, target, attempt, selected, starts, events, event)
        )
    return observations


def cascade_attempt_observation(
    report: dict[str, Any],
    target: dict[str, Any],
    attempt: dict[str, Any],
    selected: dict[str, dict[str, str]],
    starts: dict[str | None, int | None],
    events: list[dict[str, Any]],
    event: dict[str, Any],
) -> dict[str, Any]:
    event_fields = fields(event)
    bound_selected = event_fields.get("boundSelected") or "<unknown>"
    cascade = selected.get(bound_selected, {})
    stages = stage_obs(
        events,
        starts.get(event_fields.get("attempt")),
        event.get("sequence"),
    )
    status, failure_scope = cascade_status(event_fields, bound_selected, stages)
    return {
        "path": report.get("_path"),
        "scope": "dialer-bound",
        "observedAtUnixMs": event_time(event),
        "outbound": bound_selected,
        "targetFamily": target_family(str(target.get("host", ""))),
        "transport": fields(attempt).get("transport") or "tcp",
        "status": status,
        "reason": event_fields.get("error") or report.get("reason"),
        "cascade": {
            "dialer": event_fields.get("dialer") or cascade.get("dialer"),
            "bound": cascade.get("bound"),
            "private": cascade.get("private"),
            "failureScope": failure_scope,
        },
        "stages": stages,
    }


def cascade_status(
    event_fields: dict[str, str],
    bound_selected: str,
    stages: list[dict[str, Any]],
) -> tuple[str, str]:
    if event_fields.get("status") == "success":
        return "pass", "none"
    bound_prefix = f"{bound_selected}:"
    for stage in stages:
        if stage.get("status") == "failed" and str(stage.get("stage", "")).startswith(bound_prefix):
            return "deny", "bound"
    return "pass", "downstream"

def first_event(events: list[dict[str, Any]], kind: str) -> dict[str, Any]:
    for event in events:
        if event.get("kind") == kind:
            return event
    return {}


def cascade_selected_by_bound(events: list[dict[str, Any]]) -> dict[str, dict[str, str]]:
    rows = {}
    for event in events:
        if event.get("kind") != "dialer-cascade-selected":
            continue
        event_fields = fields(event)
        bound_selected = event_fields.get("boundSelected")
        if bound_selected:
            rows[bound_selected] = event_fields
    return rows


def cascade_start_sequences(events: list[dict[str, Any]]) -> dict[str | None, int | None]:
    rows = {}
    for event in events:
        if event.get("kind") != "dialer-cascade-attempt-started":
            continue
        event_fields = fields(event)
        rows[event_fields.get("attempt")] = event.get("sequence")
    return rows


def max_event_time(events: list[dict[str, Any]]) -> int:
    values = [
        int(event["emittedAtUnixMs"])
        for event in events
        if isinstance(event.get("emittedAtUnixMs"), int)
    ]
    return max(values) if values else int(time.time() * 1000)


def event_time(event: dict[str, Any]) -> int:
    value = event.get("emittedAtUnixMs")
    return int(value) if isinstance(value, int) else int(time.time() * 1000)


def observed_now(observations: list[dict[str, Any]]) -> int:
    if observations:
        return max(item["observedAtUnixMs"] for item in observations)
    return int(time.time() * 1000)


def stage_obs(
    events: list[dict[str, Any]],
    start_sequence: int | None = None,
    end_sequence: int | None = None,
) -> list[dict[str, Any]]:
    rows = []
    for event in events:
        if event.get("kind") != "outbound-stage-finished":
            continue
        sequence = event.get("sequence")
        if start_sequence is not None and isinstance(sequence, int) and sequence < start_sequence:
            continue
        if end_sequence is not None and isinstance(sequence, int) and sequence > end_sequence:
            continue
        event_fields = fields(event)
        outbound = event_fields.get("outbound", "<unknown>")
        stage = event_fields.get("stage", "unknown")
        rows.append(
            {
                "stage": f"{outbound}:{stage}",
                "status": event_fields.get("status"),
                "errorType": event_fields.get("errorType"),
                "elapsedMs": int_or_none(event_fields.get("elapsedMs")),
            }
        )
    return rows


def fields(event: dict[str, Any]) -> dict[str, str]:
    value = event.get("fields", {})
    if not isinstance(value, dict):
        return {}
    return {str(key): str(item) for key, item in value.items()}


def int_or_none(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def target_family(host: str) -> str:
    labels = [item for item in host.lower().strip(".").split(".") if item]
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return labels[0] if labels else "<unknown>"


def command_build(args: argparse.Namespace) -> int:
    if not any([args.input, args.probe_batch, args.trace_batch, args.previous_state]):
        raise SystemExit(
            "build requires at least one input report, --probe-batch, "
            "--trace-batch, or --previous-state"
        )
    state = build_state(args)
    output_json = Path(args.output_json)
    output_md = Path(args.output_md)
    write_json(output_json, state)
    write_quality_report(output_md, state)
    print(
        json.dumps(
            {
                "outputJson": str(output_json),
                "outputMd": str(output_md),
                "entries": len(state["outbounds"]),
                "signals": len(state["signals"]),
            },
            sort_keys=True,
        )
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build outbound quality state from dynet probe reports."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    build = subparsers.add_parser("build")
    build.add_argument("input", nargs="*")
    build.add_argument("--output-json", default=DEFAULT_OUTPUT_JSON)
    build.add_argument("--output-md", default=DEFAULT_OUTPUT_MD)
    build.add_argument("--ttl-seconds", type=int, default=300)
    build.add_argument("--window-seconds", type=int, default=1800)
    build.add_argument("--now-unix-ms", type=int)
    build.add_argument(
        "--previous-state",
        action="append",
        help="existing quality-state JSON to retain while it is still fresh",
    )
    build.add_argument(
        "--probe-batch",
        action="append",
        help="probe-batch attribution JSON with repeated quality-gap signals",
    )
    build.add_argument(
        "--trace-batch",
        action="append",
        help="trace-attribution batch JSON with runtime fallback signals",
    )
    build.add_argument(
        "--quality-gap-mode",
        choices=["observe", "penalize", "auto"],
        default="observe",
        help="observe, penalize, or auto-promote repeated quality gaps with proof",
    )
    build.add_argument(
        "--quality-gap-promotion-proof",
        action="append",
        help="VM private-runtime repeat summary proving penalty promotion safety",
    )
    build.add_argument(
        "--quality-gap-promotion-context",
        action="append",
        help="maturity/product-effect summary carrying observe-only policy context",
    )
    build.set_defaults(handler=command_build)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
