#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import time
from collections import defaultdict
from pathlib import Path
from typing import Any


STATE_SCHEMA = "dynet-outbound-quality-state/v1alpha1"
REPORT_SCHEMA = "dynet-probe/v1alpha1"
DEFAULT_OUTPUT_JSON = ".task/resources/dynet-probe-quality-state.json"
DEFAULT_OUTPUT_MD = ".task/resources/dynet-probe-quality-state.md"


def load_json(path: Path) -> Any:
    return json.loads(path.read_text())


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True))


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


def build_state(args: argparse.Namespace) -> dict[str, Any]:
    reports = load_reports(args.input)
    observations = [item for report in reports for item in observe(report)]
    now_ms = args.now_unix_ms or observed_now(observations)
    fresh = [
        item
        for item in observations
        if 0 <= now_ms - item["observedAtUnixMs"] <= args.window_seconds * 1000
    ]
    entries = quality_entries(fresh)
    return {
        "schema": STATE_SCHEMA,
        "generatedAtUnixMs": now_ms,
        "ttlSecs": args.ttl_seconds,
        "windowSecs": args.window_seconds,
        "expiresAtUnixMs": now_ms + args.ttl_seconds * 1000,
        "privacy": {
            "identityInformationSent": False,
            "cookiesSent": False,
            "authorizationSent": False,
            "responseBodiesStored": False,
            "resolvedIpsStored": False,
        },
        "source": {
            "reports": len(reports),
            "observations": len(observations),
            "freshObservations": len(fresh),
        },
        "outbounds": entries,
        "signals": signals(entries),
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
    outbound = (
        fields(graph).get("selected")
        or fields(attempt).get("outbound")
        or fields(route).get("outbound")
        or "<unknown>"
    )
    return {
        "path": report.get("_path"),
        "scope": "candidate-direct",
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
    return {
        "path": report.get("_path"),
        "scope": "dialer-bound",
        "observedAtUnixMs": event_time(event),
        "outbound": bound_selected,
        "targetFamily": target_family(str(target.get("host", ""))),
        "transport": fields(attempt).get("transport") or "tcp",
        "status": "pass" if event_fields.get("status") == "success" else "deny",
        "reason": event_fields.get("error") or report.get("reason"),
        "cascade": {
            "dialer": event_fields.get("dialer") or cascade.get("dialer"),
            "bound": cascade.get("bound"),
            "private": cascade.get("private"),
        },
        "stages": stage_obs(
            events,
            starts.get(event_fields.get("attempt")),
            event.get("sequence"),
        ),
    }

def first_event(events: list[dict[str, Any]], kind: str) -> dict[str, Any]:
    for event in events:
        if event.get("kind") == kind:
            return event
    return {}


def first_event_with_field(
    events: list[dict[str, Any]], kind: str, key: str, value: str
) -> dict[str, Any]:
    for event in events:
        if event.get("kind") == kind and fields(event).get(key) == value:
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


def quality_entries(observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[
        tuple[str, str | None, str | None, str | None, str | None, str | None],
        list[dict[str, Any]],
    ] = defaultdict(list)
    for item in observations:
        cascade = item.get("cascade", {})
        base = (
            item["outbound"],
            item.get("scope"),
            cascade.get("dialer"),
            cascade.get("private"),
        )
        grouped[(*base, None, item.get("transport"))].append(item)
        grouped[(*base, item["targetFamily"], item.get("transport"))].append(item)
    return [
        quality_entry(outbound, scope, dialer, private, family, transport, items)
        for (outbound, scope, dialer, private, family, transport), items in sorted(
            grouped.items(), key=group_key
        )
    ]


def group_key(
    item: tuple[
        tuple[str, str | None, str | None, str | None, str | None, str | None],
        list[dict[str, Any]],
    ],
) -> tuple[str, str, str, str, str, str]:
    (outbound, scope, dialer, private, family, transport), _ = item
    return (outbound, scope or "", dialer or "", private or "", family or "", transport or "")


def quality_entry(
    outbound: str,
    scope: str | None,
    dialer: str | None,
    private: str | None,
    family: str | None,
    transport: str | None,
    items: list[dict[str, Any]],
) -> dict[str, Any]:
    attempts = len(items)
    failures = sum(1 for item in items if item.get("status") != "pass")
    successes = attempts - failures
    error_rate = failures / attempts if attempts else 0.0
    entry = {
        "outbound": outbound,
        "scope": scope,
        "dialer": dialer,
        "private": private,
        "targetFamily": family,
        "transport": transport,
        "verdict": verdict(attempts, error_rate),
        "attempts": attempts,
        "successes": successes,
        "failures": failures,
        "errorRate": round(error_rate, 4),
        "confidence": confidence(attempts),
        "stages": stage_quality(items),
    }
    return {key: value for key, value in entry.items() if value is not None}


def stage_quality(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in items:
        for stage in item["stages"]:
            grouped[stage["stage"]].append(stage)
    rows = []
    for stage, stages in sorted(grouped.items()):
        attempts = len(stages)
        failures = sum(1 for item in stages if item.get("status") == "failed")
        elapsed = [item["elapsedMs"] for item in stages if item.get("elapsedMs") is not None]
        error_rate = failures / attempts if attempts else 0.0
        rows.append(
            {
                "stage": stage,
                "attempts": attempts,
                "failures": failures,
                "errorRate": round(error_rate, 4),
                "p95Ms": percentile(elapsed, 95),
            }
        )
    return rows


def percentile(values: list[int], target: int) -> int | None:
    if not values:
        return None
    ordered = sorted(values)
    index = round((len(ordered) - 1) * (target / 100))
    return ordered[index]


def verdict(attempts: int, error_rate: float) -> str:
    if attempts == 0:
        return "unknown"
    if error_rate == 0:
        return "healthy"
    if error_rate <= 0.5:
        return "degraded"
    return "unhealthy"


def confidence(attempts: int) -> str:
    if attempts >= 10:
        return "high"
    if attempts >= 3:
        return "medium"
    return "low"


def signals(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    overall = {
        quality_key(item): item
        for item in entries
        if "targetFamily" not in item and item.get("outbound")
    }
    for item in entries:
        family = item.get("targetFamily")
        if not family:
            continue
        parent = overall.get(quality_key(item))
        if item["verdict"] == "unhealthy" and parent and parent["verdict"] != "unhealthy":
            rows.append(
                {
                    "type": "target-family-risk",
                    "outbound": item["outbound"],
                    "scope": item.get("scope"),
                    "dialer": item.get("dialer"),
                    "private": item.get("private"),
                    "targetFamily": family,
                    "reason": "target family is unhealthy while outbound aggregate is not",
                }
            )
    return rows


def quality_key(item: dict[str, Any]) -> tuple[str, str | None, str | None, str | None, str | None]:
    return (
        item["outbound"],
        item.get("scope"),
        item.get("dialer"),
        item.get("private"),
        item.get("transport"),
    )


def write_report(path: Path, state: dict[str, Any]) -> None:
    lines = [
        "# Dynet Probe Quality State",
        "",
        f"- observations: `{state['source']['freshObservations']}` fresh / `{state['source']['observations']}` total",
        f"- ttl: `{state['ttlSecs']}` seconds",
        f"- window: `{state['windowSecs']}` seconds",
        "",
        "## Outbounds",
        "",
    ]
    for item in state["outbounds"]:
        family = item.get("targetFamily", "*")
        lines.append(
            f"- `{item['outbound']}` scope=`{item.get('scope', '*')}` "
            f"dialer=`{item.get('dialer', '*')}` private=`{item.get('private', '*')}` "
            f"family=`{family}` verdict=`{item['verdict']}` "
            f"attempts={item['attempts']} failures={item['failures']} "
            f"errorRate={item['errorRate']}"
        )
    if state["signals"]:
        lines.extend(["", "## Signals", ""])
        for item in state["signals"]:
            lines.append(
                f"- `{item['type']}` outbound=`{item['outbound']}` "
                f"scope=`{item.get('scope', '*')}` "
                f"family=`{item['targetFamily']}`"
            )
    path.write_text("\n".join(lines) + "\n")


def command_build(args: argparse.Namespace) -> int:
    state = build_state(args)
    output_json = Path(args.output_json)
    output_md = Path(args.output_md)
    write_json(output_json, state)
    write_report(output_md, state)
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
    build.add_argument("input", nargs="+")
    build.add_argument("--output-json", default=DEFAULT_OUTPUT_JSON)
    build.add_argument("--output-md", default=DEFAULT_OUTPUT_MD)
    build.add_argument("--ttl-seconds", type=int, default=300)
    build.add_argument("--window-seconds", type=int, default=1800)
    build.add_argument("--now-unix-ms", type=int)
    build.set_defaults(handler=command_build)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
