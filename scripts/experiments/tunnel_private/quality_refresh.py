from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from dynet_probe.quality_pipeline import build_quality_pipeline
from dynet_probe.reports import write_summary
from tunnel_private_config import ConfigInputs, build_config, metadata, write_json
from tunnel_private.quality.verify import read_failure_summary, verify


REFRESH_SCHEMA = "dynet-tunnel-private-quality-refresh/v1alpha1"

ProbeFn = Callable[[argparse.Namespace, Path], dict[str, Any]]
CleanFn = Callable[[dict[str, Any]], dict[str, Any]]


def command_quality_refresh(
    args: argparse.Namespace,
    *,
    inputs: ConfigInputs,
    run_probe: ProbeFn,
    clean_report: CleanFn,
) -> int:
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    write_json(output_dir / "meta.json", refresh_meta(args, inputs))
    with tempfile.TemporaryDirectory(prefix="dynet-tunnel-private-refresh-") as temp_dir:
        temp_root = Path(temp_dir)
        if refresh_mode(args) == "candidate":
            run_candidate_refresh_pair(args, inputs, output_dir, temp_root, run_probe, clean_report)
        else:
            config_path = temp_root / "config.json"
            write_json(
                config_path,
                build_config(
                    args,
                    inputs.candidates,
                    inputs.private,
                    tag_offset=candidate_tag_offset(args),
                ),
                secret=True,
            )
            run_refresh_pair(args, output_dir, config_path, run_probe, clean_report)
    verification = verify(
        output_dir,
        require_pass=not args.allow_failures,
        probe_mode=refresh_mode(args),
    )
    print(json.dumps({
        "outputDir": str(output_dir),
        "status": verification["status"],
        "firstWindow": verification["firstWindow"],
        "secondWindow": verification["secondWindow"],
        "qualityState": verification["qualityState"],
    }, sort_keys=True))
    return 0 if verification["status"] == "pass" else 1


def run_refresh_pair(
    args: argparse.Namespace,
    output_dir: Path,
    config_path: Path,
    run_probe: ProbeFn,
    clean_report: CleanFn,
) -> None:
    run_refresh_window(
        args,
        output_dir / "window-a",
        config_path,
        run_probe,
        clean_report,
        quality_state=args.initial_quality_state,
        previous_state=args.initial_quality_state,
        previous_attr=args.initial_attribution,
    )
    first_state = output_dir / "window-a" / "quality-state.json"
    first_attr = output_dir / "window-a" / "attribution.json"
    run_refresh_window(
        args,
        output_dir / "window-b",
        config_path,
        run_probe,
        clean_report,
        quality_state=str(first_state),
        previous_state=str(first_state),
        previous_attr=str(first_attr),
    )


def run_candidate_refresh_pair(
    args: argparse.Namespace,
    inputs: ConfigInputs,
    output_dir: Path,
    temp_root: Path,
    run_probe: ProbeFn,
    clean_report: CleanFn,
) -> None:
    configs = candidate_config_paths(args, inputs, temp_root)
    run_candidate_refresh_window(
        args,
        output_dir / "window-a",
        configs,
        run_probe,
        clean_report,
        quality_state=args.initial_quality_state,
        previous_state=args.initial_quality_state,
        previous_attr=args.initial_attribution,
    )
    first_state = output_dir / "window-a" / "quality-state.json"
    first_attr = output_dir / "window-a" / "attribution.json"
    run_candidate_refresh_window(
        args,
        output_dir / "window-b",
        configs,
        run_probe,
        clean_report,
        quality_state=str(first_state),
        previous_state=str(first_state),
        previous_attr=str(first_attr),
    )


def candidate_config_paths(
    args: argparse.Namespace,
    inputs: ConfigInputs,
    temp_root: Path,
) -> list[tuple[str, Path]]:
    if not inputs.candidates:
        raise SystemExit("candidate quality refresh requires at least one candidate")
    rows = []
    offset = candidate_tag_offset(args)
    for index, proxy in enumerate(inputs.candidates, start=1):
        tag = f"tunnel-{offset + index:03d}"
        path = temp_root / f"{tag}.json"
        write_json(
            path,
            build_config(
                args,
                [proxy],
                inputs.private,
                tag_offset=offset + index - 1,
                private_path=False,
            ),
            secret=True,
        )
        rows.append((tag, path))
    return rows


def refresh_meta(args: argparse.Namespace, inputs: ConfigInputs) -> dict[str, Any]:
    return {
        "schema": REFRESH_SCHEMA,
        "targetUrl": args.target_url,
        "protocol": args.protocol,
        "probeMode": refresh_mode(args),
        "windowSize": args.window_size,
        "initialInputs": {
            "qualityState": args.initial_quality_state is not None,
            "attribution": args.initial_attribution is not None,
        },
        "config": metadata(
            inputs.group,
            inputs.all_candidates,
            inputs.supported_candidates,
            inputs.selected_candidates,
            inputs.candidates,
            inputs.private,
            inputs.resolution,
        ),
        "privacy": {
            "rawSecretsStored": False,
            "identityInformationSent": False,
            "cookiesSent": False,
            "authorizationSent": False,
        },
    }


def refresh_mode(args: argparse.Namespace) -> str:
    return str(getattr(args, "probe_mode", "private"))


def candidate_tag_offset(args: argparse.Namespace) -> int:
    return int(getattr(args, "candidate_offset", 0) or 0)


def run_refresh_window(
    args: argparse.Namespace,
    output_dir: Path,
    config_path: Path,
    run_probe: ProbeFn,
    clean_report: CleanFn,
    quality_state: str | None = None,
    previous_state: str | None = None,
    previous_attr: str | None = None,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    items = []
    for index in range(1, args.window_size + 1):
        probe_args = argparse.Namespace(**vars(args))
        probe_args.quality_state = quality_state
        report = run_probe(probe_args, config_path)
        report_path = output_dir / f"{index:04d}-{target_domain(args.target_url)}.json"
        write_json(report_path, clean_report(report))
        items.append(summary_item(args, index, report, report_path))
    summary_args = pipeline_args(args, previous_state, previous_attr)
    summary = write_summary(output_dir, items, summary_args)
    pipeline = build_quality_pipeline(output_dir, summary_args)
    write_summary(output_dir, items, summary_args, pipeline)
    return summary


def run_candidate_refresh_window(
    args: argparse.Namespace,
    output_dir: Path,
    configs: list[tuple[str, Path]],
    run_probe: ProbeFn,
    clean_report: CleanFn,
    quality_state: str | None = None,
    previous_state: str | None = None,
    previous_attr: str | None = None,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    items = []
    for attempt in range(1, args.window_size + 1):
        for tag, config_path in configs:
            probe_args = argparse.Namespace(**vars(args))
            probe_args.quality_state = quality_state
            report = run_probe(probe_args, config_path)
            item_id = f"{attempt:04d}-{tag}"
            report_path = output_dir / f"{item_id}-{target_domain(args.target_url)}.json"
            write_json(report_path, clean_report(report))
            items.append(summary_item(args, item_id, report, report_path, candidate_tag=tag))
    summary_args = pipeline_args(args, previous_state, previous_attr)
    summary = write_summary(output_dir, items, summary_args)
    pipeline = build_quality_pipeline(output_dir, summary_args)
    write_summary(output_dir, items, summary_args, pipeline)
    return summary


def summary_item(
    args: argparse.Namespace,
    index: int | str,
    report: dict[str, Any],
    report_path: Path,
    candidate_tag: str | None = None,
) -> dict[str, Any]:
    item_id = f"{index:04d}" if isinstance(index, int) else index
    return {
        "id": item_id,
        "bucket": "tunnel-private-dogfood",
        "behavior": refresh_behavior(args),
        "groupId": refresh_group_id(args, candidate_tag),
        "domain": target_domain(args.target_url),
        "sourceProbe": args.protocol,
        "dynetProtocol": args.protocol,
        "scheduledOffsetMs": None,
        "targetStartOffsetMs": None,
        "actualStartOffsetMs": None,
        "exitCode": report.get("_exitCode"),
        "status": report.get("status"),
        "reason": report.get("reason"),
        "failureScope": report.get("failureScope"),
        "selectedOutbound": selected_outbound(report),
        "candidate": candidate_tag,
        "boundSelection": bound_selection(report),
        "failedStage": failed_stage(report),
        "readFailure": read_failure_summary(report),
        "httpStatus": http_status(report),
        "reportPath": str(report_path),
    }


def refresh_behavior(args: argparse.Namespace) -> str:
    if refresh_mode(args) == "candidate":
        return "tunnel-private-candidate-refresh"
    return "tunnel-private-refresh"


def refresh_group_id(args: argparse.Namespace, candidate_tag: str | None) -> str:
    base = f"refresh-{target_domain(args.target_url)}"
    if refresh_mode(args) == "candidate" and candidate_tag:
        return f"{base}-{candidate_tag}"
    return base


def pipeline_args(
    args: argparse.Namespace,
    previous_state: str | None,
    previous_attr: str | None,
) -> argparse.Namespace:
    return argparse.Namespace(
        replay_schedule=False,
        schedule_scale=1.0,
        replay_mode="sequential",
        max_concurrency=1,
        lag_budget_ms=1000,
        attribution_output_json=None,
        attribution_output_md=None,
        probe_batch_output_json=None,
        probe_batch_output_md=None,
        quality_output_json=None,
        quality_output_md=None,
        previous_attribution=[previous_attr] if previous_attr else None,
        previous_quality_state=[previous_state] if previous_state else None,
        min_repeat_runs=2,
        quality_now_unix_ms=None,
        quality_window_seconds=args.quality_window_seconds,
        quality_ttl_seconds=args.quality_ttl_seconds,
        quality_gap_mode="observe",
    )


def bound_selection(report: dict[str, Any]) -> dict[str, Any]:
    event = bound_candidate_event(report)
    selected = final_bound_selected(report)
    candidates = bound_candidate_rows(event, selected)
    selected_row = selected_candidate(candidates)
    best_row = best_candidate(candidates)
    selected_score = candidate_score(selected_row)
    best_score = candidate_score(best_row)
    return {
        "selected": selected,
        "candidateCount": candidate_count(event, candidates),
        "selectedScore": selected_score,
        "bestScore": best_score,
        "selectedBest": selected_score is not None and selected_score == best_score,
        "selectedBehind": selected_score is not None and best_score is not None and selected_score < best_score,
        "selectedHasQuality": candidate_has_quality(selected_row),
        "selectedReason": candidate_reason(selected_row),
    }


def bound_candidate_event(report: dict[str, Any]) -> dict[str, Any]:
    for event in report.get("events", []):
        if event.get("kind") != "outbound-candidate-set":
            continue
        if fields(event).get("scope") == "dialer-bound":
            return event
    return {}


def bound_candidate_rows(event: dict[str, Any], selected: str | None) -> list[dict[str, Any]]:
    raw = fields(event).get("candidatesJson")
    if raw is None:
        return []
    try:
        candidates = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if not isinstance(candidates, list):
        return []
    rows = []
    for candidate in candidates:
        if isinstance(candidate, dict):
            row = dict(candidate)
            row["selected"] = row.get("to") == selected
            rows.append(row)
    return rows


def final_bound_selected(report: dict[str, Any]) -> str | None:
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


def candidate_count(event: dict[str, Any], candidates: list[dict[str, Any]]) -> int:
    value = fields(event).get("candidateCount")
    if value is not None:
        try:
            return int(value)
        except ValueError:
            pass
    return len(candidates)


def selected_candidate(candidates: list[dict[str, Any]]) -> dict[str, Any]:
    for candidate in candidates:
        if candidate.get("selected"):
            return candidate
    return {}


def best_candidate(candidates: list[dict[str, Any]]) -> dict[str, Any]:
    scored = [candidate for candidate in candidates if candidate_score(candidate) is not None]
    if not scored:
        return {}
    return max(scored, key=lambda item: (candidate_score(item) or 0, bool(item.get("selected"))))


def candidate_score(candidate: dict[str, Any]) -> int | None:
    quality = candidate.get("quality")
    if not isinstance(quality, dict):
        return None
    score = quality.get("score")
    return score if isinstance(score, int) else None


def candidate_has_quality(candidate: dict[str, Any]) -> bool:
    quality = candidate.get("quality")
    if not isinstance(quality, dict):
        return False
    matches = quality.get("matches")
    return isinstance(matches, list) and bool(matches)


def candidate_reason(candidate: dict[str, Any]) -> str | None:
    quality = candidate.get("quality")
    if not isinstance(quality, dict):
        return None
    reason = quality.get("reason")
    return reason if isinstance(reason, str) else None


def selected_outbound(report: dict[str, Any]) -> str | None:
    for event in report.get("events", []):
        if event.get("kind") == "outbound-graph-selected":
            return fields(event).get("selected")
    for event in report.get("events", []):
        if event.get("kind") in {"route-matched", "rule-matched"}:
            return fields(event).get("outbound")
    return None


def failed_stage(report: dict[str, Any]) -> str | None:
    for event in report.get("events", []):
        event_fields = fields(event)
        if event.get("kind") == "outbound-stage-finished" and event_fields.get("status") == "failed":
            return event_fields.get("stage")
    return None


def http_status(report: dict[str, Any]) -> int | None:
    for event in report.get("events", []):
        if event.get("kind") != "outbound-attempt-finished":
            continue
        value = fields(event).get("httpStatus")
        if value is None:
            continue
        try:
            return int(value)
        except ValueError:
            return None
    return None


def fields(event: dict[str, Any]) -> dict[str, str]:
    value = event.get("fields", {})
    if not isinstance(value, dict):
        return {}
    return {str(key): str(item) for key, item in value.items()}


def target_domain(url: str) -> str:
    return urlparse(url).hostname or url
