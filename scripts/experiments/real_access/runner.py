from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

from real_access.aggregate import summarize_run
from real_access.common import (
    ATTRIBUTION_TRACE_FIELDS,
    TARGET_POLICY_VERSION,
    observer_model,
    utc_now,
    write_json,
)
from real_access.controller import ClashSampler, sampler_from_args
from real_access.net import classify_error, first_failed_stage, probe
from real_access.reports import write_report


def run_manifest(manifest: dict[str, Any], args: argparse.Namespace, output_dir: Path) -> dict[str, Any]:
    started = utc_now()
    started_monotonic = time.perf_counter()
    results = []
    sampler = sampler_from_args(args)
    jsonl = output_dir / "results.jsonl"
    jsonl.parent.mkdir(parents=True, exist_ok=True)
    with jsonl.open("w") as sink:
        for entry in manifest["entries"]:
            lag = sleep_until_entry(entry, args, started_monotonic)
            result = run_probe(entry, args.timeout_seconds, lag, sampler)
            results.append(result)
            sink.write(json.dumps(result, ensure_ascii=False, sort_keys=True) + "\n")
            sink.flush()
            if not args.respect_schedule and args.spacing_ms > 0:
                time.sleep(args.spacing_ms / 1000)
    summary = summarize_run(manifest, results, started, utc_now())
    write_json(output_dir / "summary.json", summary)
    write_report(output_dir / "report.md", summary)
    return summary

def sleep_until_entry(
    entry: dict[str, Any],
    args: argparse.Namespace,
    started_monotonic: float,
) -> int | None:
    if not args.respect_schedule:
        return None
    offset = int(entry.get("scheduledOffsetMs") or 0)
    due = started_monotonic + offset / 1000
    now = time.perf_counter()
    if due > now:
        time.sleep(due - now)
        return 0
    return int((now - due) * 1000)

def run_probe(
    entry: dict[str, Any],
    timeout_seconds: float,
    schedule_lag_ms: int | None,
    sampler: ClashSampler | None = None,
) -> dict[str, Any]:
    started = utc_now()
    begin = time.perf_counter()
    stages: list[dict[str, Any]] = []
    policy = target_policy(entry)
    capture = sampler.capture(entry) if sampler else None
    try:
        details = probe(
            entry,
            timeout_seconds,
            stages,
            on_resolved=capture.add_target_records if capture else None,
        )
        ok = True
        error = None
        error_stage = None
        error_class = None
    except Exception as exc:  # noqa: BLE001 - black-box classification boundary
        details = {}
        ok = False
        failed_stage = first_failed_stage(stages)
        error = failed_stage.get("errorType") if failed_stage else classify_error(exc)
        error_stage = failed_stage.get("name") if failed_stage else "probe"
        error_class = type(exc).__name__
    finally:
        clash_controller = capture.close() if capture else {"enabled": False}
    elapsed = int((time.perf_counter() - begin) * 1000)
    result = {
        "id": entry["id"],
        "startedAt": started,
        "observer": observer_model(timeout_seconds),
        "bucket": entry["bucket"],
        "domain": entry["domain"],
        "behavior": entry.get("behavior", "single"),
        "groupId": entry.get("groupId"),
        "probe": entry["probe"],
        "port": entry.get("port"),
        "scheduledOffsetMs": entry.get("scheduledOffsetMs"),
        "scheduleLagMs": schedule_lag_ms,
        "ok": ok,
        "elapsedMs": elapsed,
        "stages": stages,
        "targetPolicy": policy,
        "errorType": error,
        "errorStage": error_stage,
        "errorClass": error_class,
        "clashController": clash_controller,
        "attribution": result_attribution(entry, ok, elapsed, error, error_stage, policy),
    }
    result.update(details)
    return result

def target_policy(entry: dict[str, Any]) -> dict[str, Any]:
    domain = str(entry["domain"]).lower()
    bucket = str(entry["bucket"])
    probe_name = str(entry["probe"])
    tags = []
    reasons = []
    confidence_weight = 1.0
    fault_signal = "normal"
    if bucket == "platform-background":
        tags.append("platform-background")
        confidence_weight = 0.5
        fault_signal = "weak"
        reasons.append("background platform endpoints are not user-intent traffic")
    if domain.endswith(".push.apple.com") or ".courier.push.apple.com" in domain:
        tags.extend(["platform-push", "apple-push"])
        confidence_weight = 0.0
        fault_signal = "informational"
        reasons.append("Apple push/courier endpoints may reject generic black-box TLS/HTTP probes")
    elif bucket == "platform-background" and probe_name in {"tls-handshake", "https-head", "https-get"}:
        tags.append("platform-service-probe")
        confidence_weight = min(confidence_weight, 0.25)
        fault_signal = "weak"
        reasons.append("generic TLS/HTTP probes against platform services are weak fault signals")
    return {
        "version": TARGET_POLICY_VERSION,
        "faultSignal": fault_signal,
        "confidenceWeight": confidence_weight,
        "lowConfidence": confidence_weight < 0.5,
        "tags": sorted(set(tags)),
        "reasons": reasons,
    }

def result_attribution(
    entry: dict[str, Any],
    ok: bool,
    elapsed_ms_value: int,
    error: str | None,
    error_stage: str | None,
    policy: dict[str, Any],
) -> dict[str, Any]:
    needs_trace = list(ATTRIBUTION_TRACE_FIELDS)
    if ok:
        outcome = "healthy"
    elif policy["faultSignal"] == "informational":
        outcome = "target-or-probe-semantics"
    elif policy["faultSignal"] == "weak":
        outcome = "weak-blackbox-failure"
    else:
        outcome = "path-or-target-failure"
    return {
        "blackboxOnly": True,
        "canAttributePlanVsNode": False,
        "outcome": outcome,
        "faultSignal": policy["faultSignal"],
        "requiresDynetTraceFields": needs_trace,
        "probeKey": f"{entry['bucket']}:{entry['probe']}",
        "elapsedMs": elapsed_ms_value,
        "errorType": error,
        "errorStage": error_stage,
    }
