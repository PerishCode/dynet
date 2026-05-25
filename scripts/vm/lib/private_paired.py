from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from common import (
    ROOT,
    CommandError,
    Lab,
    RESOURCE_LIMITS,
    guard_repo_resources,
    guest_ssh,
    join,
    q,
    validate_name,
)
from lib.interface import resolve_trojan_interface
from lib.probe_summary import (
    failed_stage,
    failure_scope,
    final_bound_selected,
)


EXPERIMENTS = ROOT / "scripts" / "experiments"
if str(EXPERIMENTS) not in sys.path:
    sys.path.insert(0, str(EXPERIMENTS))

from lib.private_paired_summary import write_outputs
from real_access.common import utc_now
from real_access.runner import run_probe as run_clash_probe

import private_probe


DEFAULT_PROBES = {"https-head", "tls-handshake"}


def command_paired(lab: Lab, args: Any) -> None:
    guest = validate_name(args.guest, "guest")
    label = args.label or datetime.now(timezone.utc).strftime("vm-private-paired-%Y%m%dT%H%M%SZ")
    label = validate_name(label, "label")
    output_dir = task_output_dir(args.output_dir, label)
    guard_repo_resources(
        "VM private paired artifacts",
        [("vm-private-paired", output_dir.parent)],
        RESOURCE_LIMITS["local-collect"],
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    dynet_dir = output_dir / "dynet"
    clash_dir = output_dir / "clash"
    report_dir = dynet_dir / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)

    manifest = load_manifest(args.manifest)
    entries = selected_entries(manifest, args)
    if not entries:
        raise CommandError("--manifest selection has no paired entries")
    args.limit = args.candidate_limit
    add_entry_domains(args, entries)
    maybe_install(lab, guest, args)
    resolve_trojan_interface(lab, guest, args)
    config_text, meta = private_probe.build_secret_config(args, output_dir)
    remote_config = f"/tmp/dynet-{label}-paired.json"
    remote_quality = f"/tmp/dynet-{label}-paired-quality.json" if args.quality_state else None
    guest_files = [remote_config] + ([remote_quality] if remote_quality else [])

    started_at = utc_now()
    started = time.monotonic()
    try:
        private_probe.stage_guest_inputs(
            lab,
            guest,
            remote_config,
            config_text,
            remote_quality,
            args,
        )
        version = private_probe.guest_dynet_version(lab, guest, args)
        pairs = run_pairs(
            lab,
            guest,
            entries,
            remote_config,
            remote_quality,
            report_dir,
            started,
            args,
        )
    finally:
        private_probe.cleanup_guest_files(
            lab,
            guest,
            guest_files,
            user=args.user,
            source=args.source,
        )

    ended_at = utc_now()
    write_outputs(
        output_dir,
        manifest,
        entries,
        pairs,
        meta,
        version,
        started_at,
        ended_at,
        args,
    )


def task_output_dir(raw: str | None, label: str) -> Path:
    base = (ROOT / ".task" / "resources").resolve(strict=False)
    if raw:
        path = Path(raw).expanduser()
        candidate = path if path.is_absolute() else ROOT / path
    else:
        candidate = base / "vm-private-paired" / label
    resolved = candidate.resolve(strict=False)
    if resolved != base and base not in resolved.parents:
        raise CommandError(f"output must stay under .task/resources: {candidate}")
    return resolved


def load_manifest(raw_path: str) -> dict[str, Any]:
    path = Path(raw_path).expanduser()
    if not path.is_absolute():
        path = ROOT / path
    return json.loads(path.read_text())


def selected_entries(manifest: dict[str, Any], args: Any) -> list[dict[str, Any]]:
    probes = set(args.probe_type or DEFAULT_PROBES)
    rows = []
    for entry in manifest.get("entries", []):
        if not isinstance(entry, dict) or entry.get("probe") not in probes:
            continue
        if args.bucket and entry.get("bucket") not in args.bucket:
            continue
        if args.domain and entry.get("domain") not in args.domain:
            continue
        if args.behavior and entry.get("behavior") not in args.behavior:
            continue
        rows.append({**entry, "port": int(entry.get("port") or 443)})
        if args.entry_limit and len(rows) >= args.entry_limit:
            break
    return sorted(rows, key=scheduled_offset_ms)


def add_entry_domains(args: Any, entries: list[dict[str, Any]]) -> None:
    suffixes = set(args.domain_suffix or [])
    for entry in entries:
        domain = str(entry.get("domain") or "")
        if domain:
            suffixes.add(target_family(domain))
    args.domain_suffix = sorted(suffixes)


def maybe_install(lab: Lab, guest: str, args: Any) -> None:
    if args.skip_install:
        return
    artifact = private_probe.build_artifact(lab, args)
    private_probe.install_artifact(lab, guest, artifact, args)


def run_pairs(
    lab: Lab,
    guest: str,
    entries: list[dict[str, Any]],
    remote_config: str,
    remote_quality: str | None,
    report_dir: Path,
    started: float,
    args: Any,
) -> list[dict[str, Any]]:
    pairs = []
    base_offset = scheduled_offset_ms(entries[0]) if entries else 0
    for index, entry in enumerate(entries):
        target_ms = replay_target_ms(entry, base_offset, args)
        sleep_until(target_ms, started)
        pairs.append(
            run_pair(
                lab,
                guest,
                entry,
                index,
                target_ms,
                remote_config,
                remote_quality,
                report_dir,
                started,
                args,
            )
        )
        if not args.respect_schedule and args.spacing_ms > 0:
            time.sleep(args.spacing_ms / 1000)
    return sorted(pairs, key=lambda pair: str(pair.get("id")))


def run_pair(
    lab: Lab,
    guest: str,
    entry: dict[str, Any],
    index: int,
    target_ms: int,
    remote_config: str,
    remote_quality: str | None,
    report_dir: Path,
    started: float,
    args: Any,
) -> dict[str, Any]:
    sides = pair_order(args.side_order, index)
    starts: dict[str, int] = {}
    results: dict[str, dict[str, Any]] = {}
    pair_started_ms = monotonic_offset_ms(started)
    lag_ms = max(0, pair_started_ms - target_ms) if args.respect_schedule else None
    if args.side_mode == "parallel":
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = {
                executor.submit(
                    run_side_with_stagger,
                    lab,
                    guest,
                    entry,
                    side,
                    side_stagger_ms(args, side, sides),
                    lag_ms,
                    remote_config,
                    remote_quality,
                    report_dir,
                    started,
                    args,
                ): side
                for side in sides
            }
            for future in as_completed(futures):
                side = futures[future]
                starts[side], results[side] = future.result()
    else:
        for side in sides:
            starts[side], results[side] = run_side(
                lab,
                guest,
                entry,
                side,
                lag_ms,
                remote_config,
                remote_quality,
                report_dir,
                started,
                args,
            )
    return {
        "id": entry.get("id"),
        "bucket": entry.get("bucket"),
        "domain": entry.get("domain"),
        "probe": entry.get("probe"),
        "targetStartOffsetMs": target_ms if args.respect_schedule else None,
        "pairStartedOffsetMs": pair_started_ms if args.respect_schedule else None,
        "pairLagMs": lag_ms,
        "sideMode": args.side_mode,
        "sideOrder": sides,
        "parallelSideStaggerMs": args.parallel_side_stagger_ms,
        "pairGapMs": abs(starts.get("clash", 0) - starts.get("dynet", 0)),
        "clash": results["clash"],
        "dynet": results["dynet"],
    }


def run_side_with_stagger(
    lab: Lab,
    guest: str,
    entry: dict[str, Any],
    side: str,
    stagger_ms: int,
    lag_ms: int | None,
    remote_config: str,
    remote_quality: str | None,
    report_dir: Path,
    started: float,
    args: Any,
) -> tuple[int, dict[str, Any]]:
    if stagger_ms > 0:
        time.sleep(stagger_ms / 1000)
    return run_side(
        lab,
        guest,
        entry,
        side,
        lag_ms,
        remote_config,
        remote_quality,
        report_dir,
        started,
        args,
    )


def run_side(
    lab: Lab,
    guest: str,
    entry: dict[str, Any],
    side: str,
    lag_ms: int | None,
    remote_config: str,
    remote_quality: str | None,
    report_dir: Path,
    started: float,
    args: Any,
) -> tuple[int, dict[str, Any]]:
    actual_ms = monotonic_offset_ms(started)
    if side == "clash":
        return actual_ms, run_clash_probe(entry, args.timeout_seconds, lag_ms, None, actual_ms)
    result = run_guest_dynet_probe(
        lab,
        guest,
        entry,
        remote_config,
        remote_quality,
        report_dir,
        actual_ms,
        lag_ms,
        args,
    )
    return actual_ms, result


def run_guest_dynet_probe(
    lab: Lab,
    guest: str,
    entry: dict[str, Any],
    remote_config: str,
    remote_quality: str | None,
    report_dir: Path,
    actual_ms: int,
    lag_ms: int | None,
    args: Any,
) -> dict[str, Any]:
    started = time.monotonic()
    url = entry_url(entry)
    command = [
        args.dynet_bin,
        "probe",
        "--config",
        remote_config,
        "--url",
        url,
        "--protocol",
        dynet_protocol(entry, args),
        "--format",
        "json",
    ]
    if remote_quality:
        command.extend(["--quality-state", remote_quality])
    result = guest_ssh(
        lab,
        guest,
        join(command),
        user=args.user,
        source=args.source,
        check=False,
        capture=True,
    )
    report = parse_report(result)
    report["_exitCode"] = result.returncode
    path = report_dir / f"{safe_slug(str(entry.get('id') or entry.get('domain')))}.json"
    private_probe.write_json(path, private_probe.clean_report(report))
    return dynet_result(entry, url, report, path, actual_ms, lag_ms, started)


def parse_report(result: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        return {
            "schema": "dynet-probe/invalid-output",
            "status": "deny",
            "reason": f"invalid dynet probe JSON: {error}; stderr={result.stderr.strip()}",
            "events": [],
        }


def dynet_result(
    entry: dict[str, Any],
    url: str,
    report: dict[str, Any],
    path: Path,
    actual_ms: int,
    lag_ms: int | None,
    started: float,
) -> dict[str, Any]:
    status = str(report.get("status") or "")
    return {
        "id": entry.get("id"),
        "bucket": entry.get("bucket"),
        "domain": entry.get("domain"),
        "behavior": entry.get("behavior"),
        "probe": entry.get("probe"),
        "targetUrl": url,
        "actualStartOffsetMs": actual_ms,
        "scheduleLagMs": lag_ms,
        "status": status,
        "ok": status == "pass",
        "elapsedMs": round((time.monotonic() - started) * 1000),
        "exitCode": report.get("_exitCode"),
        "boundSelected": final_bound_selected(report),
        "failedStage": None if status == "pass" else failed_stage(report),
        "failureScope": failure_scope(report),
        "runtimeCarrier": "linux-interface-bound",
        "reportPath": str(path),
    }


def pair_order(mode: str, index: int) -> list[str]:
    if mode == "clash-first":
        return ["clash", "dynet"]
    if mode == "dynet-first":
        return ["dynet", "clash"]
    return ["clash", "dynet"] if index % 2 == 0 else ["dynet", "clash"]


def side_stagger_ms(args: Any, side: str, sides: list[str]) -> int:
    if args.side_mode != "parallel" or side == sides[0]:
        return 0
    return max(0, int(args.parallel_side_stagger_ms or 0))


def replay_target_ms(entry: dict[str, Any], base_offset: int, args: Any) -> int:
    if not args.respect_schedule:
        return 0
    return round(max(0, scheduled_offset_ms(entry) - base_offset) * args.schedule_scale)


def scheduled_offset_ms(entry: dict[str, Any]) -> int:
    return int(entry.get("scheduledOffsetMs") or 0)


def sleep_until(target_ms: int, started: float) -> None:
    sleep_ms = target_ms - monotonic_offset_ms(started)
    if sleep_ms > 0:
        time.sleep(sleep_ms / 1000)


def monotonic_offset_ms(started: float) -> int:
    return round((time.monotonic() - started) * 1000)


def dynet_protocol(entry: dict[str, Any], args: Any) -> str:
    if args.dynet_protocol != "source":
        return str(args.dynet_protocol)
    return str(entry.get("probe") or "https-head")


def entry_url(entry: dict[str, Any]) -> str:
    if entry.get("url"):
        return str(entry["url"])
    domain = str(entry.get("domain") or "")
    return f"https://{domain}/"


def target_family(domain: str) -> str:
    labels = [item for item in domain.lower().strip(".").split(".") if item]
    return ".".join(labels[-2:]) if len(labels) >= 2 else (labels[0] if labels else "<unknown>")


def target_hosts(rows: list[dict[str, Any]]) -> list[str]:
    return sorted({urlparse(str(row.get("targetUrl") or "")).hostname or "" for row in rows} - {""})


def safe_slug(value: str) -> str:
    return "".join(char if char.isalnum() or char in ".-" else "-" for char in value)
