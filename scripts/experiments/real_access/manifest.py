from __future__ import annotations

import argparse
import random
from pathlib import Path
from typing import Any

from real_access.common import (
    DEFAULT_BEHAVIORS,
    DEFAULT_CONTROL_DOMAINS,
    DEFAULT_PROBES,
    MANIFEST_SCHEMA,
    load_json,
    parse_csv,
    parse_csv_ordered,
    privacy_model,
    utc_now,
)


def load_pools(profile: dict[str, Any], buckets: set[str] | None) -> list[dict[str, Any]]:
    pools = profile.get("experimentProfile", {}).get("samplePools", [])
    selected = []
    for pool in pools:
        if buckets and pool.get("name") not in buckets:
            continue
        domains = [
            domain
            for domain in pool.get("domains", [])
            if isinstance(domain, str) and domain and not domain.startswith("ip:")
        ]
        modes = [
            mode
            for mode in pool.get("probeModes", [])
            if isinstance(mode, str) and mode in DEFAULT_PROBES
        ]
        if "https-head" in modes and "https-get" not in modes:
            modes.append("https-get")
        if domains and modes:
            selected.append({**pool, "domains": domains, "probeModes": modes})
    return selected

def control_pool(args: argparse.Namespace) -> dict[str, Any] | None:
    domains = list(args.control_domain or [])
    if not args.no_default_controls:
        domains.extend(DEFAULT_CONTROL_DOMAINS)
    domains = unique_domains(domains)
    if not domains:
        return None
    return {
        "name": "control-global",
        "weight": args.control_weight,
        "purpose": "stable zero-identity control endpoints",
        "domains": domains,
        "probeModes": list(DEFAULT_PROBES),
    }

def build_manifest(args: argparse.Namespace) -> dict[str, Any]:
    profile_path = Path(args.profile)
    profile = load_json(profile_path)
    pools = load_pools(profile, parse_csv(args.buckets))
    control = control_pool(args)
    if control is not None:
        pools.append(control)
    if not pools:
        raise SystemExit("profile has no selectable sample pools")
    requested_modes = parse_csv(args.probe_modes)
    if requested_modes:
        unsupported = requested_modes - set(DEFAULT_PROBES)
        if unsupported:
            raise SystemExit(f"unsupported probe modes: {', '.join(sorted(unsupported))}")
    behaviors = [
        behavior
        for behavior in parse_csv_ordered(args.behaviors, DEFAULT_BEHAVIORS)
        if behavior in DEFAULT_BEHAVIORS
    ]
    if not behaviors:
        raise SystemExit("no supported workload behaviors selected")
    rng = random.Random(args.seed)
    weights = [max(int(pool.get("weight", 1)), 1) for pool in pools]
    entries = manifest_entries(args, pools, weights, requested_modes, behaviors, rng)
    apply_schedule(entries, args, rng)
    return {
        "schema": MANIFEST_SCHEMA,
        "generatedAt": utc_now(),
        "environment": args.environment,
        "seed": args.seed,
        "profile": {
            "path": str(profile_path),
            "schema": profile.get("schema"),
            "summary": profile.get("summary", {}),
        },
        "privacy": privacy_model(),
        "workload": {
            "version": "v1",
            "durationSeconds": args.duration_seconds,
            "count": args.count,
            "behaviors": behaviors,
            "schedule": "seeded-offsets" if args.duration_seconds > 0 else "spacing-only",
            "burstGroups": args.burst_groups,
            "burstWindowMs": args.burst_window_ms,
            "jitterMs": args.jitter_ms,
            "zeroIdentity": True,
        },
        "sampling": {
            "count": args.count,
            "buckets": sorted({pool["name"] for pool in pools}),
            "probeModes": sorted(requested_modes or DEFAULT_PROBES),
            "controlDomains": control["domains"] if control else [],
        },
        "entries": entries,
    }

def manifest_entries(
    args: argparse.Namespace,
    pools: list[dict[str, Any]],
    weights: list[int],
    requested_modes: set[str] | None,
    behaviors: list[str],
    rng: random.Random,
) -> list[dict[str, Any]]:
    entries = []
    history: list[str] = []
    burst_domains: dict[str, str] = {}
    for index in range(args.count):
        pool = rng.choices(pools, weights=weights, k=1)[0]
        modes = manifest_modes(pool, requested_modes)
        behavior = rng.choice(behaviors)
        domain, burst_id = select_manifest_domain(args, pool, behavior, history, burst_domains, rng)
        probe = rng.choice(modes)
        entries.append(manifest_entry(index, pool, domain, behavior, burst_id, probe, args))
        history.append(domain)
    return entries

def manifest_modes(pool: dict[str, Any], requested_modes: set[str] | None) -> list[str]:
    modes = [
        mode
        for mode in pool["probeModes"]
        if requested_modes is None or mode in requested_modes
    ]
    return modes or list(DEFAULT_PROBES)

def select_manifest_domain(
    args: argparse.Namespace,
    pool: dict[str, Any],
    behavior: str,
    history: list[str],
    burst_domains: dict[str, str],
    rng: random.Random,
) -> tuple[str, str | None]:
    if behavior == "repeat" and history:
        return rng.choice(history), None
    if behavior == "burst":
        burst_id = f"burst-{rng.randrange(max(args.burst_groups, 1)) + 1:02d}"
        return burst_domains.setdefault(burst_id, rng.choice(pool["domains"])), burst_id
    return rng.choice(pool["domains"]), None

def manifest_entry(
    index: int,
    pool: dict[str, Any],
    domain: str,
    behavior: str,
    burst_id: str | None,
    probe: str,
    args: argparse.Namespace,
) -> dict[str, Any]:
    return {
        "id": f"{index + 1:04d}",
        "bucket": pool["name"],
        "domain": domain,
        "behavior": behavior,
        "groupId": burst_id or f"{behavior}-{site_for_domain(domain)}",
        "probe": probe,
        "port": default_port(probe),
        "timeoutMs": int(args.timeout_seconds * 1000),
    }

def unique_domains(values: list[str]) -> list[str]:
    output = []
    seen = set()
    for value in values:
        domain = value.lower().strip(".")
        if domain and domain not in seen:
            seen.add(domain)
            output.append(domain)
    return output

def site_for_domain(domain: str) -> str:
    labels = [label for label in domain.lower().strip(".").split(".") if label]
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return labels[0] if labels else "unknown"

def apply_schedule(
    entries: list[dict[str, Any]],
    args: argparse.Namespace,
    rng: random.Random,
) -> None:
    duration_ms = max(int(args.duration_seconds * 1000), 0)
    if not entries:
        return
    if duration_ms == 0:
        for index, entry in enumerate(entries):
            entry["scheduledOffsetMs"] = index * args.spacing_ms
        return
    burst_bases = {
        entry["groupId"]: rng.randrange(0, duration_ms + 1)
        for entry in entries
        if entry.get("behavior") == "burst"
    }
    for index, entry in enumerate(entries):
        behavior = entry.get("behavior")
        if behavior == "burst":
            base = burst_bases[str(entry["groupId"])]
            offset = base + rng.randrange(0, max(args.burst_window_ms, 1))
        elif behavior == "interval":
            offset = int(index * duration_ms / max(len(entries) - 1, 1))
        else:
            offset = rng.randrange(0, duration_ms + 1)
        if args.jitter_ms:
            offset += rng.randrange(-args.jitter_ms, args.jitter_ms + 1)
        entry["scheduledOffsetMs"] = max(0, min(duration_ms, offset))
    entries.sort(key=lambda item: (int(item["scheduledOffsetMs"]), item["id"]))
    for index, entry in enumerate(entries, start=1):
        entry["id"] = f"{index:04d}"

def default_port(probe: str) -> int | None:
    if probe == "dns":
        return None
    return 443
