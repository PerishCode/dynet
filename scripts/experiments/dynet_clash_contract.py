#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
from typing import Any


CONTRACT_SCHEMA = "dynet-clash-github-proof-contract/v1alpha1"
DEFAULT_PROFILE = ".task/resources/clash-verge-access-profile.json"
DEFAULT_OUTPUT_JSON = ".task/resources/dynet-clash-github-proof-contract.json"
DEFAULT_OUTPUT_MD = ".task/resources/dynet-clash-github-proof-contract.md"


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True))


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def build_contract(args: argparse.Namespace) -> dict[str, Any]:
    profile_path = Path(args.profile)
    profile = load_json(profile_path)
    return build_contract_from_profile(profile, args, profile_path)


def build_contract_from_profile(
    profile: dict[str, Any],
    args: argparse.Namespace,
    profile_path: Path | None = None,
) -> dict[str, Any]:
    profile_path = profile_path or Path(args.profile)
    primary_site = site_row(profile, args.primary_site)
    primary_domains = matching_domains(profile, args.primary_site, args.primary_limit)
    direct_controls = direct_control_domains(profile, args.control_limit)
    weak_signal = weak_baseline_signal(primary_site, args)
    return {
        "schema": CONTRACT_SCHEMA,
        "generatedAt": utc_now(),
        "privacy": {
            "rawClashLinesStored": False,
            "sourceAddressesStored": False,
            "nodeNamesStored": False,
            "contractReadsDynetState": False,
        },
        "sourceProfile": {
            "path": str(profile_path),
            "schema": profile.get("schema"),
            "source": profile.get("source", {}),
            "summary": profile.get("summary", {}),
        },
        "hypothesis": {
            "name": "github-stable-weak-baseline-can-prove-dynet-plan-superiority",
            "primarySite": args.primary_site,
            "interpretation": (
                "If GitHub weakness is caused by route strategy or path selection, "
                "dynet should reproduce the weakness under Clash-compatible probes "
                "and beat the paired Clash baseline with planner trace evidence."
            ),
            "weakBaselineSignal": weak_signal,
        },
        "targetLanes": {
            "primary": primary_target_lane(args.primary_site, primary_site, primary_domains),
            "directControls": direct_control_lane(direct_controls),
            "backgroundControls": background_control_lane(profile),
        },
        "pairedWindow": {
            "bucketMinutes": args.bucket_minutes,
            "minimumComparableBuckets": args.min_comparable_buckets,
            "comparisonRule": (
                "Only compare dynet and Clash observations that overlap in the same "
                "time bucket and target lane."
            ),
        },
        "metrics": metrics(args),
        "evidenceContract": evidence_contract(),
        "commands": command_hints(args, primary_domains),
        "openRisks": open_risks(),
    }


def site_row(profile: dict[str, Any], site: str) -> dict[str, Any] | None:
    return next((row for row in profile.get("topSites", []) if row.get("site") == site), None)


def matching_domains(profile: dict[str, Any], site: str, limit: int) -> list[dict[str, Any]]:
    rows = [
        row
        for row in profile.get("topDomains", [])
        if row.get("site") == site and not str(row.get("domain", "")).startswith("ip:")
    ]
    return [
        {
            "domain": row.get("domain"),
            "events": int(row.get("count", 0)),
            "warnings": int(row.get("errors", 0)),
            "warningPer100Events": rate(row.get("errors", 0), row.get("count", 0)),
            "activeWindows5m": int(row.get("activeWindows5m", 0)),
            "maxPer5m": int(row.get("maxPer5m", 0)),
            "egressGroups": row.get("egressGroups", []),
            "matches": row.get("matches", []),
        }
        for row in rows[:limit]
    ]


def direct_control_domains(profile: dict[str, Any], limit: int) -> list[dict[str, Any]]:
    candidates = []
    for row in profile.get("topDomains", []):
        if str(row.get("domain", "")).startswith("ip:"):
            continue
        if "DIRECT" not in row.get("egressGroups", []):
            continue
        candidates.append(
            {
                "domain": row.get("domain"),
                "site": row.get("site"),
                "category": row.get("category"),
                "events": int(row.get("count", 0)),
                "warnings": int(row.get("errors", 0)),
                "warningPer100Events": rate(row.get("errors", 0), row.get("count", 0)),
                "activeWindows5m": int(row.get("activeWindows5m", 0)),
                "maxPer5m": int(row.get("maxPer5m", 0)),
                "egressGroups": row.get("egressGroups", []),
            }
        )
    candidates.sort(key=lambda row: (row["warnings"] == 0, row["events"]), reverse=True)
    return candidates[:limit]


def background_control_lane(profile: dict[str, Any]) -> dict[str, Any]:
    sites = [
        compact_site(row)
        for row in profile.get("topSites", [])
        if row.get("category") in {"google", "apple", "microsoft", "music-media-cn"}
    ]
    return {
        "purpose": "detect local network or target-class volatility outside the GitHub lane",
        "sites": sites[:8],
    }


def compact_site(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "site": row.get("site"),
        "category": row.get("category"),
        "events": int(row.get("count", 0)),
        "warnings": int(row.get("errors", 0)),
        "warningPer100Events": rate(row.get("errors", 0), row.get("count", 0)),
        "activeWindows5m": int(row.get("activeWindows5m", 0)),
        "egressGroups": row.get("egressGroups", []),
    }


def weak_baseline_signal(primary_site: dict[str, Any] | None, args: argparse.Namespace) -> dict[str, Any]:
    if primary_site is None:
        return {
            "status": "missing-primary-site",
            "reason": f"profile did not contain site {args.primary_site}",
        }
    events = int(primary_site.get("count", 0))
    warnings = int(primary_site.get("errors", 0))
    active = int(primary_site.get("activeWindows5m", 0))
    status = "stable-weak" if (
        events >= args.min_primary_events
        and warnings >= args.min_primary_warnings
        and active >= args.min_primary_windows
    ) else "insufficient"
    return {
        "status": status,
        "events": events,
        "warnings": warnings,
        "warningPer100Events": rate(warnings, events),
        "activeWindows5m": active,
        "minPrimaryEvents": args.min_primary_events,
        "minPrimaryWarnings": args.min_primary_warnings,
        "minPrimaryWindows": args.min_primary_windows,
    }


def primary_target_lane(
    site: str,
    site_item: dict[str, Any] | None,
    domains: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "site": site,
        "purpose": "high-frequency weak baseline and planner-superiority proof lane",
        "siteSummary": compact_site(site_item) if site_item else None,
        "domains": domains,
        "recommendedProbeModes": ["tcp-connect", "tls-handshake", "https-head"],
        "pairedDynetProbeModes": ["tls-handshake", "https-head"],
        "faultInterpretation": {
            "clashAndDynetBothDegrade": "target-or-probe-suspect",
            "dynetOnlyDegrades": "dynet-infra-or-plan-suspect",
            "clashOnlyDegrades": "dynet-plan-superior-candidate",
        },
    }


def direct_control_lane(domains: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "purpose": "guardrail for local network health and false GitHub attribution",
        "domains": domains,
        "passExpectation": "near-zero timeout increase in paired windows",
    }


def metrics(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "primary": [
            "timeoutRateDelta",
            "p95LatencyDeltaMs",
            "retryCountDelta",
            "failedStageDelta",
        ],
        "successCriteria": {
            "directControlMaxTimeoutRate": args.direct_control_max_timeout_rate,
            "githubTimeoutRateImprovementMin": args.github_timeout_improvement_min,
            "githubP95LatencyImprovementMinMs": args.github_p95_improvement_min_ms,
            "minimumComparableBuckets": args.min_comparable_buckets,
        },
        "decisionRule": (
            "Claim planner superiority only when GitHub improves against Clash in paired "
            "windows, direct controls stay clean, and dynet trace explains the selected "
            "candidate/fallback path."
        ),
    }


def evidence_contract() -> dict[str, Any]:
    return {
        "clashBaselineFields": [
            "bucket",
            "target.host",
            "target.site",
            "rule.match",
            "egress.group",
            "warning.reason",
        ],
        "dynetTraceFields": [
            "probe.id",
            "bucket",
            "target.host",
            "dns.chain",
            "dns.result",
            "route.rule",
            "route.intent",
            "plan.strategy",
            "plan.candidates",
            "plan.selectedCandidate",
            "dial.attempt",
            "dial.elapsedMs",
            "protocol.stage",
            "close.reason",
            "normalizedError.reason",
        ],
        "attributionClasses": [
            "node-suspect",
            "dynet-infra-suspect",
            "plan-suspect",
            "target-or-probe-suspect",
            "experiment-shape-suspect",
            "unknown",
        ],
    }


def command_hints(args: argparse.Namespace, primary_domains: list[dict[str, Any]]) -> dict[str, str]:
    manifest = ".task/resources/github-proof-manifest.json"
    focus = " ".join(
        f"--focus-domain {item['domain']}"
        for item in primary_domains[:3]
        if item.get("domain")
    )
    return {
        "profile": (
            "python3 scripts/experiments/clash_verge_profile.py "
            "--output-json .task/resources/clash-verge-access-profile.json "
            "--output-md .task/resources/clash-verge-access-profile.md"
        ),
        "manifest": (
            "python3 scripts/experiments/real_access_blackbox.py plan "
            f"--profile {args.profile} --buckets work-direct "
            f"{focus} --focus-bucket github-proof --focus-weight 40 "
            "--no-default-controls --control-domain www.cloudflare.com "
            "--control-domain example.com --control-domain www.google.com "
            "--probe-modes tls-handshake,https-head "
            f"--count {args.manifest_count} --duration-seconds {args.manifest_duration_seconds} "
            f"--output {manifest}"
        ),
        "clashRun": (
            "python3 scripts/experiments/real_access_blackbox.py run "
            f"--manifest {manifest} --environment local-clash --label github-proof-clash"
        ),
        "dynetRun": (
            "python3 scripts/experiments/dynet_probe_manifest.py "
            f"--manifest {manifest} --config dynet.json "
            "--output-dir .task/resources/dynet-probe-runs/github-proof"
        ),
    }


def open_risks() -> list[dict[str, str]]:
    return [
        {
            "risk": "black-box-only attribution",
            "mitigation": "require dynet trace fields before blaming plan or node",
        },
        {
            "risk": "target-side or CDN volatility",
            "mitigation": "compare only paired windows and keep direct/background controls",
        },
        {
            "risk": "generic HTTP probes may not match app semantics",
            "mitigation": "prefer tcp/tls/head for zero-identity proof lanes",
        },
    ]


def rate(part: Any, total: Any) -> float:
    total_int = int(total or 0)
    if total_int == 0:
        return 0.0
    return round(int(part or 0) * 100 / total_int, 2)


def write_markdown(path: Path, contract: dict[str, Any]) -> None:
    weak = contract["hypothesis"]["weakBaselineSignal"]
    primary = contract["targetLanes"]["primary"]
    controls = contract["targetLanes"]["directControls"]["domains"]
    lines = [
        "# Dynet vs Clash GitHub Proof Contract",
        "",
        f"- Schema: `{contract['schema']}`",
        f"- Source profile: `{contract['sourceProfile']['path']}`",
        f"- Primary site: `{contract['hypothesis']['primarySite']}`",
        f"- Weak baseline status: `{weak['status']}`",
        f"- Events: `{weak.get('events')}`",
        f"- Warnings: `{weak.get('warnings')}`",
        f"- Warning rate: `{weak.get('warningPer100Events')}` per 100 events",
        f"- Active 5m windows: `{weak.get('activeWindows5m')}`",
        "",
        "## Primary Domains",
        "",
    ]
    for item in primary["domains"]:
        lines.append(
            f"- `{item['domain']}` events={item['events']} warnings={item['warnings']} "
            f"rate={item['warningPer100Events']} active5m={item['activeWindows5m']} "
            f"max5m={item['maxPer5m']}"
        )
    lines.extend(["", "## Direct Controls", ""])
    for item in controls:
        lines.append(
            f"- `{item['domain']}` site=`{item['site']}` events={item['events']} "
            f"warnings={item['warnings']} active5m={item['activeWindows5m']}"
        )
    lines.extend(
        [
            "",
            "## Decision Rule",
            "",
            contract["metrics"]["decisionRule"],
            "",
            "## Required Dynet Trace Fields",
            "",
        ]
    )
    for field in contract["evidenceContract"]["dynetTraceFields"]:
        lines.append(f"- `{field}`")
    lines.extend(["", "## Command Hints", ""])
    for name, command in contract["commands"].items():
        lines.append(f"- `{name}`: `{command}`")
    path.write_text("\n".join(lines) + "\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build a GitHub-focused dynet-vs-Clash proof contract."
    )
    parser.add_argument("--profile", default=DEFAULT_PROFILE)
    parser.add_argument("--output-json", default=DEFAULT_OUTPUT_JSON)
    parser.add_argument("--output-md", default=DEFAULT_OUTPUT_MD)
    parser.add_argument("--primary-site", default="github.com")
    parser.add_argument("--primary-limit", type=int, default=8)
    parser.add_argument("--control-limit", type=int, default=8)
    parser.add_argument("--bucket-minutes", type=int, default=5)
    parser.add_argument("--min-primary-events", type=int, default=500)
    parser.add_argument("--min-primary-warnings", type=int, default=10)
    parser.add_argument("--min-primary-windows", type=int, default=4)
    parser.add_argument("--min-comparable-buckets", type=int, default=4)
    parser.add_argument("--direct-control-max-timeout-rate", type=float, default=0.01)
    parser.add_argument("--github-timeout-improvement-min", type=float, default=0.01)
    parser.add_argument("--github-p95-improvement-min-ms", type=int, default=100)
    parser.add_argument("--manifest-count", type=int, default=96)
    parser.add_argument("--manifest-duration-seconds", type=int, default=300)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    contract = build_contract(args)
    write_json(Path(args.output_json), contract)
    write_markdown(Path(args.output_md), contract)
    print(
        json.dumps(
            {
                "outputJson": args.output_json,
                "outputMd": args.output_md,
                "weakBaseline": contract["hypothesis"]["weakBaselineSignal"]["status"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
