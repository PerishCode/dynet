from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from real_access.aggregate import summarize_run
from real_access.reports import write_report

import private_probe


PAIRED_SCHEMA = "dynet-vm-private-paired-product-effect/v1alpha1"
DYNET_SIDE_SCHEMA = "dynet-vm-private-paired-dynet/v1alpha1"
COMPARISON_SCHEMA = "dynet-clash-proof-comparison/v1alpha1"


def write_outputs(
    output_dir: Path,
    manifest: dict[str, Any],
    entries: list[dict[str, Any]],
    pairs: list[dict[str, Any]],
    meta: dict[str, Any],
    version: subprocess.CompletedProcess[str],
    started_at: str,
    ended_at: str,
    args: Any,
) -> None:
    private_probe.write_json(output_dir / "manifest.json", {**manifest, "entries": entries})
    pair_summary = pair_summary_for(pairs, args)
    private_probe.write_json(output_dir / "pairs.json", pair_summary)
    clash_summary = summarize_run(
        summary_manifest(manifest, entries, args),
        [pair["clash"] for pair in pairs],
        started_at,
        ended_at,
    )
    clash_summary["pairedReplay"] = pair_brief(pair_summary)
    private_probe.write_json(output_dir / "clash" / "summary.json", clash_summary)
    write_report(output_dir / "clash" / "report.md", clash_summary)
    dynet_summary = dynet_summary_for(pairs, meta, version, args)
    private_probe.write_json(output_dir / "dynet" / "summary.json", dynet_summary)
    comparison = comparison_summary(clash_summary, dynet_summary, pair_summary)
    private_probe.write_json(output_dir / "comparison.json", comparison)
    write_markdown(output_dir / "summary.md", comparison, pair_summary)
    print(json.dumps(print_summary(output_dir, comparison), sort_keys=True))


def summary_manifest(manifest: dict[str, Any], entries: list[dict[str, Any]], args: Any) -> dict[str, Any]:
    return {
        **manifest,
        "entries": entries,
        "environment": args.clash_environment,
        "seed": manifest.get("seed") or "vm-private-paired",
    }


def dynet_summary_for(
    pairs: list[dict[str, Any]],
    meta: dict[str, Any],
    version: subprocess.CompletedProcess[str],
    args: Any,
) -> dict[str, Any]:
    results = [pair["dynet"] for pair in pairs]
    success = sum(1 for row in results if row.get("ok"))
    failure = len(results) - success
    return {
        "schema": DYNET_SIDE_SCHEMA,
        "runtimeCarrier": "linux-interface-bound",
        "dynetVersion": dynet_version(version),
        "metadata": meta,
        "qualityStateUsed": bool(args.quality_state),
        "privacy": privacy_summary(remote_secret_config_cleaned=True),
        "totals": {
            "count": len(results),
            "success": success,
            "failure": failure,
            "successRate": ratio(success, len(results)),
        },
        "targetHosts": target_hosts(results),
        "results": results,
    }


def comparison_summary(
    clash_summary: dict[str, Any],
    dynet_summary: dict[str, Any],
    pair_summary: dict[str, Any],
) -> dict[str, Any]:
    clash = clash_summary.get("totals", {})
    dynet = dynet_summary.get("totals", {})
    delta = float(dynet.get("successRate") or 0) - float(clash.get("successRate") or 0)
    return {
        "schema": COMPARISON_SCHEMA,
        "status": "dynet-parity-candidate" if delta >= 0 else "below-parity",
        "runtimeCarrier": "linux-interface-bound",
        "targetHosts": dynet_summary.get("targetHosts", []),
        "totals": {
            "key": "all",
            "clash": clash,
            "dynet": dynet,
            "successRateDelta": round(delta, 4),
            "failureDelta": int(dynet.get("failure") or 0) - int(clash.get("failure") or 0),
        },
        "pairedReplay": pair_brief(pair_summary),
        "privacy": {"rawSecretsStored": False, "rawLogsStored": False},
    }


def pair_summary_for(pairs: list[dict[str, Any]], args: Any) -> dict[str, Any]:
    return {
        "schema": PAIRED_SCHEMA,
        "runtimeCarrier": "linux-interface-bound",
        "sideMode": args.side_mode,
        "sideOrder": args.side_order,
        "parallelSideStaggerMs": args.parallel_side_stagger_ms,
        "count": len(pairs),
        "pairGapMs": percentile_summary([int(pair.get("pairGapMs") or 0) for pair in pairs]),
        "items": [
            {
                "id": pair.get("id"),
                "domain": pair.get("domain"),
                "probe": pair.get("probe"),
                "pairLagMs": pair.get("pairLagMs"),
                "pairGapMs": pair.get("pairGapMs"),
                "clashOk": bool(pair.get("clash", {}).get("ok")),
                "dynetOk": bool(pair.get("dynet", {}).get("ok")),
            }
            for pair in pairs
        ],
    }


def pair_brief(summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": summary.get("schema"),
        "runtimeCarrier": summary.get("runtimeCarrier"),
        "sideMode": summary.get("sideMode"),
        "sideOrder": summary.get("sideOrder"),
        "parallelSideStaggerMs": summary.get("parallelSideStaggerMs"),
        "count": summary.get("count"),
        "pairGapMs": summary.get("pairGapMs", {}),
    }


def write_markdown(path: Path, comparison: dict[str, Any], pairs: dict[str, Any]) -> None:
    totals = comparison["totals"]
    lines = [
        "# VM Private Paired Product Effect",
        "",
        f"- status: `{comparison['status']}`",
        f"- runtime carrier: `{comparison['runtimeCarrier']}`",
        f"- clash: `{totals['clash']['success']}/{totals['clash']['count']}`",
        f"- dynet: `{totals['dynet']['success']}/{totals['dynet']['count']}`",
        f"- success rate delta: `{totals['successRateDelta']}`",
        f"- pair gap p95 ms: `{pairs['pairGapMs']['p95']}`",
    ]
    path.write_text("\n".join(lines) + "\n")


def print_summary(output_dir: Path, comparison: dict[str, Any]) -> dict[str, Any]:
    totals = comparison["totals"]
    return {
        "outputDir": str(output_dir),
        "clashPassed": totals["clash"]["success"],
        "dynetPassed": totals["dynet"]["success"],
        "count": totals["clash"]["count"],
        "status": comparison["status"],
    }


def dynet_version(version: subprocess.CompletedProcess[str]) -> str:
    text = (version.stdout or version.stderr).strip()
    return text.splitlines()[-1] if text else ""


def privacy_summary(*, remote_secret_config_cleaned: bool) -> dict[str, bool]:
    return {
        "rawSecretsStored": False,
        "identityInformationSent": False,
        "cookiesSent": False,
        "authorizationSent": False,
        "remoteSecretConfigCleaned": remote_secret_config_cleaned,
    }


def target_hosts(rows: list[dict[str, Any]]) -> list[str]:
    return sorted({urlparse(str(row.get("targetUrl") or "")).hostname or "" for row in rows} - {""})


def ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def percentile_summary(values: list[int]) -> dict[str, int | None]:
    return {
        "p50": percentile(values, 50),
        "p95": percentile(values, 95),
        "max": max(values) if values else None,
    }


def percentile(values: list[int], target: int) -> int | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[round((len(ordered) - 1) * (target / 100))]
