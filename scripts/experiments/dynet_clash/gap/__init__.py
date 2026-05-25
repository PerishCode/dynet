from __future__ import annotations

import argparse
import datetime as dt
import json
import math
from collections import Counter
from pathlib import Path
from typing import Any

from dynet_clash import attribution, batch, batch_scope


SCHEMA = "dynet-clash-product-effect-gap/v1alpha1"
DEFAULT_OUTPUT_JSON = ".task/resources/dynet-clash-product-effect-gap.json"
DEFAULT_OUTPUT_MD = ".task/resources/dynet-clash-product-effect-gap.md"


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True))


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def build(args: argparse.Namespace) -> dict[str, Any]:
    paths = [Path(path) for path in args.comparison]
    reports = [load_json(path) for path in paths]
    return build_from_reports(reports, args, paths)


def build_from_reports(
    reports: list[dict[str, Any]],
    args: argparse.Namespace,
    paths: list[Path] | None = None,
) -> dict[str, Any]:
    input_paths = paths or [
        Path(f"comparison-{index + 1}.json") for index in range(len(reports))
    ]
    windows = [
        window(index, path, report, args)
        for index, (path, report) in enumerate(zip(input_paths, reports), start=1)
    ]
    primary = aggregate_primary(windows, args.primary_bucket)
    aggregate_delta = float(primary.get("successRateDelta") or 0)
    return {
        "schema": SCHEMA,
        "generatedAt": utc_now(),
        "inputs": [str(path) for path in input_paths],
        "thresholds": {
            "primaryBucket": args.primary_bucket,
            "minSuperiorDelta": args.min_superior_delta,
        },
        "privacy": {
            "rawResultsStored": False,
            "responseBodiesStored": False,
            "sourceAddressesStored": False,
        },
        "conclusion": conclusion(
            aggregate_delta,
            args.min_superior_delta,
            int(primary.get("clash", {}).get("count") or 0),
        ),
        "primary": primary,
        "windows": windows,
        "runtimeGate": batch_scope.runtime_batch(windows),
        "outcomeBalance": aggregate_outcomes(windows),
        "byDomainProbe": aggregate_domain_probe(windows),
        "clashFailureSurfaces": aggregate_rows(windows, "clashFailureSurfaces"),
        "dynetFailureSurfaces": aggregate_rows(windows, "dynetFailureSurfaces"),
    }


def window(
    index: int,
    path: Path,
    report: dict[str, Any],
    args: argparse.Namespace,
) -> dict[str, Any]:
    inputs = report.get("inputs", {})
    clash_summary = load_optional_summary(inputs.get("clashSummary"))
    dynet_summary = load_optional_summary(inputs.get("dynetSummary"))
    pairs = load_optional_summary(infer_pairs_path(inputs.get("dynetSummary")))
    primary = find_row(report.get("byBucket", []), args.primary_bucket)
    limits = report.get("limitDetails", [])
    product_limits = scoped_limits(limits, "product-effect")
    attribution_limits = scoped_limits(limits, "attribution")
    return {
        "index": index,
        "path": str(path),
        "status": report.get("verdict", {}).get("status"),
        "primaryDelta": report.get("verdict", {}).get("primaryDelta"),
        "primary": primary,
        "productEffectClean": not product_limits,
        "productLimits": product_limits,
        "attributionLimits": attribution_limits,
        "runtimeGate": batch_scope.runtime_window(report.get("dynetRuntimeGate")),
        "pairedReplay": paired_replay(clash_summary, dynet_summary, pairs),
        "outcomeBalance": outcome_balance(pairs, args.primary_bucket),
        "byDomainProbe": domain_probe_balance(pairs, args.primary_bucket),
        "clashFailureSurfaces": clash_surfaces(clash_summary, args.primary_bucket),
        "dynetFailureSurfaces": dynet_surfaces(dynet_summary, args.primary_bucket),
    }


def load_optional_summary(path: Any) -> dict[str, Any]:
    if not path:
        return {}
    raw = Path(str(path))
    if not raw.exists():
        return {}
    return load_json(raw)


def infer_pairs_path(dynet_summary_path: Any) -> str | None:
    if not dynet_summary_path:
        return None
    raw = Path(str(dynet_summary_path))
    if raw.name != "summary.json":
        return None
    return str(raw.parent.parent / "pairs.json")


def scoped_limits(details: Any, scope: str) -> list[dict[str, Any]]:
    if not isinstance(details, list):
        return []
    return [
        item
        for item in details
        if isinstance(item, dict) and item.get("scope") == scope
    ]


def paired_replay(
    clash_summary: dict[str, Any],
    dynet_summary: dict[str, Any],
    pairs: dict[str, Any],
) -> dict[str, Any]:
    replay = clash_summary.get("pairedReplay") or dynet_summary.get("pairedReplay") or {}
    if not isinstance(replay, dict):
        replay = {}
    return {
        "present": bool(replay or pairs),
        "pairScheduler": replay.get("pairScheduler") or pairs.get("pairScheduler"),
        "sideMode": replay.get("sideMode") or pairs.get("sideMode"),
        "count": replay.get("count") or pairs.get("count"),
        "pairLagMs": replay.get("pairLagMs") or pairs.get("pairLagMs"),
        "pairGapMs": replay.get("pairGapMs") or pairs.get("pairGapMs"),
        "controllerAttribution": (
            replay.get("controllerAttribution")
            or pairs.get("controllerAttribution")
            or {}
        ),
    }


def outcome_balance(pairs: dict[str, Any], primary_bucket: str) -> dict[str, Any]:
    counts = Counter()
    for item in primary_pair_items(pairs, primary_bucket):
        counts[outcome_key(item)] += 1
    return {
        "count": sum(counts.values()),
        "bothPass": counts["both-pass"],
        "clashOnlyFailure": counts["clash-only-failure"],
        "dynetOnlyFailure": counts["dynet-only-failure"],
        "bothFailure": counts["both-failure"],
        "netDynetFailureAdvantage": (
            counts["clash-only-failure"] - counts["dynet-only-failure"]
        ),
    }


def domain_probe_balance(
    pairs: dict[str, Any],
    primary_bucket: str,
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], Counter[str]] = {}
    for item in primary_pair_items(pairs, primary_bucket):
        key = (str(item.get("domain") or "unknown"), str(item.get("probe") or "unknown"))
        grouped.setdefault(key, Counter())[outcome_key(item)] += 1
    rows = []
    for (domain, probe), counts in grouped.items():
        rows.append({
            "domain": domain,
            "probe": probe,
            "count": sum(counts.values()),
            "clashOnlyFailure": counts["clash-only-failure"],
            "dynetOnlyFailure": counts["dynet-only-failure"],
            "bothFailure": counts["both-failure"],
            "netDynetFailureAdvantage": (
                counts["clash-only-failure"] - counts["dynet-only-failure"]
            ),
        })
    return sorted(rows, key=balance_sort_key)


def primary_pair_items(
    pairs: dict[str, Any],
    primary_bucket: str,
) -> list[dict[str, Any]]:
    return [
        item
        for item in pairs.get("items", [])
        if isinstance(item, dict) and item.get("bucket") == primary_bucket
    ]


def outcome_key(item: dict[str, Any]) -> str:
    clash_failed = not bool(item.get("clashOk"))
    dynet_failed = item.get("dynetStatus") != "pass"
    if clash_failed and dynet_failed:
        return "both-failure"
    if clash_failed:
        return "clash-only-failure"
    if dynet_failed:
        return "dynet-only-failure"
    return "both-pass"


def clash_surfaces(
    summary: dict[str, Any],
    primary_bucket: str,
) -> list[dict[str, Any]]:
    rows = []
    for item in summary.get("failureClusters", []):
        if not isinstance(item, dict) or item.get("bucket") != primary_bucket:
            continue
        rows.append({
            "domain": item.get("domain") or "unknown",
            "probe": item.get("probe") or "unknown",
            "behavior": item.get("behavior") or "unknown",
            "stage": item.get("errorStage") or "unknown",
            "error": item.get("errorType") or "unknown",
            "count": int(item.get("count") or 0),
        })
    return sorted(rows, key=surface_sort_key)


def dynet_surfaces(
    summary: dict[str, Any],
    primary_bucket: str,
) -> list[dict[str, Any]]:
    counts: Counter[tuple[str, str, str, str, str, str]] = Counter()
    for item in summary.get("items", []):
        if (
            not isinstance(item, dict)
            or item.get("bucket") != primary_bucket
            or item.get("status") == "pass"
        ):
            continue
        counts[(
            str(item.get("domain") or "unknown"),
            str(item.get("sourceProbe") or "unknown"),
            str(item.get("failedStage") or "unknown"),
            str(item.get("failureScope") or "unknown"),
            str(item.get("selectedOutbound") or "unknown"),
            attribution.reason_marker(item.get("reason")),
        )] += 1
    rows = [
        {
            "domain": domain,
            "probe": probe,
            "stage": stage,
            "scope": scope,
            "outbound": outbound,
            "reasonMarker": reason,
            "count": count,
        }
        for (domain, probe, stage, scope, outbound, reason), count in counts.items()
    ]
    return sorted(rows, key=surface_sort_key)


def aggregate_primary(
    windows: list[dict[str, Any]],
    primary_bucket: str,
) -> dict[str, Any]:
    clash = batch.sum_side(
        (window.get("primary") or {}).get("clash", {}) for window in windows
    )
    dynet = batch.sum_side(
        (window.get("primary") or {}).get("dynet", {}) for window in windows
    )
    return batch.compare_totals(primary_bucket, clash, dynet)


def aggregate_outcomes(windows: list[dict[str, Any]]) -> dict[str, Any]:
    total = Counter()
    for window in windows:
        outcome = window.get("outcomeBalance", {})
        total["count"] += int(outcome.get("count") or 0)
        total["bothPass"] += int(outcome.get("bothPass") or 0)
        total["clashOnlyFailure"] += int(outcome.get("clashOnlyFailure") or 0)
        total["dynetOnlyFailure"] += int(outcome.get("dynetOnlyFailure") or 0)
        total["bothFailure"] += int(outcome.get("bothFailure") or 0)
    total["netDynetFailureAdvantage"] = (
        total["clashOnlyFailure"] - total["dynetOnlyFailure"]
    )
    return dict(total)


def aggregate_domain_probe(windows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    totals: dict[tuple[str, str], Counter[str]] = {}
    for window in windows:
        for row in window.get("byDomainProbe", []):
            key = (str(row.get("domain") or "unknown"), str(row.get("probe") or "unknown"))
            counter = totals.setdefault(key, Counter())
            counter["count"] += int(row.get("count") or 0)
            counter["clashOnlyFailure"] += int(row.get("clashOnlyFailure") or 0)
            counter["dynetOnlyFailure"] += int(row.get("dynetOnlyFailure") or 0)
            counter["bothFailure"] += int(row.get("bothFailure") or 0)
    rows = []
    for (domain, probe), counter in totals.items():
        rows.append({
            "domain": domain,
            "probe": probe,
            "count": counter["count"],
            "clashOnlyFailure": counter["clashOnlyFailure"],
            "dynetOnlyFailure": counter["dynetOnlyFailure"],
            "bothFailure": counter["bothFailure"],
            "netDynetFailureAdvantage": (
                counter["clashOnlyFailure"] - counter["dynetOnlyFailure"]
            ),
        })
    return sorted(rows, key=balance_sort_key)


def aggregate_rows(
    windows: list[dict[str, Any]],
    key: str,
) -> list[dict[str, Any]]:
    counts: Counter[tuple[tuple[str, str], ...]] = Counter()
    for window in windows:
        for row in window.get(key, []):
            identity = tuple(
                sorted(
                    (field, str(value))
                    for field, value in row.items()
                    if field != "count"
                )
            )
            counts[identity] += int(row.get("count") or 0)
    rows = [
        {**{field: value for field, value in identity}, "count": count}
        for identity, count in counts.items()
    ]
    return sorted(rows, key=surface_sort_key)


def conclusion(
    delta: float,
    min_superior_delta: float,
    primary_count: int,
) -> dict[str, Any]:
    gap = round(max(0.0, min_superior_delta - delta), 4)
    if delta >= min_superior_delta:
        status = "superior-supported"
    elif delta >= 0:
        status = "parity-supported-superior-gap"
    else:
        status = "below-parity"
    return {
        "status": status,
        "aggregatePrimaryDelta": round(delta, 4),
        "minSuperiorDelta": min_superior_delta,
        "superiorDeltaGap": gap,
        "additionalNetSuccessesForSuperior": math.ceil(gap * primary_count),
    }


def find_row(rows: list[dict[str, Any]], key: str) -> dict[str, Any] | None:
    return next((row for row in rows if row.get("key") == key), None)


def balance_sort_key(row: dict[str, Any]) -> tuple[int, int, str, str]:
    return (
        -abs(int(row.get("netDynetFailureAdvantage") or 0)),
        -int(row.get("count") or 0),
        str(row.get("domain") or ""),
        str(row.get("probe") or ""),
    )


def surface_sort_key(row: dict[str, Any]) -> tuple[int, str]:
    return (-int(row.get("count") or 0), json.dumps(row, sort_keys=True))


def write_markdown(path: Path, report: dict[str, Any]) -> None:
    lines = [
        "# Dynet vs Clash Product-Effect Gap",
        "",
        f"- Conclusion: `{report['conclusion']['status']}`",
        f"- Aggregate primary delta: `{report['conclusion']['aggregatePrimaryDelta']}`",
        f"- Superior delta gap: `{report['conclusion']['superiorDeltaGap']}`",
        f"- Additional net successes for superior: "
        f"`{report['conclusion']['additionalNetSuccessesForSuperior']}`",
        f"- Primary: {primary_line(report['primary'])}",
        "",
        "## Outcome Balance",
        "",
        outcome_line(report["outcomeBalance"]),
        "",
        "## Domain Probe Balance",
        "",
    ]
    for row in report["byDomainProbe"][:12]:
        lines.append(balance_line(row))
    append_surfaces(lines, "Clash Failure Surfaces", report["clashFailureSurfaces"])
    append_surfaces(lines, "Dynet Failure Surfaces", report["dynetFailureSurfaces"])
    path.write_text("\n".join(lines) + "\n")


def primary_line(row: dict[str, Any]) -> str:
    return (
        f"clash=`{row['clash']['success']}/{row['clash']['count']}` "
        f"dynet=`{row['dynet']['success']}/{row['dynet']['count']}` "
        f"delta=`{row['successRateDelta']}`"
    )


def outcome_line(row: dict[str, Any]) -> str:
    return (
        f"- count=`{row['count']}` bothPass=`{row['bothPass']}` "
        f"clashOnlyFailure=`{row['clashOnlyFailure']}` "
        f"dynetOnlyFailure=`{row['dynetOnlyFailure']}` "
        f"bothFailure=`{row['bothFailure']}` "
        f"netDynetFailureAdvantage=`{row['netDynetFailureAdvantage']}`"
    )


def balance_line(row: dict[str, Any]) -> str:
    return (
        f"- `{row['domain']}` probe=`{row['probe']}` count=`{row['count']}` "
        f"clashOnlyFailure=`{row['clashOnlyFailure']}` "
        f"dynetOnlyFailure=`{row['dynetOnlyFailure']}` "
        f"bothFailure=`{row['bothFailure']}` "
        f"net=`{row['netDynetFailureAdvantage']}`"
    )


def append_surfaces(
    lines: list[str],
    title: str,
    rows: list[dict[str, Any]],
) -> None:
    lines.extend(["", f"## {title}", ""])
    for row in rows[:12]:
        compact = " ".join(
            f"{key}=`{value}`"
            for key, value in row.items()
            if key != "count"
        )
        lines.append(f"- count=`{row['count']}` {compact}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Explain product-effect gap between dynet parity and superiority."
    )
    parser.add_argument("--comparison", action="append", required=True)
    parser.add_argument("--output-json", default=DEFAULT_OUTPUT_JSON)
    parser.add_argument("--output-md", default=DEFAULT_OUTPUT_MD)
    parser.add_argument("--primary-bucket", default="github-proof")
    parser.add_argument("--min-superior-delta", type=float, default=0.05)
    return parser


def command(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = build(args)
    output_json = Path(args.output_json)
    output_md = Path(args.output_md)
    write_json(output_json, report)
    write_markdown(output_md, report)
    print(json.dumps({
        "outputJson": str(output_json),
        "outputMd": str(output_md),
        "conclusion": report["conclusion"]["status"],
        "primaryDelta": report["conclusion"]["aggregatePrimaryDelta"],
        "superiorDeltaGap": report["conclusion"]["superiorDeltaGap"],
    }, sort_keys=True))
    return 0
