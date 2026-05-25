from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from dynet_clash.paired_surface.boundary import (
    actionable_pressure_conclusion,
    pressure_boundaries,
)


SCHEMA = "dynet-clash-paired-read-surface-batch/v1alpha1"
DEFAULT_OUTPUT_JSON = ".task/resources/dynet-clash-paired-read-surface-batch.json"
DEFAULT_OUTPUT_MD = ".task/resources/dynet-clash-paired-read-surface-batch.md"


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True))


def command(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    summary = build(args)
    write_json(Path(args.output_json), summary)
    write_markdown(Path(args.output_md), summary)
    print(json.dumps({
        "outputJson": args.output_json,
        "outputMd": args.output_md,
        "status": summary["conclusion"]["status"],
        "readFailureCount": summary["totals"]["readFailureCount"],
    }, sort_keys=True))
    return 0 if summary["sourceCount"] else 1


def build(args: argparse.Namespace) -> dict[str, Any]:
    pair_paths = [Path(path) for path in args.pairs or []]
    followup_paths = [Path(path) for path in args.followup or []]
    if len(pair_paths) != len(followup_paths):
        raise SystemExit("--pairs and --followup must be provided the same number of times")
    labels = labels_from_args(args, pair_paths)
    return paired_read_surface_batch(pair_paths, followup_paths, labels)


def labels_from_args(args: argparse.Namespace, pair_paths: list[Path]) -> list[str]:
    raw = list(args.label or [])
    if raw and len(raw) != len(pair_paths):
        raise SystemExit("--label must match --pairs count when provided")
    return raw or [path.parent.name for path in pair_paths]


def paired_read_surface_batch(
    pair_paths: list[Path],
    followup_paths: list[Path],
    labels: list[str],
) -> dict[str, Any]:
    sources = [
        paired_read_surface_source(pair_path, followup_path, label)
        for pair_path, followup_path, label in zip(pair_paths, followup_paths, labels)
    ]
    items = [item for source in sources for item in source["items"]]
    failures = [failure for source in sources for failure in source["readFailures"]]
    by_position = count_by_item_key(items, "dynetPosition")
    by_order = count_by_item_key(items, "sideOrderKey")
    by_stagger = count_by_item_key(items, "parallelSideStaggerMs")
    by_source = [source_summary(source) for source in sources]
    surfaces = count_surfaces(failures)
    boundaries = pressure_boundaries(sources)
    boundary = boundaries["actionable"]
    return {
        "schema": SCHEMA,
        "sourceCount": len(sources),
        "totals": totals(sources, items, failures),
        "conclusion": conclusion(by_position, surfaces, failures),
        "actionableConclusion": actionable_pressure_conclusion(boundaries),
        "byDynetPosition": by_position,
        "bySideOrder": by_order,
        "byParallelSideStaggerMs": by_stagger,
        "bySource": by_source,
        "pressureBoundary": boundary,
        "pressureBoundaries": boundaries,
        "readFailureSurfaces": surfaces,
        "sources": sources,
        "privacy": {
            "rawLogsStored": False,
            "rawSecretsStored": False,
            "responseBodiesStored": False,
        },
    }


def paired_read_surface_source(
    pair_path: Path,
    followup_path: Path,
    label: str,
) -> dict[str, Any]:
    pairs = load_json(pair_path)
    followup = load_json(followup_path)
    pair_items = [normalize_pair_item(item, pairs) for item in pairs.get("items", [])]
    failures = [
        normalize_failure(source, pair_items)
        for source in followup_sources(followup)
        if isinstance(source.get("readFailure"), dict) and source["readFailure"]
    ]
    failures_by_id = failure_count_by_id(failures)
    for item in pair_items:
        item["readFailureCount"] = failures_by_id.get(item["id"], 0)
    return {
        "label": label,
        "configFreshness": config_freshness(label),
        "pairs": str(pair_path),
        "followup": str(followup_path),
        "sideMode": str(pairs.get("sideMode") or ""),
        "sideOrder": pairs.get("sideOrder"),
        "parallelSideStaggerMs": int_or_zero(pairs.get("parallelSideStaggerMs")),
        "pairLagMs": pairs.get("pairLagMs") or {},
        "pairGapMs": pairs.get("pairGapMs") or {},
        "count": len(pair_items),
        "readFailureCount": len(failures),
        "readFailures": failures,
        "items": pair_items,
    }


def source_summary(source: dict[str, Any]) -> dict[str, Any]:
    items = source.get("items") or []
    has_clash = any(item.get("clashOk") is not None for item in items)
    clash_passed = sum(1 for item in items if item.get("clashOk")) if has_clash else None
    dynet_passed = sum(1 for item in items if item.get("dynetStatus") == "pass")
    count = len(items)
    clash_failed = count - clash_passed if clash_passed is not None else None
    dynet_failed = count - dynet_passed
    read_failures = int(source.get("readFailureCount") or 0)
    return {
        "label": source.get("label", ""),
        "configFreshness": source.get("configFreshness", "legacy-or-unspecified"),
        "count": count,
        "clashPassed": clash_passed,
        "clashFailed": clash_failed,
        "dynetPassed": dynet_passed,
        "dynetFailed": dynet_failed,
        "readFailureCount": read_failures,
        "sourceKind": "paired" if has_clash else "dynet-only",
        "productShape": product_shape(read_failures, clash_failed, dynet_failed),
        "sideMode": source.get("sideMode", ""),
        "sideOrder": source.get("sideOrder"),
        "parallelSideStaggerMs": source.get("parallelSideStaggerMs", 0),
        "pairLagMs": source.get("pairLagMs") or {},
        "pairGapMs": source.get("pairGapMs") or {},
    }


def product_shape(
    read_failures: int,
    clash_failed: int | None,
    dynet_failed: int,
) -> str:
    if read_failures > 0:
        return "dynet-read-failures"
    if clash_failed is None:
        return "dynet-only-product-failures" if dynet_failed > 0 else "dynet-only-clean"
    if dynet_failed == 0 and clash_failed > 0:
        return "dynet-clean-clash-failures"
    if dynet_failed > 0 and clash_failed > 0:
        return "both-product-failures"
    if dynet_failed > 0:
        return "dynet-product-failures"
    return "clean"


def config_freshness(label: str) -> str:
    if "fresh-config" in label:
        return "fresh-config"
    if "saved-config-drift" in label:
        return "saved-config-drift"
    return "legacy-or-unspecified"


def normalize_pair_item(item: dict[str, Any], pairs: dict[str, Any]) -> dict[str, Any]:
    side_order = side_order_list(item.get("sideOrder"))
    position = dynet_position(side_order)
    return {
        "id": str(item.get("id") or ""),
        "domain": str(item.get("domain") or ""),
        "probe": str(item.get("probe") or item.get("dynetProtocol") or item.get("sourceProbe") or ""),
        "dynetStatus": str(item.get("dynetStatus") or item.get("status") or ""),
        "clashOk": bool(item.get("clashOk")) if "clashOk" in item else None,
        "sideMode": str(item.get("sideMode") or pairs.get("sideMode") or ""),
        "sideOrder": side_order,
        "sideOrderKey": ",".join(side_order) if side_order else "unknown",
        "dynetPosition": position,
        "parallelSideStaggerMs": int_or_zero(
            item.get("parallelSideStaggerMs", pairs.get("parallelSideStaggerMs")),
        ),
        "pairLagMs": int_or_none(item.get("pairLagMs")),
        "pairGapMs": int_or_none(item.get("pairGapMs")),
    }


def normalize_failure(
    source: dict[str, Any],
    pair_items: list[dict[str, Any]],
) -> dict[str, Any]:
    failure = source["readFailure"]
    item = item_for_report_path(str(source.get("path") or ""), pair_items)
    return {
        "id": item.get("id", ""),
        "domain": item.get("domain", ""),
        "probe": item.get("probe", ""),
        "path": str(source.get("path") or ""),
        "sideMode": item.get("sideMode", ""),
        "sideOrder": item.get("sideOrder", []),
        "sideOrderKey": item.get("sideOrderKey", "unknown"),
        "dynetPosition": item.get("dynetPosition", "unknown"),
        "parallelSideStaggerMs": item.get("parallelSideStaggerMs", 0),
        "pairLagMs": item.get("pairLagMs"),
        "pairGapMs": item.get("pairGapMs"),
        "marker": str(failure.get("marker") or ""),
        "disposition": str(failure.get("disposition") or ""),
        "protocolStage": str(failure.get("protocolStage") or ""),
        "context": str(failure.get("context") or ""),
        "stage": str(failure.get("stage") or ""),
        "outbound": str(failure.get("outbound") or ""),
        "pendingBudgetMs": int_or_zero(failure.get("pendingBudgetMs")),
    }


def followup_sources(summary: dict[str, Any]) -> list[dict[str, Any]]:
    report = summary.get("reportEvidence") or {}
    return [item for item in report.get("sources", []) if isinstance(item, dict)]


def item_for_report_path(path: str, pair_items: list[dict[str, Any]]) -> dict[str, Any]:
    name = Path(path).name
    for item in pair_items:
        item_id = str(item.get("id") or "")
        if item_id and (name == f"{item_id}.json" or name.startswith(f"{item_id}-")):
            return item
    return {}


def failure_count_by_id(failures: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for failure in failures:
        item_id = str(failure.get("id") or "")
        if item_id:
            counts[item_id] = counts.get(item_id, 0) + 1
    return counts


def count_by_item_key(items: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    rows: dict[str, dict[str, int | str]] = {}
    for item in items:
        value = str(item.get(key) if item.get(key) is not None else "unknown")
        row = rows.setdefault(value, {"key": value, "items": 0, "readFailures": 0})
        row["items"] = int(row["items"]) + 1
        row["readFailures"] = int(row["readFailures"]) + int(item.get("readFailureCount") or 0)
    return [with_rate(row) for row in sorted(rows.values(), key=lambda item: str(item["key"]))]


def with_rate(row: dict[str, int | str]) -> dict[str, int | float | str]:
    items = int(row["items"])
    failures = int(row["readFailures"])
    return {
        **row,
        "failureRate": round(failures / items, 4) if items else 0,
    }


def count_surfaces(failures: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: dict[tuple[str, str, str, str, str], int] = {}
    for failure in failures:
        key = (
            str(failure.get("marker") or ""),
            str(failure.get("disposition") or ""),
            str(failure.get("protocolStage") or ""),
            str(failure.get("context") or ""),
            str(failure.get("stage") or ""),
        )
        counts[key] = counts.get(key, 0) + 1
    return [
        {
            "marker": marker,
            "disposition": disposition,
            "protocolStage": protocol_stage,
            "context": context,
            "stage": stage,
            "count": count,
        }
        for (marker, disposition, protocol_stage, context, stage), count in sorted(counts.items())
    ]


def conclusion(
    by_position: list[dict[str, Any]],
    surfaces: list[dict[str, Any]],
    failures: list[dict[str, Any]],
) -> dict[str, Any]:
    failure_count = len(failures)
    failure_positions = {
        str(item.get("dynetPosition") or "unknown")
        for item in failures
    }
    if failure_count == 0:
        status = "paired-read-surface-clean"
    elif failure_positions == {"second"} and failure_count >= 2:
        status = surface_status("dynet-later-read-surface-repeat", surfaces)
    elif failure_count >= 2:
        status = surface_status("paired-read-surface-repeat", surfaces)
    elif failure_positions == {"second"}:
        status = "dynet-later-read-surface-observed-once"
    else:
        status = "paired-read-surface-observed-once"
    return {
        "status": status,
        "readFailureCount": failure_count,
        "surfaceKinds": len(surfaces),
        "failurePositions": sorted(failure_positions),
        "dynetFirstItems": item_count(by_position, "first"),
        "dynetFirstReadFailures": failure_count_for(by_position, "first"),
        "dynetSecondItems": item_count(by_position, "second"),
        "dynetSecondReadFailures": failure_count_for(by_position, "second"),
        "classificationClean": all(
            failure.get("marker") and failure.get("disposition")
            for failure in failures
        ),
    }


def surface_status(prefix: str, surfaces: list[dict[str, Any]]) -> str:
    return f"{prefix}-stable" if len(surfaces) == 1 else f"{prefix}-drift"


def item_count(rows: list[dict[str, Any]], key: str) -> int:
    return int(next((row.get("items", 0) for row in rows if row.get("key") == key), 0))


def failure_count_for(rows: list[dict[str, Any]], key: str) -> int:
    return int(next((row.get("readFailures", 0) for row in rows if row.get("key") == key), 0))


def totals(
    sources: list[dict[str, Any]],
    items: list[dict[str, Any]],
    failures: list[dict[str, Any]],
) -> dict[str, int]:
    return {
        "windows": len(sources),
        "items": len(items),
        "windowsWithReadFailure": sum(1 for source in sources if source["readFailureCount"] > 0),
        "readFailureCount": len(failures),
        "readFailureClassified": sum(
            1 for failure in failures if failure.get("marker") and failure.get("disposition")
        ),
    }


def side_order_list(raw: Any) -> list[str]:
    if isinstance(raw, list):
        return [str(item) for item in raw]
    return []


def dynet_position(side_order: list[str]) -> str:
    if "dynet" not in side_order:
        return "unknown"
    return "first" if side_order.index("dynet") == 0 else "second"


def int_or_zero(value: Any) -> int:
    number = int_or_none(value)
    return number if number is not None else 0


def int_or_none(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def write_markdown(path: Path, summary: dict[str, Any]) -> None:
    lines = [
        "# Dynet/Clash Paired Read Surface Batch",
        "",
        f"- status: `{summary['conclusion']['status']}`",
        f"- actionable status: `{summary['actionableConclusion']['status']}`",
        f"- actionable action: `{summary['actionableConclusion']['action']}`",
        f"- windows: `{summary['totals']['windows']}`",
        f"- items: `{summary['totals']['items']}`",
        f"- read failures: `{summary['totals']['readFailureCount']}`",
        "",
        "## Dynet Position",
        "",
    ]
    for row in summary["byDynetPosition"]:
        lines.append(
            f"- `{row['key']}` items=`{row['items']}` "
            f"readFailures=`{row['readFailures']}` rate=`{row['failureRate']}`"
        )
    lines.extend(["", "## Read Surfaces", ""])
    for row in summary["readFailureSurfaces"]:
        lines.append(
            f"- marker=`{row['marker']}` disposition=`{row['disposition']}` "
            f"protocolStage=`{row['protocolStage']}` context=`{row['context']}` "
            f"stage=`{row['stage']}` "
            f"count=`{row['count']}`"
        )
    boundary = summary["pressureBoundary"]
    lines.extend([
        "",
        "## Pressure Boundary",
        "",
        f"- status: `{boundary['status']}`",
        f"- scope: `{boundary['scope']}`",
        f"- config filter: `{boundary['configFilter']}`",
        f"- max failing stagger ms: `{boundary['maxFailingStaggerMs']}`",
        f"- min clean stagger above failure ms: `{boundary['minCleanStaggerAboveFailureMs']}`",
        f"- boundary gap ms: `{boundary['boundaryGapMs']}`",
    ])
    lines.extend(["", "## Source Summary", ""])
    for source in summary["bySource"]:
        clash = "n/a"
        if source["clashPassed"] is not None:
            clash = f"{source['clashPassed']}/{source['count']}"
        lines.append(
            f"- `{source['label']}` sideMode=`{source['sideMode']}` "
            f"staggerMs=`{source['parallelSideStaggerMs']}` "
            f"configFreshness=`{source['configFreshness']}` "
            f"sourceKind=`{source['sourceKind']}` "
            f"clash=`{clash}` "
            f"dynet=`{source['dynetPassed']}/{source['count']}` "
            f"readFailures=`{source['readFailureCount']}` "
            f"shape=`{source['productShape']}`"
        )
    path.write_text("\n".join(lines) + "\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Join paired replay timing with protocol read-surface follow-up."
    )
    parser.add_argument("--pairs", action="append", required=True)
    parser.add_argument("--followup", action="append", required=True)
    parser.add_argument("--label", action="append")
    parser.add_argument("--output-json", default=DEFAULT_OUTPUT_JSON)
    parser.add_argument("--output-md", default=DEFAULT_OUTPUT_MD)
    return parser
