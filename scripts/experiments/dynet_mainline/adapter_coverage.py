from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from dynet_mainline.adapter_coverage_markdown import write_markdown
from dynet_mainline.adapter_coverage_sources import (
    adapter_maturity_source,
    adapter_readiness_source,
    fallback_sources,
    mainline_baseline_source,
    mainline_baseline_summary,
    maturity_summary,
    normalize_type,
    provider_availability_source,
    provider_availability_summary,
    product_effect_source,
    product_summary,
    provider_meta_source,
    provider_summary,
    readiness_summary,
    runtime_repeat_source,
    runtime_repeat_summary,
    unique,
)
from dynet_mainline.runtime_fallback import runtime_fallback_summary
from tunnel_private_config import write_json


SCHEMA = "dynet-mainline-adapter-coverage/v1alpha1"
DEFAULT_EXPECTED_ADAPTERS = ["trojan", "vmess", "ss"]
EXTERNAL_PROVIDER_GAPS = {
    "provider-acquisition-required",
    "current-provider-candidate-missing",
}


def command_mainline_adapter_coverage(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = mainline_adapter_coverage_summary(
        expected_adapter_types=[
            normalize_type(item)
            for item in getattr(args, "expected_adapter_type", []) or DEFAULT_EXPECTED_ADAPTERS
        ],
        mainline_baseline_paths=[
            Path(path) for path in getattr(args, "mainline_baseline", []) or []
        ],
        provider_meta_paths=[
            Path(path) for path in getattr(args, "provider_meta", []) or []
        ],
        provider_availability_paths=[
            Path(path) for path in getattr(args, "provider_availability", []) or []
        ],
        adapter_product_effect_paths=[
            Path(path) for path in getattr(args, "adapter_product_effect", []) or []
        ],
        adapter_readiness_paths=[
            Path(path) for path in getattr(args, "adapter_readiness", []) or []
        ],
        adapter_maturity_paths=[
            Path(path) for path in getattr(args, "adapter_maturity", []) or []
        ],
        runtime_repeat_specs=[
            str(spec) for spec in getattr(args, "runtime_repeat", []) or []
        ],
        runtime_fallback_paths=[
            Path(path) for path in getattr(args, "runtime_fallback", []) or []
        ],
    )
    write_json(output_dir / "summary.json", summary)
    write_markdown(output_dir / "summary.md", summary)
    print(json.dumps(print_summary(output_dir, summary), sort_keys=True))
    return 0 if summary["sourceCount"] else 1


def mainline_adapter_coverage_summary(
    *,
    expected_adapter_types: list[str],
    mainline_baseline_paths: list[Path],
    provider_meta_paths: list[Path],
    provider_availability_paths: list[Path],
    adapter_product_effect_paths: list[Path],
    adapter_readiness_paths: list[Path],
    adapter_maturity_paths: list[Path],
    runtime_repeat_specs: list[str],
    runtime_fallback_paths: list[Path],
) -> dict[str, Any]:
    expected = unique([normalize_type(item) for item in expected_adapter_types if item])
    baseline = mainline_baseline_summary([
        mainline_baseline_source(path) for path in mainline_baseline_paths
    ])
    provider = provider_summary([
        provider_meta_source(path) for path in provider_meta_paths
    ])
    availability = provider_availability_summary([
        provider_availability_source(path) for path in provider_availability_paths
    ])
    product_sources = [
        product_effect_source(path) for path in adapter_product_effect_paths
    ]
    readiness_sources = [
        adapter_readiness_source(path) for path in adapter_readiness_paths
    ]
    maturity_sources = [
        adapter_maturity_source(path) for path in adapter_maturity_paths
    ]
    runtime_sources = [
        runtime_repeat_source(spec) for spec in runtime_repeat_specs
    ]
    fallback = runtime_fallback_summary(fallback_sources(runtime_fallback_paths))
    adapters = adapter_rows(
        expected,
        provider,
        availability,
        product_sources,
        readiness_sources,
        maturity_sources,
        runtime_sources,
    )
    conclusion = coverage_conclusion(expected, adapters)
    return {
        "schema": SCHEMA,
        "sourceCount": (
            baseline["sourceCount"]
            + provider["sourceCount"]
            + availability["sourceCount"]
            + len(product_sources)
            + len(readiness_sources)
            + len(maturity_sources)
            + len(runtime_sources)
            + fallback["sourceCount"]
        ),
        "status": conclusion["status"],
        "recommendedUse": conclusion["recommendedUse"],
        "plannerPenaltySafe": False,
        "qualityPenaltySafe": False,
        "expectedAdapterTypes": expected,
        "mainlineBaseline": baseline,
        "provider": provider,
        "providerAvailability": availability,
        "adapters": adapters,
        "runtimeFallback": fallback,
        "conclusion": conclusion,
        "privacy": privacy_summary(),
    }


def adapter_rows(
    expected: list[str],
    provider: dict[str, Any],
    availability: dict[str, Any],
    product_sources: list[dict[str, Any]],
    readiness_sources: list[dict[str, Any]],
    maturity_sources: list[dict[str, Any]],
    runtime_sources: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    types = sorted({
        *expected,
        *provider["matchedTypeCounts"].keys(),
        *provider["selectedTypeCounts"].keys(),
        *availability["currentMatchedTypeCounts"].keys(),
        *availability["currentCompatibleTypeCounts"].keys(),
        *availability["adapterAvailability"].keys(),
        *(source["adapterType"] for source in product_sources if source["adapterType"]),
        *(source["adapterType"] for source in readiness_sources if source["adapterType"]),
        *(source["adapterType"] for source in maturity_sources if source["adapterType"]),
        *(source["adapterType"] for source in runtime_sources if source["adapterType"]),
    })
    rows = []
    for adapter_type in sorted(types, key=lambda item: (expected_index(expected, item), item)):
        row = adapter_row(
            adapter_type,
            expected,
            provider,
            availability,
            product_sources,
            readiness_sources,
            maturity_sources,
            runtime_sources,
        )
        row["gaps"] = adapter_gaps(row)
        row["coverageLevel"] = coverage_level(row)
        row["nextAction"] = adapter_next_action(row)
        rows.append(row)
    return rows


def adapter_row(
    adapter_type: str,
    expected: list[str],
    provider: dict[str, Any],
    availability: dict[str, Any],
    product_sources: list[dict[str, Any]],
    readiness_sources: list[dict[str, Any]],
    maturity_sources: list[dict[str, Any]],
    runtime_sources: list[dict[str, Any]],
) -> dict[str, Any]:
    availability_label = str(
        availability["adapterAvailability"].get(adapter_type) or ""
    )
    return {
        "adapterType": adapter_type,
        "expected": adapter_type in expected,
        "providerMatched": int(provider["matchedTypeCounts"].get(adapter_type, 0)),
        "providerSelected": int(provider["selectedTypeCounts"].get(adapter_type, 0)),
        "providerAvailability": {
            "sourceCount": availability["sourceCount"],
            "availability": availability_label,
            "currentMatched": int(
                availability["currentMatchedTypeCounts"].get(adapter_type, 0)
            ),
            "currentCompatible": int(
                availability["currentCompatibleTypeCounts"].get(adapter_type, 0)
            ),
            "gaps": availability["adapterGaps"].get(adapter_type, []),
            "nextAction": availability["adapterNextActions"].get(adapter_type, ""),
        },
        "productEffect": product_summary([
            source for source in product_sources if source["adapterType"] == adapter_type
        ]),
        "readiness": readiness_summary([
            source for source in readiness_sources if source["adapterType"] == adapter_type
        ]),
        "maturity": maturity_summary([
            source for source in maturity_sources if source["adapterType"] == adapter_type
        ]),
        "runtimeRepeat": runtime_repeat_summary([
            source for source in runtime_sources if source["adapterType"] == adapter_type
        ]),
    }


def adapter_gaps(row: dict[str, Any]) -> list[str]:
    if not row["expected"]:
        return []
    product = row["productEffect"]
    maturity = row["maturity"]
    runtime = row["runtimeRepeat"]
    if not provider_available(row) and product["sourceCount"] == 0 and runtime["sourceCount"] == 0:
        return provider_missing_gaps(row)
    gaps = []
    if product["sourceCount"] > 0 and not product["clean"]:
        gaps.append("product-effect-unclean")
    if runtime["sourceCount"] > 0 and not runtime["clean"]:
        gaps.append("runtime-repeat-unclean")
    if product["sourceCount"] == 0:
        if runtime["sourceCount"] > 0 and runtime["clean"] and maturity["sourceCount"] == 0:
            gaps.append("adapter-maturity-evidence-missing")
        elif runtime["sourceCount"] > 0 and runtime["clean"] and not maturity["candidateMature"]:
            gaps.append("adapter-maturity-depth-missing")
        elif runtime["sourceCount"] > 0 and runtime["clean"]:
            gaps.append("product-effect-baseline-missing")
        elif provider_available(row):
            gaps.append("runtime-repeat-evidence-missing")
    return gaps


def provider_available(row: dict[str, Any]) -> bool:
    availability = row["providerAvailability"]
    return (
        row["providerMatched"] > 0
        or int(availability.get("currentCompatible") or 0) > 0
    )


def provider_missing_gaps(row: dict[str, Any]) -> list[str]:
    availability = row["providerAvailability"]
    if int(availability.get("sourceCount") or 0) == 0:
        return ["provider-candidate-missing"]
    adapter_availability = availability.get("availability")
    if adapter_availability == "current-provider-shape-blocked":
        return ["provider-candidate-shape-unusable"]
    if adapter_availability == "historical-only":
        return ["current-provider-candidate-missing"]
    if adapter_availability == "missing":
        return ["provider-acquisition-required"]
    return availability.get("gaps") or ["provider-candidate-missing"]


def coverage_level(row: dict[str, Any]) -> str:
    if row["productEffect"]["clean"]:
        return "product-effect-baseline"
    if row["runtimeRepeat"]["clean"]:
        return "runtime-repeat-clean"
    if row["readiness"]["ready"] or row["maturity"]["candidateMature"]:
        return "adapter-readiness"
    if row["providerSelected"] > 0:
        return "provider-selected"
    if row["providerMatched"] > 0:
        return "provider-available"
    if int(row["providerAvailability"].get("currentCompatible") or 0) > 0:
        return "provider-current-compatible"
    if row["providerAvailability"].get("availability") == "current-provider-shape-blocked":
        return "provider-shape-blocked"
    return "no-provider"


def adapter_next_action(row: dict[str, Any]) -> str:
    gaps = row["gaps"]
    if not gaps and row["productEffect"]["clean"]:
        return "keep-as-current-product-effect-control"
    if "adapter-maturity-evidence-missing" in gaps:
        return "generate-adapter-maturity-from-runtime-repeat"
    if "adapter-maturity-depth-missing" in gaps:
        return "collect-more-runtime-repeat-for-adapter-maturity"
    if "product-effect-baseline-missing" in gaps:
        return "promote-clean-runtime-repeat-to-paired-product-effect"
    if "runtime-repeat-evidence-missing" in gaps:
        return "collect-runtime-repeat-evidence"
    if "provider-acquisition-required" in gaps:
        return "acquire-current-provider-candidate-before-runtime-work"
    if "current-provider-candidate-missing" in gaps:
        return "reacquire-current-provider-candidate-before-runtime-work"
    if "provider-candidate-shape-unusable" in gaps:
        return "fix-provider-candidate-shape-before-runtime-work"
    if "provider-candidate-missing" in gaps:
        return "resolve-provider-candidate-availability-before-runtime-work"
    if "runtime-repeat-unclean" in gaps:
        return "repair-runtime-repeat-before-product-effect"
    if "product-effect-unclean" in gaps:
        return "repair-product-effect-gate"
    return "observe-only"


def coverage_conclusion(expected: list[str], adapters: list[dict[str, Any]]) -> dict[str, Any]:
    expected_rows = [row for row in adapters if row["adapterType"] in expected]
    gap_rows = [row for row in expected_rows if row["gaps"]]
    next_rows = sorted(gap_rows, key=gap_priority)
    next_runtime = runtime_next_actions(expected_rows, gap_rows)
    status = "adapter-coverage-gaps-open" if gap_rows else "adapter-coverage-current-clean"
    return {
        "status": status,
        "recommendedUse": "use-to-select-next-mainline-runtime-slice",
        "coverageComplete": not gap_rows,
        "runtimeWorkUnblocked": bool(next_runtime),
        "gapCount": len(gap_rows),
        "gaps": [
            {
                "adapterType": row["adapterType"],
                "gaps": row["gaps"],
                "providerAvailability": row["providerAvailability"]["availability"],
                "nextAction": row["nextAction"],
            }
            for row in gap_rows
        ],
        "nextAdapterWork": [
            {
                "adapterType": row["adapterType"],
                "coverageLevel": row["coverageLevel"],
                "gaps": row["gaps"],
                "providerAvailability": row["providerAvailability"]["availability"],
                "nextAction": row["nextAction"],
            }
            for row in next_rows
        ],
        "nextActions": conclusion_actions(next_rows),
        "nextRuntimeWork": next_runtime,
        "plannerPenaltySafe": False,
        "qualityPenaltySafe": False,
    }


def runtime_next_actions(
    expected_rows: list[dict[str, Any]],
    gap_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if not gap_rows or not provider_only_external(gap_rows):
        return []
    controls = [
        row["adapterType"]
        for row in expected_rows
        if row["productEffect"]["clean"]
    ]
    if not controls:
        return []
    return [
        action(
            "continue-runtime-owned-surface-under-current-baseline",
            "adapter-coverage",
            "parallel",
            (
                "Open adapter gaps require provider acquisition; current "
                f"product-effect controls remain usable: {','.join(controls)}."
            ),
        )
    ]


def provider_only_external(rows: list[dict[str, Any]]) -> bool:
    return all(
        row["gaps"]
        and all(gap in EXTERNAL_PROVIDER_GAPS for gap in row["gaps"])
        for row in rows
    )


def conclusion_actions(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not rows:
        return [
            action(
                "keep-current-adapter-baseline",
                "baseline",
                "required",
                "Expected adapter coverage has no open inventory gaps.",
            )
        ]
    actions = []
    seen = set()
    for row in rows:
        action_id = f"{row['nextAction']}:{row['adapterType']}"
        if action_id in seen:
            continue
        seen.add(action_id)
        actions.append(action(
            row["nextAction"],
            "adapter-coverage",
            "next" if len(actions) == 0 else "follow-up",
            f"{row['adapterType']} gaps: {','.join(row['gaps'])}",
            adapter_type=row["adapterType"],
        ))
    actions.append(action(
        "keep-planner-and-quality-penalties-disabled",
        "policy",
        "required",
        "Coverage inventory is not repeated runtime-backed node failure proof.",
    ))
    return actions


def action(
    action_id: str,
    evidence: str,
    priority: str,
    reason: str,
    *,
    adapter_type: str = "",
) -> dict[str, Any]:
    payload = {
        "id": action_id,
        "evidence": evidence,
        "priority": priority,
        "reason": reason,
        "plannerPenaltySafe": False,
    }
    if adapter_type:
        payload["adapterType"] = adapter_type
    return payload


def gap_priority(row: dict[str, Any]) -> tuple[int, str]:
    order = {
        "adapter-maturity-evidence-missing": 0,
        "adapter-maturity-depth-missing": 1,
        "product-effect-baseline-missing": 2,
        "runtime-repeat-evidence-missing": 3,
        "runtime-repeat-unclean": 4,
        "product-effect-unclean": 5,
        "provider-candidate-shape-unusable": 6,
        "current-provider-candidate-missing": 7,
        "provider-acquisition-required": 8,
        "provider-candidate-missing": 9,
    }
    priority = min((order.get(gap, 99) for gap in row["gaps"]), default=99)
    return priority, row["adapterType"]


def expected_index(expected: list[str], adapter_type: str) -> int:
    if adapter_type in expected:
        return expected.index(adapter_type)
    return len(expected)


def privacy_summary() -> dict[str, bool]:
    return {
        "rawLogsStored": False,
        "rawPacketsStored": False,
        "rawSecretsStored": False,
        "responseBodiesStored": False,
        "identityInformationSent": False,
    }


def print_summary(output_dir: Path, summary: dict[str, Any]) -> dict[str, Any]:
    next_work = summary["conclusion"]["nextAdapterWork"]
    runtime_work = summary["conclusion"].get("nextRuntimeWork", [])
    return {
        "outputDir": str(output_dir),
        "status": summary["status"],
        "recommendedUse": summary["recommendedUse"],
        "gapCount": summary["conclusion"]["gapCount"],
        "nextAdapter": next_work[0]["adapterType"] if next_work else "",
        "nextRuntimeAction": runtime_work[0]["id"] if runtime_work else "",
        "plannerPenaltySafe": summary["plannerPenaltySafe"],
        "qualityPenaltySafe": summary["qualityPenaltySafe"],
    }
