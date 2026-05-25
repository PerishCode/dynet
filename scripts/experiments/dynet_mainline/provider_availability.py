from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from dynet_mainline.adapter_coverage_sources import (
    count_rows,
    load_json,
    normalize_type,
    normalized_count_map,
    unique,
)
from tunnel_private_config import selected_tunnel_proxies, write_json


SCHEMA = "dynet-mainline-provider-availability/v1alpha1"
DEFAULT_EXPECTED_ADAPTERS = ["trojan", "vmess", "ss"]
REQUIRED_FIELDS = {
    "ss": ["server", "port", "cipher", "password"],
    "trojan": ["server", "port", "password"],
    "vmess": ["server", "port", "uuid"],
}


def command_mainline_provider_availability(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    group, candidates = selected_tunnel_proxies(args)
    summary = provider_availability_summary(
        expected_adapter_types=[
            normalize_type(item)
            for item in getattr(args, "expected_adapter_type", [])
            or DEFAULT_EXPECTED_ADAPTERS
        ],
        current_candidates=candidates,
        tunnel_group=group,
        historical_provider_meta_paths=[
            Path(path)
            for path in getattr(args, "historical_provider_meta", []) or []
        ],
    )
    write_json(output_dir / "summary.json", summary)
    write_markdown(output_dir / "summary.md", summary)
    print(json.dumps(print_summary(output_dir, summary), sort_keys=True))
    return 0 if summary["currentProvider"]["matched"] else 1


def provider_availability_summary(
    *,
    expected_adapter_types: list[str],
    current_candidates: list[dict[str, Any]],
    tunnel_group: dict[str, Any] | None = None,
    historical_provider_meta_paths: list[Path] | None = None,
) -> dict[str, Any]:
    expected = unique([normalize_type(item) for item in expected_adapter_types])
    current = current_provider_summary(current_candidates, tunnel_group or {})
    historical = historical_provider_summary(historical_provider_meta_paths or [])
    adapters = adapter_rows(expected, current, historical)
    conclusion = availability_conclusion(adapters)
    return {
        "schema": SCHEMA,
        "status": conclusion["status"],
        "recommendedUse": "resolve-provider-candidate-availability-before-runtime-work",
        "plannerPenaltySafe": False,
        "qualityPenaltySafe": False,
        "expectedAdapterTypes": expected,
        "currentProvider": current,
        "historicalProvider": historical,
        "adapters": adapters,
        "conclusion": conclusion,
        "privacy": {
            "rawSecretsStored": False,
            "rawNodeNamesStored": False,
            "rawServerAddressesStored": False,
            "identityInformationSent": False,
            "cookiesSent": False,
            "authorizationSent": False,
        },
    }


def current_provider_summary(
    candidates: list[dict[str, Any]],
    tunnel_group: dict[str, Any],
) -> dict[str, Any]:
    matched = count_types(candidate_type(item) for item in candidates)
    compatible = count_types(
        candidate_type(item) for item in candidates if compatible_candidate(item)
    )
    incompatible = incompatible_counts(candidates)
    return {
        "tunnel": {
            "nameLength": len(str(tunnel_group.get("name", ""))),
            "type": tunnel_group.get("type"),
            "filterPresent": tunnel_group.get("filter") is not None,
            "providerCount": len(tunnel_group.get("use", [])),
        },
        "matched": len(candidates),
        "matchedByType": count_rows(matched),
        "matchedTypeCounts": matched,
        "compatibleByType": count_rows(compatible),
        "compatibleTypeCounts": compatible,
        "incompatibleByType": count_rows(incompatible),
        "incompatibleTypeCounts": incompatible,
        "incompatibleReasons": incompatible_reason_rows(candidates),
    }


def historical_provider_summary(paths: list[Path]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    sources = []
    for path in paths:
        summary = load_json(path)
        source_counts = normalized_count_map((summary.get("counts") or {}).get("matchedByType"))
        counts = merge_counts(counts, source_counts)
        sources.append({
            "path": str(path),
            "schema": str(summary.get("schema") or ""),
            "matchedByType": source_counts,
        })
    return {
        "sourceCount": len(paths),
        "matchedByType": count_rows(counts),
        "matchedTypeCounts": counts,
        "sources": sources,
    }


def adapter_rows(
    expected: list[str],
    current: dict[str, Any],
    historical: dict[str, Any],
) -> list[dict[str, Any]]:
    current_matched = current["matchedTypeCounts"]
    current_compatible = current["compatibleTypeCounts"]
    historical_matched = historical["matchedTypeCounts"]
    types = sorted(
        {
            *expected,
            *current_matched.keys(),
            *current_compatible.keys(),
            *historical_matched.keys(),
        },
        key=lambda item: (expected_index(expected, item), item),
    )
    rows = []
    for adapter_type in types:
        row = {
            "adapterType": adapter_type,
            "expected": adapter_type in expected,
            "currentMatched": int(current_matched.get(adapter_type, 0)),
            "currentCompatible": int(current_compatible.get(adapter_type, 0)),
            "historicalMatched": int(historical_matched.get(adapter_type, 0)),
        }
        row["availability"] = adapter_availability(row)
        row["gaps"] = adapter_gaps(row)
        row["nextAction"] = adapter_next_action(row)
        rows.append(row)
    return rows


def adapter_availability(row: dict[str, Any]) -> str:
    if row["currentCompatible"] > 0:
        return "current-compatible"
    if row["currentMatched"] > 0:
        return "current-provider-shape-blocked"
    if row["historicalMatched"] > 0:
        return "historical-only"
    return "missing"


def adapter_gaps(row: dict[str, Any]) -> list[str]:
    if not row["expected"] or row["currentCompatible"] > 0:
        return []
    if row["currentMatched"] > 0:
        return ["provider-candidate-shape-unusable"]
    if row["historicalMatched"] > 0:
        return ["current-provider-candidate-missing"]
    return ["provider-candidate-missing"]


def adapter_next_action(row: dict[str, Any]) -> str:
    if row["currentCompatible"] > 0:
        return "use-current-provider-candidate-for-runtime-work"
    if row["currentMatched"] > 0:
        return "fix-provider-candidate-shape-before-runtime-work"
    if row["historicalMatched"] > 0:
        return "reacquire-current-provider-candidate-before-runtime-work"
    return "acquire-current-provider-candidate-before-runtime-work"


def availability_conclusion(adapters: list[dict[str, Any]]) -> dict[str, Any]:
    missing = [row for row in adapters if row["expected"] and row["gaps"]]
    return {
        "status": (
            "provider-availability-gaps-open"
            if missing
            else "provider-availability-current-complete"
        ),
        "coverageComplete": not missing,
        "gapCount": len(missing),
        "gaps": [
            {
                "adapterType": row["adapterType"],
                "availability": row["availability"],
                "gaps": row["gaps"],
                "nextAction": row["nextAction"],
            }
            for row in missing
        ],
        "nextActions": [
            {
                "adapterType": row["adapterType"],
                "id": row["nextAction"],
                "priority": "next",
                "plannerPenaltySafe": False,
                "reason": f"{row['adapterType']} availability: {row['availability']}",
            }
            for row in missing
        ],
        "plannerPenaltySafe": False,
        "qualityPenaltySafe": False,
    }


def compatible_candidate(candidate: dict[str, Any]) -> bool:
    adapter_type = candidate_type(candidate)
    return adapter_type in REQUIRED_FIELDS and not candidate_issues(candidate)


def candidate_issues(candidate: dict[str, Any]) -> list[str]:
    adapter_type = candidate_type(candidate)
    issues = []
    network = str(candidate.get("network") or "tcp").lower()
    if network not in {"", "tcp"}:
        issues.append("network-not-tcp")
    for field in REQUIRED_FIELDS.get(adapter_type, []):
        value = candidate.get(field)
        if value is None or str(value) == "":
            issues.append(f"missing-{field}")
    if adapter_type not in REQUIRED_FIELDS:
        issues.append("unsupported-adapter-type")
    return issues


def incompatible_counts(candidates: list[dict[str, Any]]) -> dict[str, int]:
    return count_types(
        candidate_type(item) for item in candidates if not compatible_candidate(item)
    )


def incompatible_reason_rows(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for candidate in candidates:
        adapter_type = candidate_type(candidate)
        for issue in candidate_issues(candidate):
            key = f"{adapter_type}:{issue}"
            counts[key] = counts.get(key, 0) + 1
    return count_rows(counts)


def candidate_type(candidate: dict[str, Any]) -> str:
    return normalize_type(candidate.get("type"))


def count_types(values: Any) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        adapter_type = normalize_type(value)
        if adapter_type:
            counts[adapter_type] = counts.get(adapter_type, 0) + 1
    return dict(sorted(counts.items()))


def merge_counts(left: dict[str, int], right: dict[str, int]) -> dict[str, int]:
    result = dict(left)
    for key, value in right.items():
        result[key] = result.get(key, 0) + int(value)
    return dict(sorted(result.items()))


def expected_index(expected: list[str], adapter_type: str) -> int:
    try:
        return expected.index(adapter_type)
    except ValueError:
        return len(expected)


def write_markdown(path: Path, summary: dict[str, Any]) -> None:
    lines = [
        "# Provider Availability",
        "",
        f"- status: `{summary['status']}`",
        f"- plannerPenaltySafe: `{summary['plannerPenaltySafe']}`",
        f"- qualityPenaltySafe: `{summary['qualityPenaltySafe']}`",
        "",
        "## Current Provider",
        "",
        f"- matched: `{summary['currentProvider']['matched']}`",
        f"- matchedByType: `{summary['currentProvider']['matchedByType']}`",
        f"- compatibleByType: `{summary['currentProvider']['compatibleByType']}`",
        "",
        "## Adapters",
        "",
        "| adapter | availability | current matched | current compatible | historical matched | gaps | next action |",
        "| --- | --- | ---: | ---: | ---: | --- | --- |",
    ]
    for row in summary["adapters"]:
        lines.append(
            "| "
            f"`{row['adapterType']}` | "
            f"`{row['availability']}` | "
            f"`{row['currentMatched']}` | "
            f"`{row['currentCompatible']}` | "
            f"`{row['historicalMatched']}` | "
            f"`{', '.join(row['gaps'])}` | "
            f"`{row['nextAction']}` |"
        )
    lines.extend([
        "",
        "## Next Actions",
        "",
    ])
    for action in summary["conclusion"]["nextActions"]:
        lines.append(
            f"- `{action['adapterType']}`: `{action['id']}` "
            f"plannerPenaltySafe=`{action['plannerPenaltySafe']}`"
        )
    path.write_text("\n".join(lines) + "\n")


def print_summary(output_dir: Path, summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "outputDir": str(output_dir),
        "status": summary["status"],
        "gapCount": summary["conclusion"]["gapCount"],
        "missingAdapters": [
            row["adapterType"]
            for row in summary["adapters"]
            if row["expected"] and row["gaps"]
        ],
        "plannerPenaltySafe": summary["plannerPenaltySafe"],
    }
