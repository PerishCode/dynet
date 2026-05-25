from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from common import CommandError, Lab, validate_name


SCHEMA = "dynet-vm-private-paired-selection/v1alpha1"


def command_paired_selection(_lab: Lab, args: argparse.Namespace) -> None:
    label = validate_name(args.label or "paired-selection", "label")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = paired_selection_summary(
        label,
        output_dir,
        [Path(path) for path in args.input],
        pressure_path=Path(args.pressure_summary) if args.pressure_summary else None,
    )
    write_json(output_dir / "summary.json", summary)
    write_markdown(output_dir / "summary.md", summary)
    print(
        json.dumps(
            {
                "outputDir": str(output_dir),
                "status": summary["status"],
                "rows": summary["totals"]["rows"],
            },
            sort_keys=True,
        )
    )


def paired_selection_summary(
    label: str,
    output_dir: Path,
    inputs: list[Path],
    *,
    pressure_path: Path | None = None,
) -> dict[str, Any]:
    sources = [paired_source(path) for path in inputs]
    rows = [row for source in sources for row in source["rows"]]
    pressure = pressure_join(rows, pressure_path)
    totals = selection_totals(sources, rows)
    status = "paired-selection-product-clean" if selection_clean(totals) else "paired-selection-needs-failure-classification"
    return {
        "schema": SCHEMA,
        "label": label,
        "outputDir": str(output_dir),
        "status": status,
        "totals": totals,
        "sources": [source_row(source) for source in sources],
        "selection": {
            "rows": rows,
            "byCandidate": aggregate(rows, "candidate"),
            "byTarget": aggregate(rows, "targetHost"),
            "byCandidateTarget": aggregate_tuple(rows, ["candidate", "targetHost"]),
            "failuresByCandidateTarget": aggregate_tuple(
                [row for row in rows if not row["ok"]],
                ["candidate", "targetHost"],
            ),
        },
        "pressureJoin": pressure,
        "policy": {
            "plannerPenaltySafe": False,
            "qualityPenaltySafe": False,
            "reason": "paired selection is product-effect context; penalties require repeated runtime-backed failure evidence",
        },
        "privacy": {
            "rawSecretsStored": False,
            "rawLogsStored": False,
            "rawPacketsStored": False,
            "rawResponseBodiesStored": False,
        },
        "inputs": [str(path) for path in inputs],
    }


def paired_source(path: Path) -> dict[str, Any]:
    base = path if path.is_dir() else path.parent
    comparison_path = base / "comparison.json" if path.is_dir() else path
    comparison = load_json(comparison_path)
    dynet = load_json(base / "dynet" / "summary.json")
    pairs = load_optional_json(base / "pairs.json")
    return {
        "label": base.name,
        "path": str(base),
        "comparisonPath": str(comparison_path),
        "status": str(comparison.get("status") or "unknown"),
        "runtimeCarrier": str(comparison.get("runtimeCarrier") or "unknown"),
        "totals": comparison.get("totals", {}),
        "pairedReplay": comparison.get("pairedReplay", {}),
        "pairGapMs": pairs.get("pairGapMs", {}),
        "rows": [selection_row(base.name, row) for row in dynet.get("results", [])],
    }


def selection_row(source: str, row: dict[str, Any]) -> dict[str, Any]:
    return {
        "source": source,
        "id": str(row.get("id") or ""),
        "domain": str(row.get("domain") or ""),
        "targetHost": target_host(row),
        "probe": str(row.get("probe") or ""),
        "candidate": str(row.get("boundSelected") or "unknown"),
        "ok": bool(row.get("ok")),
        "failedStage": str(row.get("failedStage") or "none"),
        "failureScope": str(row.get("failureScope") or "none"),
        "elapsedMs": int_value(row.get("elapsedMs")),
    }


def target_host(row: dict[str, Any]) -> str:
    domain = str(row.get("domain") or "")
    if domain:
        return domain
    parsed = urlparse(str(row.get("targetUrl") or ""))
    return parsed.hostname or "unknown"


def selection_totals(sources: list[dict[str, Any]], rows: list[dict[str, Any]]) -> dict[str, Any]:
    ok_rows = [row for row in rows if row["ok"]]
    return {
        "sources": len(sources),
        "rows": len(rows),
        "success": len(ok_rows),
        "failure": len(rows) - len(ok_rows),
        "cleanSources": sum(1 for source in sources if source_clean(source)),
        "failedSources": sum(1 for source in sources if not source_clean(source)),
        "targetHosts": sorted({row["targetHost"] for row in rows} - {"unknown"}),
        "candidates": sorted({row["candidate"] for row in rows} - {"unknown"}),
    }


def source_clean(source: dict[str, Any]) -> bool:
    totals = source["totals"]
    clash = totals.get("clash", {})
    dynet = totals.get("dynet", {})
    return (
        source["status"] == "dynet-parity-candidate"
        and int_value(clash.get("failure")) == 0
        and int_value(dynet.get("failure")) == 0
    )


def selection_clean(totals: dict[str, Any]) -> bool:
    return int(totals["rows"]) > 0 and int(totals["failure"]) == 0 and int(totals["failedSources"]) == 0


def pressure_join(rows: list[dict[str, Any]], pressure_path: Path | None) -> dict[str, Any] | None:
    if pressure_path is None:
        return None
    pressure = load_json(pressure_path)
    clean_counts = candidate_target_success_counts(rows)
    joined = []
    for row in pressure.get("stagePressure", {}).get("rows", []):
        key = candidate_target_key(str(row.get("candidate") or ""), pressure_target_host(row))
        joined.append(
            {
                "candidate": row.get("candidate"),
                "targetHost": pressure_target_host(row),
                "stage": row.get("stage"),
                "disposition": row.get("disposition"),
                "recovered": bool(row.get("recovered")),
                "pairedCleanSelections": clean_counts.get(key, 0),
            }
        )
    return {
        "source": str(pressure_path),
        "status": pressure.get("status"),
        "rows": joined,
        "byCandidateTarget": aggregate_tuple(joined, ["candidate", "targetHost"]),
    }


def candidate_target_success_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        if not row["ok"]:
            continue
        key = candidate_target_key(row["candidate"], row["targetHost"])
        counts[key] = counts.get(key, 0) + 1
    return counts


def candidate_target_key(candidate: str, target_host: str) -> str:
    return f"{candidate}|{target_host}"


def pressure_target_host(row: dict[str, Any]) -> str:
    target = str(row.get("target") or "")
    return target.rsplit(":", 1)[0] if ":" in target else target or "unknown"


def source_row(source: dict[str, Any]) -> dict[str, Any]:
    return {
        "label": source["label"],
        "path": source["path"],
        "comparisonPath": source["comparisonPath"],
        "status": source["status"],
        "runtimeCarrier": source["runtimeCarrier"],
        "rows": len(source["rows"]),
        "pairGapMs": source["pairGapMs"],
    }


def aggregate(rows: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    return count_values(str(row.get(key) or "unknown") for row in rows)


def aggregate_tuple(rows: list[dict[str, Any]], keys: list[str]) -> list[dict[str, Any]]:
    return count_values(":".join(str(row.get(key) or "unknown") for key in keys) for row in rows)


def count_values(values: Any) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return [{"key": key, "count": counts[key]} for key in sorted(counts)]


def int_value(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise CommandError(f"missing JSON artifact: {path}")
    return json.loads(path.read_text())


def load_optional_json(path: Path) -> dict[str, Any]:
    return load_json(path) if path.exists() else {}


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def write_markdown(path: Path, summary: dict[str, Any]) -> None:
    totals = summary["totals"]
    lines = [
        "# VM Private Paired Selection",
        "",
        f"- status: `{summary['status']}`",
        f"- sources: `{totals['sources']}`",
        f"- rows: `{totals['rows']}`",
        f"- success: `{totals['success']}`",
        f"- failure: `{totals['failure']}`",
        f"- planner penalty safe: `{summary['policy']['plannerPenaltySafe']}`",
        "",
        "## Candidate/Target",
    ]
    for row in summary["selection"]["byCandidateTarget"]:
        lines.append(f"- `{row['key']}` count=`{row['count']}`")
    pressure = summary.get("pressureJoin")
    if pressure:
        lines.extend(["", "## Runtime Pressure Join"])
        for row in pressure["rows"]:
            lines.append(
                f"- `{row['candidate']}:{row['targetHost']}` "
                f"stage=`{row['stage']}` recovered=`{row['recovered']}` "
                f"pairedCleanSelections=`{row['pairedCleanSelections']}`"
            )
    path.write_text("\n".join(lines) + "\n")
