from __future__ import annotations

from pathlib import Path
from typing import Any

from scripts.lib.jsonio import load_summary
from scripts.lib.nv import count_keys, merge_items
from scripts.lib.privacy import (
    empty_surface_privacy_flags as empty_privacy_flags,
)


TCP_TARGET_SCHEMA = "dynet-vm-private-runtime-tcp-target-surface/v1alpha1"
COUNT_FIELDS = [
    "runs", "cleanRuns", "failedRuns", "eventReports", "runtimePass", "events",
    "connectingEvents", "directConnectEvents", "dialerConnectEvents",
    "unknownKindConnectEvents", "withConnectTarget", "withIdentityDomain",
    "withTargetAddressSource", "domainConnectTargets", "socketConnectTargets",
    "adapterConnectEvents", "adapterMatchedConnects",
    "socketPreservedDirectConnects", "controlledMissingAdapterConnects",
    "uncontrolledMissingAdapterConnects", "adapterMismatchedConnects",
    "adapterDuplicateFlows", "directMissingSocketPreserved",
    "dialerMissingDnsReverse", "coveredConnects",
]


def runtime_tcp_target_source(path: Path) -> dict[str, Any]:
    summary = load_summary(path)
    totals = summary.get("totals") or {}
    conclusion = summary.get("conclusion") or {}
    source = {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "label": str(summary.get("label") or ""),
        "status": str(conclusion.get("status") or ""),
        **{field: int(totals.get(field) or 0) for field in COUNT_FIELDS},
        "classifications": count_keys(totals.get("classifications")),
        "connectSourceProfiles": count_keys(totals.get("connectSourceProfiles")),
        "adapterStageProfiles": count_keys(totals.get("adapterStageProfiles")),
        "missingAdapterProfiles": count_keys(totals.get("missingAdapterProfiles")),
        "privacy": empty_privacy_flags(),
    }
    source["clean"] = runtime_tcp_target_clean(source)
    return source


def runtime_tcp_target_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "clean": bool(sources) and all(source["clean"] for source in sources),
        "statuses": sorted({source["status"] for source in sources if source["status"]}),
        **{field: sum(source[field] for source in sources) for field in COUNT_FIELDS},
        "classifications": merge_items(sources, "classifications"),
        "connectSourceProfiles": merge_items(sources, "connectSourceProfiles"),
        "adapterStageProfiles": merge_items(sources, "adapterStageProfiles"),
        "missingAdapterProfiles": merge_items(sources, "missingAdapterProfiles"),
        "sources": sources,
    }


def runtime_tcp_target_clean(source: dict[str, Any]) -> bool:
    return (
        source["schema"] == TCP_TARGET_SCHEMA
        and source["status"] == "clean"
        and source["runs"] > 0
        and source["cleanRuns"] == source["runs"]
        and source["failedRuns"] == 0
        and source["eventReports"] == source["runs"]
        and source["runtimePass"] == source["runs"]
        and source["events"] > 0
        and source["classifications"] == ["clean"]
        and source["connectingEvents"] > 0
        and source["directConnectEvents"] > 0
        and source["dialerConnectEvents"] > 0
        and source["withConnectTarget"] == source["connectingEvents"]
        and source["withIdentityDomain"] == source["connectingEvents"]
        and source["withTargetAddressSource"] == source["connectingEvents"]
        and source["coveredConnects"] == source["connectingEvents"]
        and source["adapterMatchedConnects"] > 0
        and source["socketPreservedDirectConnects"] > 0
        and source["unknownKindConnectEvents"] == 0
        and source["uncontrolledMissingAdapterConnects"] == 0
        and source["adapterMismatchedConnects"] == 0
        and source["adapterDuplicateFlows"] == 0
        and source["directMissingSocketPreserved"] == 0
        and source["dialerMissingDnsReverse"] == 0
        and not any(source["privacy"].values())
    )
