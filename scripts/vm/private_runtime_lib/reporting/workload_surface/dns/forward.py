from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from common import Lab, validate_name
from private_runtime_lib.briefs import fields


DNS_FORWARD_SCHEMA = "dynet-vm-private-runtime-dns-forward-surface/v1alpha1"
REPEAT_SCHEMA = "dynet-vm-private-runtime-repeat/v1alpha1"
CHAIN_KINDS = {
    "dns-query-received",
    "rule-matched",
    "plan-bypassed",
    "dns-proxy-forward",
    "dns-resolve-completed",
    "dns-resolve-failed",
}
COUNT_FIELDS = [
    "runs", "cleanRuns", "failedRuns", "eventReports", "runtimePass", "events",
    "dnsQueries", "diagnosticQueries", "ruleBypassQueries",
    "planBypassedQueries", "proxyForwardQueries", "terminalCompletedQueries",
    "terminalFailureQueries", "orderChecked", "orderViolations",
    "ruleMissingPlanBypass", "planBypassMissingRule",
    "planBypassMissingForward", "forwardMissingPlanBypass",
    "forwardMissingTerminal", "forwardMissingOutbound",
    "forwardMissingUpstream", "failureMissingResponseCode",
    "failureMissingDisposition", "nonUdpForward", "nonDnsRuleBypass",
]
BLOCKERS = [
    "orderViolations", "ruleMissingPlanBypass", "planBypassMissingRule",
    "planBypassMissingForward", "forwardMissingPlanBypass",
    "forwardMissingTerminal", "forwardMissingOutbound",
    "forwardMissingUpstream", "failureMissingResponseCode",
    "failureMissingDisposition", "nonUdpForward", "nonDnsRuleBypass",
]


def command_dns_forward_surface(_lab: Lab, args: argparse.Namespace) -> None:
    label = validate_name(args.label or "dns-forward-surface", "label")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = build_dns_forward_summary(
        label,
        output_dir,
        [Path(item) for item in args.input],
    )
    write_dns_forward_summary(output_dir, summary)
    print(json.dumps(dns_forward_print(output_dir, summary), sort_keys=True))


def build_dns_forward_summary(
    label: str,
    output_dir: Path,
    inputs: list[Path],
) -> dict[str, Any]:
    rows = [dns_forward_row(path) for path in expand_inputs(inputs)]
    totals = dns_forward_totals(rows)
    return {
        "schema": DNS_FORWARD_SCHEMA,
        "label": label,
        "outputDir": str(output_dir),
        "runs": rows,
        "totals": totals,
        "conclusion": dns_forward_conclusion(totals),
        "privacy": empty_privacy_flags(),
        "policy": {
            "plannerPenaltySafe": False,
            "qualityPenaltySafe": False,
            "reason": "Diagnostic DNS forwarding is observability proof, not penalty proof.",
        },
    }


def expand_inputs(inputs: list[Path]) -> list[Path]:
    paths: list[Path] = []
    for path in inputs:
        summary = load_optional_json(path / "summary.json")
        if summary.get("schema") == REPEAT_SCHEMA:
            paths.extend(
                Path(row["path"])
                for row in summary.get("runs", [])
                if isinstance(row, dict) and row.get("path")
            )
        else:
            paths.append(path)
    return paths


def dns_forward_row(run_dir: Path) -> dict[str, Any]:
    summary = load_optional_json(run_dir / "summary.json")
    current = dns_forward_counts(load_optional_json(run_dir / "runtime-report.json"))
    clean = dns_forward_clean(current)
    return {
        "label": summary.get("label") or run_dir.name,
        "path": str(run_dir),
        "classification": "clean" if clean else dns_forward_classification(current),
        "clean": clean,
        "current": current,
    }


def dns_forward_counts(report: dict[str, Any]) -> dict[str, Any]:
    raw_events = report.get("events")
    events = [
        event_row(event, index)
        for index, event in enumerate(raw_events or [])
        if isinstance(event, dict)
    ]
    dns_events = [event for event in events if event["key"] and event["kind"] in CHAIN_KINDS]
    keys = diagnostic_keys(dns_events)
    diagnostics = [event for event in dns_events if event["key"] in keys]
    return {
        "eventReports": 1 if raw_events is not None else 0,
        "runtimePass": 1 if report.get("status") == "pass" else 0,
        "events": len(events),
        "dnsQueries": count_kind(dns_events, "dns-query-received"),
        "diagnosticQueries": len(keys),
        "ruleBypassQueries": len(rule_bypass_keys(dns_events)),
        "planBypassedQueries": len(kind_keys(dns_events, "plan-bypassed")),
        "proxyForwardQueries": len(kind_keys(dns_events, "dns-proxy-forward")),
        "terminalCompletedQueries": len(kind_keys(diagnostics, "dns-resolve-completed")),
        "terminalFailureQueries": len(kind_keys(diagnostics, "dns-resolve-failed")),
        **relationship_counts(dns_events, keys),
        **field_counts(diagnostics),
        **order_counts(diagnostics, keys),
    }


def event_row(event: dict[str, Any], index: int) -> dict[str, Any]:
    event_fields = fields(event)
    return {
        "index": index,
        "kind": str(event.get("kind") or ""),
        "key": event_fields.get("dnsQueryId") or event_fields.get("flowId") or "",
        "listener": event_fields.get("listener") or "",
        "transport": event_fields.get("transport") or "",
        "bypassesPlan": parse_bool(event_fields.get("bypassesPlan")),
        "outbound": bool(event_fields.get("outbound")),
        "upstream": bool(event_fields.get("upstream")),
        "failureResponseCode": bool(event_fields.get("failureResponseCode")),
        "errorDisposition": bool(event_fields.get("errorDisposition")),
    }


def diagnostic_keys(events: list[dict[str, Any]]) -> set[str]:
    return (
        rule_bypass_keys(events)
        | kind_keys(events, "plan-bypassed")
        | kind_keys(events, "dns-proxy-forward")
    )


def rule_bypass_keys(events: list[dict[str, Any]]) -> set[str]:
    return {
        event["key"] for event in events
        if event["kind"] == "rule-matched" and event["bypassesPlan"] is True
    }


def kind_keys(events: list[dict[str, Any]], kind: str) -> set[str]:
    return {event["key"] for event in events if event["kind"] == kind and event["key"]}


def count_kind(events: list[dict[str, Any]], kind: str) -> int:
    return sum(1 for event in events if event["kind"] == kind)


def relationship_counts(events: list[dict[str, Any]], keys: set[str]) -> dict[str, int]:
    rule = rule_bypass_keys(events) & keys
    plan = kind_keys(events, "plan-bypassed") & keys
    forward = kind_keys(events, "dns-proxy-forward") & keys
    terminal = (
        kind_keys(events, "dns-resolve-completed")
        | kind_keys(events, "dns-resolve-failed")
    ) & keys
    return {
        "ruleMissingPlanBypass": len(rule - plan),
        "planBypassMissingRule": len(plan - rule),
        "planBypassMissingForward": len(plan - forward),
        "forwardMissingPlanBypass": len(forward - plan),
        "forwardMissingTerminal": len(forward - terminal),
    }


def field_counts(events: list[dict[str, Any]]) -> dict[str, int]:
    forward = [event for event in events if event["kind"] == "dns-proxy-forward"]
    failed = [event for event in events if event["kind"] == "dns-resolve-failed"]
    rule = [event for event in events if event["kind"] == "rule-matched"]
    return {
        "forwardMissingOutbound": sum(1 for event in forward if not event["outbound"]),
        "forwardMissingUpstream": sum(1 for event in forward if not event["upstream"]),
        "failureMissingResponseCode": sum(
            1 for event in failed if not event["failureResponseCode"]
        ),
        "failureMissingDisposition": sum(
            1 for event in failed if not event["errorDisposition"]
        ),
        "nonUdpForward": sum(1 for event in forward if event["listener"] != "udp"),
        "nonDnsRuleBypass": sum(1 for event in rule if event["transport"] != "dns"),
    }


def order_counts(events: list[dict[str, Any]], keys: set[str]) -> dict[str, int]:
    checked = 0
    violations = 0
    for key in keys:
        indexes = first_indexes(event for event in events if event["key"] == key)
        terminal = min_index(indexes, "dns-resolve-completed", "dns-resolve-failed")
        chain = [
            indexes.get("dns-query-received"),
            indexes.get("rule-matched"),
            indexes.get("plan-bypassed"),
            indexes.get("dns-proxy-forward"),
            terminal,
        ]
        present = [item for item in chain if item is not None]
        if len(present) < 2:
            continue
        checked += 1
        if any(right <= left for left, right in zip(present, present[1:])):
            violations += 1
    return {"orderChecked": checked, "orderViolations": violations}


def first_indexes(events: Any) -> dict[str, int]:
    result: dict[str, int] = {}
    for event in events:
        result.setdefault(event["kind"], event["index"])
    return result


def min_index(indexes: dict[str, int], *kinds: str) -> int | None:
    values = [indexes[kind] for kind in kinds if kind in indexes]
    return min(values) if values else None


def dns_forward_clean(counts: dict[str, Any]) -> bool:
    return (
        counts["eventReports"] == 1
        and counts["runtimePass"] == 1
        and all(int(counts[key]) == 0 for key in BLOCKERS)
    )


def dns_forward_classification(counts: dict[str, Any]) -> str:
    for key, label in [
        ("orderViolations", "diagnostic-dns-order-invalid"),
        ("ruleMissingPlanBypass", "rule-bypass-plan-missing"),
        ("planBypassMissingRule", "plan-bypass-rule-missing"),
        ("planBypassMissingForward", "plan-bypass-forward-missing"),
        ("forwardMissingPlanBypass", "forward-plan-bypass-missing"),
        ("forwardMissingTerminal", "forward-terminal-missing"),
        ("forwardMissingOutbound", "forward-outbound-missing"),
        ("forwardMissingUpstream", "forward-upstream-missing"),
        ("failureMissingResponseCode", "failure-response-code-missing"),
        ("failureMissingDisposition", "failure-disposition-missing"),
        ("nonUdpForward", "forward-listener-not-udp"),
        ("nonDnsRuleBypass", "rule-bypass-transport-not-dns"),
    ]:
        if int(counts[key]):
            return label
    return "dns-forward-surface-incomplete"


def dns_forward_totals(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "runs": len(rows),
        "cleanRuns": sum(1 for row in rows if row["clean"]),
        "failedRuns": sum(1 for row in rows if not row["clean"]),
        "classifications": aggregate(row["classification"] for row in rows),
        **{
            key: sum(int(row["current"].get(key) or 0) for row in rows)
            for key in COUNT_FIELDS
            if key not in {"runs", "cleanRuns", "failedRuns"}
        },
    }


def dns_forward_conclusion(totals: dict[str, Any]) -> dict[str, Any]:
    clean = (
        totals["runs"] > 0
        and totals["failedRuns"] == 0
        and totals["diagnosticQueries"] > 0
        and totals["proxyForwardQueries"] > 0
        and totals["terminalFailureQueries"] > 0
    )
    return {
        "status": "clean" if clean else "dns-forward-surface-needs-evidence",
        "nextAction": "return-to-runtime-surface" if clean else "inspect-diagnostic-dns-forwarding",
        "plannerPenaltySafe": False,
        "qualityPenaltySafe": False,
    }


def write_dns_forward_summary(output_dir: Path, summary: dict[str, Any]) -> None:
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    write_dns_forward_markdown(output_dir / "summary.md", summary)


def write_dns_forward_markdown(path: Path, summary: dict[str, Any]) -> None:
    totals = summary["totals"]
    lines = [
        "# VM Private Runtime DNS Forward Surface",
        "",
        f"- label: `{summary['label']}`",
        f"- status: `{summary['conclusion']['status']}`",
        f"- runs: `{totals['runs']}`",
        f"- clean runs: `{totals['cleanRuns']}`",
        f"- diagnostic queries: `{totals['diagnosticQueries']}`",
        f"- proxy forward queries: `{totals['proxyForwardQueries']}`",
        f"- terminal failure queries: `{totals['terminalFailureQueries']}`",
        f"- order violations: `{totals['orderViolations']}`",
        "",
        "## Runs",
        "",
    ]
    for row in summary["runs"]:
        lines.append(
            f"- `{row['label']}` clean=`{row['clean']}` "
            f"classification=`{row['classification']}` "
            f"diagnostic=`{row['current']['diagnosticQueries']}` "
            f"forward=`{row['current']['proxyForwardQueries']}`"
        )
    path.write_text("\n".join(lines) + "\n")


def dns_forward_print(output_dir: Path, summary: dict[str, Any]) -> dict[str, Any]:
    totals = summary["totals"]
    return {
        "outputDir": str(output_dir),
        "status": summary["conclusion"]["status"],
        "runs": totals["runs"],
        "diagnosticQueries": totals["diagnosticQueries"],
        "proxyForwardQueries": totals["proxyForwardQueries"],
        "terminalFailureQueries": totals["terminalFailureQueries"],
        "orderViolations": totals["orderViolations"],
    }


def aggregate(values: Any) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for value in values:
        key = str(value or "unknown")
        counts[key] = counts.get(key, 0) + 1
    return [{"key": key, "count": count} for key, count in sorted(counts.items())]


def empty_privacy_flags() -> dict[str, bool]:
    return {
        "rawLogsStored": False,
        "rawPacketsStored": False,
        "rawSecretsStored": False,
        "responseBodiesStored": False,
        "identityInformationSent": False,
    }


def parse_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    lowered = value.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    return None


def load_optional_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text())
