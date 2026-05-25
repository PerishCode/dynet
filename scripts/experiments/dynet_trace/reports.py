from __future__ import annotations

from pathlib import Path
from typing import Any


def write_report(path: Path, summary: dict[str, Any]) -> None:
    lines = [
        "# Dynet Trace Attribution Summary",
        "",
        f"- Runtime: `{summary['runtimeSchema']}` status=`{summary['runtimeStatus']}`",
        f"- Events: `{summary['totals']['events']}`",
        f"- Readiness: `{summary['attributionReadiness']['canExplainPlanVsNodeForObservedPath']}`",
        "",
    ]
    if summary["probe"]:
        lines.extend(
            [
                "## Probe",
                "",
                f"- status=`{summary['probe']['status']}` reason=`{summary['probe']['reason']}`",
                "",
            ]
        )
    if summary["rules"]:
        lines.extend(["## Rules", ""])
        for item in summary["rules"]:
            lines.append(
                f"- `{item['rule']}` outbound=`{item['outbound']}` "
                f"bypassesPlan={item['bypassesPlan']}"
            )
        lines.append("")
    lines.extend(["## Plans", ""])
    for item in summary["plans"]:
        lines.append(
            f"- `{item['plan']}` strategy=`{item['strategy']}` "
            f"selected=`{item['selected']}` candidates={','.join(item['candidates'])}"
        )
    if summary["dialers"]:
        lines.extend(["", "## Dialers", ""])
        for item in summary["dialers"]:
            lines.append(
                f"- `{item['dialer']}` bound=`{item['bound']}` "
                f"selected=`{item['boundSelected']}` private=`{item['private']}`"
            )
    lines.extend(["", "## Outbounds", ""])
    for item in summary["outbounds"]:
        lines.append(
            f"- `{item['outbound']}` attempts={item['attempts']} failures={item['failures']} "
            f"p95={item['latencyMs']['p95']}ms"
        )
    lines.extend(["", "## Stages", ""])
    for item in summary["stages"]:
        lines.append(
            f"- `{item['outbound']}` stage=`{item['stage']}` count={item['count']} "
            f"failures={item['failures']} p95={item['latencyMs']['p95']}ms"
        )
    if summary["failures"]:
        lines.extend(["", "## Failures", ""])
        for item in summary["failures"]:
            lines.append(
                f"- kind=`{item['kind']}` outbound=`{item['outbound']}` "
                f"stage=`{item['stage']}` error=`{item['errorType']}` "
                f"elapsed={item['elapsedMs']}ms"
            )
    if summary.get("fallbackSignals"):
        lines.extend(["", "## Fallback Signals", ""])
        for item in summary["fallbackSignals"]:
            lines.append(
                f"- `{item['type']}` action=`{item['action']}` "
                f"flow=`{item['flowId']}` replaySafe=`{item['replaySafe']}` "
                f"failed=`{item.get('failedBound') or item.get('boundSelected')}` "
                f"recovered=`{item.get('recoveredBound')}`"
            )
    if summary["attributionReadiness"]["missing"]:
        lines.extend(["", "## Missing", ""])
        for item in summary["attributionReadiness"]["missing"]:
            lines.append(f"- `{item}`")
    append_workload_report(lines, summary.get("workloadAttribution", {}))
    path.write_text("\n".join(lines) + "\n")

def append_workload_report(lines: list[str], workload: dict[str, Any]) -> None:
    if not workload.get("enabled"):
        return
    lines.extend(["", "## Workload Attribution", ""])
    for item in workload.get("byClass", []):
        lines.append(f"- `{item['key']}`: {item['count']}")
    append_workload_candidates(lines, workload)
    append_workload_failures(lines, workload)

def append_workload_candidates(lines: list[str], workload: dict[str, Any]) -> None:
    if not workload.get("byCandidate"):
        return
    lines.extend(["", "### By Candidate", ""])
    for item in workload.get("byCandidate", []):
        lines.append(
            f"- `{item['candidate']}` failures={item['failures']}/{item['items']} "
            f"rate={item['failureRate']} classes={item['classes']}"
        )

def append_workload_failures(lines: list[str], workload: dict[str, Any]) -> None:
    failures = [item for item in workload.get("items", []) if item.get("classification") != "healthy"]
    if not failures:
        return
    lines.extend(["", "### Workload Failures", ""])
    for item in failures:
        sessions = ",".join(str(session.get("session")) for session in item.get("sessions", []))
        dns_flows = ",".join(str(flow.get("dnsQueryId")) for flow in item.get("dnsFlows", []))
        lines.append(
            f"- `{item['id']}` {item['domain']} probe=`{item['probe']}` "
            f"class=`{item['classification']}` stage=`{item['errorStage']}` "
            f"error=`{item['errorType']}` sessions=`{sessions or '<none>'}` "
            f"dns=`{dns_flows or '<none>'}` missing={','.join(item.get('missingFields', []))}"
        )

def write_batch_report(path: Path, batch: dict[str, Any]) -> None:
    lines = [
        "# Dynet Trace Attribution Batch",
        "",
        f"- Runs: `{batch['totals']['runs']}`",
        f"- Items: `{batch['totals']['items']}` failures=`{batch['totals']['failures']}`",
        f"- Unknown: `{batch['totals']['unknown']}`",
        f"- Missing repeat correlation: `{batch['totals']['missingRepeatCorrelation']}`",
        f"- Fallback signals: `{batch['totals'].get('fallbackSignals', 0)}` "
        f"recovered=`{batch['totals'].get('recoveredFallbackSignals', 0)}`",
        "",
        "## Gates",
        "",
    ]
    for gate in batch["gates"]:
        lines.append(
            f"- `{gate['name']}` passed={gate['passed']} "
            f"value=`{gate['value']}` required=`{gate['required']}`"
        )
    lines.extend(["", "## Classes", ""])
    for item in batch["byClass"]:
        lines.append(f"- `{item['key']}`: {item['count']}")
    lines.extend(["", "## Candidate Signals", ""])
    for item in batch["candidateSignals"]:
        lines.append(
            f"- `{item['candidate']}` action=`{item['plannerAction']}` "
            f"confidence=`{item['confidence']}` failures={item['failures']}/{item['items']} "
            f"nodeSuspectRuns={item['nodeSuspectRuns']} "
            f"repeatedNodeSuspectItems={item['repeatedNodeSuspectItems']}"
            )
    if batch["repeatedEvidence"]:
        lines.extend(["", "## Repeated Evidence", ""])
        for item in batch["repeatedEvidence"]:
            lines.append(
                f"- key=`{' | '.join(item['key'])}` runs={','.join(item['runs'])} "
                f"items={item['items']}"
            )
    if batch.get("fallbackSignals"):
        lines.extend(["", "## Fallback Signals", ""])
        for item in batch["fallbackSignals"]:
            lines.append(
                f"- `{item['type']}` action=`{item['plannerAction']}` "
                f"run=`{item['runLabel']}` flow=`{item['flowId']}`"
            )
    path.write_text("\n".join(lines) + "\n")
