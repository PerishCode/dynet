from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

from private_runtime_lib.briefs import runtime_brief, selection_brief, stability_brief, tcp_target_identity_brief, workload_brief
from private_runtime_lib.checks import acceptance_checks, check, product_forwarding_evidence
from private_runtime_lib.common import latest_failed_stage, sanitize_report, stage_error
from private_runtime_lib.reporting.repeat import REPEAT_MARKDOWN_KEYS, build_repeat_totals
from private_runtime_lib.tcp_flow import tcp_flow_brief, workload_flow_brief


def build_summary(
    guest: str,
    label: str,
    version: subprocess.CompletedProcess[str] | None,
    command_result: subprocess.CompletedProcess[str] | None,
    meta: dict,
    report: dict,
    install_report: dict,
    uninstall_report: dict,
    tcp_probe_report: dict,
    udp_probe_report: dict,
    ipv6_probe_report: dict,
    workload_probe_report: dict,
    log_text: str,
    stage_report: dict,
    dns_names: list[str],
    args: argparse.Namespace,
) -> dict:
    stability = stability_brief(
        report,
        log_text,
        tcp_probe_report,
        udp_probe_report,
        ipv6_probe_report,
        workload_probe_report,
    )
    selection = selection_brief(report)
    target_identity = tcp_target_identity_brief(report)
    tcp_flow = tcp_flow_brief(report)
    workload_flow = workload_flow_brief(report, workload_probe_report)
    check_report = dict(report)
    check_report["_selectionBrief"] = selection
    checks = acceptance_checks(
        check_report,
        install_report,
        uninstall_report,
        tcp_probe_report,
        udp_probe_report,
        ipv6_probe_report,
        workload_probe_report,
        dns_names,
        args,
        stability,
    )
    failed = [item for item in checks if not item["passed"]]
    return {
        "schema": "dynet-vm-private-runtime-run/v1alpha1",
        "guest": guest,
        "label": label,
        "dynetVersion": (version.stdout or version.stderr).strip().splitlines()[-1]
        if version and (version.stdout or version.stderr).strip()
        else "",
        "metadata": meta,
        "dnsNames": dns_names,
        "upstreamDns": client_dns_target(args),
        "clientDnsTarget": client_dns_target(args),
        "runtimeDnsMode": runtime_dns_mode(args),
        "qualityStateUsed": bool(args.quality_state),
        "candidateControl": candidate_control(args),
        "commandExitCode": command_result.returncode if command_result else None,
        "privacy": {
            "rawSecretsStored": False,
            "identityInformationSent": False,
            "cookiesSent": False,
            "authorizationSent": False,
            "remoteSecretConfigCleaned": True,
            "resolvedIpsRedacted": True,
        },
        "runtime": runtime_brief(report),
        "selection": selection,
        "targetIdentity": target_identity,
        "tcpFlow": tcp_flow,
        "workloadFlow": workload_flow,
        "stages": stage_report,
        "stability": stability,
        "tcpProbe": tcp_probe_report if args.tcp_forward else {},
        "udpProbe": udp_probe_report if args.udp_direct_probe else {},
        "ipv6Probe": ipv6_probe_report if args.ipv6_no_leak else {},
        "workloadProbe": workload_probe_report if args.workload_manifest else {},
        "productForwarding": {
            "tcpForwardingImplemented": bool(args.tcp_forward),
            "udpForwardingImplemented": bool(args.udp_forward),
            "ipv6NoLeakGuardEnabled": bool(args.ipv6_no_leak),
            "evidence": product_forwarding_evidence(args),
        },
        "checks": checks,
        "totals": {
            "attempted": len(checks),
            "passed": len(checks) - len(failed),
            "failed": len(failed),
        },
    }

def build_stage_failure_summary(
    guest: str,
    label: str,
    version: subprocess.CompletedProcess[str] | None,
    command_result: subprocess.CompletedProcess[str] | None,
    meta: dict,
    stage_report: dict,
    error: Exception,
    dns_names: list[str],
    workload_manifest: dict | None,
    args: argparse.Namespace,
) -> dict:
    failed_stage = latest_failed_stage(stage_report)
    checks = [
        check("pre-runtime-stages", False),
        check("remote-secret-config-cleanup", True),
    ]
    return {
        "schema": "dynet-vm-private-runtime-run/v1alpha1",
        "guest": guest,
        "label": label,
        "dynetVersion": (version.stdout or version.stderr).strip().splitlines()[-1]
        if version and (version.stdout or version.stderr).strip()
        else "",
        "metadata": meta,
        "dnsNames": dns_names,
        "upstreamDns": client_dns_target(args),
        "clientDnsTarget": client_dns_target(args),
        "runtimeDnsMode": runtime_dns_mode(args),
        "qualityStateUsed": bool(args.quality_state),
        "candidateControl": candidate_control(args),
        "commandExitCode": command_result.returncode if command_result else None,
        "privacy": {
            "rawSecretsStored": False,
            "identityInformationSent": False,
            "cookiesSent": False,
            "authorizationSent": False,
            "remoteSecretConfigCleaned": True,
            "resolvedIpsRedacted": True,
        },
        "runtime": runtime_brief({}),
        "selection": {"events": []},
        "targetIdentity": {},
        "tcpFlow": {},
        "workloadFlow": {},
        "stages": sanitize_report(stage_report),
        "stability": stability_brief({}, "", {}, {}, {}, {}),
        "tcpProbe": {},
        "udpProbe": {},
        "ipv6Probe": {},
        "workloadProbe": {"manifestLoaded": bool(workload_manifest)},
        "productForwarding": {
            "tcpForwardingImplemented": bool(args.tcp_forward),
            "udpForwardingImplemented": bool(args.udp_forward),
            "ipv6NoLeakGuardEnabled": bool(args.ipv6_no_leak),
            "evidence": "runtime was not reached; see stage report",
        },
        "failure": {
            "stage": failed_stage,
            "errorType": type(error).__name__,
            "error": stage_error(error),
        },
        "checks": checks,
        "totals": {
            "attempted": len(checks),
            "passed": 0,
            "failed": len(checks),
        },
    }

def summarize_repeat_run(summary: dict, run_dir: Path) -> dict:
    failed = int(summary.get("totals", {}).get("failed") or 0)
    stability = summary.get("stability", {})
    runtime = summary.get("runtime", {})
    bound = summary.get("selection", {}).get("boundSelection", {})
    cascade = summary.get("selection", {}).get("cascadeAttempts", {})
    target_identity = summary.get("targetIdentity", {})
    tcp_flow = summary.get("tcpFlow", {})
    workload_flow = summary.get("workloadFlow", {})
    workload = workload_brief(summary.get("workloadProbe", {}))
    return {
        "label": summary.get("label"),
        "path": str(run_dir),
        "passed": failed == 0,
        "failedChecks": failed,
        "failedStage": summary.get("failure", {}).get("stage"),
        "commandExitCode": summary.get("commandExitCode"),
        "clientDnsTarget": summary.get("clientDnsTarget"),
        "runtimeDnsMode": summary.get("runtimeDnsMode"),
        "runtimeStatus": runtime.get("status"),
        "tcpSessions": runtime.get("tcpSessions"),
        "tcpClosedSessions": runtime.get("tcpClosedSessions"),
        "tcpSessionFailures": runtime.get("tcpSessionFailures"),
        "tcpUpstreamBytes": runtime.get("tcpUpstreamBytes"),
        "tcpDownstreamBytes": runtime.get("tcpDownstreamBytes"),
        "tcpListenCapacity": runtime.get("tcpListenCapacity"),
        "tcpActiveSlotsMax": runtime.get("tcpActiveSlotsMax"),
        "tcpSlotPressureEvents": runtime.get("tcpSlotPressureEvents"),
        "boundSelection": bound,
        "cascadeAttempts": cascade,
        "targetIdentity": target_identity,
        "tcpFlow": tcp_flow,
        "workloadFlow": workload_flow,
        "udpSessions": runtime.get("udpSessions"),
        "udpSessionFailures": runtime.get("udpSessionFailures"),
        "udpUpstreamBytes": runtime.get("udpUpstreamBytes"),
        "udpDownstreamBytes": runtime.get("udpDownstreamBytes"),
        "udpDroppedPackets": runtime.get("udpDroppedPackets"),
        "ipv6PacketsDenied": runtime.get("ipv6PacketsDenied"),
        "httpsOk": stability.get("httpsOk"),
        "udpOk": stability.get("udpOk"),
        "ipv6NoLeakOk": stability.get("ipv6NoLeakOk"),
        "workloadAttempted": workload.get("attempted"),
        "workloadSuccess": workload.get("success"),
        "workloadFailure": workload.get("failure"),
        "workloadFailedByProbe": workload.get("failedByProbe", []),
        "workloadFailedByStage": workload.get("failedByStage", []),
        "workloadFailedBySurface": workload.get("failedBySurface", []),
        "workloadTunWitnessedFailures": workload.get("tunWitnessedFailures"),
        "workloadRouteViaDynetFailures": workload.get("routeViaDynetFailures"),
        "workloadSuccessRate": stability.get("workloadSuccessRate"),
        "workloadErrors": workload.get("errors", []),
        "closeReasons": stability.get("closeReasons", {}),
        "receiveWindowChallengeAcks": stability.get("receiveWindowChallengeAcks", 0),
        "dnsEarlyTimeouts": stability.get("dnsEarlyTimeouts", 0),
        "protocolShortReadErrors": stability.get("protocolShortReadErrors", 0),
        "pendingFrameTimeouts": stability.get("pendingFrameTimeouts", 0),
        "udpFailureTypes": stability.get("udpFailureTypes", {}),
        "ipDenials": stability.get("ipDenials", 0),
    }


def runtime_dns_mode(args: argparse.Namespace) -> str:
    return "udp-diagnostic-override" if getattr(args, "runtime_udp_dns", False) else "config-chain"


def client_dns_target(args: argparse.Namespace) -> str | None:
    return getattr(args, "upstream_dns", None)


def build_repeat_summary(
    guest: str,
    label: str,
    output_dir: Path,
    runs: list[dict],
    args: argparse.Namespace,
) -> dict:
    return {
        "schema": "dynet-vm-private-runtime-repeat/v1alpha1",
        "guest": guest,
        "label": label,
        "outputDir": str(output_dir),
        "tcpForward": bool(args.tcp_forward),
        "udpForward": bool(args.udp_forward),
        "udpDirectProbe": bool(args.udp_direct_probe),
        "ipv6NoLeak": bool(args.ipv6_no_leak),
        "qualityStateUsed": bool(args.quality_state),
        "clientDnsTarget": client_dns_target(args),
        "runtimeDnsMode": runtime_dns_mode(args),
        "tcpListenSlotsPerPort": args.tcp_listen_slots_per_port,
        "candidateControl": candidate_control(args),
        "workloadMinSuccessRate": args.workload_min_success_rate,
        "workloadRequireAllSuccess": bool(getattr(args, "workload_require_all_success", False)),
        "runs": runs,
        "totals": build_repeat_totals(runs, args),
    }


def candidate_control(args: argparse.Namespace) -> dict:
    return {
        "forceBoundCandidate": getattr(args, "force_bound_candidate", None),
        "poisonFirstBoundCandidate": bool(getattr(args, "poison_first_bound_candidate", False)),
        "poisonBoundOnly": bool(getattr(args, "poison_bound_only", False)),
        "forcePrivateDownstreamFailure": bool(
            getattr(args, "force_private_downstream_failure", False)
        ),
        "tcpRouteDirectFallback": bool(getattr(args, "tcp_route_direct_fallback", False)),
        "tcpRouteNonDirectFallback": bool(
            getattr(args, "tcp_route_non_direct_fallback", False)
        ),
    }


def write_markdown(path: Path, summary: dict) -> None:
    lines = [
        "# VM Private Runtime Acceptance",
        "",
        f"- guest: `{summary['guest']}`",
        f"- dns names: `{', '.join(summary['dnsNames'])}`",
        f"- attempted checks: `{summary['totals']['attempted']}`",
        f"- passed: `{summary['totals']['passed']}`",
        f"- failed: `{summary['totals']['failed']}`",
        f"- remote secret config cleaned: `{summary['privacy']['remoteSecretConfigCleaned']}`",
        "",
        "## Runtime",
        "",
    ]
    for key, value in summary["runtime"].items():
        lines.append(f"- {key}: `{value}`")
    lines.extend(["", "## Checks", ""])
    for item in summary["checks"]:
        lines.append(f"- `{item['name']}` passed=`{item['passed']}`")
    append_quality(lines, summary.get("selection", {}).get("boundSelection", {}))
    append_cascade(lines, summary.get("selection", {}).get("cascadeAttempts", {}))
    if summary.get("failure"):
        lines.extend(
            [
                "",
                "## Failure",
                "",
                f"- stage: `{summary['failure'].get('stage')}`",
                f"- errorType: `{summary['failure'].get('errorType')}`",
                f"- error: `{summary['failure'].get('error')}`",
            ]
        )
    if summary.get("stability"):
        lines.extend(["", "## Stability", ""])
        for key, value in summary["stability"].items():
            if key == "sessionTimings":
                continue
            lines.append(f"- {key}: `{value}`")
    if summary.get("targetIdentity"):
        lines.extend(["", "## Target Identity", ""])
        for key, value in summary["targetIdentity"].items():
            lines.append(f"- {key}: `{value}`")
    if summary.get("tcpFlow"):
        lines.extend(["", "## TCP Flow", ""])
        for key, value in summary["tcpFlow"].items():
            lines.append(f"- {key}: `{value}`")
    if summary.get("workloadProbe"):
        workload = summary["workloadProbe"]
        lines.extend(["", "## Workload", ""])
        totals = workload.get("totals", {})
        concurrency = workload.get("concurrency", {})
        lines.append(f"- attempted: `{totals.get('count')}`")
        lines.append(f"- success rate: `{totals.get('successRate')}`")
        lines.append(f"- concurrency: `{concurrency}`")
        lines.append(f"- errors: `{workload.get('errors', [])}`")
        for item in workload.get("byBehavior", []):
            lines.append(
                f"- behavior `{item['key']}` success={item['success']}/{item['count']} "
                f"rate={item['successRate']}"
            )
    lines.extend(["", "## Product Forwarding", "", summary["productForwarding"]["evidence"]])
    path.write_text("\n".join(lines) + "\n")

def write_repeat_markdown(path: Path, summary: dict) -> None:
    totals = summary["totals"]
    lines = [
        "# VM Private Runtime Repeat Acceptance",
        "",
        f"- guest: `{summary['guest']}`",
    ]
    for key in REPEAT_MARKDOWN_KEYS:
        lines.append(f"- {key}: `{totals.get(key)}`")
    lines.extend(["", "## Runs", ""])
    for run in summary["runs"]:
        lines.append(repeat_run_line(run))
    path.write_text("\n".join(lines) + "\n")


def repeat_run_line(run: dict) -> str:
    bound = run.get("boundSelection", {})
    cascade = run.get("cascadeAttempts", {})
    target_identity = run.get("targetIdentity", {})
    tcp_flow = run.get("tcpFlow", {})
    workload_flow = run.get("workloadFlow", {})
    return (
        f"- `{run['label']}` passed=`{run['passed']}` "
        f"failedChecks=`{run['failedChecks']}` tcpFailures=`{run['tcpSessionFailures']}` "
        f"tcpActiveMax=`{run.get('tcpActiveSlotsMax')}` "
        f"flowPath=`{tcp_flow.get('pathCompleteFlows')}/{tcp_flow.get('startedFlows')}` "
        f"flowPayload=`{tcp_flow.get('payloadBidirectionalFlows')}/{tcp_flow.get('payloadStartedFlows')}` "
        f"udpFailures=`{run['udpSessionFailures']}` ipv6Denied=`{run['ipv6PacketsDenied']}` "
        f"qualitySets=`{bound.get('candidateSets')}` "
        f"qualityBehind=`{bound.get('selectedBehind')}` "
        f"cascadeFailed=`{cascade.get('failedAttempts')}` "
        f"cascadeRetryable=`{cascade.get('retryableFailures')}` "
        f"cascadeStopped=`{cascade.get('stoppedFailures')}` "
        f"cascadeStoppedFlows=`{cascade.get('stoppedFlows')}` "
        f"domainTargets=`{target_identity.get('domainConnectTargets')}` "
        f"httpsOk=`{run['httpsOk']}` udpOk=`{run['udpOk']}` "
        f"ipv6NoLeakOk=`{run['ipv6NoLeakOk']}` workloadSR=`{run['workloadSuccessRate']}` "
        f"workloadFlow=`{workload_flow.get('matchedEntries')}/{workload_flow.get('entries')}` "
        f"stage=`{run['failedStage']}`"
    )


def append_quality(lines: list[str], bound: dict) -> None:
    if not bound:
        return
    lines.extend(["", "## Quality Bound Selection", ""])
    lines.append(f"- candidate sets: `{bound.get('candidateSets')}`")
    lines.append(f"- selected with quality: `{bound.get('selectedWithQuality')}`")
    lines.append(f"- selected behind: `{bound.get('selectedBehind')}`")
    lines.append(f"- by selected: `{bound.get('bySelected')}`")


def append_cascade(lines: list[str], cascade: dict) -> None:
    if not cascade:
        return
    lines.extend(["", "## Cascade Attempts", ""])
    lines.append(f"- finished attempts: `{cascade.get('finishedAttempts')}`")
    lines.append(f"- failed attempts: `{cascade.get('failedAttempts')}`")
    lines.append(f"- retryable failures: `{cascade.get('retryableFailures')}`")
    lines.append(f"- stopped failures: `{cascade.get('stoppedFailures')}`")
    append_cascade_stops(lines, cascade)
    lines.append(f"- recovered flows: `{cascade.get('recoveredFlows')}`")
    lines.append(f"- failed by scope: `{cascade.get('failedByScope')}`")
    lines.append(f"- failed by disposition: `{cascade.get('failedByDisposition')}`")
    lines.append(f"- failed by stage: `{cascade.get('failedByStageSurface')}`")
    lines.append(
        f"- failed by stage disposition: `{cascade.get('failedByStageDisposition')}`"
    )


def append_cascade_stops(lines: list[str], cascade: dict) -> None:
    lines.append(f"- stopped flows: `{cascade.get('stoppedFlows')}`")
    lines.append(f"- stopped bound exhausted flows: `{cascade.get('stoppedBoundExhaustedFlows')}`")
    lines.append(f"- stopped flow stop reasons: `{cascade.get('stoppedFlowByStopReason')}`")
    lines.append(f"- stopped flow stages: `{cascade.get('stoppedFlowByStageSurface')}`")
