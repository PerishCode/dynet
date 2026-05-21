from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

from private_runtime_lib.briefs import runtime_brief, selection_brief, stability_brief
from private_runtime_lib.checks import (
    acceptance_checks,
    check,
    product_forwarding_evidence,
)
from private_runtime_lib.common import latest_failed_stage, sanitize_report, stage_error


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
    checks = acceptance_checks(
        report,
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
        "upstreamDns": args.upstream_dns,
        "qualityStateUsed": bool(args.quality_state),
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
        "selection": selection_brief(report),
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
        "upstreamDns": args.upstream_dns,
        "qualityStateUsed": bool(args.quality_state),
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
    return {
        "label": summary.get("label"),
        "path": str(run_dir),
        "passed": failed == 0,
        "failedChecks": failed,
        "failedStage": summary.get("failure", {}).get("stage"),
        "commandExitCode": summary.get("commandExitCode"),
        "runtimeStatus": runtime.get("status"),
        "tcpSessions": runtime.get("tcpSessions"),
        "tcpSessionFailures": runtime.get("tcpSessionFailures"),
        "tcpUpstreamBytes": runtime.get("tcpUpstreamBytes"),
        "tcpDownstreamBytes": runtime.get("tcpDownstreamBytes"),
        "udpSessions": runtime.get("udpSessions"),
        "udpSessionFailures": runtime.get("udpSessionFailures"),
        "udpUpstreamBytes": runtime.get("udpUpstreamBytes"),
        "udpDownstreamBytes": runtime.get("udpDownstreamBytes"),
        "udpDroppedPackets": runtime.get("udpDroppedPackets"),
        "ipv6PacketsDenied": runtime.get("ipv6PacketsDenied"),
        "httpsOk": stability.get("httpsOk"),
        "udpOk": stability.get("udpOk"),
        "ipv6NoLeakOk": stability.get("ipv6NoLeakOk"),
        "workloadSuccessRate": stability.get("workloadSuccessRate"),
        "closeReasons": stability.get("closeReasons", {}),
        "receiveWindowChallengeAcks": stability.get("receiveWindowChallengeAcks", 0),
        "dnsEarlyTimeouts": stability.get("dnsEarlyTimeouts", 0),
        "protocolShortReadErrors": stability.get("protocolShortReadErrors", 0),
        "pendingFrameTimeouts": stability.get("pendingFrameTimeouts", 0),
        "udpFailureTypes": stability.get("udpFailureTypes", {}),
        "ipDenials": stability.get("ipDenials", 0),
    }

def build_repeat_summary(
    guest: str,
    label: str,
    output_dir: Path,
    runs: list[dict],
    args: argparse.Namespace,
) -> dict:
    failed_runs = [run for run in runs if not run.get("passed")]
    totals = {
        "runs": len(runs),
        "passedRuns": len(runs) - len(failed_runs),
        "failedRuns": len(failed_runs),
        "receiveWindowChallengeAcks": sum(
            int(run.get("receiveWindowChallengeAcks") or 0) for run in runs
        ),
        "dnsEarlyTimeouts": sum(int(run.get("dnsEarlyTimeouts") or 0) for run in runs),
        "protocolShortReadErrors": sum(
            int(run.get("protocolShortReadErrors") or 0) for run in runs
        ),
        "pendingFrameTimeouts": sum(int(run.get("pendingFrameTimeouts") or 0) for run in runs),
        "udpSessionFailures": sum(int(run.get("udpSessionFailures") or 0) for run in runs),
        "udpDroppedPackets": sum(int(run.get("udpDroppedPackets") or 0) for run in runs),
        "ipv6PacketsDenied": sum(int(run.get("ipv6PacketsDenied") or 0) for run in runs),
        "ipDenials": sum(int(run.get("ipDenials") or 0) for run in runs),
        "workloadFailedRuns": sum(
            1
            for run in runs
            if run.get("workloadSuccessRate") is not None
            and float(run.get("workloadSuccessRate") or 0) < float(args.workload_min_success_rate)
        ),
    }
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
        "runs": runs,
        "totals": totals,
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
    if summary.get("workloadProbe"):
        workload = summary["workloadProbe"]
        lines.extend(["", "## Workload", ""])
        totals = workload.get("totals", {})
        lines.append(f"- attempted: `{totals.get('count')}`")
        lines.append(f"- success rate: `{totals.get('successRate')}`")
        lines.append(f"- errors: `{workload.get('errors', [])}`")
        for item in workload.get("byBehavior", []):
            lines.append(
                f"- behavior `{item['key']}` success={item['success']}/{item['count']} "
                f"rate={item['successRate']}"
            )
    lines.extend(["", "## Product Forwarding", "", summary["productForwarding"]["evidence"]])
    path.write_text("\n".join(lines) + "\n")

def write_repeat_markdown(path: Path, summary: dict) -> None:
    lines = [
        "# VM Private Runtime Repeat Acceptance",
        "",
        f"- guest: `{summary['guest']}`",
        f"- runs: `{summary['totals']['runs']}`",
        f"- passed runs: `{summary['totals']['passedRuns']}`",
        f"- failed runs: `{summary['totals']['failedRuns']}`",
        f"- receive-window challenge ACKs: `{summary['totals']['receiveWindowChallengeAcks']}`",
        f"- DNS early timeouts: `{summary['totals']['dnsEarlyTimeouts']}`",
        f"- protocol short-read errors: `{summary['totals']['protocolShortReadErrors']}`",
        f"- UDP session failures: `{summary['totals']['udpSessionFailures']}`",
        f"- UDP dropped packets: `{summary['totals']['udpDroppedPackets']}`",
        f"- IPv6 packets denied: `{summary['totals']['ipv6PacketsDenied']}`",
        f"- workload failed runs: `{summary['totals'].get('workloadFailedRuns')}`",
        "",
        "## Runs",
        "",
    ]
    for run in summary["runs"]:
        lines.append(
            f"- `{run['label']}` passed=`{run['passed']}` "
            f"failedChecks=`{run['failedChecks']}` tcpFailures=`{run['tcpSessionFailures']}` "
            f"udpFailures=`{run['udpSessionFailures']}` ipv6Denied=`{run['ipv6PacketsDenied']}` "
            f"httpsOk=`{run['httpsOk']}` udpOk=`{run['udpOk']}` "
            f"ipv6NoLeakOk=`{run['ipv6NoLeakOk']}` workloadSR=`{run['workloadSuccessRate']}` "
            f"stage=`{run['failedStage']}`"
        )
    path.write_text("\n".join(lines) + "\n")
