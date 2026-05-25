from __future__ import annotations

import argparse
import copy
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from common import (
    CommandError,
    Lab,
    RESOURCE_LIMITS,
    guard_repo_resources,
    guest_ssh,
    logger,
    q,
    validate_name,
)
from lib.interface import resolve_trojan_interface
from private_probe import (
    build_artifact,
    build_secret_config,
    cleanup_guest_files,
    install_artifact,
    write_guest_file,
    write_json,
)
from private_runtime_lib.common import (
    DEFAULT_DNS_NAMES,
    StageRecorder,
    latest_failed_stage,
    sanitize_report,
    sanitize_text,
    stage_error,
    task_output_dir,
)
from private_runtime_lib.config import (
    add_required_domain_suffixes,
    augment_runtime_config,
    load_workload_manifest,
    runtime_command,
)
from private_runtime_lib.probe_scripts import nft_dropin_command
from private_runtime_lib.summary import (
    build_repeat_summary,
    build_stage_failure_summary,
    build_summary,
    summarize_repeat_run,
    write_markdown,
    write_repeat_markdown,
)


def command_guest(lab: Lab, args: argparse.Namespace) -> None:
    if args.repeat < 1:
        raise CommandError("--repeat must be at least 1")
    if args.udp_direct_probe and not args.udp_forward:
        raise CommandError("--udp-direct-probe requires --udp-forward")
    if args.repeat > 1:
        command_guest_repeat(lab, args)
        return

    guest = validate_name(args.guest, "guest")
    label = args.label or datetime.now(timezone.utc).strftime("vm-private-runtime-%Y%m%dT%H%M%SZ")
    label = validate_name(label, "label")
    output_dir = task_output_dir(args.output_dir, label)
    summary = run_guest_once(lab, args, guest, label, output_dir)
    print(json.dumps({"outputDir": str(output_dir), **summary["totals"]}, sort_keys=True))
    if summary["totals"]["failed"]:
        raise SystemExit(1)

def command_guest_repeat(lab: Lab, args: argparse.Namespace) -> None:
    guest = validate_name(args.guest, "guest")
    label = args.label or datetime.now(timezone.utc).strftime("vm-private-runtime-%Y%m%dT%H%M%SZ")
    label = validate_name(label, "label")
    output_dir = task_output_dir(args.output_dir, label)
    guard_repo_resources(
        "VM private runtime artifacts",
        [("vm-private-runtime", output_dir.parent)],
        RESOURCE_LIMITS["local-collect"],
    )
    output_dir.mkdir(parents=True, exist_ok=True)

    install_args = args
    if not args.skip_install:
        recorder = StageRecorder(output_dir / "stage-report.json", label)
        try:
            artifact = recorder.run("build-artifact", lambda: build_artifact(lab, install_args))
            recorder.run(
                "install-artifact", lambda: install_artifact(lab, guest, artifact, install_args)
            )
        except Exception as error:
            summary = build_repeat_summary(guest, label, output_dir, [], args)
            summary["failure"] = {
                "stage": latest_failed_stage(recorder.report),
                "errorType": type(error).__name__,
                "error": stage_error(error),
            }
            summary["stages"] = sanitize_report(recorder.report)
            summary["totals"]["failedRuns"] = 1
            write_json(output_dir / "summary.json", summary)
            write_repeat_markdown(output_dir / "summary.md", summary)
            print(json.dumps({"outputDir": str(output_dir), **summary["totals"]}, sort_keys=True))
            raise SystemExit(1)

    runs = []
    run_args = copy.copy(args)
    run_args.skip_install = True
    for index in range(1, args.repeat + 1):
        run_label = validate_name(f"{label}-{index:02d}", "label")
        run_dir = output_dir / f"run-{index:02d}"
        summary = run_guest_once(lab, run_args, guest, run_label, run_dir)
        runs.append(summarize_repeat_run(summary, run_dir))
        repeat_summary = build_repeat_summary(guest, label, output_dir, runs, args)
        write_json(output_dir / "summary.json", repeat_summary)
        write_repeat_markdown(output_dir / "summary.md", repeat_summary)

    summary = build_repeat_summary(guest, label, output_dir, runs, args)
    write_json(output_dir / "summary.json", summary)
    write_repeat_markdown(output_dir / "summary.md", summary)
    print(json.dumps({"outputDir": str(output_dir), **summary["totals"]}, sort_keys=True))
    if summary["totals"]["failedRuns"]:
        raise SystemExit(1)

def run_guest_once(
    lab: Lab,
    args: argparse.Namespace,
    guest: str,
    label: str,
    output_dir: Path,
) -> dict:
    guard_repo_resources(
        "VM private runtime artifacts",
        [("vm-private-runtime", output_dir.parent)],
        RESOURCE_LIMITS["local-collect"],
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    recorder = StageRecorder(output_dir / "stage-report.json", label)

    dns_names = list(args.dns_name or DEFAULT_DNS_NAMES)
    workload_manifest = recorder.run("load-workload-manifest", lambda: load_workload_manifest(args))
    add_required_domain_suffixes(args, dns_names, workload_manifest)
    guest_files: list[str] = []
    command_result = None
    version = None
    meta: dict = {}
    report: dict = {}
    log_text = ""
    install_report: dict = {}
    uninstall_report: dict = {}
    tcp_probe_report = {}
    udp_probe_report = {}
    ipv6_probe_report = {}
    workload_probe_report = {}
    error: Exception | None = None

    try:
        maybe_install_artifact(recorder, lab, guest, args)
        recorder.run(
            "resolve-trojan-interface",
            lambda: resolve_trojan_interface(lab, guest, args),
        )
        config_text, meta = build_runtime_config(recorder, args, output_dir)
        remote_paths = runtime_paths(label, args, workload_manifest)
        guest_files = runtime_guest_files(remote_paths)
        write_runtime_inputs(recorder, lab, guest, remote_paths, config_text, workload_manifest, args)
        version = collect_dynet_version(recorder, lab, guest, args)
        command_result = run_acceptance(
            recorder, lab, guest, label, remote_paths, dns_names, workload_manifest, args
        )
        (
            report,
            log_text,
            install_report,
            uninstall_report,
            tcp_probe_report,
            udp_probe_report,
            ipv6_probe_report,
            workload_probe_report,
        ) = collect_runtime_outputs(recorder, lab, guest, remote_paths, workload_manifest, args)
    except Exception as caught:
        error = caught
    finally:
        if guest_files:
            try:
                recorder.run(
                    "cleanup-guest-files",
                    lambda: cleanup_guest_files(
                        lab, guest, guest_files, user=args.user, source=args.source
                    ),
                )
            except Exception as cleanup_error:
                if error is None:
                    error = cleanup_error

    sanitized_report = sanitize_report(report)
    sanitized_install = sanitize_report(install_report)
    sanitized_uninstall = sanitize_report(uninstall_report)
    sanitized_tcp_probe = sanitize_report(tcp_probe_report)
    sanitized_udp_probe = sanitize_report(udp_probe_report)
    sanitized_ipv6_probe = sanitize_report(ipv6_probe_report)
    sanitized_workload_probe = sanitize_report(workload_probe_report)
    write_json(output_dir / "runtime-report.json", sanitized_report)
    write_json(output_dir / "install-report.json", sanitized_install)
    write_json(output_dir / "uninstall-report.json", sanitized_uninstall)
    if args.tcp_forward:
        write_json(output_dir / "tcp-probe.json", sanitized_tcp_probe)
    if args.udp_direct_probe:
        write_json(output_dir / "udp-probe.json", sanitized_udp_probe)
    if args.ipv6_no_leak:
        write_json(output_dir / "ipv6-probe.json", sanitized_ipv6_probe)
    if workload_manifest:
        write_json(output_dir / "workload-manifest.json", sanitize_report(workload_manifest))
        write_json(output_dir / "workload-probe.json", sanitized_workload_probe)
    (output_dir / "runtime-log.txt").write_text(sanitize_text(log_text))
    (output_dir / "command-stdout.txt").write_text(
        sanitize_text(command_result.stdout if command_result else "")
    )
    (output_dir / "command-stderr.txt").write_text(
        sanitize_text(command_result.stderr if command_result else "")
    )

    if error is not None:
        summary = build_stage_failure_summary(
            guest,
            label,
            version,
            command_result,
            meta,
            recorder.report,
            error,
            dns_names,
            workload_manifest,
            args,
        )
    else:
        summary = build_summary(
            guest,
            label,
            version,
            command_result,
            meta,
            sanitized_report,
            sanitized_install,
            sanitized_uninstall,
            sanitized_tcp_probe,
            sanitized_udp_probe,
            sanitized_ipv6_probe,
            sanitized_workload_probe,
            sanitize_text(log_text),
            recorder.report,
            dns_names,
            args,
        )
    write_json(output_dir / "summary.json", summary)
    write_markdown(output_dir / "summary.md", summary)
    return summary

def maybe_install_artifact(
    recorder: StageRecorder,
    lab: Lab,
    guest: str,
    args: argparse.Namespace,
) -> None:
    if args.skip_install:
        return
    artifact = recorder.run("build-artifact", lambda: build_artifact(lab, args))
    recorder.run("install-artifact", lambda: install_artifact(lab, guest, artifact, args))

def build_runtime_config(
    recorder: StageRecorder,
    args: argparse.Namespace,
    output_dir: Path,
) -> tuple[str, dict]:
    config_text, meta = recorder.run(
        "build-secret-config", lambda: build_secret_config(args, output_dir)
    )
    config_text = recorder.run(
        "augment-runtime-config", lambda: augment_runtime_config(config_text, args)
    )
    return config_text, meta

def runtime_paths(label: str, args: argparse.Namespace, workload_manifest: dict | None) -> dict[str, str | None]:
    return {
        "config": f"/tmp/dynet-{label}-private-config.json",
        "quality": f"/tmp/dynet-{label}-private-quality.json" if args.quality_state else None,
        "report": f"/tmp/dynet-{label}-private-runtime.json",
        "log": f"/tmp/dynet-{label}-private-runtime.err",
        "install": f"/tmp/dynet-{label}-private-install.json",
        "uninstall": f"/tmp/dynet-{label}-private-uninstall.json",
        "tcpProbe": f"/tmp/dynet-{label}-private-tcp-probe.json",
        "udpProbe": f"/tmp/dynet-{label}-private-udp-probe.json",
        "ipv6Probe": f"/tmp/dynet-{label}-private-ipv6-probe.json",
        "workload": f"/tmp/dynet-{label}-private-workload-manifest.json" if workload_manifest else None,
        "workloadProbe": f"/tmp/dynet-{label}-private-workload-probe.json",
    }

def runtime_guest_files(paths: dict[str, str | None]) -> list[str]:
    keys = [
        "config",
        "report",
        "log",
        "install",
        "uninstall",
        "tcpProbe",
        "udpProbe",
        "ipv6Probe",
        "workloadProbe",
        "quality",
        "workload",
    ]
    return [path for key in keys if (path := paths[key])]

def write_runtime_inputs(
    recorder: StageRecorder,
    lab: Lab,
    guest: str,
    paths: dict[str, str | None],
    config_text: str,
    workload_manifest: dict | None,
    args: argparse.Namespace,
) -> None:
    recorder.run(
        "prepare-nft-dropin",
        lambda: guest_ssh(lab, guest, nft_dropin_command(), user=args.user, source=args.source),
    )
    recorder.run(
        "write-secret-config",
        lambda: write_guest_file(
            lab, guest, str(paths["config"]), config_text, user=args.user, source=args.source
        ),
    )
    if args.quality_state and paths["quality"]:
        quality_text = Path(args.quality_state).read_text()
        recorder.run(
            "write-quality-state",
            lambda: write_guest_file(
                lab, guest, str(paths["quality"]), quality_text, user=args.user, source=args.source
            ),
        )
    if workload_manifest and paths["workload"]:
        workload_text = json.dumps(workload_manifest, ensure_ascii=False, sort_keys=True)
        recorder.run(
            "write-workload-manifest",
            lambda: write_guest_file(
                lab, guest, str(paths["workload"]), workload_text, user=args.user, source=args.source
            ),
        )

def collect_dynet_version(
    recorder: StageRecorder,
    lab: Lab,
    guest: str,
    args: argparse.Namespace,
) -> subprocess.CompletedProcess[str]:
    return recorder.run(
        "dynet-version",
        lambda: guest_ssh(
            lab,
            guest,
            f"{q(args.dynet_bin)} version",
            user=args.user,
            source=args.source,
            check=False,
            capture=True,
        ),
    )

def run_acceptance(
    recorder: StageRecorder,
    lab: Lab,
    guest: str,
    label: str,
    paths: dict[str, str | None],
    dns_names: list[str],
    workload_manifest: dict | None,
    args: argparse.Namespace,
) -> subprocess.CompletedProcess[str]:
    command = runtime_command(
        label,
        str(paths["config"]),
        paths["quality"],
        paths["workload"],
        dns_names,
        args,
        workload_manifest,
    )
    logger.info("run private runtime acceptance")
    return recorder.run(
        "run-acceptance",
        lambda: guest_ssh(
            lab, guest, command, user=args.user, source=args.source, check=False, capture=True
        ),
    )

def collect_runtime_outputs(
    recorder: StageRecorder,
    lab: Lab,
    guest: str,
    paths: dict[str, str | None],
    workload_manifest: dict | None,
    args: argparse.Namespace,
) -> tuple[dict, str, dict, dict, dict, dict, dict, dict]:
    report = recorder.run(
        "collect-runtime-report",
        lambda: read_remote_json(lab, guest, str(paths["report"]), args),
    )
    log_text = recorder.run(
        "collect-runtime-log",
        lambda: read_remote_text(lab, guest, str(paths["log"]), args),
    )
    install_report = recorder.run(
        "collect-install-report",
        lambda: read_remote_json(lab, guest, str(paths["install"]), args),
    )
    uninstall_report = recorder.run(
        "collect-uninstall-report",
        lambda: read_remote_json(lab, guest, str(paths["uninstall"]), args),
    )
    tcp_probe = optional_remote_json(recorder, lab, guest, paths["tcpProbe"], args, args.tcp_forward, "tcp")
    udp_probe = optional_remote_json(recorder, lab, guest, paths["udpProbe"], args, args.udp_direct_probe, "udp")
    ipv6_probe = optional_remote_json(recorder, lab, guest, paths["ipv6Probe"], args, args.ipv6_no_leak, "ipv6")
    workload_probe = optional_remote_json(
        recorder, lab, guest, paths["workloadProbe"], args, bool(workload_manifest), "workload"
    )
    return report, log_text, install_report, uninstall_report, tcp_probe, udp_probe, ipv6_probe, workload_probe

def optional_remote_json(
    recorder: StageRecorder,
    lab: Lab,
    guest: str,
    path: str | None,
    args: argparse.Namespace,
    enabled: bool,
    name: str,
) -> dict:
    if not enabled or not path:
        return {}
    return recorder.run(
        f"collect-{name}-probe-report",
        lambda: read_remote_json(lab, guest, path, args),
    )

def read_remote_json(lab: Lab, guest: str, path: str, args: argparse.Namespace) -> dict:
    text = read_remote_text(lab, guest, path, args)
    if not text.strip():
        return {}
    try:
        value = json.loads(text)
    except json.JSONDecodeError as error:
        return {
            "schema": "dynet-runtime/invalid-json",
            "status": "deny",
            "reason": f"invalid JSON from {path}: {error}",
        }
    if isinstance(value, dict):
        return value
    return {"schema": "dynet-runtime/unexpected-json", "valueType": type(value).__name__}

def read_remote_text(lab: Lab, guest: str, path: str, args: argparse.Namespace) -> str:
    result = guest_ssh(
        lab,
        guest,
        f"cat {q(path)} 2>/dev/null || true",
        user=args.user,
        source=args.source,
        check=False,
        capture=True,
    )
    return result.stdout
