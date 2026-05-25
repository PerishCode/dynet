#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from common import (
    ROOT,
    CommandError,
    Lab,
    RESOURCE_LIMITS,
    guard_repo_resources,
    guest_ssh,
    join,
    logger,
    q,
    validate_name,
    vmctl_command,
)
from lib.interface import resolve_trojan_interface
from lib.private_probe_cli import build_parser as build_private_probe_parser
from lib.probe_summary import (
    cascade_attempts,
    failed_stage,
    failure_scope,
    final_bound_selected,
)
from lib.private_paired_report import command_paired_selection


DEFAULT_TARGETS = ["https://www.cloudflare.com/", "https://chatgpt.com/"]


def task_output_dir(raw: str | None, label: str) -> Path:
    base = (ROOT / ".task" / "resources").resolve(strict=False)
    if raw:
        path = Path(raw).expanduser()
        candidate = path if path.is_absolute() else ROOT / path
    else:
        candidate = base / "vm-private-cascade" / label
    resolved = candidate.resolve(strict=False)
    if resolved != base and base not in resolved.parents:
        raise CommandError(f"output must stay under .task/resources: {candidate}")
    return resolved


def build_artifact(lab: Lab, args: argparse.Namespace) -> Path:
    if args.artifact:
        return Path(args.artifact).expanduser().resolve()
    command = vmctl_command(
        "dev",
        *lab_args(lab),
        "build",
        "--target",
        args.target,
    )
    if args.release:
        command.append("--release")
    logger.info("build guest artifact: %s", join(command))
    if lab.dry_run:
        return ROOT / "target" / args.target / ("release" if args.release else "debug") / "dynet"
    result = subprocess.run(command, cwd=ROOT, check=True, capture_output=True, text=True)
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if not lines:
        raise CommandError("dev build did not print an artifact path")
    return Path(lines[-1]).resolve()


def install_artifact(lab: Lab, guest: str, artifact: Path, args: argparse.Namespace) -> None:
    command = vmctl_command(
        "setup",
        *lab_args(lab),
        "install-bin",
        guest,
        str(artifact),
        "--user",
        args.user,
        "--source",
        args.source,
        "--dest",
        args.dynet_bin,
    )
    logger.info("install guest artifact: %s", join(command))
    if not lab.dry_run:
        subprocess.run(command, cwd=ROOT, check=True)


def build_secret_config(args: argparse.Namespace, output_dir: Path) -> tuple[str, dict]:
    output_dir.mkdir(parents=True, exist_ok=True)
    meta_path = output_dir / "meta.json"
    with tempfile.TemporaryDirectory(prefix="dynet-vm-private-") as temp_dir:
        config_path = Path(temp_dir) / "private-cascade.json"
        logger.info("build temporary dynet private config")
        command = private_config_command(args, config_path, meta_path)
        subprocess.run(command, check=True, capture_output=True, text=True)
        config_text = config_path.read_text()
    meta = json.loads(meta_path.read_text())
    return config_text, meta


def private_config_command(args: argparse.Namespace, config_path: Path, meta_path: Path) -> list[str]:
    command = [
        sys.executable, str(ROOT / "scripts" / "experiments" / "tunnel_private_lab.py"),
        "build", "--output-config", str(config_path), "--output-meta", str(meta_path),
        "--tunnel-name", args.tunnel_name, "--strategy-key", args.strategy_key,
    ]
    if args.filter is not None:
        command.extend(["--filter", args.filter])
    if args.limit:
        command.extend(["--limit", str(args.limit)])
    if getattr(args, "candidate_offset", 0):
        command.extend(["--candidate-offset", str(args.candidate_offset)])
    for value in args.domain_suffix:
        command.extend(["--domain-suffix", value])
    for value in args.domain:
        command.extend(["--domain", value])
    for value in args.supported_type or []:
        command.extend(["--supported-type", value])
    if getattr(args, "resolve_tunnel_server", False):
        command.append("--resolve-tunnel-server")
    if getattr(args, "tcp_route_plan_private", False):
        command.append("--tcp-route-plan-private")
    if getattr(args, "trojan_interface_name", None):
        command.extend(["--trojan-interface-name", args.trojan_interface_name])
    return command


def write_guest_file(lab: Lab, guest: str, path: str, content: str, *, user: str, source: str) -> None:
    guest_ssh(
        lab,
        guest,
        f"umask 077 && cat > {q(path)}",
        user=user,
        source=source,
        input_text=content,
    )


def cleanup_guest_files(lab: Lab, guest: str, paths: list[str], *, user: str, source: str) -> None:
    if not paths:
        return
    command = "rm -f " + " ".join(q(path) for path in paths)
    guest_ssh(lab, guest, command, user=user, source=source, check=False)


def run_guest_probe(
    lab: Lab,
    guest: str,
    url: str,
    remote_config: str,
    remote_quality: str | None,
    args: argparse.Namespace,
) -> dict:
    command = [
        args.dynet_bin,
        "probe",
        "--config",
        remote_config,
        "--url",
        url,
        "--format",
        "json",
    ]
    if remote_quality:
        command.extend(["--quality-state", remote_quality])
    result = guest_ssh(
        lab,
        guest,
        join(command),
        user=args.user,
        source=args.source,
        check=False,
        capture=True,
    )
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        report = {
            "schema": "dynet-probe/invalid-output",
            "status": "deny",
            "reason": f"invalid dynet probe JSON: {error}; stderr={result.stderr.strip()}",
            "events": [],
        }
    report["_exitCode"] = result.returncode
    return report


def command_guest(lab: Lab, args: argparse.Namespace) -> None:
    guest = validate_name(args.guest, "guest")
    label = args.label or datetime.now(timezone.utc).strftime("vm-private-%Y%m%dT%H%M%SZ")
    label = validate_name(label, "label")
    output_dir = task_output_dir(args.output_dir, label)
    guard_repo_resources(
        "VM private probe artifacts",
        [("vm-private-cascade", output_dir.parent)],
        RESOURCE_LIMITS["local-collect"],
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    report_dir = output_dir / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)

    if not args.skip_install:
        artifact = build_artifact(lab, args)
        install_artifact(lab, guest, artifact, args)

    targets = args.target_url or DEFAULT_TARGETS
    if not args.domain_suffix:
        args.domain_suffix = sorted({target_family(url) for url in targets})
    resolve_trojan_interface(lab, guest, args)
    config_text, meta = build_secret_config(args, output_dir)
    remote_config = f"/tmp/dynet-{label}-private.json"
    remote_quality = f"/tmp/dynet-{label}-quality.json" if args.quality_state else None
    guest_files = [remote_config] + ([remote_quality] if remote_quality else [])

    reports = []
    try:
        stage_guest_inputs(lab, guest, remote_config, config_text, remote_quality, args)
        version = guest_dynet_version(lab, guest, args)
        reports = run_guest_reports(lab, guest, targets, remote_config, remote_quality, report_dir, args)
    finally:
        cleanup_guest_files(lab, guest, guest_files, user=args.user, source=args.source)

    summary = build_summary(guest, label, version, meta, reports)
    write_json(output_dir / "summary.json", summary)
    write_markdown(output_dir / "summary.md", summary)
    build_quality_state(output_dir, args)
    print(json.dumps({"outputDir": str(output_dir), **summary["totals"]}, sort_keys=True))
    if summary["totals"]["failed"]:
        raise SystemExit(1)


def command_paired(lab: Lab, args: argparse.Namespace) -> None:
    from lib.private_paired import command_paired as run_paired

    run_paired(lab, args)


def stage_guest_inputs(
    lab: Lab,
    guest: str,
    remote_config: str,
    config_text: str,
    remote_quality: str | None,
    args: argparse.Namespace,
) -> None:
    write_guest_file(lab, guest, remote_config, config_text, user=args.user, source=args.source)
    if args.quality_state and remote_quality:
        quality_text = Path(args.quality_state).read_text()
        write_guest_file(lab, guest, remote_quality, quality_text, user=args.user, source=args.source)


def guest_dynet_version(lab: Lab, guest: str, args: argparse.Namespace) -> subprocess.CompletedProcess[str]:
    return guest_ssh(
        lab,
        guest,
        f"{q(args.dynet_bin)} version",
        user=args.user,
        source=args.source,
        check=False,
        capture=True,
    )


def run_guest_reports(
    lab: Lab,
    guest: str,
    targets: list[str],
    remote_config: str,
    remote_quality: str | None,
    report_dir: Path,
    args: argparse.Namespace,
) -> list[dict]:
    reports = []
    for url in targets:
        report = run_guest_probe(lab, guest, url, remote_config, remote_quality, args)
        report_path = report_dir / f"{safe_slug(url)}.json"
        write_json(report_path, clean_report(report))
        reports.append(summarize_probe(report, url, report_path))
    return reports


def build_summary(guest: str, label: str, version: subprocess.CompletedProcess[str], meta: dict, reports: list[dict]) -> dict:
    return {
        "schema": "dynet-vm-private-cascade-run/v1alpha1",
        "guest": guest,
        "label": label,
        "dynetVersion": (version.stdout or version.stderr).strip().splitlines()[-1]
        if "version" in locals() and (version.stdout or version.stderr).strip()
        else "",
        "metadata": meta,
        "privacy": {
            "rawSecretsStored": False,
            "identityInformationSent": False,
            "cookiesSent": False,
            "authorizationSent": False,
            "remoteSecretConfigCleaned": True,
        },
        "totals": {
            "attempted": len(reports),
            "passed": sum(1 for item in reports if item["status"] == "pass"),
            "failed": sum(1 for item in reports if item["status"] != "pass"),
        },
        "reports": reports,
    }


def build_quality_state(output_dir: Path, args: argparse.Namespace) -> None:
    command = [
        sys.executable,
        str(ROOT / "scripts" / "experiments" / "dynet_probe_quality.py"),
        "build",
        str(output_dir / "reports"),
        "--output-json",
        str(output_dir / "quality-state.json"),
        "--output-md",
        str(output_dir / "quality-state.md"),
        "--ttl-seconds",
        str(args.quality_ttl_seconds),
        "--window-seconds",
        str(args.quality_window_seconds),
    ]
    subprocess.run(command, check=True, capture_output=True, text=True)


def clean_report(report: dict) -> dict:
    return {key: value for key, value in report.items() if not key.startswith("_")}


def summarize_probe(report: dict, url: str, report_path: Path) -> dict:
    return {
        "targetUrl": url,
        "status": report.get("status"),
        "reason": report.get("reason"),
        "exitCode": report.get("_exitCode"),
        "boundSelected": final_bound_selected(report),
        "failedStage": None if report.get("status") == "pass" else failed_stage(report),
        "failureScope": failure_scope(report),
        "cascadeAttempts": cascade_attempts(report),
        "reportPath": str(report_path),
    }


def write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True))


def write_markdown(path: Path, summary: dict) -> None:
    lines = [
        "# VM Private Cascade Probe",
        "",
        f"- guest: `{summary['guest']}`",
        f"- attempted: `{summary['totals']['attempted']}`",
        f"- passed: `{summary['totals']['passed']}`",
        f"- failed: `{summary['totals']['failed']}`",
        f"- remote secret config cleaned: `{summary['privacy']['remoteSecretConfigCleaned']}`",
        "",
        "## Reports",
        "",
    ]
    for item in summary["reports"]:
        lines.append(
            f"- `{item['targetUrl']}` status=`{item['status']}` "
            f"scope=`{item.get('failureScope')}` bound=`{item['boundSelected']}` "
            f"failedStage=`{item['failedStage']}`"
        )
    path.write_text("\n".join(lines) + "\n")


def safe_slug(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.hostname or "target"
    path = parsed.path.strip("/").replace("/", "-") or "root"
    return "".join(char if char.isalnum() or char in ".-" else "-" for char in f"{host}-{path}")


def target_family(url: str) -> str:
    host = urlparse(url).hostname or url
    labels = [item for item in host.lower().strip(".").split(".") if item]
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return labels[0] if labels else "<unknown>"


def lab_args(lab: Lab) -> list[str]:
    args = ["--host", lab.host, "--lab-root", lab.root]
    if lab.dry_run:
        args.append("--dry-run")
    if lab.verbose:
        args.append("--verbose")
    if lab.log_level != "info":
        args.extend(["--log-level", lab.log_level])
    return args


def build_parser() -> argparse.ArgumentParser:
    return build_private_probe_parser(
        guest_handler=command_guest,
        paired_handler=command_paired,
        paired_selection_handler=command_paired_selection,
    )


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    lab = Lab.from_args(args)
    args.handler(lab, args)


if __name__ == "__main__":
    try:
        main()
    except CommandError as error:
        logger.error("%s", error)
        raise SystemExit(2)
    except subprocess.CalledProcessError as error:
        raise SystemExit(error.returncode)
