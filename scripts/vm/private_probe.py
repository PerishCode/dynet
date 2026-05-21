#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from common import (
    DEFAULT_VM_USER,
    ROOT,
    CommandError,
    Lab,
    RESOURCE_LIMITS,
    add_lab_options,
    guard_repo_resources,
    guest_ssh,
    join,
    logger,
    q,
    validate_name,
)


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
    command = [
        sys.executable,
        str(ROOT / "scripts" / "vmctl.py"),
        "dev",
        *lab_args(lab),
        "build",
        "--target",
        args.target,
    ]
    if args.release:
        command.append("--release")
    logger.info("build guest artifact: %s", join(command))
    if lab.dry_run:
        return ROOT / "target" / args.target / ("release" if args.release else "debug") / "dynet"
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if not lines:
        raise CommandError("dev build did not print an artifact path")
    return Path(lines[-1]).resolve()


def install_artifact(lab: Lab, guest: str, artifact: Path, args: argparse.Namespace) -> None:
    command = [
        sys.executable,
        str(ROOT / "scripts" / "vmctl.py"),
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
    ]
    logger.info("install guest artifact: %s", join(command))
    if not lab.dry_run:
        subprocess.run(command, check=True)


def build_secret_config(args: argparse.Namespace, output_dir: Path) -> tuple[str, dict]:
    output_dir.mkdir(parents=True, exist_ok=True)
    meta_path = output_dir / "meta.json"
    with tempfile.TemporaryDirectory(prefix="dynet-vm-private-") as temp_dir:
        config_path = Path(temp_dir) / "private-cascade.json"
        command = [
            sys.executable,
            str(ROOT / "scripts" / "experiments" / "tunnel_private_lab.py"),
            "build",
            "--output-config",
            str(config_path),
            "--output-meta",
            str(meta_path),
            "--tunnel-name",
            args.tunnel_name,
            "--filter",
            args.filter,
            "--strategy-key",
            args.strategy_key,
        ]
        if args.limit:
            command.extend(["--limit", str(args.limit)])
        for value in args.domain_suffix:
            command.extend(["--domain-suffix", value])
        for value in args.domain:
            command.extend(["--domain", value])
        for value in args.supported_type:
            command.extend(["--supported-type", value])
        if getattr(args, "resolve_tunnel_server", False):
            command.append("--resolve-tunnel-server")
        logger.info("build temporary dynet private config")
        subprocess.run(command, check=True, capture_output=True, text=True)
        config_text = config_path.read_text()
    meta = json.loads(meta_path.read_text())
    return config_text, meta


def write_guest_file(
    lab: Lab,
    guest: str,
    path: str,
    content: str,
    *,
    user: str,
    source: str,
) -> None:
    guest_ssh(
        lab,
        guest,
        f"umask 077 && cat > {q(path)}",
        user=user,
        source=source,
        input_text=content,
    )


def cleanup_guest_files(
    lab: Lab,
    guest: str,
    paths: list[str],
    *,
    user: str,
    source: str,
) -> None:
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
    config_text, meta = build_secret_config(args, output_dir)
    remote_config = f"/tmp/dynet-{label}-private.json"
    remote_quality = f"/tmp/dynet-{label}-quality.json" if args.quality_state else None
    guest_files = [remote_config] + ([remote_quality] if remote_quality else [])

    reports = []
    try:
        write_guest_file(
            lab,
            guest,
            remote_config,
            config_text,
            user=args.user,
            source=args.source,
        )
        if args.quality_state and remote_quality:
            write_guest_file(
                lab,
                guest,
                remote_quality,
                Path(args.quality_state).read_text(),
                user=args.user,
                source=args.source,
            )
        version = guest_ssh(
            lab,
            guest,
            f"{q(args.dynet_bin)} version",
            user=args.user,
            source=args.source,
            check=False,
            capture=True,
        )
        for url in targets:
            report = run_guest_probe(lab, guest, url, remote_config, remote_quality, args)
            report_path = report_dir / f"{safe_slug(url)}.json"
            write_json(report_path, clean_report(report))
            reports.append(summarize_probe(report, url, report_path))
    finally:
        cleanup_guest_files(lab, guest, guest_files, user=args.user, source=args.source)

    summary = {
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
    write_json(output_dir / "summary.json", summary)
    write_markdown(output_dir / "summary.md", summary)
    build_quality_state(output_dir)
    print(json.dumps({"outputDir": str(output_dir), **summary["totals"]}, sort_keys=True))
    if summary["totals"]["failed"]:
        raise SystemExit(1)


def build_quality_state(output_dir: Path) -> None:
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
        "300",
        "--window-seconds",
        "1800",
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
        "cascadeAttempts": cascade_attempts(report),
        "reportPath": str(report_path),
    }


def fields(event: dict) -> dict[str, str]:
    value = event.get("fields", {})
    if not isinstance(value, dict):
        return {}
    return {str(key): str(item) for key, item in value.items()}


def final_bound_selected(report: dict) -> str | None:
    for event in report.get("events", []):
        event_fields = fields(event)
        if (
            event.get("kind") == "dialer-cascade-attempt-finished"
            and event_fields.get("status") == "success"
        ):
            return event_fields.get("boundSelected")
    for event in report.get("events", []):
        if event.get("kind") == "dialer-cascade-selected":
            return fields(event).get("boundSelected")
    return None


def failed_stage(report: dict) -> str | None:
    for event in report.get("events", []):
        event_fields = fields(event)
        if event.get("kind") == "outbound-stage-finished" and event_fields.get("status") == "failed":
            return f"{event_fields.get('outbound', '<unknown>')}:{event_fields.get('stage', 'unknown')}"
    return None


def cascade_attempts(report: dict) -> list[dict[str, str]]:
    rows = []
    for event in report.get("events", []):
        if event.get("kind") != "dialer-cascade-attempt-finished":
            continue
        event_fields = fields(event)
        rows.append(
            {
                key: value
                for key, value in {
                    "attempt": event_fields.get("attempt"),
                    "boundSelected": event_fields.get("boundSelected"),
                    "status": event_fields.get("status"),
                    "errorType": event_fields.get("errorType"),
                    "elapsedMs": event_fields.get("elapsedMs"),
                    "httpStatus": event_fields.get("httpStatus"),
                }.items()
                if value is not None
            }
        )
    return rows


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
            f"bound=`{item['boundSelected']}` failedStage=`{item['failedStage']}`"
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
    parser = argparse.ArgumentParser(
        description="Run dynet Private cascade probes inside a disposable VM guest."
    )
    add_lab_options(parser)
    subparsers = parser.add_subparsers(dest="command", required=True)

    guest = subparsers.add_parser("guest")
    guest.add_argument("guest")
    guest.add_argument("--label")
    guest.add_argument("--output-dir")
    guest.add_argument("--user", default=DEFAULT_VM_USER)
    guest.add_argument("--source", default="lease", choices=["lease", "agent"])
    guest.add_argument("--target-url", action="append")
    guest.add_argument("--quality-state")
    guest.add_argument("--skip-install", action="store_true")
    guest.add_argument("--artifact")
    guest.add_argument("--target", default="x86_64-unknown-linux-gnu")
    guest.add_argument("--release", action="store_true")
    guest.add_argument("--dynet-bin", default="/usr/local/bin/dynet")
    guest.add_argument("--tunnel-name", default="Tunnel")
    guest.add_argument("--filter", default="Basic-美国")
    guest.add_argument("--limit", type=int, default=4)
    guest.add_argument("--strategy-key", default="cascade-quality")
    guest.add_argument("--resolve-tunnel-server", action="store_true")
    guest.add_argument("--domain", action="append", default=[])
    guest.add_argument("--domain-suffix", action="append", default=[])
    guest.add_argument("--supported-type", action="append", default=["vmess", "trojan"])
    guest.set_defaults(handler=command_guest)

    return parser


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
